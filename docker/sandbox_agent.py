#!/usr/bin/env python3
"""phishAI 샌드박스 브라우저 에이전트

Docker 컨테이너 내에서 실행. stdin으로 action을 받고 stdout으로 결과를 반환하는 REPL.
호스트의 AI 오케스트레이터가 Gemini Function Calling으로 결정한 action을 전달한다.

사용법 (컨테이너 내):
    python3 sandbox_agent.py https://example.com

통신 프로토콜:
    - 초기 접속 후 stdout으로 스냅샷 JSON 출력 (1줄)
    - stdin에서 action JSON 수신 (1줄) → 실행 → stdout으로 결과 JSON 출력 (1줄)
    - 반복

DOM 요소 인덱스:
    스냅샷의 links, buttons, inputs에 인덱스([L0], [B0], [I0])를 부여.
    AI는 click_element(type="link", index=3) 형태로 실제 존재하는 요소를 참조.
"""

import json
import re
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright


OUTPUT = Path("/output")
SCREENSHOTS = OUTPUT / "screenshots"
HTML_DIR = OUTPUT / "html"

# 마지막 스냅샷의 DOM 요소 참조용 (인덱스 기반 클릭에 사용)
_last_elements = {"links": [], "buttons": [], "inputs": []}


def setup_browser(pw):
    """브라우저 + 컨텍스트 + 페이지 설정"""
    browser = pw.chromium.launch(
        headless=True,
        args=["--disable-dev-shm-usage", "--disable-extensions"]
    )
    context = browser.new_context(
        locale="ko-KR",
        timezone_id="Asia/Seoul",
        viewport={"width": 1280, "height": 900},
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    )

    net_log = []
    context.on("request", lambda req: net_log.append({
        "method": req.method, "url": req.url, "type": req.resource_type,
    }))

    page = context.new_page()
    return browser, context, page, net_log


def extract_snapshot(page, net_log: list, name: str) -> dict:
    """현재 페이지 상태를 스냅샷으로 추출. DOM 요소에 인덱스 부여."""
    global _last_elements

    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    screenshot_path = str(SCREENSHOTS / f"{name}.png")
    try:
        page.screenshot(path=screenshot_path, full_page=False)
    except Exception:
        screenshot_path = ""

    try:
        dom = page.evaluate("""() => {
            // 이전 phishai-idx 태그 제거
            document.querySelectorAll('[data-phishai-idx]').forEach(
                e => e.removeAttribute('data-phishai-idx')
            );

            const visible = el => el.offsetHeight > 0 && el.offsetWidth > 0;
            const vh = window.innerHeight || 900;
            const vw = window.innerWidth || 1280;

            // y_band: 페이지 상/중/하 위치를 문자열로 (CTA는 주로 middle/bottom)
            function yBand(rect) {
                const centerY = rect.top + rect.height / 2;
                if (centerY < vh * 0.33) return 'top';
                if (centerY < vh * 0.67) return 'middle';
                return 'bottom';
            }

            // 크기 분류: 상대적으로 큰 요소는 CTA 가능성 높음
            function sizeClass(rect) {
                const area = rect.width * rect.height;
                if (area > 20000) return 'large';
                if (area > 5000) return 'medium';
                return 'small';
            }

            // 텍스트별 등장 횟수 맵 (AI가 중복 버튼을 판별할 근거)
            const buttonTextFreq = {};
            const allBtns = [...document.querySelectorAll(
                'button, [role="button"], input[type="submit"]'
            )].filter(visible);
            for (const b of allBtns) {
                const t = (b.textContent || b.value || '').trim().slice(0, 80);
                buttonTextFreq[t] = (buttonTextFreq[t] || 0) + 1;
            }

            // 모든 visible 요소를 AI에게 전달 (인위적 slice 없음)
            // — 대형 페이지의 pathological case 방지용 상한선만 500으로 설정
            const HARD_CAP = 500;

            // Links
            const links = [...document.querySelectorAll('a[href]')]
                .filter(visible)
                .slice(0, HARD_CAP)
                .map((a, i) => {
                    a.setAttribute('data-phishai-idx', 'link-' + i);
                    const r = a.getBoundingClientRect();
                    return {
                        idx: i,
                        text: a.textContent.trim().slice(0, 80),
                        href: a.href,
                        has_image: a.querySelector('img') !== null,
                        y_band: yBand(r),
                    };
                });

            // Buttons — 메타데이터(same_text_count, y_band, size)로 AI 판단 지원
            const buttons = allBtns.slice(0, HARD_CAP).map((b, i) => {
                b.setAttribute('data-phishai-idx', 'button-' + i);
                const r = b.getBoundingClientRect();
                const text = (b.textContent || b.value || '').trim().slice(0, 80);
                return {
                    idx: i,
                    text,
                    id: b.id,
                    tag: b.tagName.toLowerCase(),
                    same_text_count: buttonTextFreq[text] || 1,
                    y_band: yBand(r),
                    size: sizeClass(r),
                };
            });

            // Inputs
            const inputs = [...document.querySelectorAll('input, textarea, select')]
                .filter(i => visible(i) && i.type !== 'hidden')
                .slice(0, HARD_CAP)
                .map((i, idx) => {
                    i.setAttribute('data-phishai-idx', 'input-' + idx);
                    return {
                        idx, type: i.type || 'text', name: i.name,
                        placeholder: i.placeholder, id: i.id,
                    };
                });

            const iframes = [...document.querySelectorAll('iframe')]
                .filter(f => f.src)
                .slice(0, HARD_CAP)
                .map(f => ({src: f.src, id: f.id, name: f.name}));

            const forms = [...document.querySelectorAll('form')]
                .slice(0, HARD_CAP)
                .map(f => ({
                    action: f.action, method: f.method, id: f.id,
                    inputs: [...f.querySelectorAll('input,select,textarea')]
                        .map(i => ({name: i.name, type: i.type, placeholder: i.placeholder}))
                }));

            const scripts = [...document.querySelectorAll('script[src]')]
                .map(s => s.src).slice(0, HARD_CAP);

            const domains = [...new Set(
                [...document.documentElement.outerHTML.matchAll(
                    /https?:\\/\\/([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})/g
                )].map(m => m[1])
            )].sort();

            // 푸터 업체 정보 추출 (회사명/사업자번호/주소/전화/이메일)
            const footerEl = document.querySelector('footer, [class*="footer" i], [id*="footer" i]');
            const footerText = footerEl ? footerEl.innerText.slice(0, 3000) : '';

            // 이메일/전화번호/사업자번호 패턴 추출 (전체 페이지)
            const fullText = document.body ? document.body.innerText.slice(0, 20000) : '';
            const emails = [...new Set(
                (fullText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g) || [])
            )];
            const phones = [...new Set(
                (fullText.match(/\\+?\\d{1,3}[-\\s]?\\d{2,4}[-\\s]?\\d{3,4}[-\\s]?\\d{3,4}/g) || [])
            )].slice(0, 20);

            // 사회공학적 조작 키워드 감지
            const scamPatterns = [];
            const scamKeywords = [
                ['한정', '한정 수량'], ['남음', '남았'], ['단 ', '단 N개'],
                ['카운트다운', '카운트다운 타이머'], ['타이머', '타이머'],
                ['판매 완료', '판매 완료'], ['구매 중', '실시간 구매 중'],
                ['남은 ', '남은 시간'], ['긴급', '긴급 할인'],
                ['무료 배송', '무료 배송'], ['할인', '파격 할인'],
                ['安全验证', '중국어 CAPTCHA'], ['滑块', '중국어 슬라이더 CAPTCHA']
            ];
            for (const [k, label] of scamKeywords) {
                if (fullText.includes(k)) scamPatterns.push(label);
            }

            // 통합사회신용코드 (중국 사업자) / 대한민국 사업자 번호 추출
            const bizCodes = [...new Set([
                ...(fullText.match(/\\b9\\d{17}[A-Z0-9]\\b/g) || []),  // 중국 통합사회신용코드 18자리
                ...(fullText.match(/\\b\\d{3}-?\\d{2}-?\\d{5}\\b/g) || [])  // 한국 사업자번호
            ])];

            return {
                title: document.title, url: location.href,
                links, buttons, inputs, iframes, forms,
                external_scripts: scripts, external_domains: domains,
                footer_text: footerText,
                emails_on_page: emails,
                phones_on_page: phones,
                business_codes: bizCodes,
                scam_patterns: scamPatterns,
                page_text_preview: fullText.slice(0, 2000),
            };
        }""")
    except Exception as e:
        dom = {"title": "", "url": page.url, "error": str(e)}

    # 인덱스 기반 참조용 (클릭/입력 시 data-phishai-idx 속성으로 고유 선택)
    _last_elements["links"] = list(dom.get("links", []))
    _last_elements["buttons"] = list(dom.get("buttons", []))
    _last_elements["inputs"] = list(dom.get("inputs", []))

    # 현재 스냅샷 이후의 네트워크 요청 전부 전달 (축약 없음)
    # — tracking pixel / statistics / API 호출 URL을 AI가 분석에 활용
    all_net = list(net_log)
    # tracking pixel만 별도로 태그 (.gif, statistics, tracker, beacon, collect, pixel)
    tracking = [r for r in all_net if re.search(
        r"\.gif|/statistics/|/tracker|/beacon|/collect|/pixel|/md\.gif",
        r.get("url", ""), re.I
    )]

    return {
        "screenshot": screenshot_path,
        "dom": dom,
        "network_requests": all_net,
        "tracking_requests": tracking,
    }


def execute_action(page, action: dict) -> dict:
    """단일 action 실행. 성공/실패 결과 반환."""
    name = action.get("name", "")
    args = action.get("args", {})
    result = {"status": "ok"}

    try:
        if name == "click_element":
            el_type = args.get("type", "link")  # "link" | "button"
            index = int(args.get("index", 0))
            key = "links" if el_type == "link" else "buttons"
            elements = _last_elements.get(key, [])
            if index < 0 or index >= len(elements):
                return {"status": "error",
                        "error": f"{key}[{index}] 범위 초과 (총 {len(elements)}개)"}
            sel = f'[data-phishai-idx="{el_type}-{index}"]'
            try:
                page.locator(sel).scroll_into_view_if_needed(timeout=3000)
            except Exception:
                pass
            page.click(sel, timeout=10000)
            try:
                page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                page.wait_for_timeout(2000)

        elif name == "fill_element":
            index = int(args.get("index", 0))
            value = args.get("value", "")
            elements = _last_elements.get("inputs", [])
            if index < 0 or index >= len(elements):
                return {"status": "error",
                        "error": f"inputs[{index}] 범위 초과 (총 {len(elements)}개)"}
            sel = f'[data-phishai-idx="input-{index}"]'
            page.fill(sel, value, timeout=10000)

        elif name == "click":
            # 레거시 호환: CSS 선택자 직접 클릭
            page.click(args["selector"], timeout=10000)
            try:
                page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                page.wait_for_timeout(2000)

        elif name == "fill":
            page.fill(args["selector"], args["value"], timeout=10000)

        elif name == "goto":
            page.goto(args["url"], wait_until="domcontentloaded", timeout=15000)

        elif name == "scroll":
            amount = args.get("amount", 500)
            page.evaluate(f"window.scrollBy(0, {int(amount)})")

        elif name == "hover":
            page.hover(args["selector"], timeout=10000)

        elif name == "select_option":
            page.select_option(args["selector"], args["value"], timeout=10000)

        elif name == "wait":
            state = args.get("state", "networkidle")
            page.wait_for_load_state(state, timeout=10000)

        else:
            result = {"status": "skipped", "reason": f"unknown action: {name}"}

    except Exception as e:
        result = {"status": "error", "error": str(e)[:200]}

    return result


def emit(data: dict):
    """JSON을 stdout으로 1줄 출력 (호스트가 읽음)"""
    print(json.dumps(data, ensure_ascii=False), flush=True)


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: sandbox_agent.py <url>"}), flush=True)
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"

    with sync_playwright() as pw:
        browser, context, page, net_log = setup_browser(pw)

        try:
            page.goto(url, wait_until="networkidle", timeout=20000)
        except Exception:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                emit({"error": f"접속 실패: {str(e)[:200]}"})
                browser.close()
                sys.exit(1)

        HTML_DIR.mkdir(parents=True, exist_ok=True)
        try:
            (HTML_DIR / "index.html").write_text(page.content(), encoding="utf-8")
        except Exception:
            pass

        snapshot = extract_snapshot(page, net_log, "initial")
        emit(snapshot)

        step = 0
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                action = json.loads(line)
            except json.JSONDecodeError:
                emit({"error": "invalid JSON"})
                continue

            step += 1
            action_result = execute_action(page, action)

            snapshot = extract_snapshot(page, net_log, f"step_{step}")
            snapshot["action_result"] = action_result

            try:
                (HTML_DIR / f"step_{step}.html").write_text(
                    page.content(), encoding="utf-8")
            except Exception:
                pass

            emit(snapshot)

        net_dir = OUTPUT / "network"
        net_dir.mkdir(parents=True, exist_ok=True)
        with open(net_dir / "agent_requests.json", "w") as f:
            json.dump(net_log, f, indent=2, ensure_ascii=False)

        browser.close()


if __name__ == "__main__":
    main()
