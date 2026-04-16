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
            // 요소의 고유 CSS 선택자 생성
            function sel(el) {
                if (el.id) return '#' + CSS.escape(el.id);
                const tag = el.tagName.toLowerCase();
                const parent = el.parentElement;
                if (!parent) return tag;
                const siblings = [...parent.children].filter(c => c.tagName === el.tagName);
                const idx = siblings.indexOf(el);
                const nth = siblings.length > 1 ? ':nth-child(' + ([...parent.children].indexOf(el) + 1) + ')' : '';
                const cls = el.className && typeof el.className === 'string'
                    ? '.' + el.className.trim().split(/\\s+/).slice(0, 1).map(c => CSS.escape(c)).join('.')
                    : '';
                return tag + cls + nth;
            }

            const links = [...document.querySelectorAll('a[href]')]
                .filter(a => a.offsetHeight > 0)
                .slice(0, 30)
                .map((a, i) => ({
                    idx: i, text: a.textContent.trim().slice(0, 60),
                    href: a.href, _sel: sel(a),
                    has_image: a.querySelector('img') !== null,
                }));

            const buttons = [...document.querySelectorAll('button, [role="button"], input[type="submit"]')]
                .filter(b => b.offsetHeight > 0)
                .slice(0, 20)
                .map((b, i) => ({
                    idx: i, text: (b.textContent || b.value || '').trim().slice(0, 60),
                    id: b.id, _sel: sel(b),
                }));

            const inputs = [...document.querySelectorAll('input, textarea, select')]
                .filter(i => i.offsetHeight > 0 && i.type !== 'hidden')
                .slice(0, 20)
                .map((i, i2) => ({
                    idx: i2, type: i.type || 'text', name: i.name,
                    placeholder: i.placeholder, id: i.id, _sel: sel(i),
                }));

            const iframes = [...document.querySelectorAll('iframe')]
                .filter(f => f.src).slice(0, 10)
                .map(f => ({src: f.src, id: f.id, name: f.name}));

            const forms = [...document.querySelectorAll('form')].slice(0, 5)
                .map(f => ({
                    action: f.action, method: f.method, id: f.id,
                    inputs: [...f.querySelectorAll('input,select,textarea')]
                        .map(i => i.name || i.type).slice(0, 10)
                }));

            const scripts = [...document.querySelectorAll('script[src]')]
                .map(s => s.src).slice(0, 15);

            const domains = [...new Set(
                [...document.documentElement.outerHTML.matchAll(
                    /https?:\\/\\/([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})/g
                )].map(m => m[1])
            )].sort().slice(0, 30);

            return {
                title: document.title, url: location.href,
                links, buttons, inputs, iframes, forms,
                external_scripts: scripts, external_domains: domains,
            };
        }""")
    except Exception as e:
        dom = {"title": "", "url": page.url, "error": str(e)}

    # 인덱스 기반 참조용 선택자 저장 (AI에게는 _sel을 보내지 않음)
    _last_elements["links"] = [
        {"sel": l.pop("_sel", ""), **l} for l in dom.get("links", [])
    ]
    _last_elements["buttons"] = [
        {"sel": b.pop("_sel", ""), **b} for b in dom.get("buttons", [])
    ]
    _last_elements["inputs"] = [
        {"sel": i.pop("_sel", ""), **i} for i in dom.get("inputs", [])
    ]

    recent_net = net_log[-20:] if net_log else []

    return {
        "screenshot": screenshot_path,
        "dom": dom,
        "network_requests": recent_net,
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
            sel = elements[index]["sel"]
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
            sel = elements[index]["sel"]
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
