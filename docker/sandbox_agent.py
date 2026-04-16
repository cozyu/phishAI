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
"""

import json
import re
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright


OUTPUT = Path("/output")
SCREENSHOTS = OUTPUT / "screenshots"
HTML_DIR = OUTPUT / "html"


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

    # 네트워크 요청 로그
    net_log = []
    context.on("request", lambda req: net_log.append({
        "method": req.method, "url": req.url, "type": req.resource_type,
    }))

    page = context.new_page()
    return browser, context, page, net_log


def extract_snapshot(page, net_log: list, name: str) -> dict:
    """현재 페이지 상태를 스냅샷으로 추출"""
    # 스크린샷 저장
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    screenshot_path = str(SCREENSHOTS / f"{name}.png")
    try:
        page.screenshot(path=screenshot_path, full_page=False)
    except Exception:
        screenshot_path = ""

    # DOM 요약 추출
    try:
        dom = page.evaluate("""() => {
            const inputs = [...document.querySelectorAll('input,textarea,select')].map(i => ({
                type: i.type || 'text', name: i.name, placeholder: i.placeholder,
                id: i.id, value: i.value ? '(has value)' : ''
            })).slice(0, 30);
            const links = [...document.querySelectorAll('a[href]')].map(a => ({
                text: a.textContent.trim().slice(0, 50), href: a.href
            })).slice(0, 20);
            const buttons = [...document.querySelectorAll('button,[role="button"],input[type="submit"]')].map(b => ({
                text: b.textContent.trim().slice(0, 50),
                type: b.type || '', id: b.id, className: b.className.slice(0, 50)
            })).slice(0, 15);
            const iframes = [...document.querySelectorAll('iframe')].map(f => ({
                src: f.src, id: f.id, name: f.name
            })).filter(f => f.src).slice(0, 10);
            const forms = [...document.querySelectorAll('form')].map(f => ({
                action: f.action, method: f.method, id: f.id,
                inputs: [...f.querySelectorAll('input,select,textarea')].map(i => i.name).slice(0, 10)
            })).slice(0, 5);
            const scripts = [...document.querySelectorAll('script[src]')].map(s => s.src).slice(0, 15);
            const domains = [...new Set(
                [...document.documentElement.outerHTML.matchAll(/https?:\\/\\/([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})/g)]
                .map(m => m[1])
            )].sort().slice(0, 30);
            return {
                title: document.title,
                url: location.href,
                inputs, links, buttons, iframes, forms,
                external_scripts: scripts,
                external_domains: domains,
            };
        }""")
    except Exception as e:
        dom = {"title": "", "url": page.url, "error": str(e)}

    # 최근 네트워크 요청 (마지막 20개)
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
        if name == "click":
            page.click(args["selector"], timeout=10000)
            page.wait_for_load_state("domcontentloaded", timeout=5000)
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

        # 초기 접속
        try:
            page.goto(url, wait_until="networkidle", timeout=20000)
        except Exception:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                emit({"error": f"접속 실패: {str(e)[:200]}"})
                browser.close()
                sys.exit(1)

        # HTML 저장
        HTML_DIR.mkdir(parents=True, exist_ok=True)
        try:
            (HTML_DIR / "index.html").write_text(page.content(), encoding="utf-8")
        except Exception:
            pass

        # 초기 스냅샷 출력
        snapshot = extract_snapshot(page, net_log, "initial")
        emit(snapshot)

        # 에이전트 루프: stdin에서 action 수신 → 실행 → 스냅샷 출력
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

            # action 실행
            action_result = execute_action(page, action)

            # 실행 후 스냅샷
            snapshot = extract_snapshot(page, net_log, f"step_{step}")
            snapshot["action_result"] = action_result

            # HTML 저장 (각 스텝)
            try:
                (HTML_DIR / f"step_{step}.html").write_text(
                    page.content(), encoding="utf-8")
            except Exception:
                pass

            emit(snapshot)

        # 네트워크 로그 전체 저장
        net_dir = OUTPUT / "network"
        net_dir.mkdir(parents=True, exist_ok=True)
        with open(net_dir / "agent_requests.json", "w") as f:
            json.dump(net_log, f, indent=2, ensure_ascii=False)

        browser.close()


if __name__ == "__main__":
    main()
