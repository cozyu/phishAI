#!/usr/bin/env python3
"""phishAI 샌드박스 동적 분석 스크립트

Docker 컨테이너 내에서 실행되어 Playwright로 악성사이트를 안전하게 분석.
결과는 /output/dynamic_result.json에 저장.

사용법 (컨테이너 내):
    python3 sandbox_analyze.py https://example.com
"""

import json
import re
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright


OUTPUT = Path("/output")


def analyze(url: str) -> dict:
    result = {
        "url": url,
        "pages": [],
        "network_requests": [],
        "checkout": None,
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--disable-dev-shm-usage", "--disable-extensions"]
        )
        context = browser.new_context(
            locale="ko-KR",
            timezone_id="Asia/Seoul",
            viewport={"width": 1280, "height": 900},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        )

        # 네트워크 요청 수집
        net_log = []
        context.on("request", lambda req: net_log.append({
            "method": req.method, "url": req.url,
            "type": req.resource_type,
        }))
        context.on("response", lambda resp: _update_response(net_log, resp))

        page = context.new_page()

        # === 1단계: 메인 페이지 ===
        try:
            page.goto(url, wait_until="networkidle", timeout=20000)
        except Exception:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                result["error"] = str(e)
                browser.close()
                return result

        main_data = _extract_page_data(page)
        result["pages"].append({"step": "main", **main_data})

        # 스크린샷
        screenshots = OUTPUT / "screenshots"
        screenshots.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(screenshots / "main.png"), full_page=True)

        # HTML 저장
        html_dir = OUTPUT / "html"
        html_dir.mkdir(parents=True, exist_ok=True)
        html = page.content()
        (html_dir / "index.html").write_text(html, encoding="utf-8")

        # === 2단계: 상품 페이지 탐색 ===
        product_link = _find_product_link(page)
        if product_link:
            try:
                page.goto(product_link, wait_until="networkidle", timeout=15000)
                prod_data = _extract_page_data(page)
                result["pages"].append({"step": "product", **prod_data})
                page.screenshot(path=str(screenshots / "product.png"), full_page=True)

                # === 3단계: 결제 페이지 진입 ===
                checkout_url = _find_checkout_trigger(page)
                if checkout_url:
                    try:
                        page.goto(checkout_url, wait_until="networkidle", timeout=15000)
                    except Exception:
                        # 버튼 클릭으로 시도
                        _click_buy_button(page)

                    checkout_data = _extract_page_data(page)
                    checkout_data["payment_iframes"] = _extract_payment_iframes(page)
                    checkout_data["pii_fields"] = _extract_pii_fields(page)
                    result["checkout"] = checkout_data
                    page.screenshot(path=str(screenshots / "checkout.png"), full_page=True)
                    (html_dir / "checkout.html").write_text(page.content(), encoding="utf-8")

            except Exception as e:
                result["product_error"] = str(e)

        result["network_requests"] = net_log
        browser.close()

    return result


def _update_response(net_log: list, resp):
    """네트워크 응답 정보 업데이트"""
    for entry in reversed(net_log):
        if entry["url"] == resp.url and "status" not in entry:
            entry["status"] = resp.status
            entry["content_type"] = resp.headers.get("content-type", "")
            break


def _extract_page_data(page) -> dict:
    """페이지에서 보안 분석 정보 추출"""
    try:
        data = page.evaluate("""() => {
            const scripts = [...document.querySelectorAll('script[src]')].map(s => s.src);
            const iframes = [...document.querySelectorAll('iframe')].map(f => ({
                src: f.src, id: f.id, name: f.name
            })).filter(f => f.src);
            const inputs = [...document.querySelectorAll('input,textarea,select')].map(i => ({
                type: i.type || 'text', name: i.name,
                placeholder: i.placeholder,
                id: i.id
            }));
            const domains = [...new Set(
                [...document.documentElement.outerHTML.matchAll(/https?:\\/\\/([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})/g)]
                .map(m => m[1])
            )].sort();
            return {
                title: document.title,
                url: location.href,
                external_scripts: scripts,
                iframes: iframes,
                input_fields: inputs,
                external_domains: domains,
            };
        }""")
        return data
    except Exception:
        return {"title": page.title(), "url": page.url}


def _find_product_link(page) -> str:
    """상품 상세 페이지 링크 찾기"""
    try:
        links = page.evaluate("""() => {
            const anchors = document.querySelectorAll('a[href*="detail"], a[href*="product"], a[href*="item"]');
            return [...anchors].slice(0, 3).map(a => a.href);
        }""")
        return links[0] if links else None
    except Exception:
        return None


def _find_checkout_trigger(page) -> str:
    """결제 페이지 URL 또는 버튼 탐색"""
    try:
        links = page.evaluate("""() => {
            const buyBtns = document.querySelectorAll(
                'a[href*="checkout"], a[href*="payment"], button:has-text("구매"), button:has-text("buy")'
            );
            for (const btn of buyBtns) {
                if (btn.href) return btn.href;
            }
            return null;
        }""")
        return links
    except Exception:
        return None


def _click_buy_button(page):
    """구매 버튼 클릭 시도"""
    for selector in [
        'button:has-text("구매")', 'button:has-text("buy")',
        'a:has-text("구매")', '[class*="buy"]', '[class*="checkout"]'
    ]:
        try:
            el = page.locator(selector).first
            if el.is_visible():
                el.click(timeout=5000)
                page.wait_for_load_state("networkidle", timeout=10000)
                return
        except Exception:
            continue


def _extract_payment_iframes(page) -> list:
    """결제 관련 iframe 추출 (PG사 식별)"""
    try:
        iframes = page.evaluate("""() => {
            return [...document.querySelectorAll('iframe')]
                .filter(f => f.src)
                .map(f => f.src)
                .filter(src =>
                    src.includes('checkout') || src.includes('payment') ||
                    src.includes('stripe') || src.includes('airwallex') ||
                    src.includes('paypal') || src.includes('toss') ||
                    src.includes('kakaopay') || src.includes('fingerprint')
                );
        }""")
        return iframes
    except Exception:
        return []


def _extract_pii_fields(page) -> list:
    """개인정보 입력 필드 추출"""
    try:
        fields = page.evaluate("""() => {
            const selectors = 'input[type="text"], input[type="email"], input[type="tel"], ' +
                'input[type="password"], input[type="number"], input[name*="card"], ' +
                'input[name*="name"], input[name*="phone"], input[name*="address"], ' +
                'input[name*="email"], input[placeholder*="카드"], input[placeholder*="번호"]';
            return [...document.querySelectorAll(selectors)].map(i => ({
                type: i.type, name: i.name, placeholder: i.placeholder,
                id: i.id, autocomplete: i.autocomplete
            }));
        }""")
        return fields
    except Exception:
        return []


def main():
    if len(sys.argv) < 2:
        print("Usage: sandbox_analyze.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"

    print(f"[*] 샌드박스 동적 분석: {url}")
    result = analyze(url)

    # 결과 저장
    OUTPUT.mkdir(parents=True, exist_ok=True)
    ti_dir = OUTPUT / "ti_responses"
    ti_dir.mkdir(parents=True, exist_ok=True)

    with open(ti_dir / "dynamic_result.json", "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)

    # 네트워크 로그 별도 저장
    net_dir = OUTPUT / "network"
    net_dir.mkdir(parents=True, exist_ok=True)
    with open(net_dir / "dynamic_requests.json", "w") as f:
        json.dump(result.get("network_requests", []), f, indent=2, ensure_ascii=False)

    # 요약 출력
    pages = result.get("pages", [])
    print(f"[*] 분석 페이지: {len(pages)}개")
    for p in pages:
        print(f"  [{p.get('step')}] {p.get('url', 'N/A')}")
        print(f"    스크립트: {len(p.get('external_scripts', []))}개, "
              f"iframe: {len(p.get('iframes', []))}개, "
              f"입력필드: {len(p.get('input_fields', []))}개")

    if result.get("checkout"):
        co = result["checkout"]
        print(f"  [checkout] PG iframe: {len(co.get('payment_iframes', []))}개")
        print(f"    PII 필드: {len(co.get('pii_fields', []))}개")
        for iframe in co.get("payment_iframes", []):
            print(f"    PG: {iframe[:80]}")

    print(f"[*] 네트워크 요청: {len(result.get('network_requests', []))}개")
    print("[*] 완료")


if __name__ == "__main__":
    main()
