"""사이트 직접 접근 분석 — DOM 수집 + 동적 행위 분석

headless Chrome으로 사이트에 접근하여:
1. HTML DOM 수집 + 외부 도메인/스크립트 추출
2. 결제 페이지 식별 및 폼/iframe 분석
3. 네트워크 요청에서 데이터 전송 경로 추적

Playwright MCP 없이 독립 실행 가능.
"""

import json
import os
import re
import subprocess
from pathlib import Path

_UID_GID = f"{os.getuid()}:{os.getgid()}"
from .api_logger import log_api_call


DOCKER_IMAGE = "phishai-sandbox"


class SiteAnalyzer:
    name = "SiteAnalyzer"

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.chrome = self._find_chrome()
        self.docker = self._check_docker()

    def _find_chrome(self):
        for candidate in ["google-chrome", "google-chrome-stable", "chromium-browser", "chromium"]:
            try:
                subprocess.run([candidate, "--version"], capture_output=True, timeout=5)
                return candidate
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None

    def _check_docker(self) -> bool:
        """Docker + phishai-sandbox 이미지 사용 가능 여부"""
        try:
            r = subprocess.run(
                ["docker", "image", "inspect", DOCKER_IMAGE],
                capture_output=True, timeout=5
            )
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def dynamic_analyze(self, url: str) -> dict:
        """AI 기반 동적 분석 (실패 시 레거시 폴백)"""
        gemini_key = os.getenv("GEMINI_API_KEY", "")
        if gemini_key and self.docker:
            try:
                from .ai_dynamic_analyzer import AIDynamicAnalyzer
                result = AIDynamicAnalyzer(gemini_key, self.evidence_dir).analyze(url)
                if "error" not in result:
                    result["service"] = "SiteAnalyzer-AI"
                    return result
                print(f"  [AI동적분석] 레거시로 폴백: {result.get('error', '')[:60]}")
            except Exception as e:
                print(f"  [AI동적분석] 레거시로 폴백: {e}")

        return self._dynamic_analyze_legacy(url)

    def _dynamic_analyze_legacy(self, url: str) -> dict:
        """레거시: Docker 샌드박스 내 Playwright로 동적 분석 (쇼핑몰 특화)"""
        if not self.docker:
            return {"error": "Docker 또는 phishai-sandbox 이미지 없음"}

        edir = str(self.evidence_dir.resolve())
        try:
            result = subprocess.run([
                "docker", "run", "--rm",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--memory=512m", "--cpus=1",
                "--user", _UID_GID,
                "--tmpfs", "/tmp:size=128m",
                "-v", f"{edir}:/output",
                DOCKER_IMAGE, "sandbox_analyze.py", url
            ], capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                return {"error": f"Docker 실행 실패: {result.stderr[-300:]}"}

        except subprocess.TimeoutExpired:
            return {"error": "Docker 분석 타임아웃 (120초)"}

        # 결과 파일 읽기
        result_file = self.evidence_dir / "ti_responses" / "dynamic_result.json"
        if result_file.exists():
            with open(result_file) as f:
                data = json.load(f)
            data["service"] = "SiteAnalyzer-Docker"
            return data

        return {"error": "결과 파일 생성 실패"}

    def collect_dom(self, url: str) -> dict:
        """curl 기반 정적 DOM 분석 (Docker 없는 환경에서 사용)"""
        return self._static_dom_analysis(url)

    def _static_dom_analysis(self, url: str) -> dict:
        """curl로 HTML을 가져와서 정적 분석"""
        try:
            r = subprocess.run(
                ["curl", "-sL", "--compressed", "--max-time", "15",
                 "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                 "-H", "Accept-Language: ko-KR,ko;q=0.9",
                 url],
                capture_output=True, text=True, timeout=20
            )
            html = r.stdout
        except Exception as e:
            return {"error": str(e)}

        if not html:
            return {"error": "Empty response"}

        # HTML 저장
        html_dir = self.evidence_dir / "html"
        html_dir.mkdir(parents=True, exist_ok=True)
        (html_dir / "index.html").write_text(html, encoding="utf-8")

        return self._extract_from_html(html, url)

    def _extract_from_html(self, html: str, url: str) -> dict:
        """HTML에서 보안 분석에 필요한 정보 추출"""
        # 외부 도메인
        domains = sorted(set(re.findall(r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', html)))

        # 스크립트
        external_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', html)
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
        inline_scripts = [s.strip() for s in inline_scripts if s.strip() and 'src=' not in s[:50]]

        # iframe
        iframes = re.findall(r'<iframe[^>]+src=["\']([^"\']+)', html)

        # 입력 폼
        inputs = []
        for m in re.finditer(r'<input[^>]*>', html):
            tag = m.group()
            itype = re.search(r'type=["\']([^"\']+)', tag)
            name = re.search(r'name=["\']([^"\']+)', tag)
            placeholder = re.search(r'placeholder=["\']([^"\']+)', tag)
            inputs.append({
                "type": itype.group(1) if itype else "text",
                "name": name.group(1) if name else "",
                "placeholder": placeholder.group(1) if placeholder else "",
            })

        # 의심 패턴
        suspicious = {}
        for pattern in ["cookie", "tracking", "pixel", "fingerprint", "localStorage",
                        "eval(", "atob", "document.write", "XMLHttpRequest"]:
            count = html.lower().count(pattern.lower())
            if count:
                suspicious[pattern] = count

        # ShopPlus / 플랫폼 식별
        platform = {}
        sp = re.search(r'window\.ShopPlus\.site\s*=\s*(\{.*?\});', html)
        if sp:
            try:
                spd = json.loads(sp.group(1))
                platform = {
                    "name": "ShopPlus",
                    "site_id": spd.get("id"),
                    "uid": spd.get("uid"),
                    "org_code": spd.get("orgCode"),
                    "market_id": spd.get("marketId"),
                    "domain": spd.get("domain"),
                }
            except json.JSONDecodeError:
                pass

        # Alibaba ARMS
        arms = re.search(r'pid:["\']([^"\']+)', html)
        if arms:
            platform["alibaba_arms_pid"] = arms.group(1)

        # base64 디코딩 시도
        b64_data = []
        for m in re.findall(r"atob\(['\"]([A-Za-z0-9+/=]+)['\"]\)", html):
            try:
                import base64
                decoded = base64.b64decode(m).decode("utf-8", errors="ignore")
                b64_data.append({"encoded": m[:50], "decoded": decoded[:200]})
            except (ValueError, UnicodeDecodeError):
                pass  # 유효하지 않은 base64 데이터는 분석 대상 아님

        # meta 태그
        metas = []
        for m in re.finditer(r'<meta\s+([^>]+)>', html):
            attrs = m.group(1)
            name_m = re.search(r'(?:name|property)=["\']([^"\']+)', attrs)
            content_m = re.search(r'content=["\']([^"\']+)', attrs)
            if name_m and content_m:
                metas.append({"name": name_m.group(1), "content": content_m.group(1)})

        result = {
            "service": self.name,
            "url": url,
            "html_size": len(html),
            "script_count": html.count("<script"),
            "external_domains": domains,
            "external_scripts": external_scripts,
            "inline_script_count": len(inline_scripts),
            "iframes": iframes,
            "input_fields": inputs,
            "suspicious_patterns": suspicious,
            "platform": platform,
            "base64_decoded": b64_data,
            "meta_tags": metas,
        }

        # 결과 저장
        ti_dir = self.evidence_dir / "ti_responses"
        ti_dir.mkdir(parents=True, exist_ok=True)
        with open(ti_dir / "dom_analysis.json", "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return result

    def analyze_checkout(self, domain: str) -> dict:
        """결제 페이지 분석 — checkout/payment URL 패턴 탐색"""
        checkout_urls = [
            f"https://{domain}/checkout",
            f"https://{domain}/payment",
            f"https://{domain}/cart",
        ]
        results = {"checkout_found": False, "payment_gateways": [], "pii_fields": [], "iframes": []}

        for url in checkout_urls:
            try:
                r = subprocess.run(
                    ["curl", "-sL", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}",
                     "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                     url],
                    capture_output=True, text=True, timeout=15
                )
                if r.stdout.strip() in ("200", "301", "302"):
                    results["checkout_found"] = True
                    results["checkout_url"] = url
                    break
            except Exception:
                continue

        return results
