import time
import requests
from .api_logger import log_api_call


class URLScanClient:
    name = "URLScan"
    env_keys = ["URLSCAN_API_KEY"]
    BASE = "https://urlscan.io/api/v1"

    def __init__(self, api_key: str):
        self.headers = {"API-Key": api_key, "Content-Type": "application/json"}

    def analyze_domain(self, domain: str) -> dict:
        # 기존 스캔 결과 검색
        search_url = f"{self.BASE}/search/?q=domain:{domain}"
        r = requests.get(search_url, headers=self.headers, timeout=30)
        log_api_call(self.name, "GET", search_url, r.status_code, response_body=r.text)
        r.raise_for_status()
        results = r.json().get("results", [])
        if results:
            latest = results[0]
            result_url = latest.get("result", "")
            if result_url:
                detail = requests.get(result_url, headers=self.headers, timeout=30)
                log_api_call(self.name, "GET", result_url, detail.status_code, response_body=detail.text)
                if detail.status_code == 200:
                    d = detail.json()
                    verdicts = d.get("verdicts", {})
                    page = d.get("page", {})
                    lists = d.get("lists", {})
                    return {
                        "service": self.name,
                        "score": verdicts.get("overall", {}).get("score", 0),
                        "malicious": verdicts.get("overall", {}).get("malicious", False),
                        "categories": verdicts.get("overall", {}).get("categories", []),
                        "url": page.get("url", ""),
                        "domain": page.get("domain", ""),
                        "ip": page.get("ip", ""),
                        "country": page.get("country", ""),
                        "server": page.get("server", ""),
                        "redirects": lists.get("urls", [])[:10],
                        "ips": lists.get("ips", []),
                        "screenshot": d.get("task", {}).get("screenshotURL", ""),
                    }
        return {"service": self.name, "note": "No existing scan results found"}

    def submit_scan(self, url: str) -> dict:
        r = requests.post(
            f"{self.BASE}/scan/",
            headers=self.headers,
            json={"url": url, "visibility": "unlisted"},
            timeout=30
        )
        r.raise_for_status()
        data = r.json()
        uuid = data.get("uuid", "")
        # 결과 대기 (최대 60초)
        for _ in range(6):
            time.sleep(10)
            result = requests.get(f"{self.BASE}/result/{uuid}/", timeout=30)
            if result.status_code == 200:
                return result.json()
        return {"service": self.name, "uuid": uuid, "note": "Scan submitted, results pending"}
