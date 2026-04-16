import time
import requests
from .api_logger import log_api_call


class CriminalIPClient:
    name = "CriminalIP"
    env_keys = ["CRIMINALIP_API_KEY"]
    BASE = "https://api.criminalip.io/v1"

    def __init__(self, api_key: str):
        self.headers = {"x-api-key": api_key}

    def analyze_domain(self, domain: str) -> dict:
        """도메인 분석 — 데이터 없으면(404) 자동으로 풀스캔 요청 후 결과 반환"""
        url = f"{self.BASE}/domain/report"
        r = requests.get(url, params={"query": domain}, headers=self.headers, timeout=30)
        log_api_call(self.name, "GET", f"{url}?query={domain}", r.status_code, response_body=r.text)
        data = r.json()

        # 데이터 없으면 풀스캔 요청
        if data.get("status") == 404 or not data.get("data", True):
            scan_result = self._request_fullscan(domain)
            if scan_result:
                return scan_result

        r.raise_for_status()
        return {
            "service": self.name,
            "is_malicious": data.get("is_malicious", None),
            "phishing": data.get("phishing", {}),
            "ip_info": data.get("ip", {}),
            "certificates": data.get("certificates", [])[:5],
            "connected_domains": data.get("connected_domains", [])[:10],
            "dns": data.get("dns", {}),
            "technologies": data.get("technologies", []),
            "score": data.get("score", {}),
            "raw_status": data.get("status", None),
        }

    def _request_fullscan(self, domain: str) -> dict:
        """풀스캔 요청 → 폴링 → 결과 반환"""
        # 스캔 요청
        scan_url = f"{self.BASE}/domain/scan"
        r = requests.post(scan_url, headers=self.headers, data={"query": domain}, timeout=30)
        log_api_call(self.name, "POST", scan_url, r.status_code, response_body=r.text)
        if r.status_code != 200:
            return None
        scan_id = r.json().get("data", {}).get("scan_id")
        if not scan_id:
            return None

        # 폴링 (최대 90초)
        status_url = f"{self.BASE}/domain/status/{scan_id}"
        for _ in range(9):
            time.sleep(10)
            sr = requests.get(status_url, headers=self.headers, timeout=15)
            log_api_call(self.name, "GET", status_url, sr.status_code)
            pct = sr.json().get("data", {}).get("scan_percentage", 0)
            if pct >= 100:
                break

        # 결과 조회
        report_url = f"{self.BASE}/domain/report/{scan_id}"
        rr = requests.get(report_url, headers=self.headers, timeout=30)
        log_api_call(self.name, "GET", report_url, rr.status_code, response_body=rr.text)
        if rr.status_code != 200:
            return None
        d = rr.json().get("data", {})
        summary = d.get("summary", {})
        return {
            "service": self.name,
            "scan_id": scan_id,
            "fullscan": True,
            "dga_score": d.get("classification", {}).get("dga_score"),
            "diff_domain_favicon": summary.get("diff_domain_favicon"),
            "js_obfuscated": summary.get("js_obfuscated"),
            "mail_server": summary.get("mail_server"),
            "certificates": d.get("certificates", []),
            "technologies": [t.get("name") for t in d.get("technologies", [])],
            "connected_domains": [
                cd["main_domain"]["domain"]
                for cd in d.get("connected_domain_subdomain", [])
            ],
            "connected_ips": [
                {"ip": ip.get("ip"), "as": ip.get("as_name"), "score": ip.get("score")}
                for ip in d.get("connected_ip_info", [])
            ],
            "cookies": d.get("cookies", []),
            "security_headers": d.get("security_headers", []),
        }

    def analyze_ip(self, ip: str) -> dict:
        url = f"{self.BASE}/ip/data"
        r = requests.get(url, params={"ip": ip}, headers=self.headers, timeout=30)
        log_api_call(self.name, "GET", f"{url}?ip={ip}", r.status_code, response_body=r.text)
        r.raise_for_status()
        data = r.json()
        return {
            "service": self.name,
            "ip": ip,
            "score": data.get("score", {}),
            "issues": data.get("issues", []),
            "ports": data.get("ports", [])[:20],
            "hostname": data.get("hostname", ""),
        }
