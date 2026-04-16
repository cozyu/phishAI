import requests
from .api_logger import log_api_call


class VirusTotalClient:
    name = "VirusTotal"
    env_keys = ["VIRUSTOTAL_API_KEY"]
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.headers = {"x-apikey": api_key}

    def analyze_domain(self, domain: str) -> dict:
        url = f"{self.BASE}/domains/{domain}"
        r = requests.get(url, headers=self.headers, timeout=30)
        log_api_call(self.name, "GET", url, r.status_code, response_body=r.text)
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "service": self.name,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "categories": data.get("categories", {}),
            "reputation": data.get("reputation", None),
            "whois": data.get("whois", "")[:500],
            "dns_records": data.get("last_dns_records", []),
            "total_votes": data.get("total_votes", {}),
            "registrar": data.get("registrar", ""),
            "creation_date": data.get("creation_date", ""),
        }

    def get_resolutions(self, domain: str, limit: int = 20) -> list:
        """Passive DNS — 과거 IP 해석 기록 조회"""
        url = f"{self.BASE}/domains/{domain}/resolutions"
        r = requests.get(url, headers=self.headers, params={"limit": limit}, timeout=30)
        log_api_call(self.name, "GET", url, r.status_code, response_body=r.text)
        if r.status_code != 200:
            return []
        results = []
        for item in r.json().get("data", []):
            attrs = item.get("attributes", {})
            results.append({
                "ip": attrs.get("ip_address", ""),
                "date": attrs.get("date", 0),
            })
        return results

    def analyze_url(self, url: str) -> dict:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        api_url = f"{self.BASE}/urls/{url_id}"
        r = requests.get(api_url, headers=self.headers, timeout=30)
        log_api_call(self.name, "GET", api_url, r.status_code, response_body=r.text)
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "service": self.name,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "final_url": data.get("last_final_url", ""),
            "title": data.get("title", ""),
            "trackers": data.get("trackers", {}),
        }
