import requests
from .api_logger import log_api_call


class CensysClient:
    name = "Censys"
    env_keys = ["CENSYS_API_ID", "CENSYS_API_SECRET"]
    BASE = "https://search.censys.io/api"

    def __init__(self, api_id: str, api_secret: str = ""):
        self.auth = (api_id, api_secret)

    def analyze_domain(self, domain: str) -> dict:
        # 호스트 검색
        url = f"{self.BASE}/v2/hosts/search"
        r = requests.get(url, params={"q": domain, "per_page": 5}, auth=self.auth, timeout=30)
        log_api_call(self.name, "GET", f"{url}?q={domain}", r.status_code, response_body=r.text)
        r.raise_for_status()
        data = r.json()
        hits = data.get("result", {}).get("hits", [])
        results = []
        for hit in hits:
            results.append({
                "ip": hit.get("ip", ""),
                "services": [
                    {"port": s.get("port"), "service_name": s.get("service_name", "")}
                    for s in hit.get("services", [])
                ],
                "location": hit.get("location", {}),
                "autonomous_system": hit.get("autonomous_system", {}),
                "operating_system": hit.get("operating_system", {}),
            })
        return {
            "service": self.name,
            "total": data.get("result", {}).get("total", 0),
            "hosts": results,
        }

    def get_host(self, ip: str) -> dict:
        url = f"{self.BASE}/v2/hosts/{ip}"
        r = requests.get(url, auth=self.auth, timeout=30)
        log_api_call(self.name, "GET", url, r.status_code, response_body=r.text)
        r.raise_for_status()
        data = r.json().get("result", {})
        return {
            "service": self.name,
            "ip": ip,
            "services": [
                {
                    "port": s.get("port"),
                    "service_name": s.get("service_name", ""),
                    "certificate": s.get("tls", {}).get("certificates", {}).get("leaf", {}).get("subject_dn", ""),
                }
                for s in data.get("services", [])
            ],
            "location": data.get("location", {}),
            "autonomous_system": data.get("autonomous_system", {}),
            "last_updated": data.get("last_updated_at", ""),
        }
