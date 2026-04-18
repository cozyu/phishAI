"""phishAI TI(Threat Intelligence) 분석 모듈

DNS/WHOIS 조회, TI API 병렬 조회, Passive DNS, 인프라 프로빙을 수행한다.
"""

import json
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ti_clients.whois_client import whois_lookup


def dns_lookup(domain: str) -> dict:
    result = {"A": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        result["A"] = list(set(addr[4][0] for addr in ips))
    except socket.gaierror:
        pass
    for rtype in ["MX", "NS", "TXT", "CNAME"]:
        try:
            out = subprocess.run(
                ["dig", "+short", domain, rtype],
                capture_output=True, text=True, timeout=10
            )
            lines = [l.strip() for l in out.stdout.strip().split("\n") if l.strip()]
            result[rtype] = lines
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return result


def _run_ti_client(client_cls, domain: str, env: dict) -> dict:
    keys = client_cls.env_keys
    vals = [env.get(k, "") for k in keys]
    if not all(vals):
        return {"service": client_cls.name, "error": f"API key missing ({', '.join(keys)})"}
    try:
        client = client_cls(*vals)
        return client.analyze_domain(domain)
    except Exception as e:
        return {"service": client_cls.name, "error": str(e)}


def run_ti_analysis(domain: str, env: dict, edir: Path) -> dict:
    """TI 분석 전체를 수행하고 결과를 반환한다.

    Returns:
        {"dns": dict, "whois": str, "ti_results": list,
         "passive_dns": list, "infra_probe": dict}
    """
    # DNS/WHOIS
    print("[*] DNS 조회 중...")
    dns = dns_lookup(domain)
    with open(edir / "dns_whois" / "dns.json", "w") as f:
        json.dump(dns, f, indent=2, ensure_ascii=False)

    print("[*] WHOIS 조회 중...")
    whois = whois_lookup(domain)
    with open(edir / "dns_whois" / "whois.txt", "w") as f:
        f.write(whois)

    # TI API 병렬 조회
    from ti_clients import ALL_CLIENTS
    ti_results = []
    active = [c for c in ALL_CLIENTS if all(env.get(k) for k in c.env_keys)]
    skipped = [c for c in ALL_CLIENTS if not all(env.get(k) for k in c.env_keys)]

    if skipped:
        print(f"[!] API 키 없어 건너뜀: {', '.join(c.name for c in skipped)}")
    if active:
        print(f"[*] TI 조회 중: {', '.join(c.name for c in active)}")

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_run_ti_client, c, domain, env): c for c in ALL_CLIENTS}
        for future in as_completed(futures):
            result = future.result()
            ti_results.append(result)
            svc = result.get("service", "?")
            if "error" in result:
                print(f"  [{svc}] ⚠ {result['error']}")
            else:
                print(f"  [{svc}] ✓ 완료")
            fname = svc.lower().replace(" ", "_") + ".json"
            with open(edir / "ti_responses" / fname, "w") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

    # VT Passive DNS
    passive_dns = []
    vt_key = env.get("VIRUSTOTAL_API_KEY", "")
    if vt_key:
        print("[*] VT Passive DNS 조회 중...")
        try:
            from ti_clients.virustotal import VirusTotalClient
            vt = VirusTotalClient(vt_key)
            passive_dns = vt.get_resolutions(domain)
            if passive_dns:
                non_cdn = [r for r in passive_dns if not r["ip"].startswith(("18.", "13.", "3.", "108."))]
                print(f"  [PassiveDNS] {len(passive_dns)}건 (비-CDN: {len(non_cdn)}건)")
            with open(edir / "ti_responses" / "passive_dns.json", "w") as f:
                json.dump(passive_dns, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"  [PassiveDNS] ⚠ {e}")

    # 인프라 프로빙
    infra_result = _run_infra_probe(domain, ti_results, {}, edir)

    return {
        "dns": dns,
        "whois": whois[:2000],
        "ti_results": ti_results,
        "passive_dns": passive_dns,
        "infra_probe": infra_result,
    }


def _run_infra_probe(domain: str, ti_results: list,
                     dom_result: dict, edir: Path) -> dict:
    """인프라 프로빙 (CDN 우회 원본 서버 추적)"""
    print("[*] 인프라 도메인 프로빙 중...")
    infra_result = {}
    try:
        from ti_clients.infra_prober import probe_infrastructure
        infra_domains = set()
        for ti in ti_results:
            for url in ti.get("redirects", []):
                m = re.search(r'https?://([a-zA-Z0-9.-]+)', url)
                if m and m.group(1) != domain:
                    infra_domains.add(m.group(1))
        for d in dom_result.get("external_domains", []):
            if d != domain:
                infra_domains.add(d)
        for ti in ti_results:
            if ti.get("service") == "CriminalIP":
                for d in ti.get("connected_domains", []):
                    if d != domain:
                        infra_domains.add(d)
        if infra_domains:
            print(f"  대상: {', '.join(sorted(infra_domains)[:6])}...")
            infra_result = probe_infrastructure(sorted(infra_domains))
            with open(edir / "ti_responses" / "infra_probe.json", "w") as f:
                json.dump(infra_result, f, indent=2, ensure_ascii=False, default=list)
            if infra_result.get("origin_candidates"):
                for oc in infra_result["origin_candidates"]:
                    print(f"  [원본 서버] {oc['domain']} → {oc['ips']} "
                          f"(server: {oc.get('server','?')}, ALB: {oc.get('alb_name','N/A')})")
            if infra_result.get("scam_network_domains"):
                print(f"  [SSL SAN] 스캠 네트워크 도메인 "
                      f"{len(infra_result['scam_network_domains'])}개 발견")
        else:
            print("  외부 인프라 도메인 없음 - 건너뜀")
    except Exception as e:
        print(f"  [인프라 프로빙] ⚠ {e}")
    return infra_result
