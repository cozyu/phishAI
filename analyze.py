#!/usr/bin/env python3
"""phishAI - 악성사이트 분석 CLI 도구

사용법:
    python3 analyze.py <domain>
    python3 analyze.py ppxxzz.com
"""

import argparse
import json
import os
import sys
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORTS_DIR = BASE_DIR / "reports"


def create_evidence_dirs(domain: str, date_str: str) -> Path:
    edir = EVIDENCE_DIR / f"{domain}_{date_str}"
    for sub in ["screenshots", "html", "network", "ti_responses", "dns_whois", "additional_urls"]:
        (edir / sub).mkdir(parents=True, exist_ok=True)
    return edir


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


def whois_lookup(domain: str) -> str:
    try:
        out = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15
        )
        return out.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def run_ti_client(client_cls, domain: str, env: dict) -> dict:
    keys = client_cls.env_keys
    vals = [env.get(k, "") for k in keys]
    if not all(vals):
        return {"service": client_cls.name, "error": f"API key missing ({', '.join(keys)})"}
    try:
        client = client_cls(*vals)
        return client.analyze_domain(domain)
    except Exception as e:
        return {"service": client_cls.name, "error": str(e)}


def print_summary(results: dict):
    print("\n" + "=" * 60)
    print(f"  phishAI 분석 결과 요약")
    print("=" * 60)

    # DNS
    dns = results.get("dns", {})
    if dns.get("A"):
        print(f"\n[DNS] A 레코드: {', '.join(dns['A'])}")
    if dns.get("MX"):
        print(f"[DNS] MX 레코드: {', '.join(dns['MX'])}")
    if dns.get("NS"):
        print(f"[DNS] NS 레코드: {', '.join(dns['NS'])}")

    # WHOIS 요약
    whois = results.get("whois", "")
    if whois:
        important_fields = ["Registrar:", "Creation Date:", "Registry Expiry Date:",
                           "Registrant Organization:", "Registrant Country:"]
        print("\n[WHOIS]")
        for line in whois.split("\n"):
            for field in important_fields:
                if field.lower() in line.lower():
                    print(f"  {line.strip()}")
                    break

    # TI 결과
    for ti in results.get("ti_results", []):
        service = ti.get("service", "Unknown")
        print(f"\n[{service}]")
        if "error" in ti:
            print(f"  ⚠ {ti['error']}")
            continue
        if service == "VirusTotal":
            m = ti.get("malicious", 0)
            s = ti.get("suspicious", 0)
            h = ti.get("harmless", 0)
            print(f"  탐지: malicious={m}, suspicious={s}, harmless={h}")
            print(f"  평판 점수: {ti.get('reputation', 'N/A')}")
            cats = ti.get("categories", {})
            if cats:
                print(f"  카테고리: {json.dumps(cats, ensure_ascii=False)}")
        elif service == "URLScan":
            print(f"  악성 판정: {ti.get('malicious', 'N/A')}")
            print(f"  점수: {ti.get('score', 'N/A')}")
            print(f"  IP: {ti.get('ip', 'N/A')}, 국가: {ti.get('country', 'N/A')}")
            if ti.get("screenshot"):
                print(f"  스크린샷: {ti['screenshot']}")
        elif service == "CriminalIP":
            print(f"  악성 판정: {ti.get('is_malicious', 'N/A')}")
            print(f"  점수: {json.dumps(ti.get('score', {}), ensure_ascii=False)}")
        elif service == "Censys":
            print(f"  발견 호스트: {ti.get('total', 0)}개")
            for host in ti.get("hosts", [])[:3]:
                svcs = ", ".join(f"{s['port']}/{s['service_name']}" for s in host.get("services", []))
                print(f"  - {host.get('ip', '')} [{svcs}]")

    # 인프라 프로빙 결과
    infra = results.get("infra_probe", {})
    if infra.get("origin_candidates"):
        print(f"\n[인프라 프로빙 - 원본 서버]")
        for oc in infra["origin_candidates"]:
            print(f"  {oc['domain']} → {', '.join(oc['ips'])}")
            if oc.get("alb_name"):
                print(f"    ALB: {oc['alb_name']}")
            if oc.get("server"):
                print(f"    Server: {oc['server']}")
    if infra.get("scam_network_domains"):
        print(f"\n[SSL 인증서 SAN - 스캠 네트워크 도메인]")
        for d in infra["scam_network_domains"][:15]:
            print(f"  - {d}")

    # Passive DNS
    pdns = results.get("passive_dns", [])
    if pdns:
        non_cdn = [r for r in pdns if not r["ip"].startswith(("18.", "13.", "3.", "108."))]
        if non_cdn:
            print(f"\n[Passive DNS - 비-CDN IP (과거)]")
            for r in non_cdn[:5]:
                from datetime import datetime as _dt
                dt = _dt.fromtimestamp(r["date"]).strftime("%Y-%m-%d") if r.get("date") else "N/A"
                print(f"  {dt} → {r['ip']}")

    # 동적 분석 결과
    dyn = results.get("dynamic_analysis", {})
    if dyn and "error" not in dyn:
        print(f"\n[동적 분석 (Docker 샌드박스)]")
        pages = dyn.get("pages", [])
        print(f"  분석 페이지: {len(pages)}개")
        co = dyn.get("checkout")
        if co:
            pg_iframes = co.get("payment_iframes", [])
            pii = co.get("pii_fields", [])
            print(f"  결제 페이지: 발견")
            if pg_iframes:
                for iframe in pg_iframes[:3]:
                    # PG사 도메인 추출
                    import re as _re
                    m = _re.search(r'https?://([^/]+)', iframe)
                    print(f"    PG: {m.group(1) if m else iframe[:60]}")
            if pii:
                print(f"    PII 입력 필드: {len(pii)}개")

    # AI 종합 분석
    ai = results.get("ai_analysis", {})
    if ai.get("analysis"):
        print(f"\n{'─' * 60}")
        print("  🤖 Gemini AI 종합 분석")
        print(f"{'─' * 60}")
        print(ai["analysis"])

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description="phishAI - 악성사이트 분석 도구")
    parser.add_argument("domain", help="분석할 도메인 (예: ppxxzz.com)")
    parser.add_argument("--depth", type=int, default=2, help="연쇄 분석 깊이 (기본: 2)")
    parser.add_argument("--json-only", action="store_true", help="JSON 결과만 출력")
    args = parser.parse_args()

    domain = args.domain.replace("http://", "").replace("https://", "").strip("/")
    date_str = datetime.now().strftime("%Y-%m-%d")
    edir = create_evidence_dirs(domain, date_str)

    env = {k: os.getenv(k, "") for k in [
        "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY",
        "CRIMINALIP_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
        "GEMINI_API_KEY"
    ]}

    print(f"[*] 대상: {domain}")
    print(f"[*] 분석 시작: {datetime.now().isoformat()}")
    print(f"[*] 증거 저장: {edir}")

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
        futures = {executor.submit(run_ti_client, c, domain, env): c for c in ALL_CLIENTS}
        for future in as_completed(futures):
            result = future.result()
            ti_results.append(result)
            svc = result.get("service", "?")
            if "error" in result:
                print(f"  [{svc}] ⚠ {result['error']}")
            else:
                print(f"  [{svc}] ✓ 완료")
            # 원본 응답 저장
            fname = svc.lower().replace(" ", "_") + ".json"
            with open(edir / "ti_responses" / fname, "w") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

    # VT Passive DNS (과거 IP 히스토리)
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

    # DOM + 동적 분석
    print("[*] 사이트 분석 중...")
    dom_result = {}
    dynamic_result = {}
    try:
        from ti_clients.site_analyzer import SiteAnalyzer
        sa = SiteAnalyzer(edir)

        # Docker 가용 → 샌드박스 동적 분석 (JS 실행, 결제 페이지 추적)
        if sa.docker:
            print("  [Docker] 샌드박스 동적 분석 실행...")
            dynamic_result = sa.dynamic_analyze(f"https://{domain}")
            if "error" not in dynamic_result:
                pages = dynamic_result.get("pages", [])
                print(f"  [Docker] ✓ {len(pages)}개 페이지 분석 완료")
                if dynamic_result.get("checkout"):
                    co = dynamic_result["checkout"]
                    print(f"  [결제] PG iframe {len(co.get('payment_iframes', []))}개, "
                          f"PII 필드 {len(co.get('pii_fields', []))}개")
                # 동적 결과에서 DOM 정보 추출
                if pages:
                    dom_result = {
                        "external_domains": pages[0].get("external_domains", []),
                        "external_scripts": pages[0].get("external_scripts", []),
                        "iframes": pages[0].get("iframes", []),
                    }
            else:
                print(f"  [Docker] ⚠ {dynamic_result.get('error')} → curl 정적 분석으로 폴백")
                dom_result = sa.collect_dom(f"https://{domain}")
        else:
            # Docker 없음 → curl 정적 분석
            print("  [curl] 정적 DOM 분석...")
            dom_result = sa.collect_dom(f"https://{domain}")

        if "error" not in dom_result:
            print(f"  [DOM] ✓ 외부 도메인 {len(dom_result.get('external_domains', []))}개")
            if dom_result.get("platform"):
                print(f"  [플랫폼] {json.dumps(dom_result['platform'], ensure_ascii=False)}")
        elif dom_result.get("error"):
            print(f"  [DOM] ⚠ {dom_result.get('error')}")
    except Exception as e:
        print(f"  [사이트분석] ⚠ {e}")

    # 인프라 프로빙 (CDN 우회 원본 서버 추적)
    print("[*] 인프라 도메인 프로빙 중...")
    infra_result = {}
    try:
        from ti_clients.infra_prober import probe_infrastructure
        # URLScan + DOM 결과에서 외부 도메인 추출
        infra_domains = set()
        for ti in ti_results:
            for url in ti.get("redirects", []):
                import re as _re
                m = _re.search(r'https?://([a-zA-Z0-9.-]+)', url)
                if m and m.group(1) != domain:
                    infra_domains.add(m.group(1))
        # DOM 분석에서 발견된 외부 도메인 추가
        for d in dom_result.get("external_domains", []):
            if d != domain:
                infra_domains.add(d)
        # CriminalIP connected_domains 추가
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
                    print(f"  [원본 서버] {oc['domain']} → {oc['ips']} (server: {oc.get('server','?')}, ALB: {oc.get('alb_name','N/A')})")
            if infra_result.get("scam_network_domains"):
                print(f"  [SSL SAN] 스캠 네트워크 도메인 {len(infra_result['scam_network_domains'])}개 발견")
        else:
            print("  외부 인프라 도메인 없음 - 건너뜀")
    except Exception as e:
        print(f"  [인프라 프로빙] ⚠ {e}")

    # 결과 조합
    results = {
        "domain": domain,
        "analyzed_at": datetime.now().isoformat(),
        "dns": dns,
        "whois": whois[:2000],
        "ti_results": ti_results,
        "resolved_ips": dns.get("A", []),
        "passive_dns": passive_dns,
        "dom_analysis": {k: v for k, v in dom_result.items() if k != "service"} if dom_result else {},
        "dynamic_analysis": {k: v for k, v in dynamic_result.items() if k != "service"} if dynamic_result else {},
        "infra_probe": infra_result,
    }

    # Gemini 종합 분석
    gemini_key = env.get("GEMINI_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
    if gemini_key:
        print("[*] Gemini AI 종합 분석 중...")
        try:
            from ti_clients.gemini_analyzer import GeminiAnalyzer
            ga = GeminiAnalyzer(gemini_key)
            ai_result = ga.synthesize(domain, results)
            results["ai_analysis"] = ai_result
            with open(edir / "ti_responses" / "gemini_analysis.json", "w") as f:
                json.dump(ai_result, f, indent=2, ensure_ascii=False)
            print("  [Gemini] ✓ 종합 분석 완료")
        except Exception as e:
            print(f"  [Gemini] ⚠ {e}")
    else:
        print("[!] GEMINI_API_KEY 없음 - AI 종합 분석 건너뜀")

    # 보고서 저장
    report_path = REPORTS_DIR / f"{domain}_{date_str}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[*] JSON 보고서 저장: {report_path}")

    if not args.json_only:
        print_summary(results)

    return results


if __name__ == "__main__":
    main()
