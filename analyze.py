#!/usr/bin/env python3
"""phishAI - 악성사이트 분석 CLI 도구

사용법:
    python3 analyze.py <domain>
    python3 analyze.py example.com
"""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORTS_DIR = BASE_DIR / "reports"


def create_evidence_dirs(domain: str, timestamp: str) -> Path:
    """evidence/<domain>/<timestamp>/ 구조로 증거 폴더 생성"""
    edir = EVIDENCE_DIR / domain / timestamp
    for sub in ["screenshots", "html", "network", "ti_responses", "dns_whois", "additional_urls"]:
        (edir / sub).mkdir(parents=True, exist_ok=True)
    return edir


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
                dt = datetime.fromtimestamp(r["date"]).strftime("%Y-%m-%d") if r.get("date") else "N/A"
                print(f"  {dt} → {r['ip']}")

    # 동적 분석 결과
    dyn = results.get("dynamic_analysis", {})
    if dyn and "error" not in dyn:
        print(f"\n[동적 분석]")
        if dyn.get("site_type"):
            print(f"  사이트 유형: {dyn['site_type']}")
            print(f"  위험도: {dyn.get('severity', 'N/A')}")
            print(f"  분석 스텝: {dyn.get('rounds_completed', 0)}회")
            findings = dyn.get("findings", "")
            if findings:
                print(f"  발견 사항: {findings[:300]}")
            for h in dyn.get("history", []):
                print(f"    Step {h.get('step')}: {h.get('action')}"
                      f"({json.dumps(h.get('args', {}), ensure_ascii=False)[:50]}) "
                      f"→ {h.get('result')}")

    # AI 종합 분석
    ai = results.get("ai_analysis", {})
    if ai.get("analysis"):
        print(f"\n{'─' * 60}")
        print("  Gemini AI 종합 분석")
        print(f"{'─' * 60}")
        print(ai["analysis"])

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description="phishAI - 악성사이트 분석 도구")
    parser.add_argument("domain", help="분석할 도메인 (예: example.com)")
    parser.add_argument("--depth", type=int, default=2, help="연쇄 분석 깊이 (기본: 2)")
    parser.add_argument("--json-only", action="store_true", help="JSON 결과만 출력")
    args = parser.parse_args()

    domain = args.domain.replace("http://", "").replace("https://", "").strip("/")

    from ti_clients.api_logger import setup_run_logger
    log_path = setup_run_logger("analyze", domain)
    print(f"[*] 실행 로그: {log_path}")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    edir = create_evidence_dirs(domain, timestamp)

    env = {k: os.getenv(k, "") for k in [
        "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY",
        "CRIMINALIP_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
        "GEMINI_API_KEY"
    ]}

    print(f"[*] 대상: {domain}")
    print(f"[*] 분석 시작: {datetime.now().isoformat()}")
    print(f"[*] 증거 저장: {edir}")

    # 1단계: TI 분석 (DNS/WHOIS + TI API + Passive DNS + 인프라 프로빙)
    from analyze_ti import run_ti_analysis
    ti_data = run_ti_analysis(domain, env, edir)

    # 2단계: 동적 분석 (Docker AI 에이전트 또는 레거시 또는 curl 폴백)
    from analyze_dynamic import run_dynamic_analysis
    dynamic_data = run_dynamic_analysis(domain, edir)

    # 결과 조합
    results = {
        "domain": domain,
        "analyzed_at": datetime.now().isoformat(),
        "resolved_ips": ti_data["dns"].get("A", []),
        **ti_data,
        **dynamic_data,
    }

    # 3단계: Gemini 종합 분석
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

    # 보고서 저장 (evidence와 동일 도메인/타임스탬프 구조)
    report_path = REPORTS_DIR / domain / f"{timestamp}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[*] JSON 보고서 저장: {report_path}")

    if not args.json_only:
        print_summary(results)

    return results


if __name__ == "__main__":
    main()
