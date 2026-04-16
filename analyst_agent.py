#!/usr/bin/env python3
"""phishAI 분석 총괄 에이전트

수집된 모든 데이터를 검토하고, 추가 조사가 필요한 항목을 식별한 뒤,
최종 분석 보고서를 생성하는 최고 분석 전문가 에이전트.

사용법:
    python3 analyst_agent.py <domain> [--max-rounds 3]
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORTS_DIR = BASE_DIR / "reports"

from ti_clients.gemini_analyzer import (
    GeminiAnalyzer, GEMINI_MODELS_LITE, GEMINI_MODELS_STANDARD,
    BASE_URL, safe_truncate_json,
)
import requests


def get_gemini_response(api_key: str, prompt: str, tier: str = "standard") -> str:
    models = GEMINI_MODELS_LITE if tier == "lite" else GEMINI_MODELS_STANDARD
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8192}
    }
    last_error = None
    for model in models:
        url = f"{BASE_URL}/{model}:generateContent?key={api_key}"
        try:
            r = requests.post(url, json=payload, timeout=90)
            if r.status_code == 429:
                continue
            r.raise_for_status()
            return r.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        except Exception as e:
            last_error = e
            continue
    if last_error:
        print(f"  [Gemini] 모든 모델 실패: {last_error}")
    return ""


def collect_evidence(domain: str, date_str: str) -> dict:
    """evidence 폴더에서 모든 수집 데이터를 로드"""
    edir = EVIDENCE_DIR / f"{domain}_{date_str}"
    if not edir.exists():
        return {}

    data = {"domain": domain, "date": date_str, "sources": {}}

    # TI 응답들
    ti_dir = edir / "ti_responses"
    if ti_dir.exists():
        for f in ti_dir.glob("*.json"):
            with open(f) as fh:
                content = json.load(fh)
                data["sources"][f.stem] = content

    # DNS/WHOIS
    dns_dir = edir / "dns_whois"
    if dns_dir.exists():
        for f in dns_dir.iterdir():
            if f.suffix == ".json":
                with open(f) as fh:
                    data["sources"][f"dns_{f.stem}"] = json.load(fh)
            elif f.suffix == ".txt":
                with open(f) as fh:
                    data["sources"][f"whois"] = fh.read()[:2000]

    # 네트워크 로그 요약
    net_file = edir / "network" / "requests.log"
    if net_file.exists():
        with open(net_file) as fh:
            lines = fh.readlines()
            domains_seen = set()
            for line in lines:
                m = re.search(r'https?://([a-zA-Z0-9.-]+)', line)
                if m:
                    domains_seen.add(m.group(1))
            data["sources"]["network_domains"] = sorted(domains_seen)

    # HTML 분석 요약
    html_file = edir / "html" / "index.html"
    if html_file.exists():
        with open(html_file) as fh:
            html = fh.read()
        data["sources"]["html_summary"] = {
            "size_bytes": len(html),
            "script_count": html.count("<script"),
            "external_domains": sorted(set(re.findall(r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', html))),
        }

    # 기존 보고서
    report = REPORTS_DIR / f"{domain}_{date_str}.json"
    if report.exists():
        with open(report) as fh:
            data["sources"]["initial_report"] = json.load(fh)

    return data


def review_and_identify_gaps(api_key: str, evidence: dict) -> dict:
    """수집된 데이터를 검토하고 추가 조사 필요 항목 식별"""
    evidence_str = safe_truncate_json(evidence)

    prompt = f"""당신은 최고 수준의 사이버 보안 분석 전문가(Chief Analyst)입니다.
아래는 악성사이트 분석을 위해 수집된 모든 증거 자료입니다.

## 수집 데이터
{evidence_str}

## 당신의 임무
1. 수집된 모든 데이터를 검토하고, 분석의 완성도를 평가하세요.
2. 추가로 조사해야 할 항목이 있다면 구체적으로 나열하세요.
3. 각 추가 조사 항목에 대해 조사 방법(어떤 API, 어떤 도구)도 명시하세요.

## 출력 형식 (JSON)
{{
  "completeness_score": 0-100,
  "current_verdict": "악성/의심/정상",
  "confidence": 0-100,
  "gaps": [
    {{
      "item": "조사 항목 설명",
      "reason": "왜 필요한지",
      "method": "조사 방법 (API/도구명)",
      "priority": "high/medium/low"
    }}
  ],
  "key_findings_so_far": ["발견1", "발견2", ...],
  "additional_iocs": ["IOC1", "IOC2", ...]
}}

반드시 유효한 JSON만 출력하세요. 설명 텍스트 없이 JSON만."""

    response = get_gemini_response(api_key, prompt, tier="lite")
    # JSON 추출
    try:
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            return json.loads(json_match.group())
    except json.JSONDecodeError:
        pass
    return {"completeness_score": 0, "gaps": [], "error": "파싱 실패", "raw": response[:1000]}


def execute_additional_investigation(api_key: str, gap: dict, domain: str, date_str: str) -> dict:
    """추가 조사 항목 실행"""
    item = gap.get("item", "")
    method = gap.get("method", "")
    result = {"item": item, "method": method, "status": "skipped", "data": None}

    edir = EVIDENCE_DIR / f"{domain}_{date_str}" / "additional_urls"

    # 추가 도메인 VirusTotal 조회
    if "virustotal" in method.lower():
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if vt_key:
            target = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', item)
            if target:
                target_domain = target.group(1)
                try:
                    r = requests.get(
                        f"https://www.virustotal.com/api/v3/domains/{target_domain}",
                        headers={"x-apikey": vt_key}, timeout=30
                    )
                    if r.status_code == 200:
                        attrs = r.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        result["status"] = "completed"
                        result["data"] = {
                            "domain": target_domain,
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "categories": attrs.get("categories", {}),
                            "creation_date": attrs.get("creation_date", ""),
                        }
                        # 저장
                        with open(edir / f"vt_{target_domain}.json", "w") as f:
                            json.dump(result["data"], f, indent=2, ensure_ascii=False)
                except Exception as e:
                    result["status"] = "error"
                    result["data"] = str(e)

    # DNS 조회
    elif "dns" in method.lower() or "dig" in method.lower():
        target = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', item)
        if target:
            target_domain = target.group(1)
            try:
                import socket
                ips = socket.getaddrinfo(target_domain, None, socket.AF_INET)
                result["status"] = "completed"
                result["data"] = {
                    "domain": target_domain,
                    "ips": list(set(addr[4][0] for addr in ips))
                }
            except Exception as e:
                result["status"] = "error"
                result["data"] = str(e)

    # WHOIS 조회
    elif "whois" in method.lower():
        target = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', item)
        if target:
            try:
                out = subprocess.run(
                    ["whois", target.group(1)],
                    capture_output=True, text=True, timeout=15
                )
                result["status"] = "completed"
                result["data"] = out.stdout[:2000]
            except Exception as e:
                result["status"] = "error"
                result["data"] = str(e)

    return result


def identify_chain_targets(api_key: str, evidence: dict) -> list:
    """수집 데이터에서 연쇄 분석이 필요한 도메인/IP 목록 추출"""
    evidence_str = safe_truncate_json(evidence, 12000)

    prompt = f"""당신은 사이버 보안 분석 전문가입니다.
아래 수집 데이터에서 추가 연쇄 분석이 필요한 도메인과 IP를 추출하세요.

## 수집 데이터
{evidence_str}

## 연쇄 분석 대상 선정 기준
- 메인 도메인과 동일 인프라를 공유하는 관련 도메인
- SSL 인증서 SAN에서 발견된 도메인
- 네트워크 요청에서 발견된 의심 도메인
- 이미 분석된 도메인은 제외

## 출력 형식 (JSON 배열만)
[
  {{"target": "도메인 또는 IP", "reason": "분석 필요 이유", "type": "domain 또는 ip"}}
]

유효한 JSON 배열만 출력하세요. 최대 5개."""

    response = get_gemini_response(api_key, prompt, tier="lite")
    try:
        json_match = re.search(r'\[[\s\S]*\]', response)
        if json_match:
            return json.loads(json_match.group())
    except json.JSONDecodeError:
        pass
    return []


def run_chain_analysis(targets: list, date_str: str) -> list:
    """연쇄 분석 대상에 대해 analyze.py 실행"""
    results = []
    for t in targets:
        target = t.get("target", "")
        ttype = t.get("type", "domain")
        if ttype != "domain" or not target:
            results.append({"target": target, "status": "skipped", "reason": "IP 분석은 미지원"})
            continue

        print(f"  연쇄 분석: {target} ({t.get('reason', '')[:40]})")
        try:
            out = subprocess.run(
                [sys.executable, str(BASE_DIR / "analyze.py"), target, "--json-only"],
                capture_output=True, text=True, timeout=120,
                cwd=str(BASE_DIR)
            )
            results.append({"target": target, "status": "completed", "output": out.stdout[-500:]})
        except subprocess.TimeoutExpired:
            results.append({"target": target, "status": "timeout"})
        except Exception as e:
            results.append({"target": target, "status": "error", "error": str(e)})
    return results


def generate_final_report(api_key: str, evidence: dict, review: dict,
                          additional_results: list, domain: str, date_str: str,
                          chain_results: list = None) -> str:
    """최종 분석 보고서 생성"""
    report_data = {
        "evidence_summary": {k: type(v).__name__ for k, v in evidence.get("sources", {}).items()},
        "review": review,
        "additional_investigations": additional_results,
        "chain_analysis": chain_results or [],
    }
    report_str = safe_truncate_json(report_data)

    prompt = f"""당신은 최고 수준의 사이버 보안 분석 전문가(Chief Analyst)입니다.
아래 모든 분석 결과를 종합하여 최종 분석 보고서를 작성하세요.

## 분석 대상: {domain}
## 분석 일시: {date_str}

## 종합 데이터
{report_str}

## 보고서 작성 지침
1. 전문적이고 구체적인 보고서를 작성하세요.
2. 모든 판단에는 구체적인 증거 데이터를 인용하세요.
3. 아래 구조를 따르세요:

# {domain} 최종 분석 보고서

## Executive Summary (한 단락)

## 종합 판정
- 판정: 악성/의심/정상
- 확신도: N%
- 위협 유형: (구체적)

## 악성 행위 상세
동적 분석에서 식별된 사이트 유형에 맞게 해당하는 항목을 상세히 분석하세요:
### 개인정보 탈취 (어떤 데이터가, 어떤 경로로 수집되는지)
### 결제/금융 사기 (결제 흐름, 카드 정보 처리, 가짜 투자/대출 등)
### 로그인 정보 탈취 (사칭 대상, 크리덴셜 전송 경로)
### 사용자 추적/기기 핑거프린팅
### 사회공학적 조작 기법
### 악성파일 다운로드 / C2 통신 여부

## 공격 시나리오
피해자의 접속부터 피해 발생까지 단계별 흐름을 재현하세요.
각 단계마다: URL, 행위, 로드되는 외부 리소스, 수집되는 데이터, 전송 대상 서버를 명시.
데이터 전송 경로도 다이어그램으로 표현.

## 분석 근거 (상세)
### TI 분석 결과
### DOM/네트워크 분석
### 인프라 분석
### 연쇄 분석 결과

## IOC 목록 (표 형식)

## 스캠 네트워크 구조도

## 대응 권고

## 분석 한계 및 추가 조사 권고

한국어로 작성해 주세요."""

    return get_gemini_response(api_key, prompt)


def main():
    parser = argparse.ArgumentParser(description="phishAI 분석 총괄 에이전트")
    parser.add_argument("domain", help="분석 대상 도메인")
    parser.add_argument("--date", default=datetime.now().strftime("%Y-%m-%d"), help="분석 날짜")
    parser.add_argument("--max-rounds", type=int, default=2, help="추가 조사 최대 반복 횟수")
    args = parser.parse_args()

    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        print("[!] GEMINI_API_KEY가 필요합니다")
        sys.exit(1)

    domain = args.domain
    date_str = args.date

    print(f"{'='*60}")
    print(f"  phishAI 분석 총괄 에이전트 (Chief Analyst)")
    print(f"  대상: {domain} | 일시: {date_str}")
    print(f"{'='*60}")

    # 1단계: 수집 데이터 로드
    print("\n[1/5] 수집 데이터 로드 중...")
    evidence = collect_evidence(domain, date_str)
    print(f"  로드된 소스: {len(evidence.get('sources', {}))}개")
    for src in evidence.get("sources", {}):
        print(f"    - {src}")

    all_additional = []

    for round_num in range(1, args.max_rounds + 1):
        # 2단계: 검토 및 갭 분석
        print(f"\n[2/5] 분석 검토 (라운드 {round_num}/{args.max_rounds})...")
        review = review_and_identify_gaps(api_key, evidence)
        score = review.get("completeness_score", 0)
        gaps = review.get("gaps", [])
        print(f"  완성도: {score}%")
        print(f"  현재 판정: {review.get('current_verdict', 'N/A')} (확신도: {review.get('confidence', 'N/A')}%)")
        print(f"  추가 조사 필요: {len(gaps)}건")

        high_gaps = [g for g in gaps if g.get("priority") == "high"]
        if not high_gaps or score >= 90:
            print("  → 추가 조사 불필요 또는 충분한 완성도")
            break

        # 3단계: 추가 조사 실행
        print(f"\n[3/5] 추가 조사 실행 (우선순위 high: {len(high_gaps)}건)...")
        for gap in high_gaps[:3]:
            print(f"  조사: {gap.get('item', '')[:60]}...")
            result = execute_additional_investigation(api_key, gap, domain, date_str)
            all_additional.append(result)
            print(f"    → {result['status']}")
            if result.get("data"):
                evidence["sources"][f"additional_{len(all_additional)}"] = result["data"]

    # 4단계: 연쇄 분석
    chain_results = []
    print(f"\n[4/5] 연쇄 분석 대상 식별 중...")
    chain_targets = identify_chain_targets(api_key, evidence)
    if chain_targets:
        print(f"  연쇄 분석 대상: {len(chain_targets)}개")
        chain_results = run_chain_analysis(chain_targets[:3], date_str)
        for cr in chain_results:
            if cr.get("status") == "completed":
                # 연쇄 분석 결과를 evidence에 병합
                chain_report = REPORTS_DIR / f"{cr['target']}_{date_str}.json"
                if chain_report.exists():
                    with open(chain_report) as f:
                        evidence["sources"][f"chain_{cr['target']}"] = json.load(f)
    else:
        print("  연쇄 분석 불필요")

    # 5단계: 최종 보고서 생성
    print(f"\n[5/5] 최종 분석 보고서 생성 중...")
    final_report = generate_final_report(api_key, evidence, review, all_additional, domain, date_str, chain_results)

    if final_report:
        report_path = REPORTS_DIR / f"{domain}_{date_str}_final_report.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            f.write(final_report)
        print(f"\n[*] 최종 보고서 저장: {report_path}")
    else:
        print("[!] 보고서 생성 실패")

    print(f"\n{'='*60}")
    print(f"  분석 총괄 에이전트 완료")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
