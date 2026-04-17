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


def get_gemini_response(api_key: str, prompt: str, tier: str = "standard",
                        max_output_tokens: int = 8192) -> str:
    from ti_clients.gemini_analyzer import _get_api_keys
    api_keys = [api_key] + [k for k in _get_api_keys() if k != api_key]
    models = GEMINI_MODELS_LITE if tier == "lite" else GEMINI_MODELS_STANDARD
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": max_output_tokens}
    }
    last_error = None
    for key in api_keys:
        for model in models:
            url = f"{BASE_URL}/{model}:generateContent?key={key}"
            try:
                r = requests.post(url, json=payload, timeout=90)
                if r.status_code in (429, 503):
                    continue
                r.raise_for_status()
                return r.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            except Exception as e:
                last_error = e
                continue
    if last_error:
        print(f"  [Gemini] 모든 키/모델 실패: {last_error}")
    return ""


def _find_latest_evidence_dir(domain: str, date_str: str) -> Path | None:
    """evidence/<domain>/ 아래에서 date_str로 시작하는 가장 최신 폴더를 찾는다."""
    domain_dir = EVIDENCE_DIR / domain
    if domain_dir.exists():
        candidates = sorted(
            [d for d in domain_dir.iterdir() if d.is_dir() and d.name.startswith(date_str)],
            key=lambda d: d.name, reverse=True
        )
        if candidates:
            return candidates[0]
    # 레거시 폴더 호환 (순번 패턴 또는 구 패턴)
    if EVIDENCE_DIR.exists():
        legacy_patterns = [
            d for d in EVIDENCE_DIR.iterdir()
            if d.is_dir() and domain in d.name and date_str in d.name
        ]
        if legacy_patterns:
            return sorted(legacy_patterns, key=lambda d: d.name, reverse=True)[0]
    return None


def collect_evidence(domain: str, date_str: str) -> dict:
    """evidence 폴더에서 모든 수집 데이터를 로드"""
    edir = _find_latest_evidence_dir(domain, date_str)
    if not edir or not edir.exists():
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

    # 네트워크 요청 로그 (JSON 우선, log 폴백)
    net_dir = edir / "network"
    net_json = net_dir / "requests.json"
    net_log = net_dir / "requests.log"
    if net_json.exists():
        with open(net_json) as fh:
            requests_data = json.load(fh)
        domains_seen = set()
        for req in requests_data:
            m = re.search(r'https?://([a-zA-Z0-9.-]+)', req.get("url", ""))
            if m:
                domains_seen.add(m.group(1))
        data["sources"]["network_domains"] = sorted(domains_seen)
    elif net_log.exists():
        with open(net_log) as fh:
            lines = fh.readlines()
            domains_seen = set()
            for line in lines:
                m = re.search(r'https?://([a-zA-Z0-9.-]+)', line)
                if m:
                    domains_seen.add(m.group(1))
            data["sources"]["network_domains"] = sorted(domains_seen)

    # 방문 페이지 정보
    visited_file = edir / "visited_urls.json"
    if visited_file.exists():
        with open(visited_file) as fh:
            data["sources"]["visited_urls"] = json.load(fh)

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

    # 기존 보고서 (새 폴더 구조 우선)
    report = REPORTS_DIR / domain / f"{date_str}.json"
    if not report.exists():
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

    edir_base = _find_latest_evidence_dir(domain, date_str)
    edir = (edir_base / "additional_urls") if edir_base else (EVIDENCE_DIR / f"{domain}_{date_str}" / "additional_urls")

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


def _dga_score(name: str) -> float:
    """DGA(Domain Generation Algorithm) 의심 점수. 0~1, 높을수록 의심.

    하드코딩 없이 문자열 통계 특성만 사용하여 범용 판별.
    """
    if not name or len(name) < 3:
        return 0.0
    s = name.lower().split(".")[0]  # TLD 제거
    if not s:
        return 0.0
    vowels = sum(1 for c in s if c in "aeiou")
    vr = vowels / len(s)
    # 최대 연속 자음 길이
    import re as _re
    clusters = _re.findall(r"[^aeiou]+", s)
    mcc = max((len(c) for c in clusters), default=0)

    score = 0.0
    if vr < 0.2:
        score += 0.4
    elif vr < 0.3:
        score += 0.2
    if mcc >= 5:
        score += 0.35
    elif mcc >= 4:
        score += 0.15
    return min(score, 1.0)


def _build_known_domains(evidence: dict) -> set:
    """evidence 전체에서 관찰된 모든 도메인 집합을 구성 (범용).

    이 집합은 infra_probe SAN 필터링에서 probe 연관성 판별에 사용된다.
    """
    known = set()
    sources = evidence.get("sources", {})

    # 분석 대상 도메인 자체
    target = evidence.get("domain", "")
    if target:
        known.add(target)

    # dom_analysis → external_domains, external_scripts에서 도메인 추출
    dom = sources.get("dom_analysis", {})
    for d in dom.get("external_domains", []):
        known.add(d)
    for script_url in dom.get("external_scripts", []):
        m = re.search(r"https?://([a-zA-Z0-9.-]+)", script_url)
        if m:
            known.add(m.group(1))

    # network_domains
    for d in sources.get("network_domains", []):
        known.add(d)

    # urlscan → redirects에서 도메인 추출
    urlscan = sources.get("urlscan", {})
    for url in urlscan.get("redirects", []):
        m = re.search(r"https?://([a-zA-Z0-9.-]+)", url)
        if m:
            known.add(m.group(1))
    for ip_info in urlscan.get("ips", []):
        if isinstance(ip_info, dict) and ip_info.get("domain"):
            known.add(ip_info["domain"])

    # criminalip → connected_domains
    cip = sources.get("criminalip", {})
    for d in cip.get("connected_domains", []):
        known.add(d)

    # visited_urls → URL에서 도메인 추출
    for page in sources.get("visited_urls", []):
        url = page.get("url", "")
        m = re.search(r"https?://([a-zA-Z0-9.-]+)", url)
        if m:
            known.add(m.group(1))

    # html_summary → external_domains
    html_summary = sources.get("html_summary", {})
    for d in html_summary.get("external_domains", []):
        known.add(d)

    return known


def _is_target_infra_probe(probe_info: dict, known_domains: set) -> bool:
    """이 probe가 분석 대상의 인프라인지 판별 (범용).

    known_domains: evidence에서 수집된 모든 도메인 집합.
    하드코딩된 도메인 리스트 없이, evidence 교차 참조만으로 판별.

    핵심 원리: 스캠 인프라의 SAN은 스캠 네트워크 도메인으로 구성되므로
    SAN 도메인의 상당 비율이 evidence에서 관찰되거나 서로 유사한 패턴.
    반면 대형 서비스(CDN/클라우드)의 SAN은 수십~수백 개이며
    evidence와 겹치는 비율이 매우 낮음.
    """
    san_domains = set(probe_info.get("san_domains", []))
    san_count = len(san_domains)

    if san_count == 0:
        return False

    # SAN과 evidence의 교집합 비율로 판별
    overlap = san_domains & known_domains
    overlap_ratio = len(overlap) / san_count if san_count else 0

    # 비율이 높으면 (SAN의 20%+ 이상이 evidence에 등장) → 스캠 인프라
    if overlap_ratio >= 0.2:
        return True

    # origin_candidates이면서 SAN이 소수(≤20)인 경우
    # → 소규모 인증서를 사용하는 공격자 인프라일 가능성
    if probe_info.get("is_origin") and san_count <= 20:
        return True

    return False


def _filter_san_domains(infra_probe: dict, known_domains: set) -> list:
    """infra_probe에서 분석 대상 인프라의 SAN 도메인만 필터링 (범용).

    Returns:
        [{"domain": str, "dga_score": float, "source_probe": str}, ...]
    """
    san_by_probe = infra_probe.get("san_by_probe", {})

    # san_by_probe가 없으면 probes에서 재구성 (기존 데이터 호환)
    if not san_by_probe:
        origin_domains = {oc["domain"] for oc in infra_probe.get("origin_candidates", [])}
        for probe in infra_probe.get("probes", []):
            if probe.get("ssl_san"):
                san_by_probe[probe["domain"]] = {
                    "san_domains": sorted(set(s.lstrip("*.") for s in probe["ssl_san"])),
                    "ssl_subject": probe.get("ssl_subject"),
                    "ssl_issuer": probe.get("ssl_issuer"),
                    "server": probe.get("server"),
                    "san_count": len(probe["ssl_san"]),
                    "is_origin": probe["domain"] in origin_domains,
                }

    result = []
    seen = set()

    for probe_domain, probe_info in san_by_probe.items():
        if not _is_target_infra_probe(probe_info, known_domains):
            continue
        for d in probe_info.get("san_domains", []):
            if d not in seen:
                seen.add(d)
                result.append({
                    "domain": d,
                    "dga_score": round(_dga_score(d), 2),
                    "source_probe": probe_domain,
                })

    return sorted(result, key=lambda x: -x["dga_score"])


def extract_evidence_summary(evidence: dict) -> dict:
    """evidence에서 보고서 생성에 핵심적인 데이터만 추출.

    Gemini 프롬프트에 실제 데이터를 전달하기 위한 compact 요약.
    """
    sources = evidence.get("sources", {})
    summary = {"domain": evidence.get("domain", ""), "date": evidence.get("date", "")}

    # known_domains 구성 (SAN 필터링용)
    known_domains = _build_known_domains(evidence)

    # VirusTotal
    vt = sources.get("virustotal", {})
    if vt and "error" not in vt:
        summary["virustotal"] = {
            "malicious": vt.get("malicious", 0),
            "suspicious": vt.get("suspicious", 0),
            "harmless": vt.get("harmless", 0),
            "undetected": vt.get("undetected", 0),
            "reputation": vt.get("reputation"),
            "whois": (vt.get("whois") or "")[:500],
        }

    # CriminalIP
    cip = sources.get("criminalip", {})
    if cip and "error" not in cip:
        cip_summary = {}
        if cip.get("dga_score") is not None:
            cip_summary["dga_score"] = cip["dga_score"]
        if cip.get("js_obfuscated") is not None:
            cip_summary["js_obfuscated"] = cip["js_obfuscated"]
        cip_summary["connected_domains"] = cip.get("connected_domains", [])[:20]
        cip_summary["connected_ips"] = [
            {"ip": ip.get("ip"), "as_name": ip.get("as_name")}
            for ip in cip.get("connected_ips", [])[:10]
        ]
        cip_summary["technologies"] = cip.get("technologies", [])[:15]
        cip_summary["certificates"] = [
            {"subject": c.get("subject"), "issuer": c.get("issuer")}
            for c in cip.get("certificates", [])[:5]
        ]
        if cip.get("cookies"):
            cip_summary["cookies"] = [
                {"name": c.get("name"), "domain": c.get("domain")}
                for c in cip["cookies"][:10]
            ]
        summary["criminalip"] = cip_summary

    # URLScan
    us = sources.get("urlscan", {})
    if us and "error" not in us:
        summary["urlscan"] = {
            "score": us.get("score"),
            "malicious": us.get("malicious"),
            "ip": us.get("ip"),
            "country": us.get("country"),
            "redirects": us.get("redirects", [])[:10],
            "ips": us.get("ips", [])[:10],
        }

    # DOM 분석
    dom = sources.get("dom_analysis", {})
    if dom:
        summary["dom_analysis"] = {
            "external_domains": dom.get("external_domains", []),
            "external_scripts": dom.get("external_scripts", [])[:15],
            "input_fields": dom.get("input_fields", []),
            "suspicious_patterns": dom.get("suspicious_patterns", {}),
            "platform": dom.get("platform", {}),
            "meta_tags": dom.get("meta_tags", [])[:10],
            "base64_decoded": dom.get("base64_decoded", [])[:5],
            "iframes": dom.get("iframes", []),
            "html_size": dom.get("html_size"),
            "script_count": dom.get("script_count"),
        }

    # 인프라 프로빙 — 범용 SAN 필터링
    infra = sources.get("infra_probe", {})
    if infra:
        filtered_san = _filter_san_domains(infra, known_domains)
        summary["infra_probe"] = {
            "origin_candidates": infra.get("origin_candidates", []),
            "alb_names": infra.get("alb_names", []),
            "filtered_san_domains": filtered_san,
            "total_san_before_filter": len(infra.get("scam_network_domains", [])),
        }

    # DNS
    dns = sources.get("dns_dns", {})
    if dns:
        summary["dns"] = dns

    # WHOIS
    whois = sources.get("whois", "")
    if whois:
        summary["whois"] = whois[:1500]

    # Gemini 1단계 분석 (이미 수행된 종합 분석 — 보고서 기반으로 활용)
    ga = sources.get("gemini_analysis", {})
    if ga and ga.get("analysis"):
        summary["prior_analysis"] = ga["analysis"][:3000]

    # 방문 페이지
    visited = sources.get("visited_urls", [])
    if visited:
        summary["visited_pages"] = [
            {"url": p.get("url", ""), "title": p.get("title", ""), "type": p.get("type", "")}
            for p in visited[:10]
        ]

    # 네트워크 도메인
    net_domains = sources.get("network_domains", [])
    if net_domains:
        summary["network_domains"] = net_domains

    # 동적 분석 결과
    dynamic = sources.get("dynamic_result", {})
    if dynamic and "error" not in dynamic:
        summary["dynamic_analysis"] = {
            "site_type": dynamic.get("site_type"),
            "severity": dynamic.get("severity"),
            "findings": dynamic.get("findings", "")[:800],
            "rounds_completed": dynamic.get("rounds_completed"),
        }
        # AI 에이전트가 탐색 중 수집한 victim_flow (checkout/결제/입력 페이지 증거)
        vf = dynamic.get("victim_flow", {})
        if vf:
            summary["victim_flow"] = {
                "visited_pages": vf.get("visited_pages", [])[:10],
                "iframes": vf.get("iframes", [])[:15],
                "input_fields": vf.get("input_fields", [])[:30],
                "forms": vf.get("forms", [])[:10],
                "external_domains": vf.get("external_domains", [])[:40],
            }
        history = dynamic.get("history", [])
        if history:
            summary["dynamic_analysis"]["action_history"] = [
                f"Step {h.get('step')}: {h.get('action')}({json.dumps(h.get('args', {}), ensure_ascii=False)[:60]}) -> {h.get('result')}"
                for h in history[:15]
            ]

    return summary


def _build_evidence_file_table(domain: str, date_str: str) -> str:
    """evidence 폴더의 파일 목록으로 '수집 자료 참조' 표를 코드로 직접 생성"""
    edir = _find_latest_evidence_dir(domain, date_str)
    if not edir or not edir.exists():
        return ""

    lines = ["\n## 수집 자료 참조\n", "| 자료 | 경로 |", "| :--- | :--- |"]
    label_map = {
        "dns.json": "DNS 조회 결과", "whois.txt": "WHOIS 결과",
        "virustotal.json": "VirusTotal 응답", "urlscan.json": "URLScan 응답",
        "criminalip.json": "CriminalIP 응답", "censys.json": "Censys 응답",
        "dom_analysis.json": "DOM 분석", "infra_probe.json": "인프라 프로빙",
        "passive_dns.json": "Passive DNS", "gemini_analysis.json": "Gemini AI 분석",
        "dynamic_result.json": "동적 분석 결과", "index.html": "HTML 원본",
        "requests.json": "네트워크 요청 로그", "visited_urls.json": "방문 URL 목록",
    }

    rel_base = f"evidence/{domain}/{edir.name}"
    for fpath in sorted(edir.rglob("*")):
        if fpath.is_file():
            label = label_map.get(fpath.name, fpath.name)
            rel = f"{rel_base}/{fpath.relative_to(edir)}"
            lines.append(f"| {label} | `{rel}` |")

    return "\n".join(lines) if len(lines) > 3 else ""


def generate_final_report(api_key: str, evidence: dict, review: dict,
                          additional_results: list, domain: str, date_str: str,
                          chain_results: list = None) -> str:
    """최종 분석 보고서 생성 (2-pass: 핵심 분석 + 인프라 심층)"""
    extracted = extract_evidence_summary(evidence)

    # --- Pass 1: 핵심 분석 ---
    # prior_analysis를 별도로 빼서 프롬프트에 명시적으로 배치
    prior_analysis = extracted.pop("prior_analysis", "")
    # infra_probe 상세는 Pass 2에서 사용
    infra_data = extracted.pop("infra_probe", {})

    core_str = safe_truncate_json(extracted, max_chars=12000)

    pass1_prompt = f"""당신은 최고 수준의 사이버 보안 분석 전문가(Chief Analyst)입니다.
아래 **실제 수집 데이터**를 기반으로 악성사이트 분석 보고서를 작성하세요.

## 절대 규칙
1. 아래 증거 데이터에 존재하는 값만 인용하세요. **데이터를 절대 지어내지 마세요.**
2. IP, 해시, URL, 도메인은 증거에서 **정확히 복사**하세요. placeholder(x.x.x, abc123...)는 금지.
3. VirusTotal malicious 수가 0이면 "탐지 엔진 0개"라고 정확히 기술하세요.
4. 확인되지 않은 항목은 **"미확인"** 또는 **"추가 조사 필요"**로 표시하세요.
5. 사이트 유형은 DOM 분석의 platform/구조 정보를 기준으로 판단하세요.
6. 모든 섹션에서 반드시 증거의 구체적 수치/도메인/IP를 인용하세요.

## 분석 대상: {domain}
## 분석 일시: {date_str}

## 1단계 분석 결과 (참조용 — 오류가 있을 수 있으니 raw 데이터와 대조하세요)
{prior_analysis[:2500] if prior_analysis else "(없음)"}

## 수집 데이터 (raw)
{core_str}

## 보고서 구조 (이 순서대로 작성)

# {domain} 악성사이트 분석 보고서

| 항목 | 내용 |
|---|---|
| 분석 대상 | {domain} |
| 분석 일시 | {date_str} |
| 판정 결과 | (악성/의심/정상 — 확신도 N%) |
| 위협 유형 | (구체적) |

## 1. 개요
한 단락으로 사이트의 성격과 핵심 위협을 요약.

## 2. TI 조회 결과 요약
각 TI 소스별(VirusTotal, URLScan, CriminalIP, DNS/WHOIS) **실제 수치**를 기재.
데이터가 없는 소스는 "데이터 없음"으로 표시.

## 3. 직접 접근 분석
사이트 구조, 방문 페이지 제목, 기재된 업체 정보, 네트워크 요청에서 관찰된 외부 도메인.
DOM 분석의 platform 정보, input_fields, suspicious_patterns 인용.
**반드시 `victim_flow` 데이터를 활용하세요:**
- `visited_pages`: AI 에이전트가 실제로 탐색한 페이지 경로 (메인 → 상품 → checkout 등)
- `iframes`: 결제/로그인 iframe의 src (예: Airwallex, Stripe 같은 결제 GW 식별)
- `input_fields`: checkout/로그인 페이지에서 수집되는 입력 필드 (type/name/placeholder)
- `forms`: form action URL → 실제 데이터가 전송되는 서버 파악
- `dynamic_analysis.action_history`: AI 에이전트가 수행한 행동 단계별 기록 (어떤 버튼을 눌러 어디에 도달했는지)
이 데이터를 근거로 "AI 에이전트가 X 페이지까지 자동 탐색했고, 결제 iframe Y 또는 입력 필드 Z가 확인됨"처럼 구체적으로 서술하세요.

## 4. 핵심 악성 근거
증거 데이터에 기반한 구체적 악성 근거를 번호 매겨 나열. 각 근거에 증거 인용 필수.

## 5. 악성 행위 상세
실제 사이트 유형에 해당하는 항목만 작성 (해당 없는 항목은 생략):
- 개인정보 탈취 (어떤 데이터가, 어떤 경로로)
- 결제/금융 사기 (결제 흐름, 카드 정보 처리)
- 로그인 정보 탈취 (사칭 대상, 크리덴셜 전송 경로)
- 사용자 추적/기기 핑거프린팅
- 사회공학적 조작 기법
- 악성파일 다운로드 / C2 통신

## 6. 공격 시나리오
[STEP 1]~[STEP N] 형식. 각 단계마다: URL, 행위, 로드되는 외부 리소스, 수집되는 데이터, 전송 대상 서버를 **구체적으로** 명시.

## 7. 데이터 전송 경로 요약
텍스트 다이어그램으로 데이터 유형별(개인정보, 카드정보, 추적데이터 등) 전송 경로 표현.

## 8. IOC 목록
도메인 표(도메인 | 역할), IP 표(IP | 용도), 기타 IOC(이메일, 전화번호 등).
**증거 데이터에서 추출한 실제 값만 사용.**

한국어로 작성해 주세요."""

    print("  [Pass 1] 핵심 분석 보고서 생성 중...")
    pass1_result = get_gemini_response(api_key, pass1_prompt, max_output_tokens=16384)

    if not pass1_result:
        return ""

    # --- Pass 2: 인프라/네트워크 심층 + 대응 권고 ---
    infra_str = safe_truncate_json(infra_data, max_chars=6000) if infra_data else "(인프라 데이터 없음)"

    # review 결과에서 핵심 정보 추출
    review_summary = {
        "current_verdict": review.get("current_verdict"),
        "confidence": review.get("confidence"),
        "key_findings": review.get("key_findings_so_far", [])[:5],
        "additional_iocs": review.get("additional_iocs", [])[:10],
    }
    review_str = safe_truncate_json(review_summary, max_chars=2000)

    chain_str = ""
    if chain_results:
        chain_str = safe_truncate_json(chain_results, max_chars=2000)

    pass2_prompt = f"""당신은 사이버 보안 분석 전문가입니다.
아래 인프라 분석 데이터를 기반으로 보고서의 후반부를 작성하세요.

## 절대 규칙
1. 아래 데이터에 존재하는 값만 인용하세요. 데이터를 지어내지 마세요.
2. IP, 도메인은 증거에서 정확히 복사하세요.

## 분석 대상: {domain}

## 인프라 프로빙 데이터
{infra_str}

## 갭 분석 결과
{review_str}

## 연쇄 분석 결과
{chain_str if chain_str else "(미수행)"}

## 작성할 섹션

## 9. 인프라 분석
원본 서버(origin candidates) 정보, ALB/CNAME 구조, CDN 우회 결과.
SSL 인증서 SAN에서 발견된 관련 도메인 목록 (DGA 의심 여부 포함).

## 10. 스캠 네트워크 구조도
mermaid graph TD 형식으로 인프라 관계도 작성.
사용자 → CDN → 원본서버, 리소스서버, 추적서버 등 실제 데이터 기반.

## 11. 대응 권고
네트워크 차단, 사용자 주의보, 기관 신고, 모니터링 등 구체적 권고.

## 12. 분석 한계 및 추가 조사 권고
현재 분석에서 확인되지 않은 사항과 추가 조사가 필요한 영역.

한국어로 작성해 주세요."""

    print("  [Pass 2] 인프라/대응 권고 생성 중...")
    pass2_result = get_gemini_response(api_key, pass2_prompt, max_output_tokens=8192)

    # --- 최종 조합 ---
    report_parts = [pass1_result]
    if pass2_result:
        report_parts.append(pass2_result)

    # 수집 자료 참조 표 (코드로 직접 생성)
    evidence_table = _build_evidence_file_table(domain, date_str)
    if evidence_table:
        report_parts.append(evidence_table)

    report_parts.append(f"\n---\n분석 수행: phishAI 자동 분석 도구 + Gemini AI")

    return "\n\n".join(report_parts)


def main():
    parser = argparse.ArgumentParser(description="phishAI 분석 총괄 에이전트")
    parser.add_argument("domain", help="분석 대상 도메인")
    parser.add_argument("--date", default=datetime.now().strftime("%Y-%m-%d"), help="분석 날짜")
    parser.add_argument("--max-rounds", type=int, default=2, help="추가 조사 최대 반복 횟수")
    parser.add_argument("--chain", action="store_true", help="연쇄 분석 활성화")
    args = parser.parse_args()

    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        print("[!] GEMINI_API_KEY가 필요합니다")
        sys.exit(1)

    domain = args.domain
    date_str = args.date

    from ti_clients.api_logger import setup_run_logger
    log_path = setup_run_logger("analyst_agent", domain)

    print(f"{'='*60}")
    print(f"  phishAI 분석 총괄 에이전트 (Chief Analyst)")
    print(f"  대상: {domain} | 일시: {date_str}")
    print(f"  실행 로그: {log_path}")
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
    if args.chain:
        print(f"\n[4/5] 연쇄 분석 대상 식별 중...")
        chain_targets = identify_chain_targets(api_key, evidence)
        if chain_targets:
            print(f"  연쇄 분석 대상: {len(chain_targets)}개")
            chain_results = run_chain_analysis(chain_targets[:3], date_str)
            for cr in chain_results:
                if cr.get("status") == "completed":
                    chain_dir = REPORTS_DIR / cr['target']
                    chain_report = None
                    if chain_dir.exists():
                        candidates = sorted(
                            [f for f in chain_dir.glob(f"{date_str}*.json")],
                            key=lambda f: f.name, reverse=True
                        )
                        if candidates:
                            chain_report = candidates[0]
                    if chain_report and chain_report.exists():
                        with open(chain_report) as f:
                            evidence["sources"][f"chain_{cr['target']}"] = json.load(f)
        else:
            print("  연쇄 분석 불필요")
    else:
        print(f"\n[4/5] 연쇄 분석: 건너뜀 (--chain 옵션으로 활성화)")

    # 5단계: 최종 보고서 생성
    print(f"\n[5/5] 최종 분석 보고서 생성 중...")
    final_report = generate_final_report(api_key, evidence, review, all_additional, domain, date_str, chain_results)

    if final_report:
        edir_found = _find_latest_evidence_dir(domain, date_str)
        timestamp = edir_found.name if edir_found else date_str
        report_path = REPORTS_DIR / domain / f"{timestamp}_final_report.md"
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
