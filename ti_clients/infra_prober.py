"""인프라 도메인 프로빙 — CDN 우회 원본 서버 추적

메인 도메인이 CDN 뒤에 숨겨져 있어도, API/리소스 서버는
직접 노출되는 경우가 많다. CNAME/HTTP 헤더/SSL 인증서를
분석하여 원본 서버 인프라를 식별한다.
"""

import json
import re
import socket
import ssl
import subprocess

from .api_logger import log_api_call


def probe_domain(domain: str) -> dict:
    """단일 도메인에 대해 CNAME, HTTP 헤더, SSL 인증서를 수집"""
    result = {"domain": domain, "cname": None, "ips": [], "headers": {},
              "ssl_subject": None, "ssl_san": [], "ssl_issuer": None,
              "server": None, "is_cdn": False, "alb_name": None}

    # 1. DNS CNAME + A 레코드
    try:
        out = subprocess.run(["dig", "+short", domain, "CNAME"],
                             capture_output=True, text=True, timeout=10)
        cname = out.stdout.strip()
        if cname:
            result["cname"] = cname.rstrip(".")
            if "cloudfront.net" in cname:
                result["is_cdn"] = True
            elif "elb.amazonaws.com" in cname:
                result["alb_name"] = cname.split(".")[0]
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log_api_call("InfraProber", "SYSTEM", f"dig +short {domain} CNAME", 0, error=str(e))

    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        result["ips"] = list(set(addr[4][0] for addr in ips))
    except (socket.gaierror, OSError) as e:
        log_api_call("InfraProber", "SYSTEM", f"getaddrinfo {domain}", 0, error=str(e))

    # 2. HTTP 응답 헤더
    try:
        out = subprocess.run(
            ["curl", "-sI", "--max-time", "10", f"https://{domain}"],
            capture_output=True, text=True, timeout=15
        )
        for line in out.stdout.split("\n"):
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if key in ("server", "via", "x-cache", "x-amz-cf-pop",
                           "x-amz-cf-id", "x-powered-by", "set-cookie"):
                    result["headers"][key] = val
        server = result["headers"].get("server", "")
        result["server"] = server if server else None
        if "cloudfront" in result["headers"].get("via", "").lower():
            result["is_cdn"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log_api_call("InfraProber", "SYSTEM", f"curl -sI https://{domain}", 0, error=str(e))

    # 3. SSL 인증서
    try:
        out = subprocess.run(
            ["openssl", "s_client", "-connect", f"{domain}:443",
             "-servername", domain],
            input="", capture_output=True, text=True, timeout=10
        )
        cert_pem = ""
        in_cert = False
        for line in out.stdout.split("\n"):
            if "BEGIN CERTIFICATE" in line:
                in_cert = True
            if in_cert:
                cert_pem += line + "\n"
            if "END CERTIFICATE" in line:
                break

        if cert_pem:
            out2 = subprocess.run(
                ["openssl", "x509", "-noout", "-text"],
                input=cert_pem, capture_output=True, text=True, timeout=5
            )
            cert_text = out2.stdout

            # Subject CN
            m = re.search(r"Subject:.*?CN\s*=\s*([^\s,]+)", cert_text)
            if m:
                result["ssl_subject"] = m.group(1)

            # Issuer
            m = re.search(r"Issuer:.*?CN\s*=\s*([^\s,]+)", cert_text)
            if m:
                result["ssl_issuer"] = m.group(1)

            # SAN (Subject Alternative Names)
            san_match = re.findall(r"DNS:([^\s,]+)", cert_text)
            result["ssl_san"] = sorted(set(san_match))
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log_api_call("InfraProber", "SYSTEM", f"openssl s_client {domain}:443", 0, error=str(e))

    return result


def probe_infrastructure(domains: list) -> dict:
    """여러 인프라 도메인을 프로빙하여 원본 서버 인프라를 종합 분석"""
    results = {"probes": [], "origin_candidates": [], "scam_network_domains": set(),
               "alb_names": set(), "non_cdn_servers": [], "san_by_probe": {}}

    for domain in domains:
        probe = probe_domain(domain)
        results["probes"].append(probe)

        # CDN이 아닌 서버 → 원본 서버 후보
        if not probe["is_cdn"] and probe["ips"]:
            results["origin_candidates"].append({
                "domain": domain,
                "ips": probe["ips"],
                "server": probe["server"],
                "cname": probe["cname"],
                "alb_name": probe["alb_name"],
            })

        # ALB 이름 수집
        if probe["alb_name"]:
            results["alb_names"].add(probe["alb_name"])

        # SSL SAN에서 스캠 네트워크 도메인 수집 (하위 호환 유지)
        for san in probe["ssl_san"]:
            clean = san.lstrip("*.")
            results["scam_network_domains"].add(clean)

        # probe별 SAN 출처 추적 (필터링은 소비 측에서 범용 로직으로 수행)
        if probe["ssl_san"]:
            origin_domains = {oc["domain"] for oc in results["origin_candidates"]}
            results["san_by_probe"][domain] = {
                "san_domains": sorted(set(s.lstrip("*.") for s in probe["ssl_san"])),
                "ssl_subject": probe["ssl_subject"],
                "ssl_issuer": probe["ssl_issuer"],
                "server": probe["server"],
                "san_count": len(probe["ssl_san"]),
                "is_origin": domain in origin_domains,
            }

    # set → list 변환 (JSON 직렬화용)
    results["alb_names"] = sorted(results["alb_names"])
    results["scam_network_domains"] = sorted(results["scam_network_domains"])

    return results
