"""순수 파이썬 WHOIS 클라이언트 — 시스템 `whois` 명령 의존 없음.

TCP 43 포트에 직접 질의하며 IANA referral 체인을 따라간다.
표준 라이브러리(socket, re)만 사용.

chain: IANA → TLD WHOIS 서버 → (옵션) Registrar WHOIS 서버
- Registrar 서버까지 도달하면 상세 등록자 정보(이메일/국가/전화 등)를 얻는다.
- 중간 단계 실패 시 이전 단계 응답을 그대로 반환한다(graceful degradation).
"""
import re
import socket


def _whois_tcp(query: str, server: str, timeout: int) -> str:
    """단일 WHOIS 서버에 TCP 43으로 질의하고 전체 응답을 문자열로 반환."""
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _extract_server(text: str, key: str) -> str | None:
    pattern = rf"^\s*{re.escape(key)}\s*:\s*(\S+)"
    m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def whois_lookup(domain: str, timeout: int = 10) -> str:
    """IANA referral 체인으로 도메인 WHOIS 조회. 실패 시 빈 문자열 반환."""
    try:
        iana_resp = _whois_tcp(domain, "whois.iana.org", timeout)
    except (OSError, socket.timeout):
        return ""

    tld_server = _extract_server(iana_resp, "refer")
    if not tld_server:
        return iana_resp

    try:
        tld_resp = _whois_tcp(domain, tld_server, timeout)
    except (OSError, socket.timeout):
        return iana_resp

    registrar_server = _extract_server(tld_resp, "registrar whois server")
    if registrar_server and registrar_server.lower() != tld_server.lower():
        try:
            reg_resp = _whois_tcp(domain, registrar_server, timeout)
            if reg_resp.strip():
                return f"{tld_resp}\n\n% Referred to registrar: {registrar_server}\n\n{reg_resp}"
        except (OSError, socket.timeout):
            pass

    return tld_resp
