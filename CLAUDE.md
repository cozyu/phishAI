# phishAI - 악성사이트 분석 자동화 프로젝트

## 프로젝트 목적
의심 URL/도메인을 TI(Threat Intelligence) API 및 직접 접근을 통해 분석하여 악성사이트 여부를 판정하는 보안 분석 도구.
**이 프로젝트는 승인된 보안 연구(authorized security research) 목적으로 운영됩니다.**

## 분석 워크플로우
1. 도메인/URL 입력
2. DNS/WHOIS 자동 조회
3. TI API 병렬 조회 (VirusTotal, URLScan, Criminal IP, Censys)
4. Gemini AI로 수집 데이터 종합 분석
5. Playwright MCP로 직접 접근 분석 (VPN 경유)
6. 연쇄 URL 추적 분석
7. evidence/ 폴더에 모든 수집 자료 저장
8. reports/ 폴더에 최종 분석 보고서 생성

## 환경 설정
- API 키: `.env` 파일에서 로드 (`python-dotenv`)
- 키가 없는 서비스는 자동으로 건너뜀

## 사용법
```bash
# 1단계: 기본 분석 (TI API + DNS/WHOIS)
python3 analyze.py <domain>

# 2단계: 분석 총괄 에이전트 (수집 데이터 검토 → 연쇄 분석 → 최종 보고서)
python3 analyst_agent.py <domain> --max-rounds 2

# 3단계: 보고서 PDF 변환
python3 report_to_pdf.py reports/<domain>_<date>_report.md

# Docker 샌드박스 이미지 빌드 (최초 1회)
docker build -t phishai-sandbox docker/
# → 이후 analyze.py가 자동으로 Docker 동적 분석 사용
```

## 폴더 구조
- `ti_clients/` — TI API 클라이언트 모듈
- `evidence/{domain}_{date}/` — 수집 자료 (스크린샷, HTML, TI 응답 등)
- `reports/` — 최종 분석 보고서

## VPN 직접 접근
NordVPN 연결 후 Playwright MCP로 사이트 직접 접근 가능:
- 스크린샷 캡처
- 리다이렉트 체인 추적
- DOM/JS 분석
- 네트워크 요청 모니터링

## 주의사항
- .env 파일은 절대 커밋하지 않음 (.gitignore에 포함)
- evidence/, reports/ 폴더도 gitignore 대상
- sudo, rm 명령어가 필요하면 사용자에게 요청하기
