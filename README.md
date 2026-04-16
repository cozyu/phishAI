# phishAI

악성사이트(피싱/스캠) 자동 분석 도구. TI(Threat Intelligence) API, DOM 분석, 인프라 프로빙, 생성형 AI를 결합하여 의심 도메인을 7단계로 심층 분석합니다.

## 분석 파이프라인

```
python3 analyze.py <domain>

  [1] DNS/WHOIS 조회
  [2] TI API 병렬 조회 (VirusTotal, URLScan, CriminalIP, Censys)
  [3] VT Passive DNS (과거 IP 히스토리, 비-CDN IP 식별)
  [4] DOM 분석 (Docker Playwright / curl 정적 분석)
  [5] 인프라 프로빙 (CNAME, HTTP 헤더, SSL 인증서 SAN)
  [6] Gemini AI 종합 분석
  → JSON 보고서 + 콘솔 요약
```

## 주요 기능

| 기능 | 설명 |
|------|------|
| **TI API 통합** | VirusTotal, URLScan, CriminalIP, Censys 병렬 조회 |
| **CriminalIP 풀스캔** | 데이터 없으면 자동 스캔 요청 + 폴링 |
| **VT Passive DNS** | CDN 이전 원본 IP 추적 |
| **인프라 프로빙** | CDN 우회 원본 서버 추적 (CNAME/헤더/SSL SAN 분석) |
| **Docker 샌드박스** | Playwright로 안전한 동적 분석 (결제 페이지 자동 진입) |
| **Gemini AI** | 수집 데이터 종합 판정 (4개 모델 자동 폴백) |
| **분석 총괄 에이전트** | 갭 분석 + 연쇄 분석 자동화 |
| **PDF 보고서** | 마크다운 보고서를 PDF로 변환 |

## 시스템 요구사항

### 필수
- Python 3.8+
- curl

### 권장 (없으면 해당 기능 건너뜀)
- dig (`dnsutils` 패키지) — DNS MX/NS/TXT/CNAME 조회
- whois — 도메인 등록 정보 조회
- openssl — SSL 인증서 SAN 분석 (인프라 프로빙)

### 선택
- docker — 동적 분석 샌드박스
- google-chrome 또는 chromium — PDF 보고서 변환

```bash
# Ubuntu/Debian 설치 예시
sudo apt install dnsutils whois curl openssl
```

## 빠른 시작

```bash
# 의존성 설치
pip install requests python-dotenv

# API 키 설정
cp .env.example .env   # 키 입력 후 사용 (없는 서비스는 자동 건너뜀)

# 분석 실행
python3 analyze.py example.com

# 총괄 에이전트 (추가 조사 + 연쇄 분석 + 최종 보고서)
python3 analyst_agent.py example.com

# PDF 변환
python3 report_to_pdf.py reports/example.com_2026-04-16_report.md
```

## Docker 샌드박스 (선택)

악성사이트에 JS 실행이 필요한 동적 분석을 안전하게 수행합니다.

```bash
# 이미지 빌드 (최초 1회)
docker build -t phishai-sandbox docker/

# 이후 analyze.py가 자동으로 Docker 동적 분석 사용
# Docker 없으면 curl 정적 분석으로 자동 폴백
```

보안 격리: `--cap-drop=ALL`, `--read-only`, `--no-new-privileges`, `--memory=512m`, 비-root 실행

## 프로젝트 구조

```
phishAI/
├── analyze.py              # 메인 분석 CLI
├── analyst_agent.py        # 분석 총괄 에이전트 (검토 + 연쇄 분석 + 최종 보고서)
├── report_to_pdf.py        # MD → PDF 변환
├── ti_clients/
│   ├── virustotal.py       # VirusTotal API + Passive DNS
│   ├── urlscan.py          # URLScan API
│   ├── criminalip.py       # Criminal IP API + 풀스캔 자동화
│   ├── censys.py           # Censys API
│   ├── gemini_analyzer.py  # Gemini AI 종합 분석 (모델 폴백)
│   ├── infra_prober.py     # 인프라 프로빙 (CNAME/헤더/SSL SAN)
│   ├── site_analyzer.py    # DOM 분석 + Docker 동적 분석
│   └── api_logger.py       # API 호출 로깅
├── docker/
│   ├── Dockerfile          # Playwright 샌드박스 이미지
│   └── sandbox_analyze.py  # 컨테이너 내 동적 분석 스크립트
├── evidence/               # 수집 자료 (도메인별)
├── reports/                # 분석 보고서 (JSON, MD, PDF)
└── log/                    # API 호출 로그
```

## API 키 설정

| 환경 변수 | 서비스 | 필수 |
|-----------|--------|:----:|
| `VIRUSTOTAL_API_KEY` | VirusTotal | 권장 |
| `URLSCAN_API_KEY` | URLScan.io | 권장 |
| `CRIMINALIP_API_KEY` | Criminal IP | 권장 |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys | 선택 |
| `GEMINI_API_KEY` | Google Gemini | 권장 |

키가 없는 서비스는 자동으로 건너뛰며, 사용 가능한 서비스만으로 분석을 진행합니다.

## 분석 방법론

이 도구는 다음과 같은 분석 인사이트를 자동화합니다:

- **TI 탐지율 0 ≠ 안전** — 신규 도메인은 블랙리스트 미등록. 정황 증거(인프라 패턴, 기업정보 위조)가 더 중요
- **API 서버가 보안의 약한 고리** — 메인 도메인은 CDN 뒤에 숨겨도 API/리소스 서버는 직접 노출되는 경우가 대부분
- **SSL 인증서 SAN이 강력한 IOC 소스** — 하나의 인증서에서 수십 개 스캠 도메인을 한 번에 발견 가능
- **DOM 분석이 TI보다 정보량 많음** — 플랫폼 식별자, 추적 스크립트, 외부 도메인이 DOM에 존재
