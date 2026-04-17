# phishAI

악성사이트(피싱/스캠) 자동 분석 도구. TI(Threat Intelligence) API, DOM 분석, 인프라 프로빙, AI 기반 동적 분석을 결합하여 의심 도메인을 심층 분석합니다.

## 분석 파이프라인

```
python3 analyze.py <domain>

  [1] DNS/WHOIS 조회
  [2] TI API 병렬 조회 (VirusTotal, URLScan, CriminalIP, Censys)
  [3] VT Passive DNS (과거 IP 히스토리, 비-CDN IP 식별)
  [4] 인프라 프로빙 (CNAME, HTTP 헤더, SSL 인증서 SAN, DGA 점수)
  [5] AI 동적 분석 (Docker + Gemini Vision/Function Calling)
      — AI 에이전트가 피해자 관점에서 사이트를 탐색
      — 상품 링크 → CTA 버튼 → checkout/로그인 페이지까지 자동 진입
      — DOM 요소에 data-phishai-idx 부여, 메타데이터 기반 클릭
      — victim_flow(방문 페이지, iframe, PII 입력 필드, form action) 누적 수집
        → ti_responses/dynamic_result.json 에 저장되어 최종 보고서의 핵심 증거로 활용
  [6] Gemini AI 종합 판정
  → evidence/ 에 원본 자료 저장, JSON 보고서 + 콘솔 요약
```

## 주요 기능

| 기능 | 설명 |
|------|------|
| **TI API 통합** | VirusTotal, URLScan, CriminalIP, Censys 병렬 조회 |
| **CriminalIP 풀스캔** | 데이터 없으면 자동 스캔 요청 + 폴링 |
| **VT Passive DNS** | CDN 이전 원본 IP 추적 |
| **인프라 프로빙** | CDN 우회 원본 서버 추적 + SSL SAN 도메인 범용 필터링 |
| **AI 동적 분석** | Gemini Vision + Function Calling으로 샌드박스 내 사이트 자율 탐색 |
| **Gemini AI 판정** | 수집 데이터 종합 판정 (4개 모델 자동 폴백) |
| **분석 총괄 에이전트** | 갭 분석 + 추가 조사 + 연쇄 분석 + 최종 보고서(2-pass 생성) |
| **실행 로그 자동 저장** | stdout/stderr를 `log/run_*.log`에 자동 기록 |
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

악성사이트에 JS 실행이 필요한 동적 분석을 안전하게 수행합니다. AI 에이전트(Gemini Vision + Function Calling)가 샌드박스 내에서 페이지 스크린샷과 DOM을 보고 `click_element` / `fill_element` / `goto` / `scroll` 등 도구를 호출하여 사이트를 자율 탐색합니다.

```bash
# 이미지 빌드 (최초 1회)
docker build -t phishai-sandbox docker/

# 이후 analyze.py가 자동으로 AI 동적 분석 사용
# GEMINI_API_KEY 또는 Docker 미구성 시 레거시 Playwright 분석으로 자동 폴백
```

보안 격리: `--cap-drop=ALL`, `--read-only`, `--no-new-privileges`, `--memory=512m`, 비-root 실행

### AI 에이전트 탐색 전략
- DOM 요소(links/buttons/inputs)에 `data-phishai-idx` 고유 속성 부여 → selector 충돌 없이 정확한 클릭
- 각 요소에 메타데이터 제공(`same_text_count`, `y_band`, `size`) → 상품 카드 반복 버튼과 메인 CTA를 AI가 구별
- SYSTEM_PROMPT에 피해자 관점 탐색 지침 제공 → 범용 피싱 유형(쇼핑몰/로그인/투자 사기 등)에 대응

## 프로젝트 구조

```
phishAI/
├── analyze.py                  # 메인 분석 CLI
├── analyze_dynamic.py          # 동적 분석 엔트리 (AI / 레거시 폴백)
├── analyst_agent.py            # 분석 총괄 에이전트 (검토 + 추가 조사 + 연쇄 분석 + 최종 보고서)
├── report_to_pdf.py            # MD → PDF 변환
├── ti_clients/
│   ├── virustotal.py           # VirusTotal API + Passive DNS
│   ├── urlscan.py              # URLScan API
│   ├── criminalip.py           # Criminal IP API + 풀스캔 자동화
│   ├── censys.py               # Censys API
│   ├── gemini_analyzer.py      # Gemini AI 종합 분석 (모델 폴백)
│   ├── gemini_vision.py        # Gemini Vision + Function Calling 브라우저 에이전트
│   ├── ai_dynamic_analyzer.py  # AI 동적 분석 오케스트레이터 (Docker ↔ Gemini)
│   ├── infra_prober.py         # 인프라 프로빙 + SAN 범용 필터링 + DGA 휴리스틱
│   ├── site_analyzer.py        # DOM 정적 분석 + Docker 동적 분석 진입점
│   └── api_logger.py           # API 호출 로그 + 실행 로그(stdout/stderr) 자동 저장
├── docker/
│   ├── Dockerfile              # Playwright 샌드박스 이미지
│   ├── sandbox_agent.py        # AI 에이전트용 REPL (인덱스 기반 클릭/입력)
│   └── sandbox_analyze.py      # 레거시 Playwright 동적 분석 스크립트
├── evidence/<domain>/<ts>/     # 수집 자료 (스크린샷/HTML/네트워크/TI 응답)
├── reports/<domain>/           # 분석 보고서 (JSON + MD + PDF)
└── log/                        # API 호출 로그(api_YYYY-MM-DD.log) + 실행 로그(run_*.log)
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
- **SSL 인증서 SAN이 강력한 IOC 소스** — 하나의 인증서에서 수십 개 스캠 도메인을 한 번에 발견 가능. evidence 교차 참조로 제3자 SAN을 필터링하여 범용 적용
- **DOM 분석이 TI보다 정보량 많음** — 플랫폼 식별자, 추적 스크립트, 외부 도메인이 DOM에 존재
- **AI 에이전트가 피해자 경로를 자율 추적** — 단순 스크레이핑이 아니라 Gemini Vision이 스크린샷+DOM을 보고 "피해자라면 무엇을 클릭할까"를 판단하여 checkout/입력 페이지까지 진입
