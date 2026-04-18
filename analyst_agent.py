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

# =============================================================================
# Prompt 템플릿 — `.format()` 사용. 리터럴 중괄호는 `{{`, `}}` 로 이스케이프.
# 실제 호출은 이 파일 하단의 `_build_*_prompt()` 헬퍼로 수행.
# =============================================================================

_REVIEW_GAPS_PROMPT = """당신은 최고 수준의 사이버 보안 분석 전문가(Chief Analyst)입니다.
아래는 악성사이트 분석을 위해 수집된 모든 증거 자료입니다.

## 수집 데이터
{evidence_str}

## 당신의 임무
1. 수집된 모든 데이터를 검토하고, 분석의 완성도를 평가하세요.
2. 추가로 조사해야 할 항목이 있다면 구체적으로 나열하세요.
3. 각 추가 조사 항목에 대해 조사 방법(어떤 API, 어떤 도구)도 명시하세요.

## 제약 (반드시 준수)
- **이미 수집된 항목은 gaps로 나열하지 마세요.** `sources`의 키를 보고 판단하세요:
  - `virustotal`, `urlscan`, `criminalip`, `censys`, `passive_dns`, `infra_probe`,
    `whois`, `dns_dns`, `gemini_analysis`, `dynamic_result`, `html_summary` 등이
    있으면 해당 TI/DNS/WHOIS는 **메인 도메인에 대해 이미 완료**된 것입니다.
- gaps는 **메인 도메인의 재조회가 아니라** 다음 중 하나에 한정:
  (a) 1단계 수집에서 빠진 **관련 도메인/IP**의 보조 조회,
  (b) 데이터 간 **교차검증**이 필요한 항목,
  (c) 아직 없는 새로운 **정황/근거**.
- 메인 도메인의 VT/WHOIS/DNS/URLScan/Censys/CriminalIP 재조회는 **금지**.

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


_CHAIN_TARGETS_PROMPT = """당신은 사이버 보안 분석 전문가입니다.
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


_PASS1_PROMPT = """당신은 최고 수준의 사이버 보안 분석 전문가(Chief Analyst)입니다.
아래 **실제 수집 데이터**를 기반으로 악성사이트 분석 보고서를 작성하세요.

## 절대 규칙
1. 증거 데이터에 존재하는 값만 인용하세요. **데이터를 절대 지어내지 마세요.**
2. IP, 해시, URL, 도메인은 증거에서 **정확히 복사**하세요. placeholder 금지.
3. **URL은 절대 축약하지 마세요.** 쿼리 파라미터, 세션ID, 경로를 포함한 전체 URL을 그대로 기술하세요. `.../detail/...?` 같은 축약은 금지.
4. VirusTotal malicious 수가 0이면 "탐지 엔진 0개"라고 정확히 기술하세요.
5. 확인되지 않은 항목은 **"미확인"** 또는 **"추가 조사 필요"**로 표시.
6. 모든 섹션에서 반드시 증거의 구체적 수치/도메인/IP/URL을 인용.
7. 섹션 번호 체계는 **2-1, 2-2, 3-1, 3-2 ...** 처럼 세부 번호로 작성.
8. 데이터가 풍부한 경우 축약보다 나열 우선. 독자가 독립적으로 사건을 재현할 수 있을 정도로 상세해야 합니다.

## 분석 대상: {domain}
## 분석 일시: {date_str}

## 1단계 분석 결과 (참조용 — 오류가 있을 수 있으니 raw 데이터와 대조)
{prior_analysis}

## 수집 데이터 (raw)
{core_str}

## 보고서 구조 (이 순서대로, 세부 번호 포함)

# {domain} 악성사이트 분석 보고서

| 항목 | 내용 |
|---|---|
| 분석 대상 | {domain} |
| 분석 일시 | {date_str} |
| 판정 결과 | **(악성/의심/정상) — 확신도 N%** |
| 위협 유형 | (구체적, 예: 쇼핑몰 스캠 / 피싱 / 카드 정보 탈취) |

## 1. 개요
한 단락으로 사이트의 성격과 핵심 위협을 요약.

## 2. TI 조회 결과 요약
### 2-1. VirusTotal
- 탐지: malicious=N, suspicious=N, harmless=N
- 평판 점수
- WHOIS 요약 (등록일/만료일/등록자 국가/등록 대행/privacy 여부)

### 2-2. URLScan
- 악성 판정 (True/False)
- IP (국가/CDN)
- 리다이렉트/외부 리소스 URL (도메인별 역할 포함)
- 스크린샷 경로 (있으면)

### 2-3. Criminal IP
- DGA 점수, JS 난독화 레벨, 응답 상태
- 관련 도메인/IP

### 2-4. DNS/WHOIS
- A 레코드 전체 / NS / MX / TXT (없으면 "없음" 명시)

## 3. 직접 접근 분석 — victim_flow 데이터 활용 필수
### 3-1. 사이트 구조
언어, 제품 카테고리, 가격대, 눈에 띄는 UI 문구("무료 배송", "7일 교체" 등).

### 3-2. 사이트 하단/푸터 기재 업체 정보
증거의 `victim_flow.business_info`를 표로 정리 (회사명, 대표자, 전화, 이메일, 사업자번호, 주소).
헤더/푸터 이메일 불일치, 사업자번호 지역코드 vs 기재 주소 불일치 등 **위조 증거를 교차검증**해 서술.

### 3-3. 네트워크 분석 (외부 리소스 의존성)
모든 외부 CDN/API 도메인과 그 역할. `victim_flow.external_scripts`와 `external_domains` 전체 나열.
통계/트래킹 파라미터(siteUserId, shopId 등)가 URL에 있으면 그대로 인용.

## 4. 핵심 악성 근거
### 4-1. 기업 정보 위조/불일치
사업자번호 지역불일치, 이메일 도메인 불일치, MX 레코드 없음 등.
### 4-2. 대량생산 스캠 인프라
템플릿 CDN(lndpy.com 등), 공유 API 서버(btrbdf.com 등), shopId/siteUserId 같은 대량운영 식별자.
### 4-3. 도메인 신뢰도 결여
생성 시점, 의미 없는 이름(DGA), WHOIS privacy, 등록자 국가와 사이트 언어 불일치.
### 4-4. 개인정보 탈취 수법
수집 페이지 URL, 수집되는 필드 종류 (개인통관고유부호, 주민번호 등 특수 필드 감지 시 강조).

## 5. 악성 행위 상세 (동적 분석)
**중요:** 이 섹션은 참조 보고서(고품질)와 동일한 **상세도**로 작성해야 합니다. 각 서브섹션에 bullet/표 + 설명이 반드시 들어가야 하고, URL은 전체 그대로.

### 5-1. 개인정보 탈취 (Credential Harvesting)
결제 페이지(`/checkout/...`)에서 다음 개인정보를 입력받는 폼 확인 — **2열 표 (입력 필드 | 설명)** 형식.
`victim_flow.input_fields` 전부 나열. 설명 컬럼에는 반드시 다음 중 해당 내용 포함:
- 포맷(예: "010-1234-5678 형식, 한국 번호"), 수집 명목(예: "배송 정보 수신"), 연동 API(예: "다음 우편번호 API(t1.daumcdn.net/mapjsapi) 연동"), 수집 방식(예: "Airwallex iframe으로 수집")
표 아래에 강조 문장: "피해자의 실명, 전화번호, 주소, 이메일, 신용카드 전체 정보가 한 번에 수집됨."

### 5-2. 결제 게이트웨이 악용 (Airwallex 등)
**4개 bullet 형식**으로 작성:
- **결제 처리**: `checkout.airwallex.com` iframe을 통한 카드 결제.
- **PG사 소개**: Airwallex는 홍콩 기반 글로벌 핀테크 기업의 정식 결제 게이트웨이.
- **위험성**: 정상 PG를 악용하므로 결제 자체는 실제로 처리될 수 있음 → **실제 금전 피해 발생**.
- **로깅 엔드포인트**: (확인되면) `o11y.airwallex.com/airtracker/logs` 등 관련 URL 나열.
이어서 **카드 정보 수집 iframe URL 3개**(card-number, expiry, cvc)를 코드블록 또는 bullet로 **전체 URL 그대로**.

### 5-3. Device Fingerprinting (기기 추적)
**3개 bullet + 강조 문장** 형식:
- `static.airwallex.com/.../sardine-iframe.html?...` — Sardine 사기방지 SDK (전체 URL)
- `static.airwallex.com/.../risk-iframe.html?...` — 위험 평가 SDK (전체 URL)
- `deviceInfo.*.js` 같은 기기 정보 수집 스크립트 (있으면 전체 URL)
**강조**: "피해자의 기기 정보까지 수집하여 향후 추가 사기에 활용 가능".

### 5-4. 사용자 행동 추적 (Behavioral Tracking)
**4개 bullet 형식**:
- `/statistics/md.gif?tracking_data=...` — 페이지 진입/이탈/클릭/구매 이벤트를 1px GIF로 추적. (아래 코드블록에 `victim_flow.tracking_requests`의 **모든 URL 전체 나열**)
- `arms-retcode.aliyuncs.com` 등 외부 행동분석 플랫폼 — 역할 설명.
- **추적 이벤트**: URL의 eventName 파라미터에서 관찰된 **모든 이벤트명 나열** (예: `enter`, `leave`, `DOMContentLoaded`, `buyNow`, `addToCart`, `openRepeatOrder`). 가능한 한 많이 추출.
- **강조**: "공격자가 피해자의 구매 여정을 실시간으로 모니터링".

tracking URL 코드블록 예시:
```
(중복 제거 없이 전부 나열)
https://ppxxzz.com/statistics/md.gif?tracking_data={{...eventName:"enter"...}}
https://ppxxzz.com/statistics/md.gif?tracking_data={{...eventName:"openRepeatOrder"...}}
...
```
50개면 50개 다. **Gemini가 자체 축약하지 말 것.**

### 5-5. 사회공학적 조작 (Social Engineering)
`victim_flow.scam_patterns`에 있는 각 패턴을 **개별 bullet로** 작성. 각 bullet에는:
- 실제 사이트 문구 (인용)
- 해당 문구가 유도하는 심리적 효과 (긴급성/희소성/신뢰도 위조/경계심 해제 등)

참조 보고서 스타일:
- "단 20개 남았습니다" + "4명이 구매 중입니다" — 가짜 긴급성/희소성 유도
- 가짜 구매자 이름 슬라이더 ("이*", "박*" 등 20명) — 위조된 사회적 증거
- "500개 판매 완료" — 신뢰도 위조
- "카드 결제(❤현대카드 추천❤)" — 특정 카드사 추천으로 신뢰 유도
- 카운트다운 타이머 ("남은 05:59:53") — 즉각적 결제 유도
- 중국어 CAPTCHA ("安全验证", "拖动下方滑块完成拼图") — 정상 보안 절차 위장

scam_patterns가 6개 있으면 6개 전부. 축약 금지.

### 5-6. 악성 파일 다운로드 / C2 통신
**반드시 작성 (누락 금지)**. 3개 bullet:
- 분석 시점에 악성 파일 자동 다운로드 — **확인 여부** (미확인이면 "미확인"으로 명시)
- C2 서버 직접 명령제어 통신 — **확인 여부** (미확인이면 "미확인")
- 대체 통신 경로: evidence의 API 서버(api.btrbdf.com 등)로의 지속적 API 통신이 피해자 데이터 수집/전달 역할 수행.

## 5-7. URL 기반 공격 시나리오 (피해자 흐름 재현)
**코드 블록(\\`\\`\\`)** 하나로 모든 STEP을 담아 작성. visited_pages 수에 맞춰 **최소 6 STEP 이상**으로 상세화. 결제 페이지는 반드시 서브스텝([4-A]~[4-E])으로 분해.

각 STEP에 반드시 포함:
- **URL** (전체, 축약 금지 — 쿼리 파라미터·세션ID·경로 모두 유지)
- **행위** (사용자 관점에서 무엇을 하는지)
- **조작 문구** (scam_patterns 및 페이지 본문에서 관찰된 가짜 긴급성·카운트다운·가짜 구매자 등)
- **로드되는 외부 리소스** (external_scripts/domains에서 인용, 도메인별 역할)
- **추적/API 호출** (tracking_requests에서 인용, eventName·수집 필드 명시)
- **전송 대상 서버**

결제 페이지 서브스텝 형식 예:
```
[STEP 4] 결제 페이지 (개인정보 + 카드 정보 수집)
  URL: https://ppxxzz.com/checkout/<전체 경로+쿼리>
  추적: /statistics/md.gif → eventName: "addToCart" (장바구니 추가, 상품/가격 정보 포함)

  [4-A] 개인정보 입력 폼:
     - firstname (실명)
     - phone1 (전화번호)
     - zipCode / building (우편번호 + 상세주소)
     - email
     → 전송: ppxxzz.com → api.btrbdf.com

  [4-B] 결제수단 선택:
     - 사용 가능 결제수단 나열
     - 기본 선택된 옵션

  [4-C] 카드 정보 입력 (iframe):
     - iframe 1: checkout.airwallex.com/#/elements/card-number?... (전체 URL)
     - iframe 2: checkout.airwallex.com/#/elements/expiry?...
     - iframe 3: checkout.airwallex.com/#/elements/cvc?...
     - iframe 4: checkout.airwallex.com/#/frame/popup?...

  [4-D] Device Fingerprinting:
     - iframe 5: static.airwallex.com/.../sardine-iframe.html?sessionKey=... (전체)
     - iframe 6: static.airwallex.com/.../risk-iframe.html?... (전체)
     - script: imgstorage2.lndpy.com/.../deviceInfo.*.js

  [4-E] CAPTCHA 위장 (있는 경우):
     - scam_patterns에 '중국어 CAPTCHA' 있으면 안심 경계심 해제 기법 서술
```
Airwallex iframe이나 sardine/risk iframe은 URL의 쿼리 파라미터까지 그대로 복사.

## 5-8. 데이터 전송 경로 요약
**ASCII 박스 다이어그램**으로 데이터 유형별(개인정보/카드정보/기기정보/행동데이터/추적데이터) 전송 경로를 표현.
예:
```
피해자 브라우저
  ├─[개인정보]──→ ppxxzz.com (CloudFront) ──→ GIIKIN ALB (싱가포르)
  ├─[카드정보]──→ checkout.airwallex.com (Airwallex PG, 홍콩)
  ├─[기기정보]──→ static.airwallex.com (Sardine/Risk iframe)
  └─[추적데이터]─→ /statistics/md.gif → api.btrbdf.com
```
(이 섹션은 반드시 ASCII 형식. mermaid는 6-5 스캠 네트워크 구조도에서만 사용.)

한국어로 작성해 주세요."""


_PASS2_PROMPT = """당신은 사이버 보안 분석 전문가입니다.
아래 인프라 분석 데이터를 기반으로 보고서의 후반부(6~10장)를 작성하세요.

## 절대 규칙
1. 아래 데이터에 존재하는 값만 인용. 지어내지 마세요.
2. IP·도메인·URL은 증거에서 **정확히 복사**, 축약 금지.
3. 섹션 번호는 Pass 1의 연장선(6, 7, 8 ...)으로 사용.
4. 축약보다 나열 우선. SSL SAN에 50개 도메인이 있으면 50개 모두 나열.
5. **기타 IOC 섹션**은 반드시 아래 `victim_flow.business_info` + WHOIS 데이터의 **실제 값**으로 채우세요. "미표기"라고 쓰지 말고 데이터에 있는 값을 그대로 복사하세요.

## 분석 대상: {domain}

## 인프라 프로빙 데이터
{infra_str}

## Victim Flow 증거 (7-3 기타 IOC 및 6-5 구조도에 활용)
{vf_str}

## WHOIS 원본 (registrar 추출용)
{whois_str}

## 갭 분석 결과
{review_str}

## 연쇄 분석 결과
{chain_str}

## 작성할 섹션 (Pass 1에 이어서)

## 6. 추가 분석 (인프라 · SSL · DGA)
### 6-1. 원본 서버 인프라 (CDN 우회 추적)
ALB CNAME, 원본 IP (리전 포함), 웹서버 소프트웨어, 식별된 플랫폼명.
표 형식으로 정리:
| 항목 | 값 |
|---|---|
| ALB CNAME | ... |
| 원본 IP | ... |
| 웹서버 | ... |
| 플랫폼명 | ... |

### 6-2. SSL 인증서 SAN 분석 — 스캠 네트워크 전체 도메인 식별
증거의 infra_probe.ssl_san 또는 관련 데이터에서 **모든 SAN 도메인을 전부 나열**하세요.
각 인증서(CN 기준)마다 별도 코드블록으로 나열:
```
<CN>의 인증서 SAN (총 N개):
도메인1, 도메인2, 도메인3, ...
```
DGA 점수가 계산된 도메인이 있으면 점수도 함께 표기.

### 6-3. 추가 의심 인프라 도메인
| 도메인 | 역할 | 비고 |
|---|---|---|
표 형식으로 정리 (리소스 CDN, 가짜 고객센터 등).

### 6-4. JS 난독화 / 보안 헤더
난독화 건수, Content-Security-Policy 등 보안 헤더 존재 여부.

### 6-5. 스캠 네트워크 구조도
**반드시 mermaid `graph TD` 다이어그램으로 작성.** (PDF는 mermaid를 그림으로 렌더합니다.)
사용자(피해자) → CDN → 메인 도메인 → (원본 서버 / 리소스 서버 / API 추적 서버 / 결제 GW / DGA 네트워크) 구조를 표현.

형식 예:
```mermaid
graph TD
    User["피해자"] --> CDN["AWS CloudFront<br/>18.67.51.x"]
    CDN --> Main["ppxxzz.com"]
    Main --> API["api.btrbdf.com<br/>AWS ALB Singapore"]
    Main --> Resource["imgstorage2.lndpy.com<br/>리소스 CDN"]
    Main --> Payment["checkout.airwallex.com<br/>결제 GW"]
    Payment --> FP["static.airwallex.com<br/>Sardine/Risk 핑거프린팅"]
    API --> DGA["DGA 네트워크<br/>btrbdf.com, csdrbt.com<br/>dsbrtd.com ..."]
    Main --> Tracking["/statistics/md.gif<br/>행동 추적"]
```
각 노드 레이블은 실제 증거의 도메인·IP·역할 포함. **8~12개 노드 권장.**

## 7. IOC (Indicators of Compromise)

### 7-1. 도메인
| 도메인 | 역할 |
|---|---|
evidence와 victim_flow에 있는 **모든** 도메인 나열 (메인 도메인, API 서버, 리소스 CDN, 결제 GW, 가짜 고객센터, DGA SAN 도메인 전부 포함).

### 7-2. IP 주소
| IP | 용도 |
|---|---|
evidence에 있는 **모든** IP 나열. 용도 컬럼에 "ppxxzz.com (AWS CloudFront)", "api.btrbdf.com (AWS ALB Singapore)", "외부 리소스 IP" 등 구체화.

### 7-3. 기타 IOC
**반드시 다음 6개 bullet을 실제 값으로 채우세요** (추상 설명 금지, 아래 데이터 값 그대로 인용):
- **등록 대행**: `whois_structured.registrar` 값 (예: `http://www.xinnet.com` 또는 `xinnet.com`). 파일 whois가 비어있어도 VT whois에서 가져온 값 사용. 데이터에 있으면 반드시 실제 값 기재.
- **등록자 국가/이메일**: `whois_structured.registrant_country`, `whois_structured.registrant_email` (예: `China`, `bcb35a666a802f50s@`)
- **도메인 생성/만료일**: `whois_structured.creation_date`, `whois_structured.expiry_date` (예: `2025-05-27` / `2026-05-27`)
- **전화번호**: `victim_flow.business_info.phones`의 모든 값 (예: `+86 13303999778`, `010-1234-5678`)
- **이메일**: `victim_flow.business_info.emails`의 모든 값 + WHOIS 등록자 이메일 (예: `service@ppxxzz.com`, `service@mail.mido-sale.com`)
- **사업자번호/통합사회신용코드**: `victim_flow.business_info.business_codes` (있으면 값 그대로, 없으면 `footer_texts`에서 추출 — 예: `91433127MAEY1FTT16`)
- **특정 URL**: 결제 iframe/tracking pixel의 대표 URL

## 8. 연쇄 분석 추천
| 추가 조사 대상 | 이유 |
|---|---|
- 연관 도메인/IP마다 왜 추가 조사해야 하는지 구체 명시.
- 푸터 이메일의 다른 도메인, 템플릿 CDN 인프라 등.

## 9. 대응 권고 (피해 방지)
다음 **5개 카테고리**를 반드시 모두 채우세요. 각각 구체적 대상 명시.

### 9-1. 네트워크 차단
방화벽/DNS 필터링에서 차단해야 할 도메인·IP 목록을 **bullet로 전체 나열**.
(C2/tracking/payment/resource 모두 포함).

### 9-2. 사용자 주의보
사용자에게 전달할 경고 내용 — 어떤 사이트에서 무엇을 입력 금지해야 하는지.
개인통관고유부호/주민번호 등 특수 필드가 있으면 강조.

### 9-3. 기관 신고
- KISA 보호나라 (https://www.boho.or.kr/)
- 경찰청 사이버수사국 (https://ecrm.police.go.kr/)
- 호스팅 사업자 abuse 신고 (AWS abuse@amazon.com, Alibaba Cloud 등 해당 시)
- 결제 게이트웨이 abuse 신고 (Airwallex 등 악용된 경우)

### 9-4. 피해 확인 및 조치
결제가 이미 발생했을 때: 카드사 승인 취소, 카드 재발급, 개인정보 노출 시 계좌 모니터링.

### 9-5. 지속적 모니터링
관련 인프라(templates CDN, API 서버)에서 생성되는 신규 스캠 도메인 추적 방안.

## 10. 분석가 주석
VT 탐지율 0 등 오탐으로 보일 수 있는 결과에 대한 해설.
왜 TI 탐지가 없음에도 악성으로 판정했는지 **결정적 근거** 3~5개로 요약.

한국어로 작성해 주세요. 텍스트가 길어져도 괜찮으니 세부 정보를 모두 포함하세요."""


def _build_review_gaps_prompt(evidence_str: str) -> str:
    return _REVIEW_GAPS_PROMPT.format(evidence_str=evidence_str)


def _build_chain_targets_prompt(evidence_str: str) -> str:
    return _CHAIN_TARGETS_PROMPT.format(evidence_str=evidence_str)


def _build_pass1_prompt(domain: str, date_str: str,
                        prior_analysis: str, core_str: str) -> str:
    prior = (prior_analysis[:6000] if prior_analysis else "(없음)")
    return _PASS1_PROMPT.format(
        domain=domain, date_str=date_str,
        prior_analysis=prior, core_str=core_str,
    )


def _build_pass2_prompt(domain: str, infra_str: str, vf_str: str,
                        whois_str: str, review_str: str,
                        chain_str: str) -> str:
    chain = chain_str if chain_str else "(미수행)"
    return _PASS2_PROMPT.format(
        domain=domain, infra_str=infra_str, vf_str=vf_str,
        whois_str=whois_str, review_str=review_str, chain_str=chain,
    )


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
    prompt = _build_review_gaps_prompt(evidence_str)
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
            target_domain = target.group(1)
            # 메인 도메인은 1단계 DNS/WHOIS 수집 시 이미 조회됨 — 재조회 스킵
            if target_domain == domain:
                result["status"] = "already_collected"
                result["data"] = "메인 도메인 WHOIS는 1단계에서 수집됨 (evidence/.../dns_whois/whois.txt, VT whois 폴백 포함)"
            else:
                try:
                    from ti_clients.whois_client import whois_lookup as _whois
                    text = _whois(target_domain, timeout=15)
                    if text:
                        result["status"] = "completed"
                        result["data"] = text[:2000]
                    else:
                        result["status"] = "skipped"
                        result["data"] = "WHOIS 서버 응답 없음"
                except Exception as e:
                    result["status"] = "error"
                    result["data"] = str(e)

    return result


def identify_chain_targets(api_key: str, evidence: dict) -> list:
    """수집 데이터에서 연쇄 분석이 필요한 도메인/IP 목록 추출"""
    evidence_str = safe_truncate_json(evidence, 12000)
    prompt = _build_chain_targets_prompt(evidence_str)
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


def _parse_whois_fields(whois_text: str) -> dict:
    """WHOIS 원문에서 주요 필드를 구조화 (Gemini가 놓쳐도 보고서에 반영되도록)"""
    if not whois_text:
        return {}
    fields = {}
    # 'Key: Value' 패턴 추출 (VT whois 및 표준 whois 모두 매칭)
    patterns = {
        "registrar": r"(?:Registrar|Domain registrar(?:\s+url)?)\s*:\s*(.+)",
        "registrar_id": r"Domain registrar id\s*:\s*(.+)",
        "creation_date": r"(?:Create date|Creation Date|Registered on)\s*:\s*(.+)",
        "expiry_date": r"(?:Expiry date|Expiration Date|Registry Expiry Date)\s*:\s*(.+)",
        "registrant_country": r"Registrant[\s_]?country\s*:\s*(.+)",
        "registrant_email": r"Registrant[\s_]?email\s*:\s*(.+)",
        "registrant_city": r"Registrant[\s_]?city\s*:\s*(.+)",
        "registrant_org": r"Registrant[\s_]?(?:organization|company|org)\s*:\s*(.+)",
        "admin_country": r"Admin(?:istrative)?[\s_]?country\s*:\s*(.+)",
        "name_servers": r"(?:Name server|Nameserver|Name Server)\s*:\s*(.+)",
    }
    for key, pat in patterns.items():
        matches = re.findall(pat, whois_text, re.IGNORECASE)
        if matches:
            # 중복 제거 (동일 필드가 여러 번 나오는 경우, 예: Name server)
            vals = []
            for m in matches:
                v = m.strip()
                if v and v not in vals:
                    vals.append(v)
            fields[key] = vals[0] if len(vals) == 1 else vals
    return fields


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

    # WHOIS — 우선순위: dns_whois/whois.txt > virustotal.whois
    whois_text = sources.get("whois", "")
    vt = sources.get("virustotal", {}) or {}
    vt_whois = vt.get("whois", "") if isinstance(vt, dict) else ""
    if not whois_text and vt_whois:
        whois_text = vt_whois
    if whois_text:
        summary["whois"] = whois_text[:3000]
        # 주요 필드를 구조화하여 추가 (Gemini가 추출에 실패해도 놓치지 않도록)
        whois_struct = _parse_whois_fields(whois_text)
        if vt:
            # VT의 구조화된 필드 병합
            if vt.get("registrar"):
                whois_struct.setdefault("registrar", vt.get("registrar"))
            if vt.get("creation_date"):
                whois_struct.setdefault("creation_date_ts", vt.get("creation_date"))
        if whois_struct:
            summary["whois_structured"] = whois_struct

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

    # 동적 분석 결과 — 중요 필드 전체 전달, 대용량(all_network_requests)은 요약
    dynamic = sources.get("dynamic_result", {})
    if dynamic and "error" not in dynamic:
        summary["dynamic_analysis"] = {
            "site_type": dynamic.get("site_type"),
            "severity": dynamic.get("severity"),
            "findings": dynamic.get("findings", ""),
            "rounds_completed": dynamic.get("rounds_completed"),
        }
        vf = dynamic.get("victim_flow", {}) or {}
        if vf:
            # all_network_requests는 수백개가 되므로 메서드·도메인별 카운트 요약으로 대체
            all_net = vf.get("all_network_requests", []) or []
            net_domain_counts: dict = {}
            for req in all_net:
                m = re.search(r"https?://([a-zA-Z0-9.-]+)", req.get("url", ""))
                if m:
                    net_domain_counts[m.group(1)] = net_domain_counts.get(m.group(1), 0) + 1
            compact_vf = {
                "visited_pages": vf.get("visited_pages", []),
                "iframes": vf.get("iframes", []),
                "input_fields": vf.get("input_fields", []),
                "forms": vf.get("forms", []),
                "external_domains": vf.get("external_domains", []),
                "external_scripts": vf.get("external_scripts", []),
                "tracking_requests": vf.get("tracking_requests", []),  # 전체 URL 그대로
                "scam_patterns": vf.get("scam_patterns", []),
                "business_info": vf.get("business_info", {}),
                "network_traffic_summary": {
                    "total_requests": len(all_net),
                    "domain_counts": dict(sorted(
                        net_domain_counts.items(), key=lambda x: -x[1]
                    )[:50]),
                },
            }
            summary["victim_flow"] = compact_vf
        history = dynamic.get("history", [])
        if history:
            summary["dynamic_analysis"]["action_history"] = [
                f"Step {h.get('step')}: {h.get('action')}({json.dumps(h.get('args', {}), ensure_ascii=False)}) -> {h.get('result')}"
                for h in history
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

    core_str = safe_truncate_json(extracted, max_chars=120000)

    pass1_prompt = _build_pass1_prompt(domain, date_str, prior_analysis, core_str)

    print("  [Pass 1] 핵심 분석 보고서 생성 중...")
    pass1_result = get_gemini_response(api_key, pass1_prompt, max_output_tokens=32768)

    if not pass1_result:
        return ""

    # --- Pass 2: 인프라/네트워크 심층 + 대응 권고 ---
    infra_str = safe_truncate_json(infra_data, max_chars=30000) if infra_data else "(인프라 데이터 없음)"

    # Pass 2가 IOC 섹션을 작성할 때 참조할 victim_flow.business_info + 주요 victim_flow 요약
    vf_for_pass2 = extracted.get("victim_flow", {}) or {}
    business_info = vf_for_pass2.get("business_info", {})
    victim_flow_summary = {
        "business_info": business_info,
        "visited_pages": vf_for_pass2.get("visited_pages", []),
        "external_domains": vf_for_pass2.get("external_domains", []),
        "iframes": vf_for_pass2.get("iframes", []),
        "forms": vf_for_pass2.get("forms", []),
        "scam_patterns": vf_for_pass2.get("scam_patterns", []),
    }
    vf_str = safe_truncate_json(victim_flow_summary, max_chars=20000)

    # WHOIS 등록 대행 정보 — 파일 whois 없으면 VT whois 사용, 구조화된 필드도 포함
    whois_raw = extracted.get("whois", "")
    whois_struct = extracted.get("whois_structured", {})
    if whois_raw or whois_struct:
        whois_str = safe_truncate_json(
            {"whois_raw": whois_raw, "whois_structured": whois_struct},
            max_chars=5000,
        )
    else:
        whois_str = "(미수집)"

    review_summary = {
        "current_verdict": review.get("current_verdict"),
        "confidence": review.get("confidence"),
        "key_findings": review.get("key_findings_so_far", []),
        "additional_iocs": review.get("additional_iocs", []),
    }
    review_str = safe_truncate_json(review_summary, max_chars=6000)

    chain_str = ""
    if chain_results:
        chain_str = safe_truncate_json(chain_results, max_chars=6000)

    # Pass 1에서 수집된 IOC 참조
    pass2_prompt = _build_pass2_prompt(domain, infra_str, vf_str, whois_str, review_str, chain_str)

    print("  [Pass 2] 인프라/대응 권고 생성 중...")
    pass2_result = get_gemini_response(api_key, pass2_prompt, max_output_tokens=32768)

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
