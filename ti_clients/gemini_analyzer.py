import json
import requests
from .api_logger import log_api_call


GEMINI_MODELS = [
    "gemini-3-flash-preview",
    "gemini-2.5-flash",
    "gemini-3.1-flash-lite-preview",
    "gemini-2.5-flash-lite",
]

BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiAnalyzer:
    """수집된 TI 데이터를 Gemini로 종합 분석하여 최종 판정 및 보고서 생성"""
    name = "Gemini"
    env_keys = ["GEMINI_API_KEY"]

    def __init__(self, api_key: str):
        self.api_key = api_key

    def synthesize(self, domain: str, collected_data: dict) -> dict:
        prompt = f"""당신은 사이버 보안 분석 전문가입니다. 아래 수집된 위협 인텔리전스(TI) 데이터를 종합 분석하여 악성사이트 여부를 판정해 주세요.

## 분석 대상
도메인: {domain}

## 수집 데이터
{json.dumps(collected_data, indent=2, ensure_ascii=False)[:15000]}

## 요청 출력 형식
다음 항목을 포함하여 분석해 주세요:

1. **종합 판정**: 악성/의심/정상 중 하나와 확신도(%)
2. **위협 유형**: 피싱, 멀웨어 배포, C2 서버, 스캠 등 해당되는 유형
3. **핵심 근거**: 악성 판정의 주요 근거 3-5개 (구체적 데이터 인용)
4. **IOC (Indicators of Compromise)**: 관련 IP, 도메인, URL, 해시 등
5. **연관 분석 추천**: 추가로 조사해야 할 URL, IP, 도메인
6. **대응 권고**: 차단, 모니터링 등 권고 사항

한국어로 작성해 주세요."""

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096}
        }

        for model in GEMINI_MODELS:
            log_url = f"{BASE_URL}/{model}:generateContent"
            url = f"{log_url}?key={self.api_key}"
            try:
                r = requests.post(url, json=payload, timeout=60)
                log_api_call(f"Gemini/{model}", "POST", log_url, r.status_code, response_body=r.text)
                if r.status_code == 429:
                    print(f"  [Gemini] {model} 쿼터 초과, 다음 모델 시도...")
                    continue
                r.raise_for_status()
                data = r.json()
                text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                return {
                    "service": "Gemini AI Analysis",
                    "analysis": text,
                    "model": model,
                }
            except requests.exceptions.HTTPError:
                print(f"  [Gemini] {model} 오류, 다음 모델 시도...")
                continue

        raise RuntimeError("모든 Gemini 모델 쿼터 초과")
