import copy
import json
import os
import requests
from .api_logger import log_api_call


def _get_api_keys() -> list[str]:
    """사용 가능한 Gemini API 키 목록을 반환한다."""
    keys = []
    primary = os.getenv("GEMINI_API_KEY", "")
    if primary:
        keys.append(primary)
    # GEMINI_API_KEY_2, _3, ... 순서로 추가
    for i in range(2, 10):
        k = os.getenv(f"GEMINI_API_KEY_{i}", "")
        if k:
            keys.append(k)
    return keys


MAX_PROMPT_DATA_CHARS = 14000


def safe_truncate_json(data: dict, max_chars: int = MAX_PROMPT_DATA_CHARS) -> str:
    """JSON 데이터를 최대 문자 수 이내로 안전하게 축소.

    단순 문자열 슬라이싱 대신, 단계적으로 축소하여 JSON 구조를 유지한다.
    """
    full = json.dumps(data, indent=2, ensure_ascii=False)
    if len(full) <= max_chars:
        return full

    # 1단계: indent 제거
    compact = json.dumps(data, ensure_ascii=False)
    if len(compact) <= max_chars:
        return compact

    # 2단계: 깊은 복사 후 큰 값을 축소
    trimmed = copy.deepcopy(data)
    _trim_recursive(trimmed, max_list=10, max_str=500)
    result = json.dumps(trimmed, ensure_ascii=False)
    if len(result) <= max_chars:
        return result

    # 3단계: 더 공격적으로 축소
    _trim_recursive(trimmed, max_list=5, max_str=200)
    result = json.dumps(trimmed, ensure_ascii=False)
    return result[:max_chars]


def _trim_recursive(obj, max_list: int = 10, max_str: int = 500):
    """dict/list를 재귀적으로 순회하며 큰 값을 축소"""
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            val = obj[key]
            if isinstance(val, str) and len(val) > max_str:
                obj[key] = val[:max_str] + "...(truncated)"
            elif isinstance(val, list):
                if len(val) > max_list:
                    obj[key] = val[:max_list]
                _trim_recursive(obj[key], max_list, max_str)
            elif isinstance(val, dict):
                _trim_recursive(val, max_list, max_str)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                _trim_recursive(item, max_list, max_str)
            elif isinstance(item, str) and len(item) > max_str:
                obj[i] = item[:max_str] + "...(truncated)"


# 용도별 모델 티어
GEMINI_MODELS_LITE = [
    "gemini-2.5-flash-lite",  # RPD 20 — 최저 성능, 최저 비용
    "gemini-3.1-flash-lite-preview",  # RPD 500 — 단순 판단, 에이전트 루프용
    "gemini-2.5-flash",               # RPD 20 — 폴백
]
GEMINI_MODELS_STANDARD = [
    "gemini-3-flash-preview",         # RPD 20 — 최고 성능, 복잡한 종합 분석용
    "gemini-3.1-flash-lite-preview",  # RPD 500 — 폴백 (2.5 Flash보다 우수)
    "gemini-2.5-flash",               # RPD 20 — 폴백
    "gemini-2.5-flash-lite",  # RPD 20 — 최종 폴백
]

# 하위 호환용
GEMINI_MODELS = GEMINI_MODELS_STANDARD

BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiAnalyzer:
    """수집된 TI 데이터를 Gemini로 종합 분석하여 최종 판정 및 보고서 생성"""
    name = "Gemini"
    env_keys = ["GEMINI_API_KEY"]

    def __init__(self, api_key: str):
        self.api_keys = [api_key] + [k for k in _get_api_keys() if k != api_key]

    def synthesize(self, domain: str, collected_data: dict) -> dict:
        prompt = f"""당신은 사이버 보안 분석 전문가입니다. 아래 수집된 위협 인텔리전스(TI) 데이터를 종합 분석하여 악성사이트 여부를 판정해 주세요.

## 분석 대상
도메인: {domain}

## 수집 데이터
{safe_truncate_json(collected_data)}

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

        for api_key in self.api_keys:
            for model in GEMINI_MODELS_STANDARD:
                log_url = f"{BASE_URL}/{model}:generateContent"
                url = f"{log_url}?key={api_key}"
                try:
                    r = requests.post(url, json=payload, timeout=60)
                    log_api_call(f"Gemini/{model}", "POST", log_url, r.status_code, response_body=r.text)
                    if r.status_code in (429, 503):
                        reason = "쿼터 초과" if r.status_code == 429 else "서버 과부하"
                        print(f"  [Gemini] {model} {reason}, 다음 모델 시도...")
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
            print(f"  [Gemini] 키 #{self.api_keys.index(api_key)+1} 모든 모델 실패, 다음 키 시도...")

        raise RuntimeError("모든 Gemini API 키/모델 소진")
