"""Gemini Vision + Function Calling 기반 브라우저 에이전트 클라이언트

Gemini의 멀티모달(스크린샷) + Function Calling을 결합하여,
AI가 직접 브라우저 도구(click, fill, goto 등)를 호출하는 에이전트 루프를 구현한다.
"""

import base64
import json
import re
import requests
from pathlib import Path

from .api_logger import log_api_call
from .gemini_analyzer import (
    GEMINI_MODELS_LITE, BASE_URL, safe_truncate_json,
)


# 브라우저 제어 도구 정의 (Gemini Function Calling용)
BROWSER_TOOLS = [{
    "functionDeclarations": [
        {
            "name": "click",
            "description": "CSS 선택자로 요소를 클릭한다. 링크, 버튼, 입력 필드 등을 클릭할 때 사용.",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "클릭할 요소의 CSS 선택자 (예: '#login-btn', 'a.product-link')"
                    }
                },
                "required": ["selector"]
            }
        },
        {
            "name": "fill",
            "description": "입력 필드에 텍스트를 입력한다. 로그인 폼, 검색창, 개인정보 입력란 등에 사용.",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "입력할 요소의 CSS 선택자"
                    },
                    "value": {
                        "type": "string",
                        "description": "입력할 텍스트 값 (더미 데이터: test@test.com, 01012345678 등)"
                    }
                },
                "required": ["selector", "value"]
            }
        },
        {
            "name": "goto",
            "description": "지정 URL로 이동한다. 리다이렉트 추적, 하위 페이지 분석 시 사용.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "이동할 URL"
                    }
                },
                "required": ["url"]
            }
        },
        {
            "name": "scroll",
            "description": "페이지를 스크롤한다. 하단 콘텐츠 확인, 숨겨진 요소 노출 시 사용.",
            "parameters": {
                "type": "object",
                "properties": {
                    "amount": {
                        "type": "integer",
                        "description": "스크롤할 픽셀 수 (양수: 아래, 음수: 위). 기본 500."
                    }
                },
                "required": []
            }
        },
        {
            "name": "hover",
            "description": "요소에 마우스를 올린다. 드롭다운 메뉴, 숨겨진 요소 노출 시 사용.",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "hover할 요소의 CSS 선택자"
                    }
                },
                "required": ["selector"]
            }
        },
        {
            "name": "select_option",
            "description": "드롭다운/셀렉트 박스에서 옵션을 선택한다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "select 요소의 CSS 선택자"
                    },
                    "value": {
                        "type": "string",
                        "description": "선택할 옵션의 value"
                    }
                },
                "required": ["selector", "value"]
            }
        },
        {
            "name": "wait",
            "description": "페이지 로딩을 기다린다. 클릭/이동 후 콘텐츠 로딩 대기 시 사용.",
            "parameters": {
                "type": "object",
                "properties": {
                    "state": {
                        "type": "string",
                        "description": "대기 상태: networkidle (네트워크 유휴) 또는 domcontentloaded"
                    }
                },
                "required": []
            }
        },
        {
            "name": "done",
            "description": "분석을 완료하고 최종 결과를 보고한다. 충분한 증거를 수집했을 때 호출.",
            "parameters": {
                "type": "object",
                "properties": {
                    "site_type": {
                        "type": "string",
                        "description": "사이트 유형: shopping_scam, login_phishing, corp_impersonation, fake_finance, malware_download, survey_scam, tech_support, other"
                    },
                    "findings": {
                        "type": "string",
                        "description": "발견한 악성 지표와 증거를 상세히 기술"
                    },
                    "severity": {
                        "type": "string",
                        "description": "위험도: critical, high, medium, low, benign"
                    }
                },
                "required": ["site_type", "findings", "severity"]
            }
        },
    ]
}]

SYSTEM_PROMPT = """당신은 사이버 보안 분석 전문가입니다. Playwright 브라우저를 제어하여 악성 의심 사이트를 분석합니다.

## 분석 목표
주어진 사이트의 악성 여부를 판별하기 위해 브라우저 도구를 사용하여 사이트를 탐색하세요.

## 분석 관점
- 로그인 폼이 있으면: form action URL 확인, 더미 데이터(test@test.com) 입력 후 전송 경로 추적
- 쇼핑몰이면: 상품 클릭 → 결제 페이지 진입 → PG/결제 폼 분석
- 기업 사칭이면: 링크 클릭 → 리다이렉트 체인 추적
- 개인정보 수집이면: 입력 필드 분석, 데이터 전송 경로 확인
- 악성 다운로드 유도이면: 다운로드 링크/버튼 확인, 파일 유형 분석

## 규칙
- 매 스텝마다 도구를 하나씩 호출하세요
- 충분한 증거를 수집했으면 반드시 done 도구를 호출하세요
- 더미 데이터만 사용하세요 (test@test.com, 01012345678, John Doe 등)
- 실제 결제를 진행하지 마세요"""


class GeminiVisionClient:
    """Gemini Vision + Function Calling 기반 브라우저 에이전트"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.models = GEMINI_MODELS_LITE

    def analyze_page(self, screenshot_path: str, dom_summary: dict,
                     conversation: list = None) -> dict:
        """스크린샷 + DOM을 Gemini에 전달하고, 다음 도구 호출을 받는다.

        Returns:
            {"function_call": {"name": "click", "id": "...", "args": {...}}}
            또는 {"done": True, "site_type": ..., "findings": ..., "severity": ...}
            또는 {"text": "..."} (도구 호출 없이 텍스트만 반환한 경우)
            또는 {"error": "..."}
        """
        # 스크린샷을 base64로 인코딩
        image_part = self._encode_image(screenshot_path)
        if not image_part:
            return {"error": f"스크린샷 로드 실패: {screenshot_path}"}

        # DOM 요약 텍스트
        dom_text = safe_truncate_json(dom_summary, max_chars=6000)

        # 대화 히스토리 구성
        if conversation is None:
            # 첫 요청: 시스템 프롬프트 + 스크린샷 + DOM
            contents = [{
                "role": "user",
                "parts": [
                    {"text": f"{SYSTEM_PROMPT}\n\n## 현재 페이지 DOM 요약\n{dom_text}\n\n위 스크린샷의 사이트를 분석하세요. 브라우저 도구를 사용하여 탐색을 시작하세요."},
                    image_part,
                ]
            }]
        else:
            # 후속 요청: 기존 대화 + 새 스크린샷 + DOM
            contents = list(conversation)
            contents.append({
                "role": "user",
                "parts": [
                    {"text": f"## 현재 페이지 DOM 요약\n{dom_text}\n\n도구 실행 후의 현재 화면입니다. 분석을 계속하세요."},
                    image_part,
                ]
            })

        payload = {
            "contents": contents,
            "tools": BROWSER_TOOLS,
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024},
        }

        # API 호출 (모델 폴백)
        for model in self.models:
            log_url = f"{BASE_URL}/{model}:generateContent"
            url = f"{log_url}?key={self.api_key}"
            try:
                r = requests.post(url, json=payload, timeout=30)
                log_api_call(f"GeminiVision/{model}", "POST", log_url,
                             r.status_code, response_body=r.text[:2000])
                if r.status_code == 429:
                    print(f"  [GeminiVision] {model} 쿼터 초과, 다음 모델...")
                    continue
                r.raise_for_status()
                return self._parse_response(r.json(), contents)
            except requests.exceptions.HTTPError as e:
                print(f"  [GeminiVision] {model} 오류: {e}")
                continue

        return {"error": "모든 Gemini 모델 쿼터 초과"}

    def _encode_image(self, path: str) -> dict | None:
        """이미지 파일을 Gemini API용 inline_data로 변환"""
        p = Path(path)
        if not p.exists():
            return None
        data = base64.b64encode(p.read_bytes()).decode("utf-8")
        mime = "image/png" if p.suffix == ".png" else "image/jpeg"
        return {"inline_data": {"mime_type": mime, "data": data}}

    def _parse_response(self, data: dict, contents: list) -> dict:
        """Gemini 응답에서 function_call 또는 텍스트를 추출"""
        candidates = data.get("candidates", [])
        if not candidates:
            return {"error": "빈 응답"}

        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            return {"error": "빈 parts"}

        part = parts[0]

        # Function Call 응답
        if "functionCall" in part:
            fc = part["functionCall"]
            name = fc.get("name", "")
            args = fc.get("args", {})
            call_id = fc.get("id", "")

            # done 도구 호출 = 분석 완료
            if name == "done":
                return {
                    "done": True,
                    "site_type": args.get("site_type", "unknown"),
                    "findings": args.get("findings", ""),
                    "severity": args.get("severity", "medium"),
                }

            # 브라우저 도구 호출
            # 대화 히스토리에 model의 function_call을 추가
            updated_contents = list(contents)
            updated_contents.append({
                "role": "model",
                "parts": [{"functionCall": fc}]
            })

            return {
                "function_call": {
                    "name": name,
                    "id": call_id,
                    "args": args,
                },
                "conversation": updated_contents,
            }

        # 텍스트 응답 (도구 호출 없이)
        if "text" in part:
            return {"text": part["text"], "conversation": contents}

        return {"error": f"예상치 못한 응답 형식: {list(part.keys())}"}

    def build_function_response(self, conversation: list,
                                func_name: str, call_id: str,
                                result: dict) -> list:
        """도구 실행 결과를 대화 히스토리에 추가"""
        updated = list(conversation)
        updated.append({
            "role": "user",
            "parts": [{
                "functionResponse": {
                    "name": func_name,
                    "id": call_id,
                    "response": result,
                }
            }]
        })
        return updated
