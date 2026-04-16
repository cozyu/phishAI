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
            "name": "click_element",
            "description": "DOM 목록에서 인덱스로 요소를 클릭한다. links[N] 또는 buttons[N]을 참조. CSS 선택자 추측 없이 실제 존재하는 요소를 정확히 클릭할 수 있다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "description": "요소 유형: 'link' (links 목록) 또는 'button' (buttons 목록)"
                    },
                    "index": {
                        "type": "integer",
                        "description": "DOM 목록에서의 인덱스 번호 (예: links[3]이면 3)"
                    }
                },
                "required": ["type", "index"]
            }
        },
        {
            "name": "fill_element",
            "description": "DOM 목록에서 인덱스로 입력 필드를 선택하고 텍스트를 입력한다. inputs[N]을 참조.",
            "parameters": {
                "type": "object",
                "properties": {
                    "index": {
                        "type": "integer",
                        "description": "inputs 목록에서의 인덱스 번호"
                    },
                    "value": {
                        "type": "string",
                        "description": "입력할 텍스트 값"
                    }
                },
                "required": ["index", "value"]
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
            "description": "페이지를 스크롤한다.",
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
            "name": "wait",
            "description": "페이지 로딩을 기다린다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "state": {
                        "type": "string",
                        "description": "대기 상태: networkidle 또는 domcontentloaded"
                    }
                },
                "required": []
            }
        },
        {
            "name": "done",
            "description": "분석을 완료하고 최종 결과를 보고한다. 전환 페이지(checkout/login)에 도달했거나 충분한 증거를 수집했을 때 호출.",
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

SYSTEM_PROMPT = """당신은 사이버 보안 분석 전문가입니다. 악성 의심 사이트를 **피해자의 관점에서** 탐색합니다.

## 핵심 원칙
일반 사용자가 이 사이트에 접속했을 때 **자연스럽게 따라갈 경로**를 시뮬레이션하세요.
매 스텝마다 "피해자라면 무엇을 클릭하겠는가?"를 고려하세요.

## 요소 참조 방법
DOM 요약에 links, buttons, inputs 목록이 인덱스와 함께 제공됩니다.
**반드시 click_element 도구를 사용하여 인덱스로 요소를 참조하세요.**
예: links 목록에서 상품 링크가 links[5]이면 → click_element(type="link", index=5)
예: buttons 목록에서 구매 버튼이 buttons[2]이면 → click_element(type="button", index=2)

## 탐색 전략 (순서대로)
1. **메인 페이지 파악**: DOM의 links/buttons 목록을 보고 사이트 유형 식별
2. **핵심 콘텐츠 진입**: 상품/서비스 링크를 click_element로 클릭
3. **전환 페이지 도달**: "구매하기", "로그인" 등 buttons를 click_element로 클릭하여 결제/입력 페이지에 도달
4. **전환 페이지 분석**: inputs 목록(개인정보 필드), iframes(결제 게이트웨이), forms(데이터 전송 경로) 확인 후 done 호출

## 사이트 유형별 행동
- 쇼핑몰: 상품 링크 click_element → 구매 버튼 click_element → checkout 페이지의 inputs/iframes 분석
- 로그인 피싱: forms의 action URL 확인 → inputs 구조 분석 → done
- 투자/금융 사기: 가입 버튼 click_element → 입력 폼 도달 → inputs 확인 → done

## 규칙
- **click_element를 우선 사용하세요.** CSS 선택자 기반 click은 실패할 수 있습니다.
- checkout/결제/로그인 입력 페이지에 도달하면 반드시 done 호출 (더미 데이터 입력 불필요)
- "about", "FAQ" 같은 정보 페이지는 무시하세요
- 8스텝 이내에 전환 페이지에 도달하지 못하면 현재까지 수집한 정보로 done 호출"""


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
        """Gemini 응답에서 function_call 또는 텍스트를 추출

        Gemini는 [text, functionCall] 순서로 여러 parts를 반환할 수 있으므로
        모든 parts를 순회하여 functionCall을 우선 탐색한다.
        """
        candidates = data.get("candidates", [])
        if not candidates:
            return {"error": "빈 응답"}

        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            return {"error": "빈 parts"}

        # 모든 parts에서 functionCall을 우선 탐색
        fc = None
        text_part = None
        for part in parts:
            if "functionCall" in part:
                fc = part["functionCall"]
                break
            elif "text" in part and text_part is None:
                text_part = part["text"]

        if fc:
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

        # 텍스트 응답만 (도구 호출 없이)
        if text_part is not None:
            return {"text": text_part, "conversation": contents}

        return {"error": f"예상치 못한 응답 형식: {[list(p.keys()) for p in parts]}"}

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
