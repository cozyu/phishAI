"""AI 기반 동적 분석 오케스트레이터

Gemini Vision + Function Calling으로 AI가 직접 브라우저를 제어하여
모든 유형의 악성사이트를 범용적으로 분석한다.

아키텍처:
    호스트(이 모듈) ←→ Docker 컨테이너(sandbox_agent.py)
                    ←→ Gemini Vision API (Function Calling)

    1. Docker 컨테이너 시작 (Popen, stdin/stdout 파이프)
    2. 초기 스냅샷 수신 → Gemini에 전달
    3. Gemini가 function call(click, fill 등) 반환
    4. Docker에 action 전달 → 실행 결과 수신
    5. 결과를 다시 Gemini에 전달 → 반복 (Gemini가 done 호출까지)
"""

import json
import os
import subprocess
import time
from pathlib import Path

from .api_logger import log_api_call
from .gemini_vision import GeminiVisionClient


DOCKER_IMAGE = "phishai-sandbox"


class AIDynamicAnalyzer:
    """AI 에이전트 루프로 동적 분석을 수행하는 오케스트레이터"""

    MAX_STEPS = 7
    STEP_TIMEOUT = 15
    TOTAL_TIMEOUT = 180

    def __init__(self, gemini_api_key: str, evidence_dir: Path):
        self.vision = GeminiVisionClient(gemini_api_key)
        self.evidence_dir = evidence_dir

    def analyze(self, url: str) -> dict:
        """AI 에이전트 루프로 동적 분석 수행

        Returns:
            {"site_type": str, "findings": str, "severity": str,
             "rounds_completed": int, "history": list}
            또는 {"error": str}
        """
        edir = str(self.evidence_dir.resolve())
        start_time = time.time()

        # Docker 컨테이너 시작 (stdin/stdout 파이프)
        try:
            proc = subprocess.Popen(
                [
                    "docker", "run", "-i", "--rm",
                    "--cap-drop=ALL",
                    "--read-only",
                    "--security-opt=no-new-privileges",
                    "--memory=512m", "--cpus=1",
                    "--user", f"{os.getuid()}:{os.getgid()}",
                    "--tmpfs", "/tmp:size=128m",
                    "-v", f"{edir}:/output",
                    DOCKER_IMAGE,
                    "sandbox_agent.py", url,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            return {"error": "Docker를 찾을 수 없음"}

        try:
            return self._run_agent_loop(proc, start_time)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _run_agent_loop(self, proc: subprocess.Popen, start_time: float) -> dict:
        """에이전트 루프 실행"""
        # 1. 초기 스냅샷 수신
        initial = self._read_snapshot(proc)
        if "error" in initial:
            return initial

        print(f"  [AI동적분석] 초기 접속 완료: {initial.get('dom', {}).get('title', '')[:40]}")

        # 2. Gemini에 초기 스크린샷 + DOM 전달
        conversation = None
        history = []

        for step in range(self.MAX_STEPS):
            # 타임아웃 체크
            elapsed = time.time() - start_time
            if elapsed > self.TOTAL_TIMEOUT:
                print(f"  [AI동적분석] 전체 타임아웃 ({self.TOTAL_TIMEOUT}초)")
                break

            # Gemini Vision에 현재 상태 전달
            # Docker 내부 경로(/output/...)를 호스트 경로로 변환
            screenshot = initial.get("screenshot", "")
            if screenshot.startswith("/output/"):
                screenshot = str(self.evidence_dir / screenshot[len("/output/"):])
            dom = initial.get("dom", {})

            response = self.vision.analyze_page(
                screenshot_path=screenshot,
                dom_summary=dom,
                conversation=conversation,
            )

            if "error" in response:
                print(f"  [AI동적분석] Gemini 오류: {response['error']}")
                break

            # done 호출 = 분석 완료
            if response.get("done"):
                print(f"  [AI동적분석] 분석 완료 ({step + 1}스텝)")
                return {
                    "site_type": response.get("site_type", "unknown"),
                    "findings": response.get("findings", ""),
                    "severity": response.get("severity", "medium"),
                    "rounds_completed": step + 1,
                    "history": history,
                }

            # Function Call 처리
            fc = response.get("function_call")
            if not fc:
                # 텍스트만 반환한 경우 (도구 호출 없음) — 대화 이어감
                conversation = response.get("conversation")
                continue

            func_name = fc["name"]
            func_args = fc["args"]
            call_id = fc.get("id", "")
            conversation = response.get("conversation")

            print(f"  [AI동적분석] Step {step + 1}: {func_name}({json.dumps(func_args, ensure_ascii=False)[:60]})")

            # Docker에 action 전달
            action_json = json.dumps({"name": func_name, "args": func_args},
                                     ensure_ascii=False)
            proc.stdin.write(action_json + "\n")
            proc.stdin.flush()

            # 실행 결과 수신
            result_snapshot = self._read_snapshot(proc)
            if "error" in result_snapshot:
                print(f"  [AI동적분석] Docker 오류: {result_snapshot['error']}")
                break

            # 실행 결과를 히스토리에 기록
            action_result = result_snapshot.get("action_result", {})
            history.append({
                "step": step + 1,
                "action": func_name,
                "args": func_args,
                "result": action_result.get("status", "unknown"),
            })

            # Function Response를 대화 히스토리에 추가
            conversation = self.vision.build_function_response(
                conversation=conversation,
                func_name=func_name,
                call_id=call_id,
                result={
                    "status": action_result.get("status", "ok"),
                    "current_url": result_snapshot.get("dom", {}).get("url", ""),
                    "page_title": result_snapshot.get("dom", {}).get("title", ""),
                },
            )

            # 다음 스텝을 위해 스냅샷 갱신
            initial = result_snapshot

        # 최대 스텝 도달 — 수집된 정보로 결과 구성
        print(f"  [AI동적분석] 최대 스텝 도달 ({self.MAX_STEPS})")
        return {
            "site_type": "unknown",
            "findings": f"{len(history)}스텝 탐색 완료, done 미호출",
            "severity": "medium",
            "rounds_completed": len(history),
            "history": history,
        }

    def _read_snapshot(self, proc: subprocess.Popen) -> dict:
        """Docker 컨테이너에서 스냅샷 JSON 1줄 읽기"""
        try:
            line = proc.stdout.readline()
            if not line:
                stderr = ""
                try:
                    stderr = proc.stderr.read(500)
                except Exception:
                    pass
                return {"error": f"Docker 출력 없음. stderr: {stderr}"}
            return json.loads(line)
        except json.JSONDecodeError as e:
            return {"error": f"JSON 파싱 실패: {str(e)[:100]}"}
        except Exception as e:
            return {"error": f"스냅샷 수신 실패: {str(e)[:100]}"}
