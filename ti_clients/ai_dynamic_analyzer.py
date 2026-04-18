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

    MAX_STEPS = 12
    STEP_TIMEOUT = 15
    TOTAL_TIMEOUT = 240

    def __init__(self, gemini_api_key: str, evidence_dir: Path):
        self.vision = GeminiVisionClient(gemini_api_key)
        self.evidence_dir = evidence_dir

    def analyze(self, url: str) -> dict:
        """AI 에이전트 루프로 동적 분석 수행

        Returns:
            {"site_type": str, "findings": str, "severity": str,
             "rounds_completed": int, "history": list, "victim_flow": dict}
            또는 {"error": str}

        결과는 evidence_dir/ti_responses/dynamic_result.json 에도 저장된다.
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
            result = self._run_agent_loop(proc, start_time)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        self._save_result(result)
        return result

    def _save_result(self, result: dict) -> None:
        """동적 분석 결과를 evidence/.../ti_responses/dynamic_result.json 에 기록"""
        try:
            out_dir = self.evidence_dir / "ti_responses"
            out_dir.mkdir(parents=True, exist_ok=True)
            with open(out_dir / "dynamic_result.json", "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"  [AI동적분석] 결과 파일 저장 실패: {e}")

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

        # 탐색 중 발견한 victim_flow 증거 누적
        # — checkout 페이지의 iframe/inputs/forms가 최종 보고서의 핵심 증거가 됨
        visited_pages: list[dict] = []
        iframes_seen: list[dict] = []
        inputs_seen: list[dict] = []
        forms_seen: list[dict] = []
        external_domains: set[str] = set()
        external_scripts: set[str] = set()
        tracking_requests: list[dict] = []
        all_network: list[dict] = []
        business_info: dict = {
            "footer_texts": [],
            "emails": set(),
            "phones": set(),
            "business_codes": set(),
        }
        scam_patterns_seen: set[str] = set()
        self._accumulate(initial, visited_pages, iframes_seen, inputs_seen,
                         forms_seen, external_domains, external_scripts,
                         tracking_requests, all_network, business_info,
                         scam_patterns_seen)

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
                return self._build_final(
                    response.get("site_type", "unknown"),
                    response.get("findings", ""),
                    response.get("severity", "medium"),
                    step + 1, history,
                    visited_pages, iframes_seen, inputs_seen, forms_seen,
                    external_domains, external_scripts, tracking_requests,
                    all_network, business_info, scam_patterns_seen,
                )

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

            # victim_flow 증거 누적 (새 스냅샷의 iframes/inputs/forms/domains/tracking)
            self._accumulate(result_snapshot, visited_pages, iframes_seen,
                             inputs_seen, forms_seen, external_domains,
                             external_scripts, tracking_requests, all_network,
                             business_info, scam_patterns_seen)

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
        return self._build_final(
            "unknown",
            f"{len(history)}스텝 탐색 완료, done 미호출",
            "medium", len(history), history,
            visited_pages, iframes_seen, inputs_seen, forms_seen,
            external_domains, external_scripts, tracking_requests,
            all_network, business_info, scam_patterns_seen,
        )

    @staticmethod
    def _build_final(site_type, findings, severity, rounds, history,
                     visited_pages, iframes, inputs, forms,
                     domains, scripts, tracking, all_net,
                     business_info, scam_patterns) -> dict:
        return {
            "site_type": site_type,
            "findings": findings,
            "severity": severity,
            "rounds_completed": rounds,
            "history": history,
            "victim_flow": {
                "visited_pages": visited_pages,
                "iframes": iframes,
                "input_fields": inputs,
                "forms": forms,
                "external_domains": sorted(domains),
                "external_scripts": sorted(scripts),
                "tracking_requests": tracking,
                "all_network_requests": all_net,
                "business_info": {
                    "footer_texts": business_info.get("footer_texts", []),
                    "emails": sorted(business_info.get("emails", set())),
                    "phones": sorted(business_info.get("phones", set())),
                    "business_codes": sorted(business_info.get("business_codes", set())),
                },
                "scam_patterns": sorted(scam_patterns),
            },
        }

    @staticmethod
    def _accumulate(snapshot: dict, visited_pages: list, iframes: list,
                    inputs: list, forms: list, domains: set,
                    scripts: set, tracking: list, all_net: list,
                    business_info: dict, scam_patterns: set) -> None:
        """스냅샷의 victim_flow 증거를 누적한다. 중복 항목은 제거."""
        dom = snapshot.get("dom", {})
        page_url = dom.get("url", "")
        if page_url and not any(p.get("url") == page_url for p in visited_pages):
            visited_pages.append({
                "url": page_url,
                "title": dom.get("title", ""),
                "page_text_preview": dom.get("page_text_preview", ""),
            })

        for ifr in dom.get("iframes", []) or []:
            src = ifr.get("src", "")
            if src and src != "about:blank" and not any(i.get("src") == src for i in iframes):
                iframes.append({
                    "src": src,
                    "id": ifr.get("id", ""),
                    "name": ifr.get("name", ""),
                    "on_page": page_url,
                })

        for inp in dom.get("inputs", []) or []:
            t = inp.get("type", "text")
            name = inp.get("name", "")
            placeholder = inp.get("placeholder", "")
            key = f"{page_url}|{t}|{name}|{placeholder}"
            if t == "hidden":
                continue
            if not any(key == f"{i.get('on_page','')}|{i.get('type','')}|{i.get('name','')}|{i.get('placeholder','')}"
                       for i in inputs):
                inputs.append({
                    "type": t, "name": name, "placeholder": placeholder,
                    "id": inp.get("id", ""),
                    "on_page": page_url,
                })

        for form in dom.get("forms", []) or []:
            action = form.get("action", "")
            key = f"{page_url}|{action}"
            if not any(key == f"{f.get('on_page','')}|{f.get('action','')}" for f in forms):
                forms.append({
                    "action": action,
                    "method": form.get("method", ""),
                    "inputs": form.get("inputs", []),
                    "on_page": page_url,
                })

        for d in dom.get("external_domains", []) or []:
            if d:
                domains.add(d)

        for s in dom.get("external_scripts", []) or []:
            if s:
                scripts.add(s)

        # 푸터/업체 정보
        ft = dom.get("footer_text", "") or ""
        if ft and ft not in business_info["footer_texts"]:
            business_info["footer_texts"].append(ft)
        for e in dom.get("emails_on_page", []) or []:
            business_info["emails"].add(e)
        for p in dom.get("phones_on_page", []) or []:
            business_info["phones"].add(p)
        for c in dom.get("business_codes", []) or []:
            business_info["business_codes"].add(c)

        # 사회공학적 조작 패턴
        for sp in dom.get("scam_patterns", []) or []:
            scam_patterns.add(sp)

        # 네트워크 요청 (tracking pixel / API / 전체)
        for req in snapshot.get("network_requests", []) or []:
            url = req.get("url", "")
            if url and not any(r.get("url") == url for r in all_net):
                all_net.append({
                    "method": req.get("method", "GET"),
                    "url": url,
                    "type": req.get("type", ""),
                    "on_page": page_url,
                })
        for treq in snapshot.get("tracking_requests", []) or []:
            url = treq.get("url", "")
            if url and not any(t.get("url") == url for t in tracking):
                tracking.append({
                    "method": treq.get("method", "GET"),
                    "url": url,
                    "type": treq.get("type", ""),
                    "on_page": page_url,
                })

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
