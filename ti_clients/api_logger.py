import atexit
import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "log"
LOG_DIR.mkdir(exist_ok=True)


class _Tee:
    """stdout/stderr를 원본 스트림과 파일에 동시에 기록"""
    def __init__(self, stream, fh):
        self._stream = stream
        self._fh = fh

    def write(self, data):
        self._stream.write(data)
        try:
            self._fh.write(data)
            self._fh.flush()
        except Exception:
            pass

    def flush(self):
        self._stream.flush()
        try:
            self._fh.flush()
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self._stream, name)


def setup_run_logger(script: str, target: str = "") -> Path:
    """스크립트 실행 stdout/stderr를 log/run_*.log 파일로도 저장.

    Args:
        script: 스크립트 식별자 (예: "analyze", "analyst_agent")
        target: 분석 대상 (도메인 등, 선택)

    Returns:
        생성된 로그 파일 경로
    """
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)[:60] if target else ""
    fname = f"run_{script}_{safe_target}_{ts}.log" if safe_target else f"run_{script}_{ts}.log"
    log_path = LOG_DIR / fname

    fh = open(log_path, "w", encoding="utf-8", buffering=1)
    fh.write(f"# phishAI run log — {script} {target}\n")
    fh.write(f"# started: {datetime.now().isoformat()}\n")
    fh.write(f"# argv: {' '.join(sys.argv)}\n\n")
    fh.flush()

    sys.stdout = _Tee(sys.stdout, fh)
    sys.stderr = _Tee(sys.stderr, fh)

    def _close():
        try:
            fh.write(f"\n# finished: {datetime.now().isoformat()}\n")
            fh.close()
        except Exception:
            pass

    atexit.register(_close)
    return log_path


def get_logger():
    logger = logging.getLogger("phishAI")
    if not logger.handlers:
        date_str = datetime.now().strftime("%Y-%m-%d")
        handler = logging.FileHandler(LOG_DIR / f"api_{date_str}.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger


def log_api_call(service: str, method: str, url: str, status_code: int,
                 request_body: dict = None, response_body: str = None, error: str = None):
    logger = get_logger()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "method": method,
        "url": url,
        "status_code": status_code,
    }
    if request_body:
        # API 키 마스킹
        body_str = json.dumps(request_body, ensure_ascii=False)
        entry["request_body_length"] = len(body_str)
    if response_body:
        entry["response_length"] = len(response_body)
        entry["response_preview"] = response_body[:500]
    if error:
        entry["error"] = error

    logger.info(json.dumps(entry, ensure_ascii=False))
