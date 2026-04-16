import json
import logging
import os
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "log"
LOG_DIR.mkdir(exist_ok=True)


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
