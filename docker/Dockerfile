FROM mcr.microsoft.com/playwright/python:v1.52.0-noble

WORKDIR /app
COPY sandbox_analyze.py sandbox_agent.py ./

RUN pip install --no-cache-dir playwright==1.52.0 \
    && playwright install chromium

# 비-root 사용자로 실행 (보안 강화)
RUN useradd -m -s /bin/bash sandbox
USER sandbox

ENTRYPOINT ["python3"]
CMD ["sandbox_analyze.py"]
