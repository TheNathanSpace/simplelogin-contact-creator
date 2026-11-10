FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV PYTHONUNBUFFERED=1 \
    TZ=Etc/UTC \
    DATA_DIR=/config/data \
    SECRET_PATH=/config/secret \
    PORT=5982 \
    COOKIE_SECURE=1

EXPOSE 5982

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5982/health')"]

CMD ["python", "-m", "app"]
