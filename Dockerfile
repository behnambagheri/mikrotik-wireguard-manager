FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WG_WEB_STATE_FILE=/app/data/.wg_web_state.json \
    WG_WEB_ENV_FILE=/app/.env

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools curl \
    && mkdir -p /app/data \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-web.txt ./
RUN pip install --no-cache-dir -r requirements-web.txt

COPY main.py ./
COPY src ./src

EXPOSE 8088

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8088"]
