FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gettext-base nginx \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY app.py ./app.py
COPY can_sentinel/ ./can_sentinel/
COPY nginx/nginx.conf.template ./nginx/nginx.conf.template
COPY public/manus-routes.json ./public/manus-routes.json
COPY start.sh ./start.sh

EXPOSE 3000
CMD ["bash", "/app/start.sh"]
