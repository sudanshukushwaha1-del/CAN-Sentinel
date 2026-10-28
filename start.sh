#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly APP_DIR
export APP_DIR
export PORT="${PORT:-3000}"
readonly STREAMLIT_PORT=8502
readonly NGINX_CONFIG=/tmp/can-sentinel-nginx.conf
nginx_pid=""
streamlit_pid=""

cleanup() {
  if [[ -n "$nginx_pid" ]]; then kill "$nginx_pid" 2>/dev/null || true; fi
  if [[ -n "$streamlit_pid" ]]; then kill "$streamlit_pid" 2>/dev/null || true; fi
  if [[ -n "$nginx_pid" ]]; then wait "$nginx_pid" 2>/dev/null || true; fi
  if [[ -n "$streamlit_pid" ]]; then wait "$streamlit_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

mkdir -p /tmp/can-sentinel-nginx/{body,proxy,fastcgi,uwsgi,scgi}
envsubst '${PORT} ${APP_DIR}' < "$APP_DIR/nginx/nginx.conf.template" > "$NGINX_CONFIG"
nginx -t -c "$NGINX_CONFIG"

streamlit run "$APP_DIR/app.py" \
  --server.address=127.0.0.1 \
  --server.port="$STREAMLIT_PORT" \
  --server.headless=true \
  --server.fileWatcherType=none &
streamlit_pid=$!

ready=0
for _ in $(seq 1 60); do
  if ! kill -0 "$streamlit_pid" 2>/dev/null; then
    echo "Streamlit exited before becoming ready" >&2
    exit 1
  fi
  if python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8502/_stcore/health", timeout=1).read()' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  echo "Streamlit did not become healthy within 60 seconds" >&2
  exit 1
fi

nginx -c "$NGINX_CONFIG" -g 'daemon off;' &
nginx_pid=$!
wait -n "$streamlit_pid" "$nginx_pid"
