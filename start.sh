#!/usr/bin/env bash
set -e

LT_PORT="${LT_PORT:-8010}"
PORT="${PORT:-10000}"
LT_VERSION="${LT_VERSION:-6.4}"
LT_HOME="/opt/LanguageTool-${LT_VERSION}"

java -cp "${LT_HOME}/languagetool-server.jar:${LT_HOME}/libs/*" \
  org.languagetool.server.HTTPServer --port "${LT_PORT}" --public > /tmp/languagetool.log 2>&1 &

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${LT_PORT}/v2/languages" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

exec gunicorn -w 1 -b 0.0.0.0:${PORT} wsgi:app
