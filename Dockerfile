FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LT_VERSION=6.4 \
    LT_PORT=8010

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends default-jre-headless curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://languagetool.org/download/LanguageTool-${LT_VERSION}.zip" -o /tmp/lt.zip \
    && unzip /tmp/lt.zip -d /opt \
    && rm /tmp/lt.zip

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/start.sh

EXPOSE 10000

CMD ["/app/start.sh"]
