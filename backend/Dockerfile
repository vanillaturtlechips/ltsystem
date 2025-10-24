FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    --no-install-recommends \
    python3-dev \
    pkg-config \
    dos2unix \
&& rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/. .

RUN chmod +x /app/entrypoint.sh \
    && dos2unix /app/entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/app/entrypoint.sh"]