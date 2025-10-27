FROM python:3.11-slim

WORKDIR /app

ENV PYTHONPATH /app

RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    --no-install-recommends \
    python3-dev \
    pkg-config \
    dos2unix \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/entrypoint.sh \
    && dos2unix /app/entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/app/entrypoint.sh"]