FROM python:3.11-silm

RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    --no-install-recommends \
&& rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/app/entrypoint.sh"]