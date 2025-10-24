#!/bin/sh

# 1. 데이터베이스 마이그레이션 실행
echo "Running database migrations..."
python manage.py migrate --noinput

# 2. 정적 파일 수집
echo "Collecting static files..."
python manage.py collectstatic --noinput --clear

# 3. Gunicorn으로 애플리케이션 실행
echo "Starting Gunicorn on 0.0.0.0:80..."
gunicorn lts_project.wsgi:application --bind 0.0.0.0:80