# Dockerfile - slim python image, uvicorn on 8000
# bind-mount storage + data if you want files to survive restarts

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AUDITLINK_STORAGE=/app/storage \
    AUDITLINK_DB=/app/data/auditlink.db

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
RUN mkdir -p /app/storage /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
