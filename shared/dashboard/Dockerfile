FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Installer Flask avec le support async
RUN pip install --no-cache-dir \
    flask[async]==3.0.0 \
    flask-socketio==5.3.4 \
    asyncpg==0.29.0 \
    redis==5.0.1 \
    aiohttp==3.9.0 \
    plotly==5.18.0 \
    pandas==2.1.3 \
    python-dotenv==1.0.0

COPY . .
COPY templates/ ./templates/

EXPOSE 5000

CMD ["python", "app.py"]