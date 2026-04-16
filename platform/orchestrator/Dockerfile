FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Installer les dépendances avec prometheus-client
RUN pip install --no-cache-dir \
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    redis==5.0.1 \
    asyncpg==0.29.0 \
    pyjwt==2.8.0 \
    python-jose[cryptography]==3.3.0 \
    aiohttp==3.9.0 \
    requests==2.31.0 \
    python-dotenv==1.0.0 \
    pydantic==2.5.0 \
    prometheus-client==0.19.0

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]