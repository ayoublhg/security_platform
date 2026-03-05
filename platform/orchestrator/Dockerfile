FROM python:3.11-slim

WORKDIR /app

# Installer git
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Créer requirements.txt directement dans le conteneur
RUN echo "fastapi==0.104.1" >> requirements.txt && \
    echo "uvicorn[standard]==0.24.0" >> requirements.txt && \
    echo "aioredis==2.0.1" >> requirements.txt && \
    echo "asyncpg==0.29.0" >> requirements.txt && \
    echo "pyjwt==2.8.0" >> requirements.txt && \
    echo "python-jose[cryptography]==3.3.0" >> requirements.txt && \
    echo "aiohttp==3.9.0" >> requirements.txt && \
    echo "requests==2.31.0" >> requirements.txt && \
    echo "python-dotenv==1.0.0" >> requirements.txt

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]