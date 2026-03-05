FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Créer requirements.txt directement
RUN echo "fastapi==0.104.1" >> requirements.txt && \
    echo "uvicorn[standard]==0.24.0" >> requirements.txt && \
    echo "aioredis==2.0.1" >> requirements.txt && \
    echo "pyjwt==2.8.0" >> requirements.txt && \
    echo "python-jose[cryptography]==3.3.0" >> requirements.txt && \
    echo "python-dotenv==1.0.0" >> requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "8080", "--reload"]