FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Créer requirements.txt directement
RUN echo "fastapi==0.104.1" >> requirements.txt && \
    echo "uvicorn[standard]==0.24.0" >> requirements.txt && \
    echo "aiohttp==3.9.0" >> requirements.txt && \
    echo "beautifulsoup4==4.12.2" >> requirements.txt && \
    echo "lxml==4.9.3" >> requirements.txt && \
    echo "redis==5.0.1" >> requirements.txt && \
    echo "requests==2.31.0" >> requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8001

CMD ["uvicorn", "enriched_db:app", "--host", "0.0.0.0", "--port", "8001", "--reload"]