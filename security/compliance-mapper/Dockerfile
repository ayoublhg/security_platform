FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Créer requirements.txt directement
RUN echo "fastapi==0.104.1" >> requirements.txt && \
    echo "uvicorn[standard]==0.24.0" >> requirements.txt && \
    echo "pyyaml==6.0.1" >> requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8002

CMD ["uvicorn", "mapper:app", "--host", "0.0.0.0", "--port", "8002", "--reload"]