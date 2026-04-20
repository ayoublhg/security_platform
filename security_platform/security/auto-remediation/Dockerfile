FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Créer requirements.txt directement
RUN echo "aiohttp==3.9.0" >> requirements.txt && \
    echo "requests==2.31.0" >> requirements.txt && \
    echo "python-dotenv==1.0.0" >> requirements.txt && \
    echo "PyGithub==2.1.1" >> requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "remediation_engine.py"]