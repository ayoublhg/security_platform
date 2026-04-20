FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    git \
    curl \
    wget \
    tar \
    gzip \
    unzip \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Installer Semgrep (SAST)
RUN pip install semgrep checkov

# Installer Gitleaks (Secrets scanner)
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.18.1_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks && \
    rm gitleaks_8.18.1_linux_x64.tar.gz

# Installer Trivy - OFFICIAL SCRIPT (MOST RELIABLE)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Installer Flask avec le support async - VERSIONS COMPATIBLES
RUN pip install --no-cache-dir \
    flask==2.3.3 \
    flask-socketio==5.3.6 \
    eventlet==0.33.3 \
    asyncpg==0.29.0 \
    redis==5.0.1 \
    psycopg2-binary==2.9.9 \
    aiohttp==3.9.0 \
    plotly==5.18.0 \
    pandas==2.1.3 \
    python-dotenv==1.0.0 \
    reportlab==4.0.4 \
    matplotlib==3.7.2 \
    seaborn==0.12.2 \
    apscheduler==3.10.4 \
    psutil==5.9.6

# Verify installations
RUN semgrep --version && \
    gitleaks version && \
    trivy --version && \
    checkov --version

COPY . .
COPY templates/ ./templates/

EXPOSE 5000

CMD ["python", "app.py"]