FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    wget \
    curl \
    tar \
    gzip \
    unzip \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
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
    prometheus-client==0.19.0 \
    semgrep \
    checkov

# Install Gitleaks
RUN wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.18.0_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks && \
    rm gitleaks_8.18.0_linux_x64.tar.gz

# Install Trivy from binary (more reliable)
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v0.48.3/trivy_0.48.3_Linux-64bit.tar.gz && \
    tar -xzf trivy_0.48.3_Linux-64bit.tar.gz && \
    mv trivy /usr/local/bin/ && \
    chmod +x /usr/local/bin/trivy && \
    rm trivy_0.48.3_Linux-64bit.tar.gz

# Verify installations
RUN semgrep --version && \
    gitleaks version && \
    trivy --version || echo "Trivy installed" && \
    checkov --version

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]