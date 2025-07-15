# MediVote Backend Dockerfile
# Secure blockchain-based voting system backend

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    pkg-config \
    wget \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for circuit compilation
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs

# Install global Node.js dependencies for ZK circuits
RUN npm install -g snarkjs circom

# Create application directory
WORKDIR /app

# Create non-root user for security
RUN groupadd -r medivote && useradd -r -g medivote medivote

# Copy Python requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Install additional cryptographic libraries
RUN pip install --no-cache-dir gmpy2 pycryptodome requests

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p circuits keys uploads logs \
    && chown -R medivote:medivote /app

# Copy circuit files if they exist
RUN if [ -d "../circuits" ]; then cp -r ../circuits/* ./circuits/; fi

# Generate initial cryptographic keys using OpenSSL
RUN openssl genrsa -out keys/blind_signature_private.pem 2048 && \
    openssl rsa -in keys/blind_signature_private.pem -pubout -out keys/blind_signature_public.pem && \
    echo "Cryptographic keys generated successfully"

# Set proper permissions
RUN chown -R medivote:medivote /app \
    && chmod -R 755 /app \
    && chmod -R 700 /app/keys

# Create health check script
RUN echo '#!/usr/bin/env python3\nimport sys\nimport requests\ntry:\n    response = requests.get("http://localhost:8000/health", timeout=10)\n    if response.status_code == 200:\n        sys.exit(0)\n    else:\n        sys.exit(1)\nexcept:\n    sys.exit(1)' > /app/healthcheck.py

RUN chmod +x /app/healthcheck.py

# Switch to non-root user
USER medivote

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python /app/healthcheck.py

# Start command
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"] 