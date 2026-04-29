FROM python:3.11-slim

# Install iptables  and other system deps
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    sudo \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY *.py .
COPY config.yaml .

# Create log dir
RUN mkdir -p /var/log/detector


CMD ["python", "-u", "main.py"]