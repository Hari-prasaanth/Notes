FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000
ENV TARGET_NETWORK=
ENV MAX_SCAN_TIMEOUT=300

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    nikto \
    sqlmap \
    wpscan \
    dirb \
    exploitdb \
    curl \
    wget \
    git \
    net-tools \
    iputils-ping \
    dnsutils \
    whois \
    libpcap-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip && \
    pip install fastmcp uvicorn

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester

WORKDIR /app
COPY server.py /app/server.py
RUN chown -R pentester:pentester /app

RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap 2>/dev/null || true

USER pentester

EXPOSE 8000

CMD ["python3", "/app/server.py"]