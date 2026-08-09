# =============================================================================
# malwhere — static analysis container
# Base: REMnux (Ubuntu 20.04 full malware analysis distro)
# Scripts are mounted at runtime via docker-compose volumes:
#   ../static/scripts → /scripts
# Do NOT COPY scripts here — edit them on the host and they reflect immediately.
# =============================================================================
FROM remnux/remnux-distro:focal

LABEL maintainer="malwhere TFM UCM"
LABEL description="Static malware analysis environment"

# System tools + Java + build deps for ssdeep
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    libffi-dev \
    libfuzzy-dev \
    ssdeep \
    default-jre-headless \
    wget \
    unzip \
    p7zip-full \
    binwalk \
    && rm -rf /var/lib/apt/lists/*

# FLOSS binary (v3.1.1 — JSON output mode)
RUN wget -q https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip \
    -O /tmp/floss.zip && \
    unzip -q /tmp/floss.zip -d /tmp/floss/ && \
    mv /tmp/floss/floss /usr/local/bin/floss && \
    chmod +x /usr/local/bin/floss && \
    rm -rf /tmp/floss*

# Python packages — all in one layer for cache efficiency
RUN pip3 install --no-cache-dir \
    pefile==2024.8.26 \
    lief \
    ssdeep==3.4 \
    tlsh==0.2.0 \
    rich==13.7.0 \
    python-magic \
    yara-python \
    capstone \
    dnfile \
    requests

# Fix tlsh path — REMnux installs it in isolated malchive env
# This must run AFTER pip3 install so the .so already exists
RUN cp /opt/malchive/lib/python3.8/site-packages/tlsh*.so \
       /usr/local/lib/python3.8/dist-packages/ 2>/dev/null || true

# Verify dnfile installed correctly
RUN python3 -c "import dnfile; print('dnfile OK:', dnfile.__version__)"

# Ghidra headless (for automated RE scripts)
ARG GHIDRA_VERSION=11.1.2
ARG GHIDRA_DATE=20240709
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt/ && \
    rm /tmp/ghidra.zip && \
    ln -s /opt/ghidra_${GHIDRA_VERSION}_PUBLIC/support/analyzeHeadless \
          /usr/local/bin/ghidra-headless

# Create scripts directory — will be populated by volume mount at runtime
RUN mkdir -p /scripts /samples /reports

WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]
