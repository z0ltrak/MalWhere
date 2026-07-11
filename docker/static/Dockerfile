# =============================================================================
# malwhere — static analysis container
# Base: REMnux (Ubuntu 20.04 full malware analysis distro)
# Adds: FLOSS binary, pefile, ssdeep, tlsh, rich, Java, Ghidra headless
# =============================================================================
FROM remnux/remnux-distro:focal

LABEL maintainer="malwhere TFM UCM"
LABEL description="Static malware analysis environment"

# System tools + Java + build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    libffi-dev \
    libfuzzy-dev \
    ssdeep \
    default-jre-headless \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# FLOSS binary (standalone, no base image needed)
RUN wget -q https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip \
    -O /tmp/floss.zip && \
    unzip -q /tmp/floss.zip -d /tmp/floss/ && \
    mv /tmp/floss/floss /usr/local/bin/floss && \
    chmod +x /usr/local/bin/floss && \
    rm -rf /tmp/floss*

# Python packages
RUN pip3 install --no-cache-dir \
    pefile==2024.8.26 \
    lief \
    ssdeep==3.4 \
    tlsh==0.2.0 \
    rich==13.7.0 \
    python-magic \
    yara-python \
    capstone

RUN cp /opt/malchive/lib/python3.8/site-packages/tlsh*.so \
    /usr/local/lib/python3.8/dist-packages/

# Ghidra headless
ARG GHIDRA_VERSION=11.1.2
ARG GHIDRA_DATE=20240709
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt/ && \
    rm /tmp/ghidra.zip && \
    ln -s /opt/ghidra_${GHIDRA_VERSION}_PUBLIC/support/analyzeHeadless \
          /usr/local/bin/ghidra-headless

WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]
