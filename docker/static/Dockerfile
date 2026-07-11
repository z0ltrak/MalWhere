# =============================================================================
# malwhere — static analysis container
# Base: REMnux (Ubuntu 20.04 with RE tools preinstalled)
# Add: pefile, FLOSS, DIE, ssdeep, Ghidra headless
# =============================================================================

FROM remnux/remnux-distro:focal

LABEL maintainer="malwhere TFM UCM"
LABEL description="Static malware analysis environment"

# System Tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    ssdeep \
    libfuzzy-dev \
    default-jre-headless \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Python packages
RUN pip3 install --no-cache-dir \
    pefile==2023.2.7 \
    lief==0.14.1 \
    python-magic==0.4.27 \
    ssdeep==3.4 \
    tlsh==0.2.0 \
    yara-python==4.5.0 \
    capstone==5.0.1 \
    rich==13.7.0

# FLOSS (FireEye Obfuscated String Solver)
FROM clausing/flare-floss:latest

USER root

# Ghidra headless (automated analysis)
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
