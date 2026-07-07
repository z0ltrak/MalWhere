# =============================================================================
# malwhere — pipeline container
# Base: Python 3.11 slim
# Incluye: mitreattack-python, stix2, PyMISP, pandas
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="malwhere TFM UCM"
LABEL description="IOC normalization, ATT&CK mapping and STIX export pipeline"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app

CMD ["tail", "-f", "/dev/null"]
