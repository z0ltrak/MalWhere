# =============================================================================
# malwhere — static analysis container
# Base: plain Ubuntu 20.04, NOT remnux/remnux-distro:focal.
#
# This used to build FROM remnux/remnux-distro:focal for the tlsh path fix
# below, but that image bundles a dozen+ third-party apt repos (Docker,
# VS Code, Sysdig, Mono, Node, Wine, SIFT, GIFT, Wireshark-dev, ...) for
# tools this Dockerfile never uses, and the image tag hasn't been rebuilt
# in a long time — those repos' (and eventually archive.ubuntu.com's own
# frozen keyring's) signing keys expire inside the frozen image, so
# `apt-get update` starts failing on all of them at once with no fix
# possible from our side except waiting for upstream to publish a new
# tag. Confirmed nothing else in this Dockerfile or ../static/scripts
# actually depends on REMnux-specific tooling (grepped for malchive/
# remnux/opt paths) — every tool here is installed explicitly below, so
# plain ubuntu:20.04 (same base OS REMnux itself was built on, universe/
# multiverse enabled by default) is a strict subset with a live,
# non-frozen apt keyring.
#
# Scripts are mounted at runtime via docker-compose volumes:
#   ../static/scripts → /scripts
# Do NOT COPY scripts here — edit them on the host and they reflect immediately.
# =============================================================================
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

LABEL maintainer="malwhere TFM UCM"
LABEL description="Static malware analysis environment"

# System tools + Java + build deps for ssdeep/tlsh + Python itself
# (python3/pip3/libmagic1 used to come for free from REMnux's base image —
# plain ubuntu:20.04 has none of them, so they're explicit here now)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    libmagic1 \
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

# Detect It Easy (DIE) — packer/compiler signature detection used by
# packer_parser.py (looks for `diec`/`die` on PATH, falls back to a weaker
# heuristic if absent). Silently missing since the REMnux base was dropped
# above: REMnux happened to bundle DIE too, same accident tlsh's comment
# describes, but unlike tlsh it was never re-added. No generic apt/pip
# package exists -- DIE only ships per-distro .debs -- so pin the exact
# Ubuntu 20.04 build for this base image; apt resolves its Qt5 runtime
# deps (libqt5widgets5 etc.) from the standard archive.
ARG DIE_VERSION=3.21
RUN wget -q "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_20.04_amd64.deb" \
    -O /tmp/die.deb && \
    apt-get update && \
    apt-get install -y --no-install-recommends /tmp/die.deb && \
    rm -f /tmp/die.deb && \
    rm -rf /var/lib/apt/lists/*

# Fail the build loudly if DIE's console binary doesn't actually work --
# QT_QPA_PLATFORM=offscreen matches packer_parser.py's own env, since DIE's
# Qt GUI libs need a platform plugin even in console mode on a headless container.
RUN QT_QPA_PLATFORM=offscreen diec --version

# pip on focal is too old to resolve current manylinux wheel tags for some
# of these (confirmed: lief's install failed outright, "does not provide
# precompiled wheels for 'linux - x86_64'", until pip itself was upgraded
# first) — has to run before the real install below, not just be a nice-to-have.
RUN python3 -m pip install --no-cache-dir --upgrade pip

# Python packages — all in one layer for cache efficiency
#
# NOTE: PyPI's own "tlsh" package (0.2.0) is broken — it ships metadata only,
# no actual module files, so `import tlsh` fails with ModuleNotFoundError
# even though `pip install` reports success (confirmed directly: `pip show -f
# tlsh` lists nothing but a .dist-info directory). This used to work by
# accident: the old REMnux base image separately bundled a real, working
# compiled tlsh build in its own malchive env, and this Dockerfile copied
# that .so over the top of the broken pip install after the fact — the pip
# install itself was never actually functional. Now that the base image is
# plain ubuntu:20.04 (no malchive to steal from), pulling in `python-tlsh`
# instead — a different PyPI distribution, same `import tlsh` module name —
# which genuinely builds TLSH's C++ extension from source and works,
# confirmed against real (random, non-degenerate) input data.
RUN pip3 install --no-cache-dir \
    pefile==2024.8.26 \
    lief \
    ssdeep==3.4 \
    python-tlsh==4.5.0 \
    rich==13.7.0 \
    python-magic \
    yara-python \
    capstone \
    dnfile \
    numpy \
    cryptography \
    stix2 \
    requests

# Fail the build loudly if tlsh can't actually hash anything — b'test'*50
# alone isn't a valid check (TLSH legitimately returns "TNULL" for
# low-entropy/degenerate input, that's correct algorithm behavior, not a
# broken binding), so verify against real random bytes instead.
RUN python3 -c "\
import tlsh, os; \
h = tlsh.hash(os.urandom(4096)); \
assert h and h != 'TNULL', f'tlsh produced no real hash: {h!r}'; \
print('tlsh OK:', h)"

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
