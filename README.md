# 🦠 MalWhere
### Automated Threat Intelligence Extraction from Malware Samples via Reverse Engineering

> Master's Thesis (TFM) · Universidad Complutense de Madrid · MSc in Cybersecurity · 2025–2026

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-E8281B?style=flat-square)](https://attack.mitre.org)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-FF6B35?style=flat-square)](https://oasis-open.github.io/cti-documentation/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## Overview

**malwhere** is a modular, reproducible pipeline for automated extraction of Threat Intelligence (TI) from malware samples through static and dynamic reverse engineering. Findings are normalized into structured IOCs and mapped to the [MITRE ATT&CK](https://attack.mitre.org) framework, then exported as STIX 2.1 bundles for ingestion into threat intelligence platforms.

The pipeline is validated against three representative malware families:

| Family | Type | Language | Key techniques |
|---|---|---|---|
| **Akira** | Ransomware + EDR-Killer | C++ | BYOVD, VSS deletion, ChaCha20+RSA encryption, EDR process termination |
| **WhiteSnakeStealer** | Infostealer | .NET | MaaS model, credential theft, keylogging, sandbox evasion |
| **RONINGLOADER** | Loader + EDR-Killer + RAT | Multi-stage | PPL abuse, signed driver abuse, WDAC bypass, Gh0st RAT delivery |


---

## Architecture

```
malware sample
      │
      ▼
┌─────────────────┐     ┌──────────────────┐
│  Static Analysis │     │ Dynamic Analysis  │
│  pefile · FLOSS  │     │  CAPE Sandbox     │
│  DIE · ssdeep    │     │  Wireshark/tcpdump│
│  Ghidra headless │     │                  │
└────────┬────────┘     └────────┬─────────┘
         │                       │
         └──────────┬────────────┘
                    ▼
         ┌──────────────────┐
         │   Normalizer     │  → normalized_iocs.json
         │   merge · dedup  │
         │   confidence score│
         └────────┬─────────┘
                  ▼
         ┌──────────────────┐
         │  ATT&CK Mapper   │  → attck_mapping.json
         │  rule-based      │  → navigator_layer.json
         │  3-tier confidence│
         └────────┬─────────┘
                  ▼
         ┌──────────────────┐
         │    Exporter      │  → bundle.stix2
         │  STIX 2.1 · MISP │
         └──────────────────┘
```

---

## Repository Structure

```
malwhere/
├── samples/                  # Hash manifests only — NO binaries committed
│   └── .gitignore
├── static/
│   ├── scripts/              # Static analysis automation scripts
│   └── reports/              # Generated JSON reports per sample
├── dynamic/
│   ├── scripts/              # Dynamic analysis parsing scripts
│   └── reports/              # CAPE/sandbox JSON reports
├── pipeline/
│   ├── normalizer/           # IOC normalization and deduplication
│   ├── mapper/               # ATT&CK rule-based mapping engine
│   └── exporter/             # STIX 2.1 and MISP export
├── docker/
│   ├── docker-compose.yml    # Full environment definition
│   ├── cape/                 # CAPE sandbox configuration
│   ├── misp/                 # MISP instance configuration
│   └── navigator/            # ATT&CK Navigator instance
├── results/
│   ├── roning/
│   │   ├── iocs/             # Normalized IOC JSON
│   │   ├── attck/            # ATT&CK mappings + Navigator layers
│   │   └── stix/             # STIX 2.1 bundles
│   ├── wsnake/
│   └── akira/
├── paper/                    # Academic paper (LaTeX source)
├── docs/                     # Methodology documentation
└── README.md
```

---

## Quickstart

### Prerequisites

- Ubuntu 24.04.4 LTS
- Docker Engine 24.0+
- Docker Compose v2
- CPU with VT-x/AMD-V enabled (required for CAPE)
- 16 GB RAM minimum

### Deploy the full environment

```bash
git clone https://github.com/<your-username>/malwhere.git
cd malwhere/docker
docker compose up -d
```

This starts:
- **CAPE Sandbox** — dynamic analysis (`:8000`)
- **MISP** — threat intel platform (`:443`)
- **ATT&CK Navigator** — layer visualization (`:4200`)

### Run the pipeline on a sample

Static analysis runs inside its container (scripts are volume-mounted, so
edits on the host reflect immediately — no rebuild needed):

```bash
docker cp /path/to/sample.exe malwhere-static:/samples/roning/sample.exe
docker exec malwhere-static python3 /scripts/analyze.py \
    --sample /samples/roning/sample.exe --output /reports/roning/
# -> static/reports/roning/sample_static.json (host path, via the volume mount)
```

Dynamic analysis parses a CAPE report already produced by the sandbox —
either by CAPE task ID or a direct path to its `report.json`:

```bash
python3 dynamic/scripts/parse_cape.py --task-id 2 --output dynamic/reports/roning/
# or: --report docker/cape/work/storage/analyses/2/reports/report.json
# -> dynamic/reports/roning/dynamic_report.json
```

Normalize both sources, map to ATT&CK, then export:

```bash
python3 pipeline/normalizer/normalize.py \
    --static static/reports/roning/sample_static.json \
    --dynamic dynamic/reports/roning/dynamic_report.json \
    --output results/roning/iocs/
# -> results/roning/iocs/normalized_iocs.json

python3 pipeline/mapper/map_attck.py \
    --iocs results/roning/iocs/normalized_iocs.json \
    --output results/roning/attck/
# -> results/roning/attck/attck_mapping.json + navigator_layer.json

python3 pipeline/exporter/export_stix.py \
    --mapping results/roning/attck/attck_mapping.json \
    --output results/roning/stix/
# -> results/roning/stix/bundle.stix2

# Optional: push live to MISP (needs the sandbox profile's MISP running)
python3 pipeline/exporter/export_misp.py \
    --mapping results/roning/attck/attck_mapping.json --publish
```

`--task-id` maps to CAPE's own analysis IDs (`1`=wsnake, `2`=roning,
`3`=akira in this project's validated runs); `normalize.py`/`map_attck.py`
run in the host's `.venv` (`source .venv/bin/activate` first), not inside
a container.

---

## ATT&CK Confidence Model

The mapper uses a three-tier rule system to minimize false positives — a core methodological contribution of this work:

| Tier | Criteria | Example |
|---|---|---|
| **High** | Deterministic artifact → technique | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` → T1055 |
| **Medium** | Suggestive artifact, requires context | `cmd.exe /c` string → T1059.003 (needs corroboration) |
| **Low** | Weak signal, combinatorial only | High entropy section alone → possible packing |

All auto-mapped techniques are manually validated. Precision/recall metrics are reported in the paper.

---

## Malware Samples

**No binaries are stored in this repository.** The `samples/` directory contains only SHA-256 hash manifests and provenance metadata (source, acquisition date, VirusTotal score).

Samples were obtained from public threat intelligence sources (MalwareBazaar, ANY.RUN) for academic research purposes, in a controlled isolated environment.

---

## Environment Safety

All dynamic analysis runs in an **isolated Docker network with no internet egress**. Malware execution is contained within CAPE's internal VM. Never run samples outside the designated sandbox environment.

---

## Academic Context

This project is the practical component of a Master's thesis submitted to the **Universidad Complutense de Madrid** in partial fulfillment of the MSc in Cybersecurity requirements.

The accompanying academic paper presents the methodology, case studies, and evaluation metrics. See [`paper/`](paper/) for the LaTeX source.

---

## License

MIT License — see [LICENSE](LICENSE).

> ⚠️ This tool is intended strictly for academic and authorized security research. The authors assume no responsibility for misuse.
