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
│   ├── navigator/             # ATT&CK Navigator instance
│   └── resubmit_queue/        # Dropped-file resubmission queue (gitignored, generated)
├── results/
│   ├── roning/
│   │   ├── iocs/             # Normalized IOC JSON
│   │   ├── attck/            # ATT&CK mappings + Navigator layers
│   │   ├── stix/             # STIX 2.1 bundles
│   │   └── resubmitted/      # Per-dropped-file iocs/+attck/, one dir per sha256
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

### Deploy the environment

Every service sits behind a Compose `profiles:` gate — `docker compose up -d`
with no `--profile` flag starts nothing at all. `core` is the clone-and-go
part (static analysis, the normalize/map/export pipeline, ATT&CK Navigator);
`sandbox` (CAPE, MISP) needs real one-time host setup first — libvirt/KVM,
building the `cape:kvm` image, an interactive Windows guest VM install —
walked through start to finish in [`docker/README.md`](docker/README.md).

```bash
git clone https://github.com/<your-username>/malwhere.git
cd malwhere/docker

# Clone-and-go: static analysis + pipeline + Navigator
docker compose --profile core up -d

# Needs docker/README.md's host setup done first (CAPE + MISP)
docker compose --profile core --profile sandbox up -d
```

`core` alone starts:
- **static** — static analysis container (internal only, via `docker exec`)
- **pipeline** — normalizer/mapper/exporter (internal only, via `docker exec`)
- **ATT&CK Navigator** — layer visualization (`:4200`)

`sandbox` adds:
- **CAPE Sandbox** — dynamic analysis (`:8000`)
- **MISP** — threat intel platform (`:443`)

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
# WARNING printed here means real content was truncated (hash/network IOCs
# past --max-iocs, or a >10000-char technique justification) — see the
# printed note for which, and either raise --max-iocs or accept the cut.

# Optional: push live to MISP (needs the sandbox profile's MISP running)
python3 pipeline/exporter/export_misp.py \
    --mapping results/roning/attck/attck_mapping.json --publish
```

`--task-id` maps to CAPE's own analysis IDs (`1`=wsnake, `2`=roning,
`3`=akira in this project's validated runs). `parse_cape.py`, `normalize.py`,
and `map_attck.py` are all pure-stdlib and run with plain `python3` — no
venv, no container. `export_stix.py`/`export_misp.py` are the ones that
need third-party packages (`stix2`, `pymisp`): `pip install -r
docker/pipeline/requirements.txt` into a venv first, or run them inside
the `pipeline` container (`docker exec malwhere-pipeline python3
/app/exporter/export_stix.py ...`), which already has them installed.

### Resubmitting dropped files for their own analysis

Multi-stage malware drops payloads with real capabilities of their own —
RoningLoader alone drops a rootkit driver, an AV-killer DLL, and a Gh0st
RAT client. `parse_cape.py` can queue every dropped/CAPE-extracted file
for its own independent static-analysis run, tagged with lineage back to
the parent sample, instead of only recording their hashes as IOCs:

```bash
python3 dynamic/scripts/parse_cape.py --task-id 2 --output dynamic/reports/roning/ \
    --resubmit-dir docker/resubmit_queue --family roning
# -> docker/resubmit_queue/manifest/{sha256}.json + artifacts/{sha256}
#    (bind-mounted into the static/pipeline containers at /resubmit)
```

Then, run each half of the loop in its own container — static analysis
needs `static`'s pefile/YARA/FLOSS/Ghidra environment; normalize+map is
pure-stdlib and reads the tagged output back out via `pipeline`'s mounts:

```bash
# Static half: analyzes each queued artifact, tags it with parent_hash +
# discovery_mechanism, writes to static/reports/roning/{sha256}_static.json
docker exec malwhere-static python3 /scripts/process_resubmissions.py --verbose

# Merge half: finds anything tagged with resubmission_lineage that hasn't
# been normalized+mapped yet, runs it through the same pipeline as a
# top-level sample would go through
docker exec malwhere-pipeline python3 /app/process_resubmissions.py --verbose
# -> results/roning/resubmitted/{sha256}/iocs/normalized_iocs.json
# -> results/roning/resubmitted/{sha256}/attck/attck_mapping.json
```

Each resubmitted file gets its own independent `attck_mapping.json` rather
than being merged into the parent's — a dropped payload's own capabilities
aren't evidence the *parent* binary performs those techniques, and blending
the two would misattribute confidence in `pipeline/mapper/src/reconcile.py`'s
cross-source model. `RESUBMIT_MAX_ARTIFACTS`/`RESUBMIT_TIME_BUDGET_MIN` bound
how much a single run queues/processes — see `docker/docker-compose.yml`'s
`static`/`pipeline` service `environment:` blocks, or override per-invocation
with `--resubmit-max-artifacts`/`--time-budget-min`.

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
