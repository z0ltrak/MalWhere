# MalWhere
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

`run_pipeline.py` runs this whole chain automatically for a given sample,
static and dynamic analysis, resubmission of any dropped files, mapping,
and export, end to end (see [Quickstart](#quickstart)).

---

## Repository Structure

```
malwhere/
├── run_pipeline.py               # Single E2E entry point (static -> CAPE -> resubmission -> ATT&CK -> STIX/MISP)
├── samples/                     # Hash manifests only, NO binaries committed
│   └── .gitignore
├── static/
│   ├── scripts/                 # Static analysis automation scripts
│   └── reports/                 # Generated JSON reports per sample
├── dynamic/
│   ├── scripts/                 # Dynamic analysis parsing scripts
│   └── reports/                 # CAPE/sandbox JSON reports
├── pipeline/
│   ├── normalizer/               # IOC normalization and deduplication
│   ├── mapper/                   # ATT&CK rule-based mapping engine + confidence reconciliation
│   └── exporter/                 # STIX 2.1 and MISP export
├── docker/
│   ├── docker-compose.yml       # Full environment definition
│   ├── cape/                    # CAPE sandbox configuration
│   ├── misp/                    # MISP instance configuration
│   ├── navigator/                # ATT&CK Navigator instance
│   └── resubmit_queue/           # Dropped-file resubmission queue (gitignored, generated)
├── results/
│   ├── roning/
│   │   ├── iocs/                # Normalized IOC JSON
│   │   ├── attck/               # ATT&CK mappings + Navigator layers
│   │   ├── stix/                # STIX 2.1 bundles
│   │   └── resubmitted/         # Per-dropped-file iocs/+attck/, one dir per sha256 (26 for roning)
│   ├── wsnake/
│   ├── akira/
│   └── asyncrat/                # 4th family, generality smoke test (no manual ground truth yet,
│                                 #   see "Generality Smoke Test" below -- not in the F1 table)
├── evaluation/
│   ├── ground_truth/            # Structured ground truth parsed from manual_analysis/ reports
│   ├── results/                 # P/R/F1 vs. ground truth, by confidence tier and source agreement
│   └── scripts/                 # Ground-truth extraction and matching harness
├── manual_analysis/             # Function-level Ghidra RE reports/notes per family, the
│   └── akira/ roning/ wsnake/    # ground truth every automated finding is checked against
├── paper/                       # Academic paper, LaTeX source + compiled PDFs
│   ├── en/                      # English version
│   └── es/                      # Spanish version
├── docs/                        # Methodology documentation
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
- Large free disk space: ~14 GB for the container images plus the Windows 10
  guest VM's own disk (50 GB is comfortable, see
  [`docker/README.md`](docker/README.md)). CAPE also refuses to start a new
  task unless it sees real free space beyond that (`freespace` in
  `docker/cape/work/conf/cuckoo.conf`, tuned down from upstream's 50GB
  default to 10GB for this project's scale) — 100+ GB total disk keeps you
  comfortably clear of both

### Deploy the environment

Every service sits behind a Compose `profiles:` gate, `docker compose up -d`
with no `--profile` flag starts nothing at all. `core` is the clone-and-go
part (static analysis, the normalize/map/export pipeline, ATT&CK Navigator);
`sandbox` (CAPE, MISP) needs real one-time host setup first, libvirt/KVM,
building the `cape:kvm` image, an interactive Windows guest VM install,
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
- **static**: static analysis container (internal only, via `docker exec`)
- **pipeline**: normalizer/mapper/exporter (internal only, via `docker exec`)
- **ATT&CK Navigator**: layer visualization (`:4200`)

`sandbox` adds:
- **CAPE Sandbox**: dynamic analysis (`:8000`)
- **MISP**: threat intel platform (`:443`)

### Run the pipeline on a sample

Two ways to run it: the full pipeline, or static analysis alone. **The full
pipeline needs the `sandbox` profile's one-time host setup done first** —
the `cape:kvm` image built and the Windows guest VM created, both walked
through start to finish in [`docker/README.md`](docker/README.md) — since
it submits the sample to a real CAPE detonation; without that setup, `cape`
never comes up and the pipeline has nothing to detonate against. Static
analysis alone needs none of that, just the `core` profile. Drop the
sample under `samples/` first either way, that's the directory already
bind-mounted read-only into the containers as `/samples`.

#### Full pipeline

`run_pipeline.py` is the single entry point: static analysis, CAPE
submission, detonation, resubmission of every dropped file (each gets its
own independent analysis, not merged into the parent's), ATT&CK mapping,
and STIX export, all chained automatically.

```bash
python3 run_pipeline.py --sample samples/<sha256>.exe --family roning
```

Auto-starts whatever containers it needs (`static` always; `cape`/
`inetsim` only when actually detonating) and prints exactly what it
produced when done:

```
[run_pipeline] ATT&CK mapping:          results/roning/attck/attck_mapping.json
[run_pipeline] Navigator layer:         results/roning/attck/navigator_layer.json
[run_pipeline] STIX bundle:             results/roning/stix/bundle.stix2
[run_pipeline] Resubmitted components:  results/roning/resubmitted/*/attck/attck_mapping.json
```

Useful flags:
- `--task-id N`: reuse an already-completed CAPE task instead of
  re-detonating (CAPE's own analysis IDs in this project's validated
  runs: `1`=wsnake, `2`=roning, `3`=akira, `4`+=asyncrat, re-run several
  times since it's a generality smoke test, not a fixed reference sample)
- `--skip-dynamic`: static analysis only, no CAPE submission (see "Static
  analysis only" below)
- `--skip-resubmit`: skip resubmitting dropped files
- `--misp` / `--misp-publish`: also push to MISP (needs the `sandbox`
  profile's MISP running; off by default, and even with `--misp` the
  event is created as an unpublished draft unless `--misp-publish` is
  also given, matching `export_misp.py`'s own safe default)

It's idempotent: re-running against an already-processed `--task-id`
just confirms/regenerates the same output rather than redoing expensive
work (both the static resubmission pass and the merge pass skip anything
already normalized+mapped).

#### Static analysis only

No CAPE, no guest VM, the `core` profile is enough. Runs the full pipeline
but stops before any CAPE submission, straight to normalize → map → export
using static findings alone:

```bash
python3 run_pipeline.py --sample samples/<sha256>.exe --family roning --skip-dynamic
```

Or run just the static analyzer, with nothing downstream, when you only
want the raw static report:

```bash
docker exec malwhere-static python3 /scripts/analyze.py \
    --sample /samples/<sha256>.exe --output /reports/roning/
# -> static/reports/roning/<sha256>_static.json (host path, via the volume mount)
```

<details>
<summary>Running each stage by hand (what <code>run_pipeline.py</code> automates)</summary>

Static analysis runs inside its container (scripts are volume-mounted, so
edits on the host reflect immediately: no rebuild needed):

```bash
docker exec malwhere-static python3 /scripts/analyze.py \
    --sample /samples/<sha256>.exe --output /reports/roning/
# -> static/reports/roning/<sha256>_static.json (host path, via the volume mount)
```

Submit to CAPE (needs the `sandbox` profile's host setup done first, see
[`docker/README.md`](docker/README.md)), then parse its report by task ID
once detonation finishes:

```bash
# LIBVIRT_GATEWAY/LIBVIRT_BRIDGE/GUEST_VM_IP need to reach the container as
# real env vars, not just sit in docker/.env, hence source + explicit -e:
set -a; source docker/.env; set +a
docker exec -e LIBVIRT_GATEWAY -e LIBVIRT_BRIDGE -e GUEST_VM_IP malwhere-cape \
    su - cape -w LIBVIRT_GATEWAY,LIBVIRT_BRIDGE,GUEST_VM_IP -c \
    "cd /opt/CAPEv2/utils && poetry run python3 submit.py --timeout 200 --enforce-timeout /samples/<sha256>.exe"
# prints: "... added as task with ID N"; poll
# http://127.0.0.1:8000/apiv2/tasks/status/N/ for "reported"
```

```bash
python3 dynamic/scripts/parse_cape.py --task-id 2 --output dynamic/reports/roning/
# or: --report docker/cape/work/storage/analyses/2/reports/report.json
# -> dynamic/reports/roning/dynamic_report.json
```

Normalize both sources, map to ATT&CK, then export:

```bash
python3 pipeline/normalizer/normalize.py \
    --static static/reports/roning/<sha256>_static.json \
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
# past --max-iocs, or a >10000-char technique justification), see the
# printed note for which, and either raise --max-iocs or accept the cut.

# Optional: push live to MISP (needs the sandbox profile's MISP running)
python3 pipeline/exporter/export_misp.py \
    --mapping results/roning/attck/attck_mapping.json --publish
```

`parse_cape.py`, `normalize.py`, and `map_attck.py` are all pure-stdlib
and run with plain `python3`, no venv, no container. `export_stix.py`/
`export_misp.py` are the ones that need third-party packages (`stix2`,
`pymisp`): `pip install -r docker/pipeline/requirements.txt` into a venv
first, or run them inside the `pipeline` container (`docker exec
malwhere-pipeline python3 /app/exporter/export_stix.py ...`), which
already has them installed.

#### Resubmitting dropped files for their own analysis

Multi-stage malware drops payloads with real capabilities of their own,
RoningLoader alone drops a rootkit driver, an AV-killer DLL, and a Gh0st
RAT client. `parse_cape.py` can queue every dropped/CAPE-extracted file
for its own independent static-analysis run, tagged with lineage back to
the parent sample, instead of only recording their hashes as IOCs:

```bash
python3 dynamic/scripts/parse_cape.py --task-id 2 --output dynamic/reports/roning/ \
    --resubmit-dir docker/resubmit_queue --family roning
# -> docker/resubmit_queue/manifest/{sha256}.json + artifacts/{sha256}
#    (bind-mounted into the static container at /resubmit)
```

Then, run each half of the loop, static analysis needs `static`'s
pefile/YARA/FLOSS/Ghidra environment; the merge half is pure-stdlib and
runs directly on the host:

```bash
# Static half: analyzes each queued artifact, tags it with parent_hash +
# discovery_mechanism, writes to static/reports/roning/{sha256}_static.json
docker exec malwhere-static python3 /scripts/process_resubmissions.py --verbose

# Merge half: finds anything tagged with resubmission_lineage that hasn't
# been normalized+mapped yet, runs it through the same pipeline as a
# top-level sample would go through
python3 pipeline/process_resubmissions.py --verbose
# -> results/roning/resubmitted/{sha256}/iocs/normalized_iocs.json
# -> results/roning/resubmitted/{sha256}/attck/attck_mapping.json
```

Each resubmitted file gets its own independent `attck_mapping.json` rather
than being merged into the parent's: a dropped payload's own capabilities
aren't evidence the *parent* binary performs those techniques, and blending
the two would misattribute confidence in `pipeline/mapper/src/reconcile.py`'s
cross-source model. `RESUBMIT_MAX_ARTIFACTS`/`RESUBMIT_TIME_BUDGET_MIN` bound
how much a single run queues/processes: see `docker/docker-compose.yml`'s
`static` service `environment:` block, or override per-invocation with
`--resubmit-max-artifacts`/`--time-budget-min`.

</details>

---

## ATT&CK Confidence Model

All technique IDs across this pipeline, ground truth, and the Navigator
layers target **MITRE ATT&CK v19.2**. CAPE's own community signatures are
frozen to whichever version they were last written against, so
signature-sourced technique tags are remapped to their current v19
identity at curation time (`dynamic/scripts/src/cape_report_parser.py`)
rather than trusted verbatim.

Static rules use a three-tier system to avoid promoting a single generic
indicator to high confidence on its own:

| Tier | Criteria | Example |
|---|---|---|
| **High** | Deterministic artifact → technique, or a coherent multi-import combination | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` → T1055 |
| **Medium** | Suggestive artifact, requires context | `mshta.exe` string → T1218.005 (needs corroboration) |
| **Low** | Weak signal, combinatorial only | High entropy section alone → possible packing |

`pipeline/mapper/src/reconcile.py` then reconciles those static findings
against dynamic (CAPE) findings for the same technique: a technique seen by
both sources reaches high confidence unless both are individually low, and
a further cross-level pass recognizes agreement between a parent technique
reported by one source and its specific sub-technique reported by the
other (e.g. dynamic `T1547`, static `T1547.001`), not just exact-ID matches.
Multi-stage samples get a further, separate pass: the resubmission loop
independently analyzes every dropped/extracted component through the same
static → normalize → map pipeline, tagged with lineage back to the parent,
so a dropped payload's own capabilities are never folded into the parent
binary's own confidence-scored output.

Static detection rules currently cover approximately 86 of 474
Windows-relevant MITRE ATT&CK techniques, each one sourced directly from
MITRE's own technique description, not a generic API/tool name alone
(dynamic-side coverage adds 2 more this project curated the same way,
`T1571` and `T1201`, on top of whatever CAPE's own upstream community
signatures separately report). See the
paper's limitations section for what's deliberately out of scope.

---

## Evaluation Results

Every automated finding is checked against function-level manual Ghidra
reverse engineering ([`manual_analysis/`](manual_analysis/)), never against
the pipeline's own output, so the comparison isn't circular. Full
methodology, per-tier and per-source-agreement precision breakdowns, and
the false-positive audit are in
[`evaluation/results/summary.md`](evaluation/results/summary.md) and the
paper.

| Sample | Precision | Recall | F1 | Notes |
|---|---|---|---|---|
| Akira (ransomware) | 0.87 | 1.00 | 0.93 | single-stage binary |
| WhiteSnakeStealer (.NET infostealer) | 0.97 | 0.70 | 0.81 | single-stage binary |
| RoningLoader (loader only) | 0.95 | 0.77 | 0.85 | parent binary alone |
| RoningLoader (+ resubmission) | 0.86 | 0.92 | 0.89 | loader + ground-truthed dropped components |

Figures above are from the audited baseline run (commit `98235b8`).
CAPE detonation is not perfectly deterministic: re-running the pipeline
end-to-end, including on an independent clean-clone VM, can shift
individual runs' precision/recall by a few points and change which
specific dynamic-analysis techniques fire, since a CAPE behavioral
signature may or may not trigger between runs even against the same
sample. This variance is confined to dynamic-sourced techniques; static
analysis findings are stable across runs.

Family-level matching (a parent technique and its sub-technique count as
the same finding). Every discrepancy against ground truth is individually
audited against the manual report's full text, not just its own summary
table: this found and fixed 4 real pipeline detection gaps (2 CAPE
signature-reliability fixes on Akira, 2 static-detector coverage additions
on RoningLoader) and 4 ground-truth corrections (3 additions of
report-confirmed findings the original table-only extraction missed, 1
removal of a table row that contradicted the same report's own technical
detail), while confirming the remaining open false positives and missed
techniques are genuine pipeline limitations or sandbox/evasion
constraints (WhiteSnakeStealer's per-string encryption and dynamic API
resolution defeat static string matching by design; its C2 infrastructure
is unreachable from the network-isolated sandbox) rather than untraced
gaps. See the paper's evaluation and case-studies sections for the full
audit.

### Generality Smoke Test

A 4th family, AsyncRAT (a native-crypter-wrapped .NET RAT/backdoor,
structurally unlike all three validated families: not ransomware, not a
multi-stage NSIS loader, not a plain .NET infostealer), was run through
the full `run_pipeline.py` chain, including a real CAPE detonation and
automatic resubmission of its dropped payloads, to check that the
pipeline generalizes rather than being quietly overfit to the validated
set. **This has no manual ground truth and is not in the F1 table above**,
but it did what a smoke test is for: static-only analysis on the outer
stub found almost nothing (14 generic evasion signals), while dynamic
detonation plus resubmitting the unpacked payload consistently reaches
1.5-2x that many real techniques (process injection, reflective loading,
persistence, C2, credential access, 17-22 across four separate real
detonations so far, dynamic analysis isn't perfectly deterministic
run-to-run) that the outer stub alone never revealed, and
auditing the resulting IOCs against this same false-positive discipline
found and fixed three new extraction bugs: a XOR-recovery false positive
shaped like a .NET assembly version number and a repeating-byte-padding
decode artifact, both on AsyncRAT's own resubmitted components; and a
third bug class, X.509 certificate OIDs misparsed as IPs, which the
resulting broader sweep actually caught on two of RoningLoader's own
resubmitted components rather than AsyncRAT's, one of the original three
families quietly carrying a bug this exercise is what surfaced. All
three are now fixed and verified against every ground-truth IP across
both families. See `results/asyncrat/` and the paper's case studies for
the full account.

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

The accompanying academic paper presents the full methodology, related work, five detailed case studies, limitations, and evaluation metrics, in both English ([`paper/en/main.pdf`](paper/en/main.pdf)) and Spanish ([`paper/es/main.pdf`](paper/es/main.pdf)); LaTeX source for both is in [`paper/`](paper/).

---

## License

MIT License: see [LICENSE](LICENSE).

> This tool is intended strictly for academic and authorized security research. The authors assume no responsibility for misuse.
