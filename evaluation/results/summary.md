# MalWhere Pipeline Evaluation

Automated ATT&CK mappings (`pipeline/mapper/map_attck.py`) compared against
manually-validated ground truth (`manual_analysis/*/manual_*_report.md`).

> Manual analysis is the best available ground truth, not a perfect oracle —
> an automated finding absent from a manual report may be a genuine false
> positive, or simply something the manual analyst didn't write up.
>
> **Ground truth methodology**: these are comprehensive manual reverse-engineering
> reports (function-by-function Ghidra tracing, each key behavior individually
> verified — see each report's own Validation Summary), not superficial
> import/string scanning. Code-path verification of this depth captures full
> functional capability regardless of whether a given branch happens to fire
> during any one sandbox run — in that sense it's broader than a single dynamic
> execution, not narrower. The honest caveat is different: it's inference from
> code, not an empirical observation of the sample actually running (Akira's own
> report explicitly notes "no dynamic analysis performed" as a limitation), so
> environment/timing-dependent runtime specifics (e.g. which C2 response a live
> run happened to receive) can still differ from what any single CAPE detonation
> observed.

## Precision / Recall / F1

> "Sample" rows score `results/<family>/attck/attck_mapping.json` alone --
> the parent binary's own confidence-scored findings, which is also what gets
> exported to STIX/MISP. "Sample + resubmitted" rows additionally pool in
> every dropped/extracted component's own attck_mapping.json (see
> `static/scripts/process_resubmissions.py`) purely for measuring against
> ground truth, which is written from a manual report covering the whole
> infection chain -- this number is never fed back into the exported bundle,
> only shown here so recall isn't understated for multi-stage samples.

| Sample | Auto | GT | Strict P | Strict R | Strict F1 | Family P | Family R | Family F1 |
|---|---|---|---|---|---|---|---|---|
| akira | 13 | 12 | 0.85 | 0.92 | 0.88 | 1.00 | 1.00 | 1.00 |
| roning | 21 | 25 | 0.62 | 0.52 | 0.57 | 0.90 | 0.68 | 0.78 |
| roning + resubmitted | 26 | 25 | 0.62 | 0.64 | 0.63 | 0.88 | 0.84 | 0.86 |
| wsnake | 34 | 45 | 0.91 | 0.69 | 0.78 | 1.00 | 0.80 | 0.89 |

## Precision by confidence tier (family-level match)

**akira**

| Tier | Count | TP | FP | Precision |
|---|---|---|---|---|
| high | 8 | 8 | 0 | 1.00 |
| medium | 5 | 5 | 0 | 1.00 |

**roning**

| Tier | Count | TP | FP | Precision |
|---|---|---|---|---|
| high | 17 | 16 | 1 | 0.94 |
| medium | 3 | 2 | 1 | 0.67 |
| low | 1 | 1 | 0 | 1.00 |

**wsnake**

| Tier | Count | TP | FP | Precision |
|---|---|---|---|---|
| high | 24 | 24 | 0 | 1.00 |
| medium | 9 | 9 | 0 | 1.00 |
| low | 1 | 1 | 0 | 1.00 |

## Precision by source agreement (family-level match)

**akira**

| Sources | Count | TP | FP | Precision |
|---|---|---|---|---|
| dynamic | 3 | 3 | 0 | 1.00 |
| dynamic+static | 2 | 2 | 0 | 1.00 |
| static | 8 | 8 | 0 | 1.00 |

**roning**

| Sources | Count | TP | FP | Precision |
|---|---|---|---|---|
| dynamic | 13 | 12 | 1 | 0.92 |
| dynamic+static | 4 | 3 | 1 | 0.75 |
| static | 4 | 4 | 0 | 1.00 |

**wsnake**

| Sources | Count | TP | FP | Precision |
|---|---|---|---|---|
| dynamic | 18 | 18 | 0 | 1.00 |
| dynamic+static | 4 | 4 | 0 | 1.00 |
| static | 12 | 12 | 0 | 1.00 |
