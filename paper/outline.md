# MalWhere — Paper Outline

TFM 2025-2026, Universidad Complutense de Madrid, MSc Cybersecurity.
Working outline — section headers and the evidence/artifacts each one
draws from, not prose. Populate from `docs/limitations.md`,
`evaluation/results/summary.md`, and the git history (commit messages
throughout this project are written with enough detail to lift directly
into methodology/results prose).

## 1. Abstract

- Modular pipeline: static + dynamic reverse engineering → normalized
  IOCs → cross-source ATT&CK confidence reconciliation → STIX 2.1/MISP
  export.
- Validated against 3 manually-reverse-engineered malware families
  (Akira/ransomware, RoningLoader/multi-stage loader+rootkit+RAT,
  WhiteSnakeStealer/.NET infostealer), each ground-truthed via
  function-level Ghidra tracing, not superficial scanning.
- Headline result: family-level F1 1.00/0.89/0.86 (Akira/WhiteSnake/
  RoningLoader+resubmitted) after a systematic, evidence-based
  false-positive audit — precision near-perfect across all three.
- Methodological contribution framed as much on the *audit trail* as
  the numbers: every detection rule traces to specific verifiable
  evidence, every false positive fixed was individually diagnosed
  against raw evidence (a CAPE signature's actual data field, a manual
  RE report's own text) rather than tuned away.

## 2. Introduction

- Motivation: manual malware RE doesn't scale; existing sandboxes
  (CAPE) and static tools produce raw findings, not ATT&CK-mapped,
  confidence-scored, export-ready threat intelligence.
- Problem statement: reconciling static + dynamic evidence for the
  *same* sample without conflating confidence across sources, and
  without silently discarding evidence from multi-stage samples that
  drop/inject further components.
- Contributions (map each to the section that substantiates it):
  1. A cross-source confidence reconciliation model (§4.4) extended to
     cross-*level* (base/sub-technique) corroboration (§4.4.1).
  2. A resubmission loop (§4.5) that independently analyzes every
     dropped/extracted component of a multi-stage sample without
     misattributing its capability to the parent binary.
  3. A reproducible, evidence-sourced ATT&CK detection rule set (§4.6),
     extended from ~30 to ~85 Windows-relevant technique IDs against
     real MITRE technique descriptions, with every addition verified
     not to regress the validated set.
  4. An evaluation methodology (§5) distinguishing strict vs.
     family-level matching, confidence-tier-stratified precision, and
     source-agreement-stratified precision — testing whether the
     confidence model's own claims (agreement = more trustworthy)
     actually hold.

## 3. Related Work

- Sandboxing/dynamic analysis: CAPEv2 and its lineage (Cuckoo).
- Static ATT&CK mapping approaches (community projects, commercial
  EDR vendor writeups) — contrast with this project's evidence-cited,
  narrowly-scoped rule philosophy vs. broad/heuristic scoring.
- STIX 2.1 / MISP as CTI interchange standards — why export matters
  beyond a standalone report.
- Position this work: not a novel detection technique, but a
  methodologically rigorous *integration* — the contribution is the
  reconciliation model, the audit discipline, and the reproducibility,
  not any single detection primitive.

## 4. System Architecture

### 4.1 Pipeline overview
Diagram: sample → static analysis + dynamic analysis (parallel) →
normalizer (IOC/technique merge+dedup) → mapper (confidence
reconciliation) → exporter (STIX/MISP). Reference the existing
Architecture diagram in root `README.md`.

### 4.2 Static analysis engine
- Multi-pass installer handling (`_analyze_installer`): extraction,
  key discovery pooled across every extracted child, decrypt-with-
  discovered-keys, per-child analysis, evidence *aggregation* (not
  substitution — see the installer-identity bug fixed this project,
  §6.2).
- Key discovery / decryption (`KeyReconstructor`, `DecryptionEngine`):
  what's tractable (small keyspaces, e.g. single-byte XOR — exhaustive
  search) vs. what isn't (runtime-assembled keys never existing as
  bytes in the file — see §7.1).
- `.NET` handling: BCL call extraction from method bodies, since a
  .NET binary's native import table is typically just the CLR
  bootstrap stub.

### 4.3 Dynamic analysis engine
- CAPE integration: report curation (`cape_report_parser.py`) —
  signature-to-ATT&CK mapping correction table (`_UNRELIABLE_SIGNATURES`
  / `_SIGNATURE_TECHNIQUE_DROP` / `_TECHNIQUE_REMAP`), each entry
  individually justified against the signature's own raw evidence, not
  its name.
- New: command-pattern matching against raw `executed_commands` (LOLBin/
  recon patterns CAPE has no community signature for).
- Containment-first design (INetSim, no real egress) and its
  consequence for network/C2 technique observability (§7.2).

### 4.4 Cross-source confidence reconciliation
- The core model (`reconcile.py`): high unless both sources' best
  confidence is low; single-source findings keep their own tier.
- 4.4.1 **Cross-level extension**: the model originally only compared
  observations tagged with the *exact same* technique ID — a dynamic
  signature reporting a parent technique and a static rule reporting
  its specific sub-technique never corroborated each other, despite
  the evaluation harness's own family-level matching already treating
  them as equivalent. Fixed via `apply_cross_level_corroboration()`.
  Frame as a real, if currently unrealized-on-3-samples, consistency
  fix — built ahead of the coverage extension specifically because
  new sub-technique-specific rules would make the gap worse, not
  better, if left unfixed.

### 4.5 The resubmission loop
- Why: dropped/injected components of multi-stage malware have real
  capabilities of their own, but blending their evidence into the
  parent's own confidence-scored output would misattribute it to the
  wrong binary.
- Architecture: `dynamic/scripts/src/resubmit_writer.py` (host-run,
  pure stdlib) → `static/scripts/process_resubmissions.py` (static
  container) → `pipeline/process_resubmissions.py` (pipeline
  container) — split by dependency, not convenience.
- Case study: RoningLoader's 26 resubmitted components, including
  `diamondage.exe` (its actual C2 client, RC4-encrypted and never
  captured as a dropped file by CAPE — recovered via a manually
  verified key and fed through the same pipeline with explicit
  `manual_rc4_decryption` lineage tagging, never presented as
  something the pipeline discovered unaided).

### 4.6 ATT&CK detection rule methodology
- Philosophy: every rule traces to specific evidence (a named API
  combination, a literal registry path/string, a CAPE signature's raw
  data field) — never a generic single indicator alone unless
  genuinely unambiguous.
- Combination-aware confidence: single generic import → low/medium;
  a *coherent* combination (e.g. the T1055.012 process-hollowing
  5-API sequence) → high. Concrete negative example: `OpenProcess` +
  `QueueUserAPC` alone doesn't cohere into an injection primitive
  despite both being T1055-tagged imports — a real false positive
  found and fixed this project.
- Coverage extension methodology: for each MITRE tactic, technique
  IDs sourced from the technique's own official description (not
  invented), verified not to fire on any of the 3 validated samples
  before being trusted as non-overfit additions.

## 5. Evaluation

### 5.1 Methodology
- Ground truth: manual RE reports, function-level Ghidra-verified,
  not superficial. `extract_ground_truth.py` parses each report's
  ATT&CK Techniques table — note the real limitation found here (§6.3):
  an analyst-confirmed finding not promoted into that summary table is
  invisible to ground truth even though the analyst's own document
  says otherwise elsewhere.
- Matching modes: strict (exact technique ID) vs. family-level (base
  technique, sub-technique-tolerant) — `evaluation/scripts/src/
  matcher.py`.
- Confidence-tier and source-agreement stratified precision — tests
  whether the reconciliation model's central claim (cross-source
  agreement correlates with correctness) actually holds, independent
  of the raw P/R/F1 headline.
- The "+resubmitted" evaluation row: ground truth is written from a
  report covering the *whole* infection chain, so parent-only recall
  structurally understates a multi-stage sample's true coverage.
  Pooled comparison, clearly labeled as never feeding back into the
  exported STIX/MISP bundle.

### 5.2 Results
| Sample | Strict F1 | Family F1 | Missed | False Positives |
|---|---|---|---|---|
| Akira | 0.88 | **1.00** | 0 | 0 |
| WhiteSnake | 0.78 | **0.89** | 9 | 0 |
| RoningLoader | 0.57 | 0.78 | 8 | 2 |
| RoningLoader + resubmitted | 0.63 | **0.86** | 4 | 3 |

(Pull final numbers from `evaluation/results/summary.md` at submission
time — table above reflects the state as of this coverage-extension
pass, re-verify before the paper is finalized.)

### 5.3 The false-positive audit as a methodological result
- 13 false positives found across the 3 samples' initial evaluation;
  10 genuine pipeline errors (individually diagnosed against raw
  evidence, fixed), 1 a ground-truth extraction gap (fixed at the
  source document, not by editing derived data), 2 left open on
  purpose pending independent confirmation (the RoningLoader T1027/
  T1497 case — real supporting evidence, but no explicit analyst
  statement to hang a ground-truth edit on; a deliberately higher bar
  than "the pipeline found it, so it's probably right").
- Frame the RoningLoader installer-substitution bug (§6.2) as a case
  study in why cross-checking sanity fields (`hash_match`) matters,
  not just computing them.

## 6. Case Studies

### 6.1 RoningLoader's multi-stage chain
NSIS installer → side-loaded DLL → RC4-decrypted reflectively-loaded
RAT dropper → 5+ dropped components (rootkit driver, AV-killer DLL, C2
client). Use to illustrate the resubmission loop and the static
key-recovery ceiling together.

### 6.2 The installer-substitution bug
`_analyze_installer()` silently returning one arbitrarily-picked
extracted child's report as if it were the whole installer's analysis
— found via a `hash_match` field that had been silently `False` the
entire time. Good worked example of methodology (verify sanity fields,
don't just compute them) for the paper's discussion of validation
practice.

### 6.3 WhiteSnake's T1620 ground-truth gap
Analyst's own Validation Summary said "Verified" for reflective PE
loading; the same report's formal ATT&CK table omitted it. Illustrates
why automated ground-truth extraction from a structured table is only
as complete as the table, not the full document.

## 7. Limitations

Pull directly from `docs/limitations.md` §1–§11 — already drafted at
thesis-appropriate rigor (each limitation diagnosed to a specific,
verifiable cause, not asserted generally). Section numbers below map
1:1 to that document:
1. Small validation set (N=3), and why the resubmission loop's 26
   independently-scored components partially, not fully, mitigate it.
2. The installer-substitution bug (§6.2 above).
3. The false-positive audit (§5.3 above).
4. Two false positives left open on purpose.
5. Ground-truth extraction gaps (§6.3 above).
6. Containment-first dynamic analysis and network/C2 observability.
7. Static key/config recovery's real ceiling (single-byte XOR:
   tractable; runtime-assembled keys: not, without emulation).
8. Ground truth as best-available oracle, not perfect.
9. Tool-level constraints (FLOSS timeouts, AES/ChaCha20 zero-nonce-only
   decryption, new-capability false-positive risk).
10. Reproducibility (Docker `core`/`sandbox` profile split, what's
    genuinely clone-and-go vs. requires manual host setup).
11. Static rule coverage extent — 474 Windows-relevant MITRE techniques,
    ~85 covered, and the explicit tactic-by-tactic scoping rationale
    (Reconnaissance/Resource Development structurally out of scope;
    Initial Access/Lateral Movement poor fits for single-binary
    analysis).

## 8. Future Work

- **Linux/ELF dynamic analysis for IoT botnet families** (e.g.
  Mirai-lineage). The architecture already has a natural extension
  point — `analyzer.py` already dispatches on detected file type
  (`pe_file`/`pe_native`/`pe_dotnet` vs. `elf_file`), and `elf_parser.py`
  already exists as a stub (header/section parsing only, no ATT&CK
  rules wired to it). Not pursued in this pass for three concrete,
  verified reasons rather than time alone: (1) every current detection
  rule is Win32-specific and doesn't transfer — Linux persistence
  looks nothing like Windows persistence (cron/systemd/`init.d`
  instead of Registry Run keys, `LD_PRELOAD` instead of AppInit_DLLs);
  (2) CAPE's own bundled configuration describes its Linux dynamic
  analysis support as "work in progress for fun," not the stable
  Windows detonation path this project depends on; (3) this project's
  entire methodology rests on verifying every rule against a real,
  manually-reverse-engineered ground-truth sample before trusting it
  — no such sample exists yet for an IoT/Linux family, and adding
  detection rules without one would be exactly the unverified
  guessing this project has otherwise avoided throughout. A concrete
  next step: acquire and manually RE one Mirai-variant sample, then
  extend `elf_parser.py`'s output into the same
  IMPORT_MAPPING/STRING_MAPPING-style rule architecture already
  validated for PE.
- Emulation-based key recovery (e.g. Unicorn) for keys assembled at
  runtime from scattered constants — the one class of key-recovery
  problem confirmed unreachable by any static byte-pattern method
  (§7.7 in limitations), demonstrated concretely on RoningLoader's own
  RC4 key.
- Closing WhiteSnake's remaining 9 missed techniques — several
  (T1056.001 keylogging in particular) were investigated but require
  either disassembly-level constant recovery or dynamic API-resolution
  tracing beyond what static string/import scanning reaches.
- Extending coverage into Initial Access/Lateral Movement's few
  genuinely single-host-relevant sub-techniques (e.g. T1091 Removable
  Media, T1570 Lateral Tool Transfer) — the remaining bulk of both
  tactics judged out of scope for this pipeline's design (§11 in
  limitations).
- A fourth+ validated sample family, to test whether the coverage
  extension's ~55 new technique IDs (verified only not to *regress*
  the 3 existing samples, never yet confirmed to *correctly fire* on
  a genuinely new sample) hold up in practice.

## 9. Conclusion

- Restate the core methodological claim: a pipeline is only as
  trustworthy as its audit trail, not its headline numbers alone —
  every rule here traces to real evidence, every false positive fixed
  is documented with its root cause, and coverage was extended from
  cited MITRE sources rather than guessed.
- The near-perfect precision across all 3 samples (2 open, deliberately
  unresolved false positives on RoningLoader being the only exception)
  is the more defensible claim for a threat-intelligence tool than
  raw recall — a security analyst trusts a low-noise tool more than a
  high-recall, high-noise one.
