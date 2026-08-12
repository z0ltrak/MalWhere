# Limitations and Threats to Validity

This document collects the honest constraints on MalWhere's evaluation, each
diagnosed to a specific, verifiable cause rather than asserted generally.
Drafted as source material for the thesis's own limitations discussion, not
as thesis prose itself.

Current evaluation state (family-level P/R/F1, `evaluation/results/summary.md`):
Akira 1.00/1.00/1.00 (zero missed, zero false positives), WhiteSnake
1.00/0.78/0.88 (zero false positives, 10 missed techniques remaining),
RoningLoader 0.90/0.68/0.78 (0.88/0.84/0.86 counting the resubmission loop's
dropped-component coverage — see §1; 2 open false positives, §4). RoningLoader
is the only sample with any false positives left; both are deliberately
unresolved pending the analyst's own read of the evidence, not oversights.

## 1. Small validation set (N=3)

The pipeline is validated against three samples (Akira, RoningLoader,
WhiteSnake) — too few for any claim of statistical significance, and the
honest reason to expect scrutiny on this point specifically. Three
mitigations, each concrete rather than aspirational:

- **Depth over breadth.** Each sample's ground truth is a function-by-function
  Ghidra-verified manual reverse-engineering report, not a superficial
  import/string scan — a materially higher evidentiary bar per sample than a
  larger but shallower validation set would carry.
- **The overfitting risk was checked, not assumed.** A full audit of
  `static/scripts/` found and removed sample-specific hardcoding that had
  crept into ostensibly generic detection logic (`D3D11InstallHelper.dll`
  named directly in the installer-payload heuristic, `.3w` hardcoded as a
  known-encrypted extension, RoningLoader-specific product strings baked into
  NSIS filesystem detection, one function that was, despite its
  generic-sounding name, a hardcoded decoder for WhiteSnake's one specific
  XOR key pattern). Each was replaced with a generic equivalent and verified
  not to regress the three validated samples — evidence the concern is real,
  and was acted on, not just acknowledged.
- **N=3 top-level samples isn't the effective sample count for RoningLoader.**
  The resubmission loop (`static/scripts/process_resubmissions.py` +
  `pipeline/process_resubmissions.py`) independently statically analyzes and
  ATT&CK-maps every dropped/extracted component of a multi-stage sample —
  26 for RoningLoader alone (a rootkit driver, an AV-killer DLL, a C2 client,
  several CAPE-extracted payloads), each scored against the *same* manual
  report's full infection-chain coverage, not folded into the parent's own
  confidence-scored output (see reconcile.py's cross-source model, which
  assumes every observation for a technique describes the same binary —
  blending them in would misattribute confidence). This is real additional
  evaluation surface, not a statistical trick to inflate N.

Extending to additional *families* (either full manual RE, or a lighter
generality smoke-test confirming the pipeline doesn't crash or produce
garbage on unrelated families) is the highest-value follow-up, deliberately
scoped out of this pass since it requires either substantial additional RE
work or acquiring new samples.

## 2. A structural bug hid for most of the session: the "sample" wasn't the sample

RoningLoader's own `normalize.py` output has always carried a `hash_match`
field comparing static analysis's subject against dynamic analysis's
detonation target. It read `false` for the entire session up to this point,
unnoticed. Root cause: `static/scripts/src/analyzer.py`'s installer-analysis
path (`_analyze_installer`) correctly detects NSIS, extracts every bundled
file, pools discovered keys across them, and fully analyzes each one — but
its final step used to pick exactly *one* extracted child (the first `.dll`
found, by extraction order) and return **that child's own report** as the
entire installer's analysis, discarding the installer's own identity and
every other child's findings. It landed on `D3D11InstallHelper.dll` (a
side-loaded helper, not the malicious payload) purely by extraction-order
luck — meaning every static finding for RoningLoader up to the fix described
one side-loaded helper DLL, not the sample actually detonated.

Fixed by aggregating ATT&CK evidence/keys/config across every extracted
child instead of substituting one, while the installer's own hash/filename
are now what's reported (`_build_installer_report`). This is offered as a
concrete example of why the evaluation harness's own sanity fields
(`hash_match`) matter and should be checked, not just computed — the bug had
been silently present the whole time the field existed.

A second-order finding from the same fix: aggregating *every* extracted
child's evidence surfaced a real false positive of its own (T1134, from
`UserInfo.dll` — an NSIS-bundled stock plugin shipped unmodified with the
compiler, not attacker code, doing a routine privilege check). Fixed with a
`$PLUGINSDIR`-path-based filter (NSIS's own reserved runtime-plugin
directory) that excludes stock plugins from evidence aggregation while
keeping them in `embedded_files` for traceability — a generic signal, not a
RoningLoader-specific exclusion list.

## 3. The false-positive audit

Every false positive across all three samples' family-level evaluation was
individually traced to its exact evidence (the specific import combination,
CAPE signature's raw `data` field, or string pattern — never just the
technique name or category) and checked against the *full* manual report
text, not only its ATT&CK summary table. 13 were checked; 10 were genuine
pipeline errors, now fixed; 1 was a ground-truth gap, not a pipeline error
(§5); 2 remain open, deliberately (§4).

Representative fixes, chosen because each generalizes beyond the sample that
surfaced it:

- **Duplicate mapping tables drifted apart.** `attck_mapper.py`'s
  import-based T1055 (Process Injection) logic already required a coherent
  combination of imports (not just 2+ present) before reporting high
  confidence — but `string_attck_mapper.py` mapped the same APIs from their
  string-form evidence with no equivalent check, so fixing only the import
  table left Akira's `OpenProcess` false positive (its manual report maps
  this exact code — enumerate, then terminate — to T1057/T1562, never
  T1055) still firing from the string path. Both tables now apply the same
  standard.
- **A signature's own raw evidence contradicted its name.** CAPE's
  `antiav_servicestop` (`-> T1489 Service Stop`) fired on RoningLoader — but
  its raw `data` field names the specific service: `{"service":
  "vally3dka"}`, RoningLoader's *own* kernel driver, not an AV product's.
  Stopping your own service during normal install lifecycle isn't T1489.
  Checking the raw evidence field, not just the signature's community name,
  is what caught this.
- **A signature's category didn't fit the sample.** `per_file_acl_token_check`
  (`-> T1485 Data Destruction, T1069 Permission Groups Discovery`) is a
  CAPE community signature scoped to wipers/ransomware. Its own raw evidence
  (`token_query_count: 230`) is close to RoningLoader's 37 dropped files
  times ~6 token queries each — consistent with a dropper checking its own
  write permission before writing each file, not a wiper checking before
  destroying data or an actor discovering other accounts' group
  memberships. The signature's own category was the tell that it didn't fit
  a loader/RAT.

Full list in commit history (`git log --oneline | grep -i "false positiv"`
and the installer-analysis/CAPE-signature-override commits either side of
it). This audit trail — that the false-positive rate wasn't achieved by
suppressing weak signals wholesale, but by verifying each individually
against raw evidence — is the stronger methodological claim than the raw
precision number itself.

## 4. Two false positives left open on purpose

RoningLoader's T1027 (Obfuscated Files or Information) and T1497
(Virtualization/Sandbox Evasion) both have real supporting evidence — T1027
from a genuinely packed PE section (84x virtual/raw size ratio) plus a
`PAGE_NOACCESS`-protected memory allocation consistent with hiding a payload
from memory scanners; T1497 from multi-source static+dynamic corroboration
including two fairly specific signatures (`mouse_movement_detect`,
`antisandbox_windows_activation`). Neither is contradicted by the manual
report — it's simply silent on both.

These were deliberately *not* added to ground truth, unlike §5's T1620 case:
that correction rested on the analyst's own explicit statement elsewhere in
the same document ("Reflective PE loading — Verified"), a factual omission
between two parts of one report. Here there's no equivalent statement to
point to — only this project's own technical inference from CAPE evidence.
Editing ground truth on the strength of the automated finding alone would be
circular, exactly the overfitting risk described in §1. Left as open false
positives pending the analyst's own read of the evidence, not silently
resolved.

## 5. Ground truth extraction can miss what the analyst already confirmed

WhiteSnake's manual report's own Validation Summary table states
*"Reflective PE loading — Verified — In xEdACX"* — the analyst had already
confirmed the behavior — but the finding never made it into the same
report's ATT&CK Techniques table, which is what `extract_ground_truth.py`
parses into ground truth. The automated pipeline's T1620 finding
(corroborated independently: CAPE's `unbacked_api_resolution`/
`unbacked_library_load` signatures, remapped from a wrong community T1129 tag
to T1620 per MITRE's own technique definitions — see cape_report_parser.py)
was therefore scored as a false positive despite being correct and already
analyst-confirmed elsewhere in the same document.

Fixed at the source — added the missing row to the manual report itself and
regenerated ground truth from it — rather than hand-patching the derived
JSON, which would silently drift from the source report on any future
regeneration. Worth flagging as a general methodological point: a
markdown-table-based ground truth extraction pipeline is only as complete as
the *table*, even when the surrounding prose says more.

## 6. Containment-first dynamic analysis limits network/C2 observation

CAPE detonates every sample against INetSim's simulated network (no real
internet egress, by design — see `docker-compose.yml`'s `internal: true`
network). Several missed techniques across all three samples cluster
specifically around network/exfiltration behavior that a fake network can't
fully trigger: `T1041`/`T1048` (exfiltration channels), `T1090` (proxy),
`T1571`/`T1572` (non-standard port, protocol tunneling), `T1046` (network
service discovery). The malware's code path exists and may even attempt the
connection, but INetSim can't produce the specific response that would let
CAPE observe the full behavior. This is a structural property of
containment-first sandboxing, not a bug — the alternative (real egress) is
not an acceptable trade for a research environment.

## 7. Static key/config recovery has a real ceiling, precisely located

Two related but structurally different findings about what static analysis
can and can't recover, from opposite ends of the same problem:

- **What it can do:** RoningLoader's `diamondage.exe` C2 client stores its
  C2 IP (`202.95.11.173`) single-byte XOR'd. `config_parser.py` now
  exhaustively brute-forces all 256 keys and recovers it with no prior
  knowledge of the key — genuinely tractable because the keyspace is small
  enough to search exhaustively. This isn't free, though: naive brute force
  produces constant false-positive noise (a wrong key routinely decodes
  packed/compiled bytes into coincidental-looking structured data — verified
  concretely on WhiteSnake, where key `0x2e` decoded a repeating integer
  table into 8 fake "IP addresses" back to back, since `0x2e` is ASCII `.`
  and turns null-padding into literal dots). Needed two independent filters
  before it was trustworthy: a clean-boundary check (the byte immediately
  before/after a match must be 0x00 or the key itself) and a match-density
  cap (a key producing more than 2 dotted-quad-shaped matches anywhere in
  the file is discarded outright — a real embedded string is isolated, a
  cascade from one key is structural noise). The true positive this method
  targets produced exactly 1 match for its key; the false positive produced
  8 — that gap is what makes the density filter a principled cutoff, not an
  arbitrary one.
- **What it can't do:** investigated why RoningLoader's RC4-encrypted
  `9ZUPMq.3w` payload was never decrypted end-to-end despite the correct key
  (`dkwk239c0v023kx`) being independently verified via manual Ghidra RE.
  `KeyReconstructor`'s ~300 discovered key candidates never include it in
  any form — confirmed the exact string, its hex encoding, and every
  substring are simply absent from the DLL's bytes. This matches the
  report's own description of the key's origin: assembled at runtime from
  three separate `.rdata` constants combined via register arithmetic, never
  stored as a contiguous byte sequence. No static byte-pattern scan — XOR
  brute force, printable-string scanning, hex/base64 detection, RC4 S-box
  detection — can recover a key that never exists as bytes in the file.
  Recovering it would require emulating the key-assembly routine (e.g. via
  Unicorn), a materially different and larger capability than static
  byte-pattern analysis. (This specific payload was still recovered for
  evaluation purposes — via the independently-verified key, fed through the
  resubmission loop with explicit `manual_rc4_decryption` lineage tagging,
  never presented as something the pipeline discovered on its own.)

The boundary between these two isn't "encryption is hard" in general — it's
specifically whether the key exists as bytes anywhere in the sample. A
128-values-or-fewer keyspace (single-byte XOR) is exhaustively searchable
regardless of how the key is used; a key assembled at runtime from register
arithmetic isn't recoverable by any static byte-pattern method no matter how
exhaustive, only by emulation.

## 8. Ground truth is the best available oracle, not a perfect one

Standard caveat, stated precisely rather than generically: an automated
finding absent from a manual report may be a genuine false positive, or
simply something the analyst didn't write up but confirmed elsewhere in the
same document (§5's T1620 is a concrete instance, now fixed at the source);
a finding the analyst documented but the pipeline misses may reflect a real
detection gap, or (§6) a behavior the sandbox environment structurally
couldn't trigger. The evaluation harness's confidence-tier and
source-agreement breakdowns exist specifically to give a second, orthogonal
signal beyond raw precision/recall for exactly this reason — a technique's
confidence tier correlating with its actual correctness is closer to ground
truth than any single P/R/F1 number, and is the more defensible claim to
hang a methodological contribution on.

## 9. Tool-level constraints observed during validation

- **FLOSS (stack/decoded string extraction)** is emulation-based and
  correspondingly slow on heavily obfuscated binaries — it timed out on
  Akira specifically (the most anti-analysis-heavy of the three samples)
  even after its own CLI invocation bug was fixed. This surfaces as a
  real, correctly-logged error (`FLOSS timed out with: ...`) rather than a
  silent gap, but means stack/decoded-string coverage is not guaranteed to
  be complete for every sample.
- **AES/ChaCha20 decryption** can only succeed against payloads using a zero
  nonce/IV, since neither can be recovered from static analysis alone
  without per-payload context no current caller supplies. Documented as a
  real, narrower-than-ideal capability rather than a silent wrong-algorithm
  fallback.
- **A new brute-force capability needs its own false-positive defenses,
  verified empirically, not assumed correct on first success.** The XOR
  IP-recovery capability in §7 shipped, then was checked against a *second*
  sample before being trusted — which is what caught the false-positive
  cascade. The lesson generalizes: any new exhaustive-search-based recovery
  technique in this pipeline should be validated against more than the one
  sample that motivated building it before being treated as reliable.

## 10. Reproducibility

`docker/README.md` documents the full sandbox setup, including the manual,
non-scriptable parts (libvirt/KVM host setup, Windows guest VM creation,
CAPE image build) with their own troubleshooting sections. The `core`
profile (static analysis, pipeline, ATT&CK Navigator) is genuinely
clone-and-go; the `sandbox` profile (CAPE, MISP) requires the one-time
manual host setup by design — dynamic analysis needs a real, snapshot-able
Windows VM, which cannot be provisioned by `docker-compose` alone. All
commits in this session are pushed to the tracked GitHub remote.
