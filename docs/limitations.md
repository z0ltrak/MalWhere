# Limitations and Threats to Validity

This document collects the honest constraints on MalWhere's evaluation, each
diagnosed to a specific, verifiable cause rather than asserted generally.
Drafted as source material for the thesis's own limitations discussion, not
as thesis prose itself.

## 1. Small validation set (N=3)

The pipeline is validated against three samples (Akira, RoningLoader,
WhiteSnake) — too few for any claim of statistical significance, and the
honest reason to expect scrutiny on this point specifically. Two mitigations,
both concrete rather than aspirational:

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

Extending to additional samples (either full manual RE, or a lighter
generality smoke-test confirming the pipeline doesn't crash or produce
garbage on unrelated families) is the highest-value follow-up, deliberately
scoped out of this pass since it requires either substantial additional RE
work or acquiring new samples.

## 2. Static-only ground truth vs. genuinely dynamic findings

All three manual reports are static reverse-engineering documents (Ghidra
code tracing), not records of an actual sandbox run. Several automated
findings are dynamic-only observations — real, CAPE-verified behavior — that
never appear in the static ground truth because a code-reading analyst
wouldn't necessarily trace or think to document them:

| Sample | Techniques | CAPE evidence | Why static RE wouldn't catch it |
|---|---|---|---|
| RoningLoader | T1027, T1069, T1497 | Packing/anti-sandbox signatures (`pe_section_vsize_rsize_anomaly`, `mouse_movement_detect`, `antisandbox_windows_activation`, `per_file_acl_token_check`, ...) | Small, easily-overlooked evasion/discovery routines in a large codebase |
| RoningLoader | T1489 | `antiav_servicestop` ("Attempts to stop active services") | Distinct from the already-documented process-kill behavior (T1562); the report never separately traced an SCM-level service-stop call |
| RoningLoader | T1485 | `anomalous_deletefile`, `per_file_acl_token_check` | No corroborating narrative either way — left unresolved rather than guessed |
| WhiteSnake | T1562, T1564/T1564.003 | `unbacked_process_mitigation_alteration`, `stealth_window` | Same pattern: real runtime behavior, no static trace |

Each was re-checked directly against the raw CAPE signature description and
the full manual report narrative (not just its ATT&CK summary table) before
being left alone — the signatures themselves are clean and well-defined (no
hedging or definitional mismatch, unlike the ~19 genuine CAPE mis-mappings
found and fixed elsewhere in this pipeline), so these read as an honest
capability gap in the ground truth, not a pipeline error. Forcing them into
ground truth on the strength of the automated finding alone would be circular
— exactly the overfitting risk described in §1.

## 3. Containment-first dynamic analysis limits network/C2 observation

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

## 4. Static key discovery has a hard ceiling: runtime-computed keys

Investigated why RoningLoader's RC4-encrypted payload (`9ZUPMq.3w`) has never
been successfully decrypted end-to-end, using the manually-verified key
(`dkwk239c0v023kx`, confirmed via Ghidra RE) as ground truth. Two distinct
findings, one fixed and one genuinely out of reach for this approach:

- **Fixed:** decrypting with the known-correct key does produce the correct
  payload, but its PE header sits at offset 4,841 (a reflective-loader stub
  precedes it) — every validity check in the pipeline only ever looked at
  byte offset 0, so a correct decryption was structurally unrecognizable as
  one. Now searches a bounded window for a validated PE signature, not just
  the start of the buffer.
- **Not fixed, and not fixable by this approach:** `KeyReconstructor`'s 300
  discovered key candidates never include the real key in any form —
  confirmed the exact string, its hex encoding, and every substring of it
  are simply absent from the DLL's bytes. This matches the report's own
  description of the key's origin: assembled at runtime from three separate
  `.rdata` constants combined via register arithmetic, not stored anywhere
  as a contiguous byte sequence. No static byte-pattern scan — XOR
  bruteforce, printable-string scanning, hex/base64 detection, RC4 S-box
  detection, all of which `KeyReconstructor` does — can recover a key that
  never exists as bytes in the file. Recovering it would require actually
  emulating the key-assembly routine (e.g. via Unicorn or a similar
  emulation engine), a materially different and larger capability than
  static byte-pattern analysis.

This is offered as a precisely diagnosed example of where static analysis's
ceiling actually is, rather than a vague "encryption is hard" caveat — useful
for framing dynamic analysis (which observes the decrypted payload directly,
in memory, regardless of how the key was derived) as complementary to static
analysis for exactly this class of problem, not merely additive.

## 5. Ground truth is the best available oracle, not a perfect one

Standard caveat, stated precisely rather than generically: an automated
finding absent from a manual report may be a genuine false positive, or
simply something the analyst didn't write up (see §2); a finding the
analyst documented but the pipeline misses may reflect a real detection
gap, or (see §3) a behavior the sandbox environment structurally couldn't
trigger. The evaluation harness's confidence-tier and source-agreement
breakdowns exist specifically to give a second, orthogonal signal beyond
raw precision/recall for exactly this reason — a technique's confidence tier
correlating with its actual correctness is closer to ground truth than any
single P/R/F1 number, and is the more defensible claim to hang a
methodological contribution on.

## 6. Tool-level constraints observed during validation

- **FLOSS (stack/decoded string extraction)** is emulation-based and
  correspondingly slow on heavily obfuscated binaries — it timed out on
  Akira specifically (the most anti-analysis-heavy of the three samples)
  even after its own CLI invocation bug was fixed. This surfaces as a
  real, correctly-logged error (`FLOSS timed out with: ...`) rather than a
  silent gap, but means stack/decoded-string coverage is not guaranteed to
  be complete for every sample.
- **AES/ChaCha20 decryption** (added this session) can only succeed against
  payloads using a zero nonce/IV, since neither can be recovered from static
  analysis alone without per-payload context no current caller supplies.
  Documented as a real, narrower-than-ideal capability rather than the
  previous silent wrong-algorithm fallback it replaced.
