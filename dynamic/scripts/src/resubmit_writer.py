"""Writes dropped/extracted-payload files discovered during dynamic
analysis into the resubmission queue for static re-analysis.

The docker-compose.yml volumes/env vars for this ("resubmit_queue",
RESUBMIT_WATCH_DIR, RESUBMIT_MAX_DEPTH, RESUBMIT_MAX_ARTIFACTS,
RESUBMIT_TIME_BUDGET_MIN) were wired up from the start but never had code
behind them -- dropped files only ever got their hashes recorded as IOCs
in normalized_iocs.json, never their own capabilities (imports, strings,
ATT&CK techniques) extracted. This is real for multi-stage malware: a
loader that drops a rootkit driver, an AV-killer DLL, and a C2 client
(exactly RoningLoader's case) never had any of those three individually
analyzed by the automated pipeline before this.

Queue layout under resubmit_dir:
  manifest/{sha256}.json  -- one entry per candidate file (see below)
  artifacts/{sha256}      -- the file's raw bytes, copied out of CAPE's
                              own storage so static (which has no access
                              to CAPE's storage volume) can read them

Manifest schema:
  {
    "sha256": "...",
    "parent_hash": "...",       # the top-level sample's sha256
    "parent_family": "roning",
    "discovery_mechanism": "dropped_file" | "cape_payload",
    "original_name": "goldendays.dll",
    "cape_task_id": 2,
    "depth": 1,
    "discovered_at": "2026-...T...Z"
  }
"""

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# Windows/OS-generated telemetry and state files that CAPE also reports
# under dropped_files but are never going to be the malware's own payload
# -- shortcuts, event traces, and app state databases the OS or another
# process created incidentally during detonation, not something dropped
# BY the sample. Excluded by extension/type text rather than an inclusion
# allowlist: malware payloads show up in all sorts of types (the
# validated set alone includes a plain 'data'-typed RC4-encrypted
# payload, .sys drivers, .bat scripts) and excluding unrecognized types
# risks silently missing a real one -- excluding known-junk is safer than
# only including known-good.
_JUNK_NAME_SUFFIXES = (".lnk", ".etl", ".evtx")
_JUNK_TYPE_SUBSTRINGS = ("sqlite", "shortcut")


class ResubmitWriter:
    def __init__(self, resubmit_dir: Path, cape_storage_dir: Path):
        """Initialize the resubmission queue writer.

        Args:
            resubmit_dir: Root of the resubmission queue (manifest/ and artifacts/ subdirs).
            cape_storage_dir: CAPE's own per-task storage directory, to copy artifact bytes from.
        """
        self.resubmit_dir = resubmit_dir
        self.cape_storage_dir = cape_storage_dir
        self.manifest_dir = resubmit_dir / "manifest"
        self.artifacts_dir = resubmit_dir / "artifacts"
        self.errors: List[str] = []

    def _looks_like_junk(self, name: str, file_type: str) -> bool:
        """Check if a dropped-file entry is OS/sandbox telemetry rather than a real payload.

        Args:
            name: Reported filename.
            file_type: Reported file type/magic description.

        Returns:
            True if the name suffix or type matches a known-junk pattern.
        """
        name_lower = name.lower()
        type_lower = file_type.lower()
        if name_lower.endswith(_JUNK_NAME_SUFFIXES):
            return True
        if any(s in type_lower for s in _JUNK_TYPE_SUBSTRINGS):
            return True
        return False

    def _find_artifact_bytes(self, task_id: int, sha256: str) -> Optional[Path]:
        """CAPE stores raw dropped files under files/ and unpacked/decrypted
        payloads it recognizes itself under CAPE/ -- check both, files/ first
        since that's where a plain dropped file (not one CAPE also decoded)
        will be.

        Args:
            task_id: CAPE task ID the artifact was observed in.
            sha256: Artifact's hash, used as the filename under each subdir.

        Returns:
            Path to the artifact's bytes, or None if not found in either location.
        """
        for subdir in ("files", "CAPE"):
            candidate = self.cape_storage_dir / str(task_id) / subdir / sha256
            if candidate.is_file() and candidate.stat().st_size > 0:
                return candidate
        return None

    def write_manifest_entries(
        self,
        dynamic_report: Dict[str, Any],
        cape_task_id: int,
        parent_hash: str,
        parent_family: str,
        max_artifacts: int = 25,
        depth: int = 1,
    ) -> Dict[str, Any]:
        """Write a resubmission manifest entry (and copy artifact bytes) for each qualifying dropped file.

        Args:
            dynamic_report: Curated dynamic_report.json, read for its dropped_files list.
            cape_task_id: CAPE task ID these dropped files were observed in.
            parent_hash: SHA-256 of the top-level sample, recorded as lineage.
            parent_family: Family label of the top-level sample, recorded as lineage.
            max_artifacts: Maximum number of new manifest entries to write.
            depth: Recursion depth to record for these artifacts (relative to the parent).

        Returns:
            Summary dict: {written, skipped_existing, skipped_junk, skipped_missing_bytes}.
        """
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        summary = {"written": 0, "skipped_existing": 0, "skipped_junk": 0, "skipped_missing_bytes": 0}

        dropped = dynamic_report.get("dropped_files", []) or []

        # Executables and scripts first -- if max_artifacts cuts the list
        # short, the highest-value candidates are the ones actually written.
        def priority(f: Dict[str, Any]) -> int:
            """Sort key: lower is higher priority (PE, then script, then everything else)."""
            t = (f.get("type") or "").lower()
            name = (f.get("name") or "").lower()
            if "pe32" in t:
                return 0
            if name.endswith((".bat", ".ps1", ".vbs", ".cmd")):
                return 1
            return 2

        for entry in sorted(dropped, key=priority):
            if summary["written"] >= max_artifacts:
                break

            sha256 = entry.get("sha256", "")
            name = entry.get("name", "") or sha256
            file_type = entry.get("type", "")
            if not sha256:
                continue

            manifest_path = self.manifest_dir / f"{sha256}.json"
            if manifest_path.exists():
                summary["skipped_existing"] += 1
                continue

            if self._looks_like_junk(name, file_type):
                summary["skipped_junk"] += 1
                continue

            source_path = self._find_artifact_bytes(cape_task_id, sha256)
            if source_path is None:
                summary["skipped_missing_bytes"] += 1
                continue

            dest_path = self.artifacts_dir / sha256
            try:
                shutil.copyfile(source_path, dest_path)
            except Exception as e:
                self.errors.append(f"Failed to copy artifact {sha256}: {e}")
                summary["skipped_missing_bytes"] += 1
                continue

            manifest_entry = {
                "sha256": sha256,
                "parent_hash": parent_hash,
                "parent_family": parent_family,
                "discovery_mechanism": "; ".join(entry.get("roles", ["dropped"])),
                "original_name": name,
                "cape_task_id": cape_task_id,
                "depth": depth,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(manifest_path, "w") as f:
                json.dump(manifest_entry, f, indent=2)
            summary["written"] += 1

        return summary
