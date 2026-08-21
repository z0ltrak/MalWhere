#!/usr/bin/env python3
"""
Resubmission Static Analyzer for the MalWhere Pipeline

Consumes the resubmission queue written by dynamic/scripts/parse_cape.py
(dynamic/scripts/src/resubmit_writer.py) -- dropped/extracted files CAPE
observed a sample writing to disk -- and runs each one through this
container's static analysis, tagged with lineage back to the parent
sample. Deliberately does NOT run normalize.py/map_attck.py itself: this
script only has access to what the `static` docker-compose service
mounts (/resubmit read-only, /reports read-write). It has no access to
pipeline/ or /results, and no need for it -- StaticAnalyzer's dependencies
(pefile, yara-python, floss, ghidra-headless, ...) are what make this a
separate container in the first place, while normalize.py/map_attck.py
are pure-stdlib and belong in the `pipeline` service.

So the resubmission loop is two independent halves, exactly as
docker-compose.yml's comments describe: this script tags its output with
parent_hash + discovery_mechanism so lineage survives into /reports "for
the pipeline to merge" -- see pipeline/process_resubmissions.py, which
picks up anything with a resubmission_lineage key and runs it through
normalize+map_attck.

Output: static/reports/{family}/{sha256}_static.json (flat, alongside
the family's own sample_static.json -- not a resubmitted/ subdirectory,
because normalize.py infers family from the static report's parent
directory name, and that inference needs to keep resolving correctly).

Note: this only runs *static* analysis on resubmitted files -- it does
not detonate them in CAPE. RESUBMIT_MAX_DEPTH (reserved for a future
chained dynamic-resubmission loop) is not enforced here; every processed
file is effectively depth 1 relative to its immediate parent.
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.analyzer import StaticAnalyzer


def already_processed(reports_dir: Path, family: str, sha256: str) -> bool:
    """Check whether a static report already exists for this artifact.

    Args:
        reports_dir: Base static reports directory.
        family: Parent sample's family label.
        sha256: Artifact's hash.

    Returns:
        True if {reports_dir}/{family}/{sha256}_static.json already exists.
    """
    return (reports_dir / family / f"{sha256}_static.json").exists()


def process_one(manifest: dict, artifact_path: Path, reports_dir: Path, verbose: bool) -> bool:
    """Run static analysis on one resubmitted artifact and write its lineage-tagged report.

    Args:
        manifest: Resubmission queue manifest entry for this artifact.
        artifact_path: Path to the artifact's raw bytes.
        reports_dir: Base static reports directory to write the tagged report under.
        verbose: Enable verbose StaticAnalyzer logging.

    Returns:
        True if analysis succeeded and the report was written, False on failure.
    """
    sha256 = manifest["sha256"]
    family = manifest.get("parent_family", "unknown")
    family_dir = reports_dir / family
    family_dir.mkdir(parents=True, exist_ok=True)

    if verbose:
        print(f"  Static analysis: {manifest.get('original_name', sha256)} ({sha256[:12]}...)")

    try:
        analyzer = StaticAnalyzer(artifact_path, verbose=verbose)
        report = analyzer.analyze()
    except Exception as e:
        print(f"  Error: static analysis failed for {sha256}: {e}")
        return False

    report_dict = report.to_dict()
    report_dict["resubmission_lineage"] = {
        "parent_hash": manifest.get("parent_hash"),
        "parent_family": family,
        "discovery_mechanism": manifest.get("discovery_mechanism"),
        "original_name": manifest.get("original_name"),
        "cape_task_id": manifest.get("cape_task_id"),
        "depth": manifest.get("depth", 1),
        "discovered_at": manifest.get("discovered_at"),
    }

    static_file = family_dir / f"{sha256}_static.json"
    with open(static_file, "w") as f:
        json.dump(report_dict, f, indent=2, default=str)

    if verbose:
        print(f"    -> {static_file}")
    return True


def main():
    """Process every queued resubmission manifest through static analysis, within a time budget.

    Returns:
        Process exit code (always 0; failures exit early via sys.exit).
    """
    parser = argparse.ArgumentParser(
        description="Resubmission Static Analyzer for the MalWhere Pipeline"
    )
    parser.add_argument(
        "--resubmit-dir",
        default=os.environ.get("RESUBMIT_WATCH_DIR"),
        help="Resubmission queue directory written by dynamic/scripts/parse_cape.py (default: $RESUBMIT_WATCH_DIR)"
    )
    parser.add_argument(
        "--reports-dir",
        default="/reports" if os.path.isdir("/reports") else "static/reports",
        help="Base static reports directory (default: /reports inside the static container, else static/reports)"
    )
    parser.add_argument(
        "--time-budget-min",
        type=float,
        default=float(os.environ.get("RESUBMIT_TIME_BUDGET_MIN", "45")),
        help="Stop starting new files once this many minutes have elapsed (default: $RESUBMIT_TIME_BUDGET_MIN or 45)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    if not args.resubmit_dir:
        print("Error: --resubmit-dir not given and $RESUBMIT_WATCH_DIR not set")
        sys.exit(1)

    resubmit_dir = Path(args.resubmit_dir)
    manifest_dir = resubmit_dir / "manifest"
    artifacts_dir = resubmit_dir / "artifacts"

    if not manifest_dir.is_dir():
        print(f"No manifest directory at {manifest_dir}, nothing to do.")
        return 0

    reports_dir = Path(args.reports_dir)
    manifests = sorted(manifest_dir.glob("*.json"))

    processed, skipped_done, skipped_missing, failed, skipped_budget = 0, 0, 0, 0, 0
    start = time.monotonic()
    budget_seconds = args.time_budget_min * 60

    print("\n" + "=" * 60)
    print(f"RESUBMISSION STATIC ANALYSIS: {len(manifests)} manifest(s) in queue")
    print("=" * 60)

    for manifest_path in manifests:
        with open(manifest_path) as f:
            manifest = json.load(f)
        sha256 = manifest["sha256"]
        family = manifest.get("parent_family", "unknown")

        if already_processed(reports_dir, family, sha256):
            skipped_done += 1
            continue

        if time.monotonic() - start > budget_seconds:
            skipped_budget += 1
            continue

        artifact_path = artifacts_dir / sha256
        if not artifact_path.is_file():
            print(f"  Skipping {sha256[:12]}...: artifact bytes missing at {artifact_path}")
            skipped_missing += 1
            continue

        if process_one(manifest, artifact_path, reports_dir, args.verbose):
            processed += 1
        else:
            failed += 1

    print("=" * 60)
    print(f"Processed: {processed}")
    print(f"Already done: {skipped_done}")
    print(f"Skipped (time budget exceeded): {skipped_budget}")
    print(f"Skipped (artifact bytes missing): {skipped_missing}")
    print(f"Failed: {failed}")
    print("=" * 60)
    print("Tagged reports written to /reports for the pipeline service to pick up and merge")
    print("(see pipeline/process_resubmissions.py).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
