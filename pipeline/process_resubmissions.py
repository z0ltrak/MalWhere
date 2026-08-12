#!/usr/bin/env python3
"""
Resubmission Merger for the MalWhere Pipeline
TFM 2025-2026 - Universidad Complutense de Madrid

Second half of the resubmission loop (see static/scripts/process_resubmissions.py
for the first half and the full design rationale). The static service tags
each resubmitted dropped file's static report with a resubmission_lineage
block and writes it to static/reports/{family}/{sha256}_static.json --
this script watches that directory (mounted read-only here as /input/static),
finds untagged-vs-tagged reports by that key, and runs each lineage-tagged
one through normalize.py + map_attck.py on its own.

Each resubmitted file gets a fully independent pipeline output rather
than being merged into the parent sample's own technique_observations:
a dropped payload's own capabilities (e.g. RoningLoader's goldendays.dll
killing AV, or its vally3dka.sys rootkit driver) are real findings, but
they are not evidence that the *parent* binary itself performs those
techniques, and pipeline/mapper/src/reconcile.py's cross-source
confidence model assumes every observation for a technique describes the
same binary. Blending the two would misattribute confidence.

Output: results/{family}/resubmitted/{sha256}/iocs/normalized_iocs.json
        results/{family}/resubmitted/{sha256}/attck/attck_mapping.json
"""

import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path


def find_lineage_tagged_reports(static_reports_dir: Path):
    for family_dir in sorted(static_reports_dir.iterdir()):
        if not family_dir.is_dir():
            continue
        for report_path in sorted(family_dir.glob("*_static.json")):
            if report_path.name == "sample_static.json":
                continue
            try:
                with open(report_path) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            if "resubmission_lineage" in data:
                yield family_dir.name, report_path.stem.removesuffix("_static"), report_path


def already_processed(results_dir: Path, family: str, sha256: str) -> bool:
    return (results_dir / family / "resubmitted" / sha256 / "attck" / "attck_mapping.json").exists()


def process_one(static_file: Path, family: str, sha256: str, results_dir: Path, script_dir: Path, verbose: bool) -> bool:
    sample_dir = results_dir / family / "resubmitted" / sha256
    iocs_dir = sample_dir / "iocs"
    attck_dir = sample_dir / "attck"

    python = sys.executable
    normalize_script = script_dir / "normalizer" / "normalize.py"
    map_attck_script = script_dir / "mapper" / "map_attck.py"

    if verbose:
        print(f"  Normalizing + mapping: {family}/{sha256[:12]}...")

    normalize_cmd = [python, str(normalize_script), "--static", str(static_file), "--output", str(iocs_dir)]
    if verbose:
        normalize_cmd.append("--verbose")
    result = subprocess.run(normalize_cmd, capture_output=not verbose)
    if result.returncode != 0:
        print(f"  Error: normalize.py failed for {sha256}")
        if not verbose:
            print(result.stdout.decode(errors="replace"))
            print(result.stderr.decode(errors="replace"))
        return False

    map_attck_cmd = [
        python, str(map_attck_script),
        "--iocs", str(iocs_dir / "normalized_iocs.json"),
        "--output", str(attck_dir),
    ]
    if verbose:
        map_attck_cmd.append("--verbose")
    result = subprocess.run(map_attck_cmd, capture_output=not verbose)
    if result.returncode != 0:
        print(f"  Error: map_attck.py failed for {sha256}")
        if not verbose:
            print(result.stdout.decode(errors="replace"))
            print(result.stderr.decode(errors="replace"))
        return False

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Resubmission Merger for the MalWhere Pipeline"
    )
    parser.add_argument(
        "--static-reports-dir",
        default="/input/static" if os.path.isdir("/input/static") else "static/reports",
        help="Static reports directory to scan for resubmission_lineage-tagged reports "
             "(default: /input/static inside the pipeline container, else static/reports)"
    )
    parser.add_argument(
        "--results-dir",
        default="/results" if os.path.isdir("/results") else "results",
        help="Base results directory (default: /results inside the pipeline container, else results)"
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

    static_reports_dir = Path(args.static_reports_dir)
    if not static_reports_dir.is_dir():
        print(f"No static reports directory at {static_reports_dir}, nothing to do.")
        return 0

    results_dir = Path(args.results_dir)
    script_dir = Path(__file__).parent

    candidates = list(find_lineage_tagged_reports(static_reports_dir))

    processed, skipped_done, failed, skipped_budget = 0, 0, 0, 0
    start = time.monotonic()
    budget_seconds = args.time_budget_min * 60

    print("\n" + "=" * 60)
    print(f"RESUBMISSION MERGE: {len(candidates)} lineage-tagged report(s) found")
    print("=" * 60)

    for family, sha256, static_file in candidates:
        if already_processed(results_dir, family, sha256):
            skipped_done += 1
            continue

        if time.monotonic() - start > budget_seconds:
            skipped_budget += 1
            continue

        if process_one(static_file, family, sha256, results_dir, script_dir, args.verbose):
            processed += 1
        else:
            failed += 1

    print("=" * 60)
    print(f"Processed: {processed}")
    print(f"Already done: {skipped_done}")
    print(f"Skipped (time budget exceeded): {skipped_budget}")
    print(f"Failed: {failed}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
