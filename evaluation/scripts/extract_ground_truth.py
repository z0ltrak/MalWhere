#!/usr/bin/env python3
"""
Ground Truth Extractor for the MalWhere Evaluation

Extracts the manually-validated ATT&CK technique table from a
manual_*_report.md report into structured ground_truth/<family>.json,
for comparison against the pipeline's automated attck_mapping.json.

Only ever sees the report's own ATT&CK summary table -- a curator who later
adds a technique found in the report's prose instead (tagging it
"source": "manual" in ground_truth/<family>.json) needs that entry to
survive a re-run of this script, not get silently overwritten by the fresh
table-only parse. main() re-merges any such entries back in after parsing.

Symmetrically, a curator who finds the table itself wrong (e.g. the
analyst's own row contradicts their more detailed prose elsewhere -- see
roning.json's T1490 for a real example) can list that technique_id under a
top-level "excluded_technique_ids": {"T1xxx": "reason"} dict; main() drops
it from every future re-extraction too, carrying the exclusion list
forward, instead of it silently reappearing from the table on the next run.
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.ground_truth_parser import extract_ground_truth


def main():
    """Parse a manual analysis report's ATT&CK table into ground_truth/<family>.json.

    Returns:
        Process exit code (always 0; failures exit early via sys.exit).
    """
    parser = argparse.ArgumentParser(
        description="Ground Truth Extractor for the MalWhere Evaluation"
    )
    parser.add_argument(
        "--report", "-r",
        required=True,
        help="Path to a manual_*_report.md report"
    )
    parser.add_argument(
        "--family", "-f",
        required=True,
        help="Sample family name (e.g. akira, roning, wsnake)"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output directory for <family>.json"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"Error: report not found: {report_path}")
        sys.exit(1)

    if args.verbose:
        print(f"Parsing {report_path}...")

    markdown_text = report_path.read_text()

    try:
        ground_truth = extract_ground_truth(markdown_text, args.family, str(report_path))
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{args.family}.json"

    if output_file.exists():
        try:
            with open(output_file) as f:
                previous = json.load(f)
        except (OSError, json.JSONDecodeError):
            previous = {}
        manual = {
            t["technique_id"]: t
            for t in previous.get("techniques", [])
            if t.get("source") == "manual"
        }
        excluded = previous.get("excluded_technique_ids", {})
        if manual or excluded:
            by_id = {t["technique_id"]: t for t in ground_truth["techniques"]}
            by_id.update(manual)  # manual entries win on ID collision
            for technique_id in excluded:
                by_id.pop(technique_id, None)  # a curated exclusion beats a fresh table row
            ground_truth["techniques"] = sorted(by_id.values(), key=lambda t: t["technique_id"])
            if excluded:
                ground_truth["excluded_technique_ids"] = excluded
            if args.verbose:
                if manual:
                    print(f"Preserved {len(manual)} manually-added technique(s): {', '.join(sorted(manual))}")
                if excluded:
                    print(f"Kept {len(excluded)} technique(s) excluded: {', '.join(sorted(excluded))}")

    with open(output_file, "w") as f:
        json.dump(ground_truth, f, indent=2)

    print("\n" + "=" * 60)
    print(f"GROUND TRUTH EXTRACTED: {args.family}")
    print("=" * 60)
    print(f"Unique techniques: {len(ground_truth['techniques'])}")
    if ground_truth["duplicate_rows_collapsed"]:
        print(f"Duplicate rows collapsed: {ground_truth['duplicate_rows_collapsed']}")
    if args.verbose:
        for t in ground_truth["techniques"]:
            print(f"   {t['technique_id']:12} {t['name']}")
    print("=" * 60)
    print(f"Saved to: {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
