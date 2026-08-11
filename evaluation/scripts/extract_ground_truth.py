#!/usr/bin/env python3
"""
Ground Truth Extractor for the MalWhere Evaluation
TFM 2025-2026 - Universidad Complutense de Madrid

Extracts the manually-validated ATT&CK technique table from a
manual_*_report.md report into structured ground_truth/<family>.json,
for comparison against the pipeline's automated attck_mapping.json.
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.ground_truth_parser import extract_ground_truth


def main():
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
