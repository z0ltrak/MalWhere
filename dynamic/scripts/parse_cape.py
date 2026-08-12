#!/usr/bin/env python3
"""
Dynamic (CAPE) Report Parser for the MalWhere Pipeline
TFM 2025-2026 - Universidad Complutense de Madrid

Distills a raw CAPE report.json into a curated dynamic_report.json, whose
attck_mappings field mirrors static analysis's ATTACKMapping shape so the
normalizer can treat both sources symmetrically.
"""

import os
import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.cape_report_parser import CapeReportParser
from src.resubmit_writer import ResubmitWriter


def resolve_report_path(args: argparse.Namespace) -> Path:
    if args.report:
        return Path(args.report)
    if args.task_id is None:
        raise SystemExit("Error: either --report or --task-id must be given")
    storage_dir = Path(args.cape_storage_dir)
    return storage_dir / str(args.task_id) / "reports" / "report.json"


def main():
    parser = argparse.ArgumentParser(
        description="Dynamic (CAPE) Report Parser for the MalWhere Pipeline"
    )
    parser.add_argument(
        "--report", "-r",
        help="Path to a CAPE report.json"
    )
    parser.add_argument(
        "--task-id",
        type=int,
        help="CAPE task ID — resolves <cape-storage-dir>/<id>/reports/report.json when --report is omitted"
    )
    parser.add_argument(
        "--cape-storage-dir",
        default="docker/cape/work/storage/analyses",
        help="Base CAPE analyses storage directory (default: docker/cape/work/storage/analyses)"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output directory for dynamic_report.json"
    )
    parser.add_argument(
        "--max-list-items",
        type=int,
        default=200,
        help="Truncation cap for large curated lists (default: 200)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--resubmit-dir",
        default=os.environ.get("RESUBMIT_WATCH_DIR"),
        help="Resubmission queue directory to write dropped-file manifests/artifacts into "
             "(default: $RESUBMIT_WATCH_DIR). Omit to skip resubmission entirely. Requires --task-id."
    )
    parser.add_argument(
        "--resubmit-max-artifacts",
        type=int,
        default=int(os.environ.get("RESUBMIT_MAX_ARTIFACTS", "25")),
        help="Cap on dropped files queued for resubmission per run (default: $RESUBMIT_MAX_ARTIFACTS or 25)"
    )
    parser.add_argument(
        "--family",
        default="unknown",
        help="Family label recorded in resubmission manifests for lineage (default: unknown)"
    )

    args = parser.parse_args()

    report_path = resolve_report_path(args)
    if not report_path.exists():
        print(f"Error: CAPE report not found: {report_path}")
        sys.exit(1)

    if args.verbose:
        print(f"Loading {report_path} ({report_path.stat().st_size / 1_000_000:.1f} MB)...")

    with open(report_path) as f:
        raw_report = json.load(f)

    cape_parser = CapeReportParser(
        raw_report,
        source_report_path=str(report_path),
        max_list_items=args.max_list_items,
    )
    dynamic_report = cape_parser.parse()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "dynamic_report.json"

    with open(output_file, "w") as f:
        json.dump(dynamic_report, f, indent=2, default=str)

    print("\n" + "=" * 60)
    print(f"DYNAMIC ANALYSIS PARSED: {dynamic_report['target']['filename'] or report_path}")
    print("=" * 60)
    print(f"SHA-256: {dynamic_report['target']['sha256']}")
    print(f"Malscore: {dynamic_report['analysis']['malscore']}")
    print(f"Signatures: {len(dynamic_report['signatures'])}")
    print(f"ATT&CK Mappings: {len(dynamic_report['attck_mappings'])}")
    print(f"Network Domains: {len(dynamic_report['network']['domains'])}")
    print(f"Dropped Files: {len(dynamic_report['dropped_files'])}")
    print(f"Injection Signatures: {len(dynamic_report['process_injection_signatures'])}")
    if dynamic_report.get("truncation_notes"):
        print(f"Truncated: {len(dynamic_report['truncation_notes'])} list(s)")
        for note in dynamic_report["truncation_notes"]:
            print(f"   - {note}")
    print("=" * 60)
    print(f"Results saved to: {output_file}")
    print(f"Size: {output_file.stat().st_size / 1000:.1f} KB (source was {report_path.stat().st_size / 1_000_000:.1f} MB)")

    if args.resubmit_dir:
        if args.task_id is None:
            print("\nWarning: --resubmit-dir given without --task-id, skipping resubmission "
                  "(dropped-file bytes are located via <cape-storage-dir>/<task-id>/{files,CAPE}/<sha256>).")
        else:
            writer = ResubmitWriter(
                resubmit_dir=Path(args.resubmit_dir),
                cape_storage_dir=Path(args.cape_storage_dir),
            )
            summary = writer.write_manifest_entries(
                dynamic_report=dynamic_report,
                cape_task_id=args.task_id,
                parent_hash=dynamic_report["target"]["sha256"],
                parent_family=args.family,
                max_artifacts=args.resubmit_max_artifacts,
            )
            print("\n" + "-" * 60)
            print(f"RESUBMISSION QUEUE: {args.resubmit_dir}")
            print(f"  Queued: {summary['written']}")
            print(f"  Already queued: {summary['skipped_existing']}")
            print(f"  Skipped (junk): {summary['skipped_junk']}")
            print(f"  Skipped (bytes not found in CAPE storage): {summary['skipped_missing_bytes']}")
            for err in writer.errors:
                print(f"  Error: {err}")
            print("-" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
