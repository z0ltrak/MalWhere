#!/usr/bin/env python3
"""
IOC Normalizer for the MalWhere Pipeline
TFM 2025-2026 - Universidad Complutense de Madrid

Merges a static analysis report and a (curated) dynamic analysis report
into a single normalized_iocs.json: deduplicated hashes/network/host IOCs
with source provenance, and ATT&CK evidence grouped by technique ready for
pipeline/mapper/map_attck.py's cross-source confidence reconciliation.
"""

import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.loader import load_dynamic_report, load_static_report
from src.ioc_dedup import merge_hashes, merge_host_iocs, merge_network_iocs
from src.technique_grouper import group_technique_observations


def main():
    parser = argparse.ArgumentParser(
        description="IOC Normalizer for the MalWhere Pipeline"
    )
    parser.add_argument(
        "--static", "-s",
        required=True,
        help="Path to a static_report.json (from static/scripts/analyze.py)"
    )
    parser.add_argument(
        "--dynamic", "-d",
        help="Path to a dynamic_report.json (from dynamic/scripts/parse_cape.py). "
             "Optional — normalization can proceed on static-only coverage."
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output directory for normalized_iocs.json"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    static_path = Path(args.static)
    if not static_path.exists():
        print(f"Error: static report not found: {static_path}")
        sys.exit(1)

    dynamic_path = Path(args.dynamic) if args.dynamic else None
    if dynamic_path is not None and not dynamic_path.exists():
        print(f"Error: dynamic report not found: {dynamic_path}")
        sys.exit(1)

    if args.verbose:
        print(f"Loading static report: {static_path}")
    static_report = load_static_report(static_path)

    dynamic_report = None
    if dynamic_path is not None:
        if args.verbose:
            print(f"Loading dynamic report: {dynamic_path}")
        dynamic_report = load_dynamic_report(dynamic_path)

    family = static_path.parent.name

    static_sha256 = static_report.get("sha256", "")
    dynamic_sha256 = (dynamic_report or {}).get("target", {}).get("sha256", "")
    hash_match = bool(dynamic_report) and static_sha256 == dynamic_sha256

    sample = {
        "family": family,
        "static_sha256": static_sha256,
        "static_md5": static_report.get("md5", ""),
        "static_sha1": static_report.get("sha1", ""),
        "static_imphash": static_report.get("imphash"),
        "static_ssdeep": static_report.get("ssdeep"),
        "static_tlsh": static_report.get("tlsh"),
        "static_filename": static_report.get("filename", ""),
        "static_file_type": static_report.get("file_type", ""),
    }
    if dynamic_report is not None:
        target = dynamic_report.get("target", {})
        analysis = dynamic_report.get("analysis", {})
        sample.update(
            {
                "dynamic_sha256": target.get("sha256", ""),
                "dynamic_md5": target.get("md5", ""),
                "dynamic_filename": target.get("filename", ""),
                "dynamic_file_type": target.get("file_type", ""),
                "hash_match": hash_match,
                "malscore": analysis.get("malscore"),
                "malstatus": analysis.get("malstatus"),
                "family_detections": analysis.get("family_detections", []),
            }
        )

    hashes = [e.to_dict() for e in merge_hashes(static_report, dynamic_report)]
    network_iocs, network_discarded = merge_network_iocs(
        static_report.get("config", {}) or {}, dynamic_report
    )
    host_iocs = merge_host_iocs(static_report.get("config", {}) or {}, dynamic_report)
    technique_observations, technique_discarded = group_technique_observations(
        static_report, dynamic_report or {}
    )

    discarded_entries = [d.to_dict() for d in network_discarded + technique_discarded]

    result = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "static_report": str(static_path),
            "dynamic_report": str(dynamic_path) if dynamic_path else None,
        },
        "sample": sample,
        "hashes": hashes,
        "network_iocs": network_iocs,
        "host_iocs": host_iocs,
        "technique_observations": [t.to_dict() for t in technique_observations],
        "discarded_entries": discarded_entries,
    }

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "normalized_iocs.json"

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print("\n" + "=" * 60)
    print(f"NORMALIZATION COMPLETE: {family}")
    print("=" * 60)
    print(f"Static SHA-256:  {static_sha256}")
    if dynamic_report is not None:
        print(f"Dynamic SHA-256: {dynamic_sha256}")
        print(f"Hash match: {hash_match}")
        print(f"Malscore: {sample.get('malscore')}")
    print(f"Hashes: {len(hashes)}")
    print(f"Network IOCs: {sum(len(v) for v in network_iocs.values())}")
    print(f"Host IOCs: {sum(len(v) for v in host_iocs.values())}")
    print(f"Techniques observed: {len(technique_observations)}")
    both_sources = sum(
        1
        for t in technique_observations
        if {o.source for o in t.observations} == {"static", "dynamic"}
    )
    print(f"  - confirmed by both sources: {both_sources}")
    print(f"Discarded entries: {len(discarded_entries)}")
    if args.verbose:
        for d in discarded_entries:
            print(f"   - [{d['reason']}] {d.get('field') or d.get('raw_entry')}")
    print("=" * 60)
    print(f"Results saved to: {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
