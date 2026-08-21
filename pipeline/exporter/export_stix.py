#!/usr/bin/env python3
"""Builds a connected STIX 2.1 bundle (Identity, Malware, observables, Indicators, AttackPatterns) from attck_mapping.json."""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.stix_builder import StixBundleBuilder


def main():
    """Build a STIX 2.1 bundle from a reconciled attck_mapping.json and write it to disk.

    Returns:
        Process exit code (always 0; failures exit early via sys.exit).
    """
    parser = argparse.ArgumentParser(
        description="STIX 2.1 Exporter for the MalWhere Pipeline"
    )
    parser.add_argument(
        "--mapping", "-m",
        required=True,
        help="Path to attck_mapping.json (from pipeline/mapper/map_attck.py)"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output directory for bundle.stix2"
    )
    parser.add_argument(
        "--max-iocs",
        type=int,
        default=100,
        help="Cap on the number of hash/network IOCs turned into STIX objects (default: 100)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    mapping_path = Path(args.mapping)
    if not mapping_path.exists():
        print(f"Error: attck_mapping.json not found: {mapping_path}")
        sys.exit(1)

    try:
        import stix2  # noqa: F401
    except ImportError:
        print("Error: stix2 is not installed. Run: pip install -r docker/pipeline/requirements.txt")
        sys.exit(1)

    with open(mapping_path) as f:
        attck_mapping = json.load(f)

    if args.verbose:
        family = attck_mapping.get("sample", {}).get("family", "unknown")
        print(f"Building STIX bundle for {family}...")

    builder = StixBundleBuilder(attck_mapping, max_iocs=args.max_iocs)
    bundle = builder.build()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "bundle.stix2"

    with open(output_file, "w") as f:
        f.write(bundle.serialize(pretty=True))

    type_counts = {}
    for obj in bundle.objects:
        type_counts[obj.type] = type_counts.get(obj.type, 0) + 1

    print("\n" + "=" * 60)
    print(f"STIX EXPORT COMPLETE: {attck_mapping.get('sample', {}).get('family', 'unknown')}")
    print("=" * 60)
    print(f"Total STIX objects: {len(bundle.objects)}")
    for obj_type, count in sorted(type_counts.items()):
        print(f"  {obj_type}: {count}")
    print("=" * 60)
    print(f"Bundle saved to: {output_file}")

    # Previously silent: max_iocs and the description length cap could
    # both drop real threat-intel content with no trace in the output.
    # Surfaced now so a truncated export is never mistaken for a complete one.
    if builder.truncation_notes:
        print("\n" + "!" * 60)
        print("WARNING: this bundle is INCOMPLETE -- some data was truncated:")
        for note in builder.truncation_notes:
            print(f"  - {note}")
        print("Increase --max-iocs if hash/network IOCs were cut.")
        print("!" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
