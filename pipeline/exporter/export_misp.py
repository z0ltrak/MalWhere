#!/usr/bin/env python3
"""
MISP Live Export for the MalWhere Pipeline
TFM 2025-2026 - Universidad Complutense de Madrid

Pushes a reconciled attck_mapping.json into a running MISP instance as a
real Event: file objects for hashes, typed attributes for network IOCs,
and one evidence-carrying attribute per technique tagged with both the
real MITRE ATT&CK galaxy cluster and a confidence tag.
"""

import os
import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.galaxy_lookup import AttckGalaxyLookup
from src.misp_builder import MISPEventBuilder


def main():
    parser = argparse.ArgumentParser(
        description="MISP Live Export for the MalWhere Pipeline"
    )
    parser.add_argument(
        "--mapping", "-m",
        required=True,
        help="Path to attck_mapping.json (from pipeline/mapper/map_attck.py)"
    )
    parser.add_argument(
        "--misp-url",
        default=os.environ.get("MISP_URL"),
        help="MISP URL (default: $MISP_URL)"
    )
    parser.add_argument(
        "--misp-key",
        default=os.environ.get("MISP_KEY"),
        help="MISP API key (default: $MISP_KEY)"
    )
    parser.add_argument(
        "--misp-verifycert",
        default=os.environ.get("MISP_VERIFYCERT", "false"),
        help="Verify MISP's TLS certificate (default: $MISP_VERIFYCERT, or false)"
    )
    parser.add_argument(
        "--distribution",
        type=int,
        default=0,
        help="MISP distribution level (default: 0 = Your organisation only)"
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish the event after creating it (default: created unpublished)"
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

    if not args.misp_url or not args.misp_key:
        print("Error: MISP URL/key not set. Pass --misp-url/--misp-key or set MISP_URL/MISP_KEY.")
        sys.exit(1)

    verify_cert = str(args.misp_verifycert).lower() in ("1", "true", "yes")

    try:
        from pymisp import PyMISP
    except ImportError:
        print("Error: pymisp is not installed. Run: pip install -r docker/pipeline/requirements.txt")
        sys.exit(1)

    if not verify_cert:
        import urllib3
        urllib3.disable_warnings()

    if args.verbose:
        print(f"Connecting to {args.misp_url}...")

    try:
        misp = PyMISP(args.misp_url, args.misp_key, ssl=verify_cert)
    except Exception as e:
        print(f"Error: could not connect to MISP: {e}")
        sys.exit(1)

    with open(mapping_path) as f:
        attck_mapping = json.load(f)

    family = attck_mapping.get("sample", {}).get("family", "unknown")

    if args.verbose:
        print(f"Looking up ATT&CK galaxy clusters...")

    galaxy_lookup = AttckGalaxyLookup(misp)
    try:
        galaxy_lookup.tag_for("T1055")  # forces the (cached) lookup now, with a clear error if it fails
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)

    builder = MISPEventBuilder(galaxy_lookup, distribution=args.distribution)
    event = builder.build(attck_mapping)

    if args.verbose:
        print(f"Pushing event for {family} ({len(event.objects)} objects, {len(event.attributes)} attributes)...")

    result = misp.add_event(event, pythonify=True)
    if isinstance(result, dict) and result.get("errors"):
        print(f"Error: MISP rejected the event: {result['errors']}")
        sys.exit(1)

    if args.publish:
        misp.publish(result)

    print("\n" + "=" * 60)
    print(f"MISP EXPORT COMPLETE: {family}")
    print("=" * 60)
    print(f"Event ID: {result.id}")
    print(f"Event UUID: {result.uuid}")
    print(f"Objects: {len(event.objects)}")
    print(f"Attributes: {len(event.attributes)}")
    print(f"Published: {args.publish}")
    if builder.unmapped_techniques:
        print(f"Techniques with no matching galaxy cluster: {builder.unmapped_techniques}")
    print("=" * 60)
    print(f"View at: {args.misp_url}/events/view/{result.id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
