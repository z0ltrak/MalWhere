#!/usr/bin/env python3
"""
ATT&CK Mapper for the MalWhere Pipeline

Reconciles static + dynamic ATT&CK evidence into a final confidence tier
per technique (the project's core methodological contribution — see
pipeline/mapper/src/reconcile.py) and emits both a machine-readable mapping
and a MITRE ATT&CK Navigator layer.
"""

import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.models import MappedTechnique
from src.navigator_layer import build_navigator_layer
from src.reconcile import CONFIDENCE_MODEL_RULE, CONFIDENCE_MODEL_VERSION, apply_cross_level_corroboration, reconcile
from src.technique_names import resolve_technique_name


def main():
    """Reconcile static+dynamic technique observations into a final confidence tier and write the mapping + Navigator layer.

    Returns:
        Process exit code (always 0; failures exit early via sys.exit).
    """
    parser = argparse.ArgumentParser(
        description="ATT&CK Mapper for the MalWhere Pipeline"
    )
    parser.add_argument(
        "--iocs", "-i",
        required=True,
        help="Path to normalized_iocs.json (from pipeline/normalizer/normalize.py)"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output directory for attck_mapping.json and navigator_layer.json"
    )
    parser.add_argument(
        "--attck-bundle",
        help="Optional path to a local enterprise-attack.json STIX bundle for authoritative technique names"
    )
    parser.add_argument(
        "--attck-version",
        default="19",
        help="ATT&CK version to record in the Navigator layer (default: 19, matching ATTCK_VERSION)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    iocs_path = Path(args.iocs)
    if not iocs_path.exists():
        print(f"Error: normalized IOCs file not found: {iocs_path}")
        sys.exit(1)

    with open(iocs_path) as f:
        normalized = json.load(f)

    family = normalized.get("sample", {}).get("family", "unknown")

    mapped: list = []
    for entry in normalized.get("technique_observations", []):
        technique_id = entry["technique"]
        observations = entry["observations"]
        final, score, static_best, dynamic_best, sources = reconcile(observations)
        name = resolve_technique_name(technique_id, attck_bundle=args.attck_bundle, verbose=args.verbose)
        mapped.append(
            MappedTechnique(
                technique_id=technique_id,
                technique_name=name,
                final_confidence=final,
                confidence_score=score,
                sources=sources,
                static_best_confidence=static_best,
                dynamic_best_confidence=dynamic_best,
                evidence=observations,
            )
        )

    apply_cross_level_corroboration(mapped)

    _TIER_ORDER = {"low": 0, "medium": 1, "high": 2}
    mapped.sort(key=lambda t: (-_TIER_ORDER[t.final_confidence], t.technique_id))

    summary = {
        "total_techniques": len(mapped),
        "high": sum(1 for t in mapped if t.final_confidence == "high"),
        "medium": sum(1 for t in mapped if t.final_confidence == "medium"),
        "low": sum(1 for t in mapped if t.final_confidence == "low"),
        "both_sources": sum(1 for t in mapped if set(t.sources) == {"static", "dynamic"}),
        "static_only": sum(1 for t in mapped if t.sources == ["static"]),
        "dynamic_only": sum(1 for t in mapped if t.sources == ["dynamic"]),
    }

    attck_mapping = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample": normalized.get("sample", {}),
        "iocs": {
            "hashes": normalized.get("hashes", []),
            "network_iocs": normalized.get("network_iocs", {}),
            "host_iocs": normalized.get("host_iocs", {}),
        },
        "confidence_model": {
            "version": CONFIDENCE_MODEL_VERSION,
            "rule": CONFIDENCE_MODEL_RULE,
        },
        "techniques": [t.to_dict() for t in mapped],
        "summary": summary,
    }

    navigator_layer = build_navigator_layer(family, mapped, attck_version=args.attck_version)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    mapping_file = output_dir / "attck_mapping.json"
    with open(mapping_file, "w") as f:
        json.dump(attck_mapping, f, indent=2, default=str)

    layer_file = output_dir / "navigator_layer.json"
    with open(layer_file, "w") as f:
        json.dump(navigator_layer, f, indent=2, default=str)

    print("\n" + "=" * 60)
    print(f"ATT&CK MAPPING COMPLETE: {family}")
    print("=" * 60)
    print(f"Total techniques: {summary['total_techniques']}")
    print(f"  High: {summary['high']}  Medium: {summary['medium']}  Low: {summary['low']}")
    print(f"  Corroborated by both sources: {summary['both_sources']}")
    print(f"  Static only: {summary['static_only']}  Dynamic only: {summary['dynamic_only']}")
    if args.verbose:
        for t in mapped:
            cross_note = f" [cross-level via {t.cross_level_sibling}]" if t.cross_level_corroboration else ""
            print(f"   [{t.final_confidence.upper():6}] {t.technique_id} {t.technique_name} (sources: {', '.join(t.sources)}){cross_note}")
    cross_level_count = sum(1 for t in mapped if t.cross_level_corroboration)
    if cross_level_count:
        print(f"Cross-level corroborated (promoted via a sibling technique): {cross_level_count}")
    print("=" * 60)
    print(f"Mapping saved to: {mapping_file}")
    print(f"Navigator layer saved to: {layer_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
