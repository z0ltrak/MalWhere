"""Groups static + dynamic ATT&CK mapping evidence by technique ID,
filtering out anything that isn't actually a technique ID (e.g. a MITRE
Software ID like "S0105" that static's import-based mapper occasionally
emits alongside real technique IDs).
"""

import re
from typing import Any, Dict, List, Tuple

from .models import DiscardedEntry, Observation, TechniqueObservations

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def group_technique_observations(
    static_report: Dict[str, Any], dynamic_report: Dict[str, Any]
) -> Tuple[List[TechniqueObservations], List[DiscardedEntry]]:
    """Group static + dynamic ATT&CK mappings by technique ID.

    Args:
        static_report: Static analysis report dict, read for its attck_mappings list.
        dynamic_report: Curated dynamic_report.json dict, read for its attck_mappings list.

    Returns:
        A tuple of (technique observations sorted by ID, discarded entries with invalid IDs).
    """
    by_technique: Dict[str, TechniqueObservations] = {}
    discarded: List[DiscardedEntry] = []

    def ingest(mappings: List[Dict[str, Any]], origin: str) -> None:
        """Validate and add each mapping's technique ID to by_technique, or record it as discarded.

        Args:
            mappings: attck_mappings list from a static or dynamic report.
            origin: 'static' or 'dynamic', recorded on each observation/discarded entry.
        """
        for m in mappings:
            technique = m.get("technique", "")
            if not _TECHNIQUE_ID_RE.match(technique):
                discarded.append(
                    DiscardedEntry(
                        reason="invalid_technique_id_format",
                        origin=origin,
                        raw_entry=m,
                    )
                )
                continue
            if technique not in by_technique:
                by_technique[technique] = TechniqueObservations(technique=technique)
            by_technique[technique].observations.append(
                Observation(
                    source=origin,
                    source_type=m.get("source", ""),
                    evidence=m.get("evidence", ""),
                    confidence=m.get("confidence", "low"),
                    name=m.get("name", ""),
                    justification=m.get("justification", ""),
                )
            )

    ingest(static_report.get("attck_mappings", []) or [], "static")
    if dynamic_report is not None:
        ingest(dynamic_report.get("attck_mappings", []) or [], "dynamic")

    # Stable, readable ordering for the output file.
    ordered = sorted(by_technique.values(), key=lambda t: t.technique)
    return ordered, discarded
