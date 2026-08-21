"""Cross-source ATT&CK confidence reconciliation.

The core methodological contribution described in the project README: a
technique observed independently by BOTH static and dynamic analysis is
stronger evidence than either source alone, because a coincidental
false-positive hit on the *same* technique from two structurally different
detection mechanisms is unlikely. This extends (does not replace) the
existing per-finding tier system each source already applies.
"""

from typing import Any, Dict, List, Optional, Tuple

_TIER_ORDER = {"low": 0, "medium": 1, "high": 2}
_TIER_SCORE = {"high": 100, "medium": 60, "low": 30}


def base_technique(technique_id: str) -> str:
    """Strips the sub-technique suffix: T1547.001 -> T1547.

    Same definition evaluation/scripts/src/matcher.py uses for family-
    level matching; apply_cross_level_corroboration below extends that
    principle into the confidence model itself.

    Args:
        technique_id: A technique ID, with or without a sub-technique suffix.

    Returns:
        The base (parent) technique ID.
    """
    return technique_id.split(".")[0]

CONFIDENCE_MODEL_VERSION = "1.0"
CONFIDENCE_MODEL_RULE = (
    "Technique observed by BOTH static and dynamic evidence -> High, unless "
    "both sources' best individual confidence is Low -> Medium. Technique "
    "observed by a single source retains that source's own best per-finding "
    "confidence tier unchanged (cannot be promoted by a single source alone)."
)


def _best(observations: List[Dict[str, Any]], source: str) -> Optional[str]:
    """Get the highest confidence tier among one source's observations.

    Args:
        observations: Per-finding observations, each with 'source' and 'confidence'.
        source: Source to filter to ('static' or 'dynamic').

    Returns:
        The best tier ('high'/'medium'/'low'), or None if source has no observations.
    """
    tiers = [o["confidence"] for o in observations if o["source"] == source]
    if not tiers:
        return None
    return max(tiers, key=_TIER_ORDER.get)


def reconcile(observations: List[Dict[str, Any]]) -> Tuple[str, int, Optional[str], Optional[str], List[str]]:
    """Reconcile one technique's static+dynamic observations into a final confidence tier.

    Args:
        observations: Per-finding observations, each with 'source' and 'confidence'.

    Returns:
        (final_confidence, confidence_score, static_best, dynamic_best, sources).
    """
    static_best = _best(observations, "static")
    dynamic_best = _best(observations, "dynamic")
    sources = sorted({o["source"] for o in observations})

    if static_best is not None and dynamic_best is not None:
        final = "high" if (static_best != "low" or dynamic_best != "low") else "medium"
    elif static_best is not None:
        final = static_best
    else:
        final = dynamic_best or "low"

    return final, _TIER_SCORE[final], static_best, dynamic_best, sources


def _group_best_tier(tiers: List[Optional[str]]) -> Optional[str]:
    """Get the highest confidence tier among a sibling group's per-member tiers.

    Args:
        tiers: Each sibling's static_best_confidence or dynamic_best_confidence (may include None).

    Returns:
        The best non-None tier, or None if all are None.
    """
    present = [t for t in tiers if t is not None]
    if not present:
        return None
    return max(present, key=_TIER_ORDER.get)


def apply_cross_level_corroboration(mapped: List[Any]) -> None:
    """Mutate `mapped` (a list of MappedTechnique) in place, promoting siblings that jointly cover both sources.

    reconcile() above only sees observations tagged with one exact
    technique_id, so a dynamic signature reporting parent T1547 and a
    static rule reporting sub-technique T1547.001 for the same real
    mechanism never corroborate each other (technique_grouper.py groups
    by exact ID string upstream). matcher.py already treats T1547 and
    T1547.001 as equivalent for scoring against ground truth; this brings
    the confidence model itself into line with that same principle.

    For each base-technique group (siblings under the same parent ID)
    where static_best/dynamic_best jointly cover both sources somewhere
    among its members, any individual member missing one side borrows
    that side's group-best and recomputes final_confidence with
    reconcile()'s "high unless both low" rule -- never invented, always
    traceable to a real sibling's own observations, and only applied
    when it actually changes the verdict.
    """
    groups: Dict[str, List[Any]] = {}
    for t in mapped:
        groups.setdefault(base_technique(t.technique_id), []).append(t)

    for base, group in groups.items():
        if len(group) < 2:
            continue
        group_static_best = _group_best_tier([t.static_best_confidence for t in group])
        group_dynamic_best = _group_best_tier([t.dynamic_best_confidence for t in group])
        if group_static_best is None or group_dynamic_best is None:
            continue  # group doesn't have both sources represented anywhere

        for t in group:
            if t.static_best_confidence is not None and t.dynamic_best_confidence is not None:
                continue  # already directly corroborated at its own exact ID
            effective_static = t.static_best_confidence or group_static_best
            effective_dynamic = t.dynamic_best_confidence or group_dynamic_best
            new_final = "high" if (effective_static != "low" or effective_dynamic != "low") else "medium"
            if _TIER_ORDER[new_final] > _TIER_ORDER[t.final_confidence]:
                sibling = next(
                    (s.technique_id for s in group
                     if s is not t and (
                         (t.static_best_confidence is None and s.static_best_confidence is not None)
                         or (t.dynamic_best_confidence is None and s.dynamic_best_confidence is not None)
                     )),
                    None,
                )
                t.final_confidence = new_final
                t.confidence_score = _TIER_SCORE[new_final]
                t.cross_level_corroboration = True
                t.cross_level_sibling = sibling
