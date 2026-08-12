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
    """Strips the sub-technique suffix: T1547.001 -> T1547. Same definition
    evaluation/scripts/src/matcher.py already uses for family-level
    matching -- apply_cross_level_corroboration below extends that same
    principle into the confidence model itself, not just evaluation.
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
    tiers = [o["confidence"] for o in observations if o["source"] == source]
    if not tiers:
        return None
    return max(tiers, key=_TIER_ORDER.get)


def reconcile(observations: List[Dict[str, Any]]) -> Tuple[str, int, Optional[str], Optional[str], List[str]]:
    """Returns (final_confidence, confidence_score, static_best, dynamic_best, sources)."""
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
    present = [t for t in tiers if t is not None]
    if not present:
        return None
    return max(present, key=_TIER_ORDER.get)


def apply_cross_level_corroboration(mapped: List[Any]) -> None:
    """Mutates `mapped` (a list of MappedTechnique) in place.

    reconcile() above only ever sees observations tagged with ONE exact
    technique_id -- a dynamic signature reporting the parent T1547 and a
    static import rule reporting the specific T1547.001 for what is
    clearly the same real persistence mechanism never corroborate each
    other, because they're grouped into two entirely separate
    TechniqueObservations upstream (technique_grouper.py groups by exact
    ID string). evaluation/scripts/src/matcher.py already treats T1547
    and T1547.001 as equivalent for scoring against ground truth (its own
    base_technique() helper) -- this brings the confidence model itself
    into line with that same principle, rather than leaving an
    inconsistency between how a technique is scored and how it's
    evaluated.

    For each base-technique group (siblings under the same parent ID)
    where the group's own static_best/dynamic_best cover BOTH sources
    somewhere among its members, any individual member missing one side
    gets that side's group-best borrowed in and final_confidence
    recomputed with the same "high unless both low" rule reconcile() uses
    -- never invented, always traceable to a real sibling technique's own
    observations, and only ever applied when it actually changes the
    verdict (an entry already independently high stays as it was, not
    re-labeled as cross-level-corroborated when it didn't need to be).
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
