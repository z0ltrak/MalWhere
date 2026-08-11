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
