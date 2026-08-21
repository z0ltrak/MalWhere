"""Per-finding confidence bucketing for CAPE signature matches."""

_TIER_ORDER = {"low": 0, "medium": 1, "high": 2}


def bucket_confidence(severity: int, confidence_pct: int) -> str:
    """Bucket a CAPE signature match into high/medium/low.

    CAPE signatures carry two independent quality signals: severity
    (author-assigned criticality) and confidence (per-signature detection
    confidence %). Taking the weaker of the two is the same conservative
    philosophy static/scripts/src/detectors/attck_mapper.py already applies
    (a single weak match stays low-confidence even if the technique itself
    sounds severe).

    Args:
        severity: CAPE signature severity (1-3+).
        confidence_pct: CAPE signature confidence percentage (0-100).

    Returns:
        'high', 'medium', or 'low' -- the weaker of the two input tiers.
    """
    severity_tier = "high" if severity >= 3 else "medium" if severity == 2 else "low"
    confidence_tier = "high" if confidence_pct >= 80 else "medium" if confidence_pct >= 50 else "low"
    return min(severity_tier, confidence_tier, key=_TIER_ORDER.get)
