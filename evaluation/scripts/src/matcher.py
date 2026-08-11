"""Compares automated ATT&CK mappings against manually-validated ground
truth, in two matching modes, plus confidence/source-stratified precision
to directly test whether pipeline/mapper/src/reconcile.py's cross-source
confidence reconciliation actually correlates with correctness.
"""

from typing import Any, Dict, List, Tuple


def base_technique(technique_id: str) -> str:
    """Strips the sub-technique suffix: T1071.001 -> T1071."""
    return technique_id.split(".")[0]


def _prf1(tp: int, fp: int, fn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def _match_mode(auto: List[Dict[str, Any]], gt: List[Dict[str, Any]], strict: bool) -> Dict[str, Any]:
    if strict:
        auto_key = lambda t: t["technique_id"]  # noqa: E731
        gt_key = lambda t: t["technique_id"]  # noqa: E731
    else:
        auto_key = lambda t: base_technique(t["technique_id"])  # noqa: E731
        gt_key = lambda t: base_technique(t["technique_id"])  # noqa: E731

    gt_keys = {gt_key(t) for t in gt}
    auto_keys = {auto_key(t) for t in auto}

    auto_matched = [t for t in auto if auto_key(t) in gt_keys]
    auto_unmatched = [t for t in auto if auto_key(t) not in gt_keys]
    gt_matched = [t for t in gt if gt_key(t) in auto_keys]
    gt_unmatched = [t for t in gt if gt_key(t) not in auto_keys]

    tp_for_precision = len(auto_matched)
    fp = len(auto_unmatched)
    tp_for_recall = len(gt_matched)
    fn = len(gt_unmatched)

    metrics = _prf1(tp_for_precision, fp, fn)
    # Recall needs its own TP count (from the ground-truth side) since
    # matching isn't guaranteed to be a strict 1:1 bijection in family
    # mode; only override recall here, precision/f1 above already used
    # the precision-side TP correctly.
    metrics["recall"] = round(tp_for_recall / (tp_for_recall + fn), 4) if (tp_for_recall + fn) else 0.0
    if metrics["precision"] + metrics["recall"]:
        metrics["f1"] = round(2 * metrics["precision"] * metrics["recall"] / (metrics["precision"] + metrics["recall"]), 4)

    return {
        "tp": tp_for_precision,
        "fp": fp,
        "fn": fn,
        "gt_matched_count": tp_for_recall,
        **metrics,
        "matched_techniques": [t["technique_id"] for t in auto_matched],
        "false_positive_techniques": [t["technique_id"] for t in auto_unmatched],
        "missed_techniques": [t["technique_id"] for t in gt_unmatched],
    }


def evaluate_sample(auto_techniques: List[Dict[str, Any]], gt_techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
    strict = _match_mode(auto_techniques, gt_techniques, strict=True)
    family = _match_mode(auto_techniques, gt_techniques, strict=False)

    gt_base_keys = {base_technique(t["technique_id"]) for t in gt_techniques}

    def stratify(group_fn) -> Dict[str, Dict[str, Any]]:
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for t in auto_techniques:
            key = group_fn(t)
            groups.setdefault(key, []).append(t)
        result = {}
        for key, items in groups.items():
            tp = sum(1 for t in items if base_technique(t["technique_id"]) in gt_base_keys)
            fp = len(items) - tp
            result[key] = {
                "count": len(items),
                "tp": tp,
                "fp": fp,
                "precision": round(tp / len(items), 4) if items else 0.0,
            }
        return result

    by_confidence = stratify(lambda t: t.get("final_confidence", "unknown"))
    by_source = stratify(lambda t: "+".join(sorted(t.get("sources", []))) or "unknown")

    return {
        "counts": {"automated": len(auto_techniques), "ground_truth": len(gt_techniques)},
        "strict": strict,
        "family_level": family,
        "precision_by_confidence": by_confidence,
        "precision_by_source": by_source,
    }
