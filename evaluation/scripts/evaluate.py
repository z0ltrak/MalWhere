#!/usr/bin/env python3
"""Compares the pipeline's automated ATT&CK mappings against manually-validated ground truth.

Reports strict + family-level precision/recall, and a confidence/source-
stratified breakdown that tests whether reconcile.py's cross-source
confidence reconciliation actually correlates with correctness.

Manual analysis is the best available ground truth here, not a perfect
oracle: an automated finding absent from a manual report may be a genuine
false positive, or something the manual analyst didn't write up.
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).parent))
from src.matcher import evaluate_sample


def load_json(path: Path) -> dict:
    """Load and parse a JSON file.

    Args:
        path: Path to the JSON file.

    Returns:
        The parsed JSON content.
    """
    with open(path) as f:
        return json.load(f)


def load_family_total_techniques(results_dir: Path, family: str, parent_techniques: list) -> list:
    """Parent techniques plus every resubmitted (dropped/extracted) file's own techniques, pooled together.

    Ground truth is built from a manual RE report covering the whole
    sample, every dropped component, not just the outermost binary -- so
    parent-only recall structurally understates what the pipeline as a
    whole (including the resubmission loop) actually found. A dropped
    payload's own findings are deliberately kept out of the parent's own
    scored attck_mapping.json (blending them in would misattribute
    confidence to the wrong binary, and STIX/MISP should never claim a
    dropped payload's behavior is the parent's own) -- this pools
    everything for evaluation purposes only, never touching
    results/<family>/attck/attck_mapping.json itself.

    Args:
        results_dir: Base results directory to look for resubmitted/ under.
        family: Family label to pool resubmitted techniques for.
        parent_techniques: The parent sample's own reconciled technique list.

    Returns:
        parent_techniques plus every resubmitted file's techniques,
        deduplicated by technique_id keeping the highest-confidence occurrence.
    """
    pooled = list(parent_techniques)
    resubmitted_dir = results_dir / family / "resubmitted"
    if resubmitted_dir.is_dir():
        for sample_dir in sorted(resubmitted_dir.iterdir()):
            mapping_file = sample_dir / "attck" / "attck_mapping.json"
            if mapping_file.exists():
                child_mapping = load_json(mapping_file)
                pooled.extend(child_mapping.get("techniques", []))

    # Collapse to one entry per technique_id, keeping the highest-
    # confidence occurrence: matching counts by instance, not unique ID,
    # and a technique can legitimately show up in most of two dozen
    # resubmitted files independently, which would otherwise inflate
    # both tp and fp by instance count.
    _TIER_RANK = {"high": 2, "medium": 1, "low": 0}
    best_by_id: Dict[str, Any] = {}
    for t in pooled:
        tid = t["technique_id"]
        existing = best_by_id.get(tid)
        if existing is None or _TIER_RANK.get(t.get("final_confidence"), -1) > _TIER_RANK.get(existing.get("final_confidence"), -1):
            best_by_id[tid] = t

    return list(best_by_id.values())


def render_summary_md(all_results: dict) -> str:
    """Render the per-family evaluation results as a Markdown summary report.

    Args:
        all_results: Per-family evaluation dicts, as produced by evaluate_sample.

    Returns:
        The rendered summary.md content.
    """
    lines = [
        "# MalWhere Pipeline Evaluation",
        "",
        "Automated ATT&CK mappings (`pipeline/mapper/map_attck.py`) compared against",
        "manually-validated ground truth (`manual_analysis/*/manual_*_report.md`).",
        "",
        "> Manual analysis is the best available ground truth, not a perfect oracle —",
        "> an automated finding absent from a manual report may be a genuine false",
        "> positive, or simply something the manual analyst didn't write up.",
        ">",
        "> **Ground truth methodology**: these are comprehensive manual reverse-engineering",
        "> reports (function-by-function Ghidra tracing, each key behavior individually",
        "> verified — see each report's own Validation Summary), not superficial",
        "> import/string scanning. Code-path verification of this depth captures full",
        "> functional capability regardless of whether a given branch happens to fire",
        "> during any one sandbox run — in that sense it's broader than a single dynamic",
        "> execution, not narrower. The honest caveat is different: it's inference from",
        "> code, not an empirical observation of the sample actually running (Akira's own",
        "> report explicitly notes \"no dynamic analysis performed\" as a limitation), so",
        "> environment/timing-dependent runtime specifics (e.g. which C2 response a live",
        "> run happened to receive) can still differ from what any single CAPE detonation",
        "> observed.",
        "",
        "## Precision / Recall / F1",
        "",
        "> \"Sample\" rows score `results/<family>/attck/attck_mapping.json` alone --",
        "> the parent binary's own confidence-scored findings, which is also what gets",
        "> exported to STIX/MISP. \"Sample + resubmitted\" rows additionally pool in",
        "> every dropped/extracted component's own attck_mapping.json (see",
        "> `static/scripts/process_resubmissions.py`) purely for measuring against",
        "> ground truth, which is written from a manual report covering the whole",
        "> infection chain -- this number is never fed back into the exported bundle,",
        "> only shown here so recall isn't understated for multi-stage samples.",
        "",
        "| Sample | Auto | GT | Strict P | Strict R | Strict F1 | Family P | Family R | Family F1 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for family, r in all_results.items():
        c = r["counts"]
        s = r["strict"]
        fam = r["family_level"]
        lines.append(
            f"| {family} | {c['automated']} | {c['ground_truth']} | "
            f"{s['precision']:.2f} | {s['recall']:.2f} | {s['f1']:.2f} | "
            f"{fam['precision']:.2f} | {fam['recall']:.2f} | {fam['f1']:.2f} |"
        )
        ft = r.get("family_total")
        if ft:
            c2, s2, fam2 = ft["counts"], ft["strict"], ft["family_level"]
            lines.append(
                f"| {family} + resubmitted | {c2['automated']} | {c2['ground_truth']} | "
                f"{s2['precision']:.2f} | {s2['recall']:.2f} | {s2['f1']:.2f} | "
                f"{fam2['precision']:.2f} | {fam2['recall']:.2f} | {fam2['f1']:.2f} |"
            )

    lines += ["", "## Precision by confidence tier (family-level match)", ""]
    for family, r in all_results.items():
        lines.append(f"**{family}**")
        lines.append("")
        lines.append("| Tier | Count | TP | FP | Precision |")
        lines.append("|---|---|---|---|---|")
        for tier in ("high", "medium", "low"):
            b = r["precision_by_confidence"].get(tier)
            if b:
                lines.append(f"| {tier} | {b['count']} | {b['tp']} | {b['fp']} | {b['precision']:.2f} |")
        lines.append("")

    lines += ["## Precision by source agreement (family-level match)", ""]
    for family, r in all_results.items():
        lines.append(f"**{family}**")
        lines.append("")
        lines.append("| Sources | Count | TP | FP | Precision |")
        lines.append("|---|---|---|---|---|")
        for key, b in sorted(r["precision_by_source"].items()):
            lines.append(f"| {key} | {b['count']} | {b['tp']} | {b['fp']} | {b['precision']:.2f} |")
        lines.append("")

    return "\n".join(lines)


def main():
    """Evaluate every family with a ground truth file against its automated ATT&CK mapping, writing per-sample JSON and a summary.md.

    Returns:
        Process exit code (always 0; failures exit early via sys.exit).
    """
    parser = argparse.ArgumentParser(
        description="Pipeline Evaluation for the MalWhere TFM"
    )
    parser.add_argument(
        "--ground-truth", "-g",
        required=True,
        help="Directory containing <family>.json ground truth files"
    )
    parser.add_argument(
        "--results", "-r",
        required=True,
        help="Directory containing <family>/attck/attck_mapping.json (the pipeline's results/ dir)"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output directory for per-sample evaluation JSON and summary.md"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    ground_truth_dir = Path(args.ground_truth)
    results_dir = Path(args.results)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    gt_files = sorted(ground_truth_dir.glob("*.json"))
    if not gt_files:
        print(f"Error: no ground truth files found in {ground_truth_dir}")
        sys.exit(1)

    all_results = {}
    for gt_file in gt_files:
        family = gt_file.stem
        mapping_file = results_dir / family / "attck" / "attck_mapping.json"
        if not mapping_file.exists():
            print(f"Warning: no automated mapping found for {family} ({mapping_file}), skipping")
            continue

        if args.verbose:
            print(f"Evaluating {family}...")

        gt = load_json(gt_file)
        mapping = load_json(mapping_file)
        parent_techniques = mapping.get("techniques", [])

        result = evaluate_sample(parent_techniques, gt.get("techniques", []))

        family_total_techniques = load_family_total_techniques(results_dir, family, parent_techniques)
        if len(family_total_techniques) > len(parent_techniques):
            result["family_total"] = evaluate_sample(family_total_techniques, gt.get("techniques", []))

        all_results[family] = result

        with open(output_dir / f"{family}_evaluation.json", "w") as f:
            json.dump(result, f, indent=2)

    if not all_results:
        print("Error: no samples were evaluated (no matching automated mappings found)")
        sys.exit(1)

    summary_md = render_summary_md(all_results)
    summary_path = output_dir / "summary.md"
    with open(summary_path, "w") as f:
        f.write(summary_md)

    print("\n" + "=" * 60)
    print("EVALUATION COMPLETE")
    print("=" * 60)
    for family, r in all_results.items():
        s, fam = r["strict"], r["family_level"]
        print(f"{family}: strict P/R/F1 = {s['precision']:.2f}/{s['recall']:.2f}/{s['f1']:.2f}  "
              f"family P/R/F1 = {fam['precision']:.2f}/{fam['recall']:.2f}/{fam['f1']:.2f}")
        if args.verbose:
            print(f"  missed (family-level): {fam['missed_techniques']}")
            print(f"  false positives (family-level): {fam['false_positive_techniques']}")
        ft = r.get("family_total")
        if ft:
            s2, fam2 = ft["strict"], ft["family_level"]
            print(f"{family} + resubmitted: strict P/R/F1 = {s2['precision']:.2f}/{s2['recall']:.2f}/{s2['f1']:.2f}  "
                  f"family P/R/F1 = {fam2['precision']:.2f}/{fam2['recall']:.2f}/{fam2['f1']:.2f}")
            if args.verbose:
                print(f"  missed (family-level): {fam2['missed_techniques']}")
                print(f"  false positives (family-level): {fam2['false_positive_techniques']}")
    print("=" * 60)
    print(f"Per-sample results: {output_dir}/<family>_evaluation.json")
    print(f"Summary: {summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
