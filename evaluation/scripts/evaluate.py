#!/usr/bin/env python3
"""
Pipeline Evaluation for the MalWhere TFM
TFM 2025-2026 - Universidad Complutense de Madrid

Compares the pipeline's automated ATT&CK mappings against manually-
validated ground truth: strict + family-level precision/recall, and a
confidence/source-stratified breakdown that directly tests whether
pipeline/mapper/src/reconcile.py's cross-source confidence reconciliation
actually correlates with correctness.

Manual analysis is the BEST AVAILABLE ground truth here, not a perfect
oracle: an automated finding absent from a manual report may be a genuine
false positive, or something the manual analyst simply didn't write up.
Treat "false positive" counts with that caveat, not as proven errors.
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.matcher import evaluate_sample


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def render_summary_md(all_results: dict) -> str:
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

        result = evaluate_sample(mapping.get("techniques", []), gt.get("techniques", []))
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
    print("=" * 60)
    print(f"Per-sample results: {output_dir}/<family>_evaluation.json")
    print(f"Summary: {summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
