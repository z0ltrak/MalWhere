"""Extracts the ATT&CK technique table from a manual static-analysis
report (Markdown) into structured ground truth.

Confirmed against all 3 real reports in manual_analysis/: the heading text
varies ("Summary of ATT&CK Techniques" vs "ATT&CK Techniques") but always
matches `## ... ATT&CK Techni...`, and the table is always
`| Technique | ID | Implementation |` — including bold `**Technique**`
cells (WhiteSnake's report), which a naive per-column split regex misses;
matching directly on the ID column position handles both.
"""

import re
from typing import Any, Dict, List

_SECTION_HEADING_RE = re.compile(r"^## .*ATT&CK Techni.*$", re.MULTILINE)
_TABLE_ROW_RE = re.compile(
    r"^\|\s*(?P<name>.+?)\s*\|\s*(?P<id>T\d{4}(?:\.\d{3})?)\s*\|\s*(?P<evidence>.+?)\s*\|$",
    re.MULTILINE,
)


def _strip_markdown_bold(text: str) -> str:
    """Remove Markdown bold markers and surrounding whitespace.

    Args:
        text: Text to clean.

    Returns:
        text with '**' removed and stripped.
    """
    return text.replace("**", "").strip()


def extract_ground_truth(markdown_text: str, family: str, source_report: str) -> Dict[str, Any]:
    """Parse the ATT&CK Techniques table out of a manual analysis report.

    Args:
        markdown_text: Full text of the manual report.
        family: Family label to attach to the result.
        source_report: Path or name of the source report, for error messages and provenance.

    Returns:
        Dict with family, source_report, techniques[], and duplicate_rows_collapsed.
    """
    heading_match = _SECTION_HEADING_RE.search(markdown_text)
    if not heading_match:
        raise ValueError(f"No ATT&CK techniques section found in {source_report}")

    section = markdown_text[heading_match.end():]
    next_heading = re.search(r"\n## ", section)
    if next_heading:
        section = section[: next_heading.start()]

    rows = _TABLE_ROW_RE.findall(section)
    # First row after the heading is the "|-----|-----|" separator, which
    # _TABLE_ROW_RE won't match (no T#### in it) — no special-casing needed,
    # it's just naturally skipped.

    seen: Dict[str, Dict[str, Any]] = {}
    duplicate_count = 0
    for name, technique_id, evidence in rows:
        if technique_id in seen:
            duplicate_count += 1
            continue
        seen[technique_id] = {
            "technique_id": technique_id,
            "name": _strip_markdown_bold(name),
            "evidence": _strip_markdown_bold(evidence),
        }

    techniques: List[Dict[str, Any]] = sorted(seen.values(), key=lambda t: t["technique_id"])

    return {
        "family": family,
        "source_report": source_report,
        "techniques": techniques,
        "duplicate_rows_collapsed": duplicate_count,
    }
