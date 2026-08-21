"""Thin loaders for static/dynamic report JSON files."""

import json
from pathlib import Path
from typing import Any, Dict, Optional


def load_static_report(path: Path) -> Dict[str, Any]:
    """Load a static analysis report JSON file.

    Args:
        path: Path to the static report.

    Returns:
        The parsed report.
    """
    with open(path) as f:
        return json.load(f)


def load_dynamic_report(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    """Load a dynamic_report.json file.

    Args:
        path: Path to the dynamic report, or None if dynamic analysis was skipped.

    Returns:
        The parsed report, or None if path was None.
    """
    if path is None:
        return None
    with open(path) as f:
        return json.load(f)
