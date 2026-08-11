"""Thin loaders for static/dynamic report JSON files."""

import json
from pathlib import Path
from typing import Any, Dict, Optional


def load_static_report(path: Path) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def load_dynamic_report(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None:
        return None
    with open(path) as f:
        return json.load(f)
