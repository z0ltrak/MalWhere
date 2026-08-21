"""Base interface for all static analysis engines."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List, Optional
from ..models.report import StaticReport


class AnalysisEngine(ABC):
    """Base interface for all analysis engines."""

    @abstractmethod
    def analyze(self, file_path: Path, depth: int = 0) -> StaticReport:
        """Analyze a file and return a report.

        Args:
            file_path: Path to the file to analyze.
            depth: Current recursion depth.

        Returns:
            The completed StaticReport.
        """
        pass

    @abstractmethod
    def supports_file(self, file_type: str) -> bool:
        """Check if this engine supports the given file type."""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Get engine name."""
        pass
