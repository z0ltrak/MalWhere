"""Fallback .NET analysis engine using ILSpy, with a pure-Python fallback."""

import subprocess
import json
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from .base_engine import AnalysisEngine
from ..models.report import StaticReport, StringInfo


class DotNetEngine(AnalysisEngine):
    """.NET analysis using ILSpy/dnSpy."""

    SUPPORTED_TYPES = ['pe_dotnet']

    def __init__(self, verbose: bool = False, timeout: int = 300):
        """Initialize the engine and locate the ilspycmd binary, if installed.

        Args:
            verbose: Enable verbose progress logging.
            timeout: Timeout in seconds for the ilspycmd subprocess.
        """
        self.verbose = verbose
        self.timeout = timeout
        self.errors: List[str] = []
        self.ilspy_bin = shutil.which('ilspycmd')

    def supports_file(self, file_type: str) -> bool:
        """Check if this engine supports the given file type.

        Args:
            file_type: Detected file type string.

        Returns:
            True if file_type is in SUPPORTED_TYPES.
        """
        return file_type in self.SUPPORTED_TYPES

    def get_name(self) -> str:
        return ".NET (ILSpy)"

    def analyze(self, file_path: Path, depth: int = 0) -> StaticReport:
        """Run ILSpy analysis on a .NET assembly, falling back to pure-Python analysis if ILSpy isn't installed.

        Args:
            file_path: Path to the .NET assembly to analyze.
            depth: Current recursion depth (unused; accepted for AnalysisEngine interface consistency).

        Returns:
            The completed StaticReport, tagged is_dotnet=True.
        """
        self._log(f"Analyzing .NET assembly: {file_path.name}")

        report = self._create_empty_report(file_path)

        if self.ilspy_bin:
            report = self._analyze_with_ilspy(file_path)
        else:
            self.errors.append("ILSpy not installed, using fallback")
            report = self._analyze_with_fallback(file_path)

        report.is_dotnet = True
        report.file_type = 'pe_dotnet'

        return report

    def _analyze_with_ilspy(self, file_path: Path) -> StaticReport:
        """Run the ilspycmd subprocess and build a report from its output.

        Args:
            file_path: Path to the .NET assembly to analyze.

        Returns:
            A StaticReport built from ILSpy's JSON (or text, as fallback) output,
            or an empty report tagged with an error if ILSpy failed.
        """
        try:
            cmd = [
                self.ilspy_bin,
                '-p', '-t', '-h', '-j',  # parameters, types, hidden members, JSON output
                str(file_path)
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if proc.returncode == 0 and proc.stdout:
                try:
                    data = json.loads(proc.stdout)
                    return self._build_report_from_ilspy(file_path, data)
                except json.JSONDecodeError:
                    return self._parse_ilspy_text(file_path, proc.stdout)

        except Exception as e:
            self.errors.append(f"ILSpy error: {e}")

        return self._create_empty_report(file_path, "ILSpy analysis failed")

    def _build_report_from_ilspy(self, file_path: Path, data: Dict) -> StaticReport:
        """Build a StaticReport from ILSpy's parsed JSON output.

        Args:
            file_path: Path to the analyzed assembly, for basic file info.
            data: Parsed ILSpy JSON output.

        Returns:
            A StaticReport with type/method-derived strings and a suspicious-pattern subset.
        """
        from ..models.report import StaticReport, StringInfo

        strings = []
        types = data.get('types', [])

        for t in types:
            strings.append(t.get('name', ''))

            for method in t.get('methods', []):
                strings.append(method.get('name', ''))

                body = method.get('body', '')
                if body:
                    import re
                    for match in re.finditer(r'"([^"]+)"', body):
                        s = match.group(1)
                        if len(s) >= 4:
                            strings.append(s)

        suspicious_patterns = [
            'ransom', 'encrypt', 'decrypt', 'xor', 'base64',
            'http', 'https', 'socket', 'connect',
            'process', 'inject', 'create', 'terminate',
            'registry', 'key', 'value'
        ]

        suspicious = [s for s in strings if any(p in s.lower() for p in suspicious_patterns)]

        return StaticReport(
            filename=file_path.name,
            size_bytes=file_path.stat().st_size,
            size_mb=file_path.stat().st_size / (1024 * 1024),
            extension=file_path.suffix,
            file_type='pe_dotnet',
            file_type_info={'analyzer': 'ilspy'},
            strings=StringInfo(standard=strings[:5000]),
            indicators=suspicious[:100]
        )

    def _parse_ilspy_text(self, file_path: Path, text: str) -> StaticReport:
        """Parse ILSpy's plain-text output as a fallback when JSON parsing fails.

        Args:
            file_path: Path to the analyzed assembly, for basic file info.
            text: Raw ILSpy stdout.

        Returns:
            A StaticReport with string literals extracted from the text output.
        """
        strings = []
        lines = text.split('\n')

        for line in lines:
            import re
            matches = re.findall(r'"([^"]+)"', line)
            for s in matches:
                if len(s) >= 4 and not s.isdigit():
                    strings.append(s)

        return StaticReport(
            filename=file_path.name,
            size_bytes=file_path.stat().st_size,
            size_mb=file_path.stat().st_size / (1024 * 1024),
            extension=file_path.suffix,
            file_type='pe_dotnet',
            file_type_info={'analyzer': 'ilspy_text'},
            strings=StringInfo(standard=strings[:5000])
        )

    def _analyze_with_fallback(self, file_path: Path) -> StaticReport:
        """Fall back to the pure-Python PE/strings parsers when ILSpy isn't installed.

        Args:
            file_path: Path to the .NET assembly to analyze.

        Returns:
            A StaticReport built from PEParser + StringsParser output.
        """
        from ..parsers.pe_parser import PEParser
        from ..parsers.strings_parser import StringsParser

        pe_parser = PEParser(file_path)
        pe_data = pe_parser.parse()

        strings_parser = StringsParser(file_path)
        strings = strings_parser.extract(include_floss=False)

        return StaticReport(
            filename=file_path.name,
            size_bytes=file_path.stat().st_size,
            size_mb=file_path.stat().st_size / (1024 * 1024),
            extension=file_path.suffix,
            file_type='pe_dotnet',
            file_type_info={'analyzer': 'fallback'},
            strings=StringInfo(standard=strings.get('standard', [])),
            imports=pe_data.get('imports', []),
            is_dotnet=True
        )

    def _create_empty_report(self, file_path: Path, error: str = "") -> StaticReport:
        """Build a minimal StaticReport carrying only basic file info and an optional error.

        Args:
            file_path: Path to the file, for basic file info.
            error: Error message to record, if any.

        Returns:
            A StaticReport with file_type='pe_dotnet' and no analysis content.
        """
        from ..models.report import StaticReport
        return StaticReport(
            filename=file_path.name,
            size_bytes=file_path.stat().st_size,
            size_mb=file_path.stat().st_size / (1024 * 1024),
            extension=file_path.suffix,
            file_type='pe_dotnet',
            errors=[error] if error else []
        )

    def _log(self, message: str):
        if self.verbose:
            print(f"[*] {self.get_name()}: {message}")
