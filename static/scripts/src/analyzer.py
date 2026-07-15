"""Main static analysis orchestrator"""
from pathlib import Path
from typing import Dict, Any, List

from .models.report import (
    StaticReport, SectionInfo, ImportInfo, ExportInfo,
    StringInfo, PackerInfo, IndicatorInfo
)
from .parsers.pe_parser import PEParser
from .parsers.strings_parser import StringsParser
from .parsers.packer_parser import PackerDetector
from .detectors.indicators import IndicatorDetector
from .utils.hashes import HashCalculator


"""Orchestrates the complete static analysis process"""
class StaticAnalyzer:

    def __init__(self, file_path: Path, verbose: bool = False, no_floss: bool = False):
        self.file_path = file_path
        self.verbose = verbose
        self.no_floss = no_floss
        self.errors: List[str] = []

        # Initialize components
        self.pe_parser = PEParser(file_path)
        self.strings_parser = StringsParser(file_path)
        self.packer_detector = PackerDetector(file_path)
        self.indicator_detector = IndicatorDetector()
        self.hash_calculator = HashCalculator()


    """Run complete static analysis"""
    def analyze(self) -> StaticReport:
        self._log(f"Starting static analysis of {self.file_path.name}")

        # File info
        file_info = self._get_file_info()

        # Hashes
        hashes = self.hash_calculator.calculate_all(self.file_path)

        # Parse PE
        pe_data = self.pe_parser.parse()
        self.errors.extend(self.pe_parser.get_errors())

        # Extract strings
        strings = self.strings_parser.extract(include_floss=not self.no_floss)
        self.errors.extend(self.strings_parser.get_errors())

        # Detect packers - first with DIE, then with section info
        packer_data = self.packer_detector.detect()
        self.errors.extend(self.packer_detector.get_errors())

        # If DIE didn't detect anything, try heuristic with sections
        if not packer_data['detected'] and pe_data.get('sections'):
            section_packer = self.packer_detector.detect_with_sections(pe_data['sections'])
            if section_packer['detected']:
                packer_data = section_packer

        # Detect indicators
        sections = pe_data.get('sections', [])
        imports = pe_data.get('imports', [])
        indicators = self.indicator_detector.analyze(imports, sections)

        # Find suspicious strings
        all_strings = strings.get('standard', []) + strings.get('floss', [])
        suspicious_strings = self.strings_parser.find_suspicious(all_strings)

        # Build report
        report = StaticReport(
            filename=self.file_path.name,
            size_bytes=file_info['size_bytes'],
            size_mb=file_info['size_mb'],
            extension=self.file_path.suffix,
            md5=hashes.get('md5', ''),
            sha1=hashes.get('sha1', ''),
            sha256=hashes.get('sha256', ''),
            ssdeep=hashes.get('ssdeep'),
            metadata=pe_data.get('metadata', {}),
            sections=[SectionInfo(**s) for s in pe_data.get('sections', [])],
            imports=[ImportInfo(**i) for i in pe_data.get('imports', [])],
            exports=[ExportInfo(**e) for e in pe_data.get('exports', [])],
            resources=pe_data.get('resources', []),
            strings=StringInfo(**strings),
            packer=PackerInfo(**packer_data),
            indicators=IndicatorInfo(
                suspicious_imports=indicators.get('suspicious_imports', []),
                suspicious_strings=suspicious_strings,
                high_entropy_sections=indicators.get('high_entropy_sections', []),
                anti_debug=indicators.get('anti_debug', []),
                anti_vm=indicators.get('anti_vm', [])
            ),
            errors=self.errors
        )

        self._log("Analysis complete")
        return report


    """Get basic file information"""
    def _get_file_info(self) -> Dict[str, Any]:
        stats = self.file_path.stat()
        return {
            'size_bytes': stats.st_size,
            'size_mb': round(stats.st_size / (1024 * 1024), 2)
        }


    """Print verbose messages"""
    def _log(self, message: str):
        if self.verbose:
            print(f"[*] {message}")
