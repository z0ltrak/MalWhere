"""Main static analysis orchestrator."""

from pathlib import Path
from typing import Dict, Any, List

from .models.report import (
    StaticReport,
    SectionInfo,
    ImportInfo,
    ExportInfo,
    StringInfo,
    PackerInfo,
    IndicatorInfo,
    YaraResult
)
from .parsers.pe_parser import PEParser
from .parsers.strings_parser import StringsParser
from .parsers.packer_parser import PackerDetector
from .parsers.config_parser import ConfigExtractor
from .parsers.yara_parser import YaraParser
from .detectors.indicators import IndicatorDetector
from .utils.hashes import HashCalculator


class StaticAnalyzer:
    """Orchestrates the complete static analysis process."""

    def __init__(self, file_path: Path, verbose: bool = False, no_floss: bool = False):
        """
        Initialize the static analyzer.

        Args:
            file_path: Path to the sample file
            verbose: Enable verbose output
            no_floss: Skip FLOSS extraction
        """
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
        self.config_extractor = ConfigExtractor(file_path)
        self.yara_parser = YaraParser(file_path)

    def analyze(self) -> StaticReport:
        """Run complete static analysis and return a report."""
        self._log(f"Starting static analysis of {self.file_path.name}")

        # File info
        file_info = self._get_file_info()

        # Parse PE
        pe_data = self.pe_parser.parse()
        self.errors.extend(self.pe_parser.get_errors())

        # Hashes
        hashes = self.hash_calculator.calculate_all(self.file_path)

        # Calculate imphash if PE is valid
        imphash = None
        if self.pe_parser.pe:
            imphash = self.hash_calculator.calculate_imphash(self.pe_parser.pe)

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
        all_strings = strings.get('standard', []) + strings.get('floss', [])

        # Pass strings to indicator detector for all indicators
        indicators = self.indicator_detector.analyze(imports, sections, all_strings)

        suspicious_strings = self.strings_parser.find_suspicious(all_strings)

        # Extract configuration
        config_data = self.config_extractor.extract()
        self.errors.extend(self.config_extractor.get_errors())

        # YARA scan
        yara_data = self.yara_parser.scan()
        self.errors.extend(self.yara_parser.get_errors())

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
            tlsh=hashes.get('tlsh'),
            imphash=imphash,
            is_dotnet=pe_data.get('is_dotnet', False),
            metadata=pe_data.get('metadata', {}),
            sections=sections,
            imports=imports,
            exports=pe_data.get('exports', []),
            resources=pe_data.get('resources', []),
            strings=StringInfo(**strings),
            packer=PackerInfo(**packer_data),
            indicators=IndicatorInfo(
                suspicious_imports=indicators.get('suspicious_imports', []),
                suspicious_strings=suspicious_strings,
                high_entropy_sections=indicators.get('high_entropy_sections', []),
                anti_debug=indicators.get('anti_debug', []),
                anti_vm=indicators.get('anti_vm', []),
                ransomware_indicators=indicators.get('ransomware_indicators', []),
                anti_sandbox=indicators.get('anti_sandbox', []),
                anti_vm_strings=indicators.get('anti_vm_strings', []),
                anti_sandbox_strings=indicators.get('anti_sandbox_strings', []),
                sleep_functions=indicators.get('sleep_functions', [])
            ),
            yara=YaraResult(
                matches=yara_data.get('matches', []),
                matched_rules=yara_data.get('matched_rules', []),
                packer_detected=yara_data.get('packer_detected', False),
                packers=yara_data.get('packers', []),
                attck_mapping=yara_data.get('attck_mapping', [])
            ),
            config=config_data,
            errors=self.errors
        )

        self._log("Analysis complete")
        return report

    def _get_file_info(self) -> Dict[str, Any]:
        """Get basic file information from the filesystem."""
        stats = self.file_path.stat()
        return {
            'size_bytes': stats.st_size,
            'size_mb': round(stats.st_size / (1024 * 1024), 2)
        }

    def _log(self, message: str):
        """Print verbose messages if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {message}")
