"""Fallback engine that uses Python-based analysis when Ghidra or other specialized engines aren't available."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Optional
import hashlib

from .base_engine import AnalysisEngine
from ..models.report import (
    StaticReport,
    SectionInfo,
    ImportInfo,
    ExportInfo,
    StringInfo,
    PackerInfo,
    IndicatorInfo,
    YaraResult,
    EntropyAnalysis,
    ATTACKMapping
)
from ..parsers.pe_parser import PEParser
from ..parsers.elf_parser import ELFParser
from ..parsers.strings_parser import StringsParser
from ..parsers.packer_parser import PackerDetector
from ..parsers.config_parser import ConfigExtractor
from ..parsers.yara_parser import YaraParser
from ..parsers.magic_carver import MagicCarver
from ..parsers.key_reconstructor import KeyReconstructor
from ..parsers.zlib_parser import ZlibParser
from ..detectors.indicators import IndicatorDetector
from ..detectors.entropy_detector import EntropyDetector
from ..detectors.attck_mapper import ATTACKMapper
from ..detectors.crypto_detector import CryptoDetector
from ..utils.hashes import HashCalculator


class PythonEngine(AnalysisEngine):
    """Fallback static analysis engine using Python libraries (pefile, strings, YARA, etc.)."""

    SUPPORTED_TYPES = [
        'pe_native',
        'pe_file',
        'pe_dotnet',
        'elf_file',
        'binary_blob',
        'unknown'
    ]

    def __init__(
        self,
        verbose: bool = False,
        no_floss: bool = False,
        use_binwalk: bool = True,
        extract_installers: bool = True,
        max_recursion_depth: int = 5
    ):
        """
        Initialize the Python engine.

        Args:
            verbose: Enable verbose logging
            no_floss: Skip FLOSS extraction (faster)
            use_binwalk: Use binwalk for embedded file detection
            extract_installers: Extract installer contents
            max_recursion_depth: Maximum depth for recursive analysis
        """
        self.verbose = verbose
        self.no_floss = no_floss
        self.use_binwalk = use_binwalk
        self.extract_installers = extract_installers
        self.max_recursion_depth = max_recursion_depth
        self.errors: List[str] = []
        self._analyzed_files: set = set()

        self.hash_calculator = HashCalculator()
        self.indicator_detector = IndicatorDetector()
        self.entropy_detector = None  # Will be initialized per file
        self.attck_mapper = ATTACKMapper()
        self.crypto_detector = CryptoDetector()

    def supports_file(self, file_type: str) -> bool:
        """Check if this engine supports the given file type.

        Returns:
            Always True -- the Python engine is the fallback, supports everything.
        """
        return True

    def get_name(self) -> str:
        """Get engine name."""
        return "Python (Fallback)"

    def analyze(self, file_path: Path, depth: int = 0) -> StaticReport:
        """
        Run Python-based analysis on the file.

        Args:
            file_path: Path to the file to analyze
            depth: Current recursion depth

        Returns:
            StaticReport: Complete analysis report
        """
        self._log(f"Running Python analysis on {file_path.name} (depth {depth})")

        # Prevent infinite recursion
        file_hash = self.hash_calculator.calculate_all(file_path).get('md5', '')
        if file_hash in self._analyzed_files:
            self._log(f"Skipping already analyzed file: {file_path.name}")
            return self._create_empty_report(file_path, "File already analyzed")
        self._analyzed_files.add(file_hash)

        # Initialize per-file detectors
        self.entropy_detector = EntropyDetector(file_path)

        file_info = self._get_file_info(file_path)
        self._log(f"File size: {file_info['size_mb']:.2f} MB")

        hashes = self.hash_calculator.calculate_all(file_path)
        self._log(f"SHA-256: {hashes.get('sha256', 'N/A')}")

        from ..detectors.file_type_detector import FileTypeDetector
        detector = FileTypeDetector(file_path)
        file_type_info = detector.detect()
        file_type = file_type_info.get('type', 'unknown')
        is_dotnet = file_type == 'pe_dotnet'

        pe_data = {}
        elf_data = {}
        imphash = None

        if file_type in ['pe_native', 'pe_file', 'pe_dotnet']:
            self._log("Parsing as PE file...")
            pe_parser = PEParser(file_path)
            pe_data = pe_parser.parse()
            self.errors.extend(pe_parser.get_errors())

            if pe_parser.pe:
                imphash = self.hash_calculator.calculate_imphash(pe_parser.pe)

            if pe_data.get('is_dotnet', False):
                is_dotnet = True
                file_type = 'pe_dotnet'

        elif file_type == 'elf_file':
            self._log("Parsing as ELF file...")
            elf_parser = ELFParser(file_path)
            elf_data = elf_parser.parse()
            self.errors.extend(elf_parser.get_errors())

        self._log("Extracting strings...")
        strings_parser = StringsParser(file_path)
        strings = strings_parser.extract(include_floss=not self.no_floss)
        self.errors.extend(strings_parser.get_errors())

        all_strings = strings.get('standard', []) + strings.get('floss', [])
        self._log(f"Found {len(strings.get('standard', []))} standard strings, "
                  f"{len(strings.get('floss', []))} FLOSS strings")

        self._log("Detecting packers...")
        packer_detector = PackerDetector(file_path)
        packer_data = packer_detector.detect()
        self.errors.extend(packer_detector.get_errors())

        sections = pe_data.get('sections', [])
        if sections and not packer_data.get('detected', False):
            section_packer = packer_detector.detect_with_sections(sections)
            if section_packer.get('detected', False):
                packer_data = section_packer
                self._log(f"Packer detected via sections: {packer_data.get('packers', [])}")

        self._log("Detecting indicators...")
        imports = pe_data.get('imports', [])
        indicators = self.indicator_detector.analyze(imports, sections, all_strings)

        suspicious_strings = strings_parser.find_suspicious(all_strings)
        self._log(f"Found {len(suspicious_strings)} suspicious strings")

        crypto_algorithms = strings_parser.find_crypto_patterns(all_strings)
        potential_keys = strings_parser.find_potential_keys(all_strings)
        self._log(f"Found {len(crypto_algorithms)} crypto algorithms, "
                  f"{len(potential_keys)} potential keys")

        self._log("Extracting configuration...")
        config_extractor = ConfigExtractor(file_path)
        config_data = config_extractor.extract()
        self.errors.extend(config_extractor.get_errors())

        self._log(f"Found {len(config_data.get('ips', []))} IPs, "
                  f"{len(config_data.get('domains', []))} domains")

        self._log("Running YARA scan...")
        yara_parser = YaraParser(file_path)
        yara_data = yara_parser.scan()
        self.errors.extend(yara_parser.get_errors())

        self._log(f"YARA matched {len(yara_data.get('matched_rules', []))} rules")

        self._log("Discovering encryption keys...")
        key_reconstructor = KeyReconstructor(file_path)
        discovered_keys = key_reconstructor.find_keys()
        self.errors.extend(key_reconstructor.get_errors())
        self._log(f"Discovered {len(discovered_keys)} potential keys")

        self._log("Carving embedded files...")
        magic_carver = MagicCarver(file_path, use_binwalk=self.use_binwalk, verbose=self.verbose)
        carved_data = magic_carver.carve()
        self.errors.extend(magic_carver.get_errors())

        embedded_files_count = len(carved_data.get('embedded_files', []))
        self._log(f"Found {embedded_files_count} embedded files")

        self._log("Analyzing entropy...")
        entropy_analysis = self.entropy_detector.analyze(sections, all_strings)
        self._log(f"Entropy: {len(entropy_analysis.high_entropy_sections)} high entropy sections, "
                  f"overall: {entropy_analysis.overall_entropy:.2f}")

        self._log("Mapping to ATT&CK techniques...")
        attck_mappings = self.attck_mapper.map_all(
            strings=all_strings,
            imports=imports,
            yara_data=yara_data,
            entropy_findings=entropy_analysis.high_entropy_sections + entropy_analysis.suspicious_entropy,
            config=config_data
        )
        self._log(f"Generated {len(attck_mappings)} ATT&CK mappings")

        report = StaticReport(
            filename=file_path.name,
            size_bytes=file_info['size_bytes'],
            size_mb=file_info['size_mb'],
            extension=file_path.suffix,
            file_type=file_type,
            file_type_info=file_type_info,
            md5=hashes.get('md5', ''),
            sha1=hashes.get('sha1', ''),
            sha256=hashes.get('sha256', ''),
            ssdeep=hashes.get('ssdeep'),
            tlsh=hashes.get('tlsh'),
            imphash=imphash,
            is_dotnet=is_dotnet,
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
            entropy_analysis=entropy_analysis,
            attck_mappings=attck_mappings,
            config=config_data,
            embedded_files=carved_data.get('embedded_files', []),
            discovered_keys=discovered_keys,
            errors=self.errors
        )

        self._log("Python analysis complete")
        return report

    def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get basic file information.

        Args:
            file_path: Path to stat.

        Returns:
            Dict with size_bytes and size_mb.
        """
        stats = file_path.stat()
        return {
            'size_bytes': stats.st_size,
            'size_mb': round(stats.st_size / (1024 * 1024), 2)
        }

    def _create_empty_report(self, file_path: Path, error: str = "") -> StaticReport:
        """Create an empty report for a skipped or already-analyzed file.

        Args:
            file_path: Path to the file, for basic file info.
            error: Error message to record, if any.

        Returns:
            A minimal StaticReport with no analysis content.
        """
        return StaticReport(
            filename=file_path.name,
            size_bytes=0,
            size_mb=0,
            extension=file_path.suffix,
            file_type='unknown',
            file_type_info={},
            md5='',
            sha1='',
            sha256='',
            errors=[error] if error else []
        )

    def _log(self, message: str):
        """Log a message if verbose is enabled."""
        if self.verbose:
            print(f"[*] {self.get_name()}: {message}")

    def get_errors(self) -> List[str]:
        """Get errors from the analysis."""
        return self.errors
