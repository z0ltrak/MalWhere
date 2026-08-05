"""Main static analysis orchestrator."""

import uuid
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional

from .models.report import (
    StaticReport,
    SectionInfo,
    ImportInfo,
    ExportInfo,
    StringInfo,
    PackerInfo,
    IndicatorInfo,
    YaraResult,
    EntropyAnalysis,
    ATTACKMapping,
    EmbeddedFile
)
from .parsers.pe_parser import PEParser
from .parsers.strings_parser import StringsParser
from .parsers.packer_parser import PackerDetector
from .parsers.config_parser import ConfigExtractor
from .parsers.yara_parser import YaraParser
from .parsers.magic_carver import MagicCarver
from .parsers.zlib_parser import ZlibParser
from .parsers.key_reconstructor import KeyReconstructor
from .parsers.decryption_engine import DecryptionEngine
from .detectors.indicators import IndicatorDetector
from .detectors.entropy_detector import EntropyDetector
from .detectors.attck_mapper import ATTACKMapper
from .utils.hashes import HashCalculator


class StaticAnalyzer:
    """Orchestrates the complete static analysis process."""

    def __init__(self, file_path: Path, verbose: bool = False, no_floss: bool = False,
                 max_recursion_depth: int = 3):
        """Initialize the static analyzer."""
        self.file_path = file_path
        self.verbose = verbose
        self.no_floss = no_floss
        self.max_recursion_depth = max_recursion_depth
        self.errors: List[str] = []
        self._analyzed_files: set = set()  # Track analyzed files to prevent loops

        # Initialize components
        self.pe_parser = PEParser(file_path)
        self.strings_parser = StringsParser(file_path)
        self.packer_detector = PackerDetector(file_path)
        self.indicator_detector = IndicatorDetector()
        self.hash_calculator = HashCalculator()
        self.config_extractor = ConfigExtractor(file_path)
        self.yara_parser = YaraParser(file_path)
        self.magic_carver = MagicCarver(file_path)
        self.zlib_parser = ZlibParser(file_path)
        self.key_reconstructor = KeyReconstructor(file_path)
        self.decryption_engine = DecryptionEngine(file_path)
        self.entropy_detector = EntropyDetector(file_path)
        self.attck_mapper = ATTACKMapper()

        # Track discovered keys from this analysis
        self.discovered_keys: List[Dict[str, Any]] = []

    def analyze(self, depth: int = 0) -> StaticReport:
        """Run complete static analysis and return a report."""
        self._log(f"Starting static analysis of {self.file_path.name} (depth {depth})")

        # Prevent infinite recursion
        file_hash = self.hash_calculator.calculate_all(self.file_path).get('md5', '')
        if file_hash in self._analyzed_files:
            self._log(f"Skipping already analyzed file: {self.file_path.name}")
            return self._create_empty_report()
        self._analyzed_files.add(file_hash)

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
        all_strings = strings.get('standard', []) + strings.get('floss', [])

        # Detect packers
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
        indicators = self.indicator_detector.analyze(imports, sections, all_strings)
        suspicious_strings = self.strings_parser.find_suspicious(all_strings)

        # Extract configuration
        config_data = self.config_extractor.extract()
        self.errors.extend(self.config_extractor.get_errors())

        # YARA scan
        yara_data = self.yara_parser.scan()
        self.errors.extend(self.yara_parser.get_errors())

        # Handle NSIS false positives
        if 'UPX_packed' in yara_data.get('matched_rules', []) or 'Themida_packed' in yara_data.get('matched_rules', []):
            if self.pe_parser._is_nsis_installer():
                self._log("Detected NSIS installer - overriding UPX/Themida false positives")
                yara_data['matched_rules'] = [r for r in yara_data.get('matched_rules', [])
                                              if r not in ['UPX_packed', 'Themida_packed']]
                yara_data['packer_detected'] = False
                yara_data['packers'] = []
                yara_data['matched_rules'].append('NSIS_installer')
                if 'attck_mapping' not in yara_data:
                    yara_data['attck_mapping'] = []
                yara_data['attck_mapping'].append({
                    'technique': 'T1036.005',
                    'name': 'Masquerading as Legitimate Software',
                    'rule': 'NSIS_installer'
                })

        # NEW: Magic carving and recursive extraction
        carved_data = self.magic_carver.carve()
        self.errors.extend(self.magic_carver.get_errors())

        # NEW: Key discovery from this file
        self.discovered_keys = self.key_reconstructor.find_keys()
        self.errors.extend(self.key_reconstructor.get_errors())
        if self.discovered_keys:
            self._log(f"Found {len(self.discovered_keys)} potential keys in this file")

        # NEW: Recursive analysis of embedded files
        embedded_files = self._extract_and_analyze_embedded_files(depth + 1)

        # NEW: Entropy analysis
        entropy_analysis = self.entropy_detector.analyze(sections, all_strings)
        self._log(f"Entropy analysis: {len(entropy_analysis.high_entropy_sections)} high entropy sections")

        # NEW: ATT&CK mapping with justification
        attck_mappings = self.attck_mapper.map_all(
            strings=all_strings,
            imports=imports,
            yara_data=yara_data,
            entropy_findings=entropy_analysis.high_entropy_sections + entropy_analysis.suspicious_entropy,
            config=config_data
        )
        self._log(f"Generated {len(attck_mappings)} ATT&CK mappings with justification")

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
            entropy_analysis=entropy_analysis,
            attck_mappings=attck_mappings,
            config=config_data,
            embedded_files=embedded_files,
            discovered_keys=self.discovered_keys,
            errors=self.errors
        )

        self._log("Analysis complete")
        return report

    def _extract_and_analyze_embedded_files(self, depth: int) -> List[Dict[str, Any]]:
        """Extract embedded files and analyze them recursively."""
        if depth > self.max_recursion_depth:
            self._log(f"Reached maximum recursion depth ({self.max_recursion_depth})")
            return []

        embedded_results = []

        # 1. Process embedded PE files
        for entry in self.magic_carver.carved_data.get('pe_files', []):
            result = self._analyze_embedded_data(
                data=entry.get('data', b''),
                file_type='pe_file',
                offset=entry.get('offset'),
                depth=depth
            )
            if result:
                embedded_results.append(result)

        # 2. Process zlib-compressed data
        for entry in self.magic_carver.carved_data.get('compressed_data', []):
            decompressed = self.zlib_parser.decompress(entry.get('data', b''))
            if decompressed and len(decompressed) > 1024:
                # Determine type of decompressed data
                file_type = self._detect_file_type(decompressed)
                result = self._analyze_embedded_data(
                    data=decompressed,
                    file_type=f"zlib_{file_type}",
                    offset=entry.get('offset'),
                    depth=depth,
                    original_type='zlib_compressed'
                )
                if result:
                    embedded_results.append(result)

        # 3. Process encrypted data (using only discovered keys)
        for entry in self.magic_carver.carved_data.get('encrypted_data', []):
            decrypted = self._try_decrypt_with_discovered_keys(entry.get('data', b''))
            if decrypted and len(decrypted) > 1024:
                file_type = self._detect_file_type(decrypted)
                result = self._analyze_embedded_data(
                    data=decrypted,
                    file_type=f"decrypted_{file_type}",
                    offset=entry.get('offset'),
                    depth=depth,
                    original_type='encrypted_data'
                )
                if result:
                    embedded_results.append(result)

        # 4. Process any other suspicious high-entropy chunks
        # (these might be encrypted or compressed payloads)
        high_entropy_chunks = self._find_high_entropy_chunks()
        for chunk in high_entropy_chunks:
            # Try to decrypt with discovered keys
            decrypted = self._try_decrypt_with_discovered_keys(chunk.get('data', b''))
            if decrypted and len(decrypted) > 1024:
                file_type = self._detect_file_type(decrypted)
                result = self._analyze_embedded_data(
                    data=decrypted,
                    file_type=f"decrypted_{file_type}",
                    offset=chunk.get('offset'),
                    depth=depth,
                    original_type='high_entropy_chunk'
                )
                if result:
                    embedded_results.append(result)

        return embedded_results

    def _analyze_embedded_data(self, data: bytes, file_type: str, offset: int,
                               depth: int, original_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Analyze embedded data using a temporary file and StaticAnalyzer."""
        try:
            # Save embedded data to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
                tmp.write(data)
                tmp_path = Path(tmp.name)

            # Calculate hashes
            hashes = self.hash_calculator.calculate_all(tmp_path)

            # Analyze the embedded file (recursive)
            analyzer = StaticAnalyzer(
                tmp_path,
                verbose=self.verbose,
                no_floss=self.no_floss,
                max_recursion_depth=self.max_recursion_depth
            )
            # Pass discovered keys to the embedded analyzer
            analyzer.discovered_keys = self.discovered_keys
            sub_report = analyzer.analyze(depth=depth)

            # Clean up
            tmp_path.unlink(missing_ok=True)

            return {
                'offset': offset,
                'type': file_type,
                'original_type': original_type,
                'size': len(data),
                'md5': hashes.get('md5', ''),
                'sha256': hashes.get('sha256', ''),
                'is_dotnet': sub_report.is_dotnet,
                'imphash': sub_report.imphash,
                'suspicious_imports': sub_report.indicators.suspicious_imports[:20],
                'suspicious_strings': [s.get('string', '') for s in sub_report.indicators.suspicious_strings[:20]],
                'yara_matches': sub_report.yara.matched_rules,
                'full_report': sub_report.to_dict()  # Include full report for deep analysis
            }

        except Exception as e:
            self.errors.append(f"Error analyzing embedded file at offset {offset}: {e}")
            return None

    def _try_decrypt_with_discovered_keys(self, data: bytes) -> Optional[bytes]:
        """Try to decrypt data using keys discovered during this analysis."""
        if not self.discovered_keys:
            return None

        for key_info in self.discovered_keys:
            key_type = key_info.get('type', '')
            key_data = key_info.get('key', '')

            try:
                if key_type == 'rc4':
                    # RC4 key
                    if len(key_data) >= 16:
                        key_bytes = bytes.fromhex(key_data) if len(key_data) > 32 else key_data.encode()
                        decrypted = self.decryption_engine.decrypt_rc4(data, key_bytes[:32])
                        if decrypted and self._is_valid_data(decrypted):
                            self._log(f"Successfully decrypted with RC4 key from analysis")
                            return decrypted

                elif key_type == 'xor':
                    # XOR key
                    key_bytes = key_data.encode()
                    decrypted = self.decryption_engine.decrypt_xor(data, key_bytes)
                    if decrypted and self._is_valid_data(decrypted):
                        self._log(f"Successfully decrypted with XOR key from analysis")
                        return decrypted

                elif key_type == 'rdata_key':
                    # Key from .rdata section
                    key_str = key_info.get('key_ascii', '')
                    if key_str:
                        key_bytes = key_str.encode()
                        decrypted = self.decryption_engine.decrypt_xor(data, key_bytes)
                        if decrypted and self._is_valid_data(decrypted):
                            self._log(f"Successfully decrypted with .rdata key from analysis")
                            return decrypted

            except Exception as e:
                self.errors.append(f"Decryption attempt with key {key_type} failed: {e}")
                continue

        return None

    def _detect_file_type(self, data: bytes) -> str:
        """Detect the type of a data blob."""
        if data[:2] == b'MZ':
            return 'pe_file'
        elif data[:4] == b'PK\x03\x04':
            return 'zip_file'
        elif data[:2] == b'\x1F\x8B':
            return 'gzip_file'
        elif data[:4] == b'RIFF':
            return 'riff_file'
        elif data[:8] == b'\x89PNG\r\n\x1A\n':
            return 'png_image'
        elif data[:2] == b'\xFF\xD8':
            return 'jpeg_image'
        elif data[:4] == b'%PDF':
            return 'pdf_file'
        elif data[:4] == b'{\n':
            return 'json_data'
        elif data[:5] == b'<?xml':
            return 'xml_data'
        else:
            # Check if it looks like plaintext
            printable = sum(1 for b in data[:256] if 32 <= b <= 126 or b in [9, 10, 13])
            if printable / min(len(data), 256) > 0.8:
                return 'plaintext'
            return 'unknown'

    def _is_valid_data(self, data: bytes) -> bool:
        """Check if decrypted data looks valid (PE, zip, or plaintext)."""
        if len(data) < 1024:
            return False

        # Check for known file signatures
        if data[:2] == b'MZ':
            return True
        if data[:4] == b'PK\x03\x04':
            return True
        if data[:2] == b'\x1F\x8B':
            return True
        if data[:4] == b'{\n':
            return True
        if data[:5] == b'<?xml':
            return True

        # Check if it looks like plaintext
        printable = sum(1 for b in data[:1024] if 32 <= b <= 126 or b in [9, 10, 13])
        if printable / min(len(data), 1024) > 0.7:
            return True

        return False

    def _find_high_entropy_chunks(self) -> List[Dict[str, Any]]:
        """Find high-entropy chunks that might be encrypted/compressed payloads."""
        chunks = []
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()

            # Scan for high-entropy regions
            chunk_size = 4096
            for offset in range(0, len(data) - chunk_size, chunk_size):
                chunk = data[offset:offset + chunk_size]
                entropy = self.entropy_detector._calculate_entropy(chunk)
                if entropy > 7.5:
                    chunks.append({
                        'offset': offset,
                        'size': chunk_size,
                        'entropy': entropy,
                        'data': chunk
                    })
        except Exception as e:
            self.errors.append(f"Error finding high-entropy chunks: {e}")

        return chunks[:10]  # Limit to 10 chunks

    def _create_empty_report(self) -> StaticReport:
        """Create an empty report for skipped files."""
        return StaticReport(
            filename=self.file_path.name,
            size_bytes=0,
            size_mb=0,
            extension='',
            md5='',
            sha1='',
            sha256='',
            errors=['File already analyzed in recursion']
        )

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
