"""Main static analysis orchestrator with universal file type detection and recursive extraction."""

from __future__ import annotations

import tempfile
import uuid
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Set

from .parsers.pe_parser import PEParser
from .parsers.strings_parser import StringsParser
from .parsers.packer_parser import PackerDetector
from .parsers.config_parser import ConfigExtractor
from .parsers.yara_parser import YaraParser
from .parsers.magic_carver import MagicCarver
from .parsers.zlib_parser import ZlibParser
from .parsers.key_reconstructor import KeyReconstructor
from .parsers.decryption_engine import DecryptionEngine
from .parsers.filesystem_extractor import FilesystemExtractor
from .parsers.installer_parser import InstallerParser
from .parsers.elf_parser import ELFParser
from .parsers.zip_parser import ZIPParser
from .parsers.nsis_parser import NSISParser
from .detectors.indicators import IndicatorDetector
from .detectors.entropy_detector import EntropyDetector
from .detectors.attck_mapper import ATTACKMapper
from .detectors.file_type_detector import FileTypeDetector
from .utils.hashes import HashCalculator
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


class StaticAnalyzer:
    """Orchestrates complete static analysis with universal file type handling."""

    # Class-level cache for keys discovered across all files
    _global_key_cache: Dict[str, List[Dict[str, Any]]] = {}
    _decrypted_payloads: Dict[str, bytes] = {}
    _analyzed_installers: Set[str] = set()

    def __init__(self, file_path: Path, verbose: bool = False, no_floss: bool = False,
                 max_recursion_depth: int = 5, use_binwalk: bool = True,
                 parent_context: Optional[Dict[str, Any]] = None,
                 extract_installers: bool = True):
        self.file_path = file_path
        self.verbose = verbose
        self.no_floss = no_floss
        self.max_recursion_depth = max_recursion_depth
        self.use_binwalk = use_binwalk
        self.parent_context = parent_context or {}
        self.extract_installers = extract_installers
        self.errors: List[str] = []
        self._analyzed_files: set = set()
        self._extracted_installer_files: List[Dict[str, Any]] = []

        # Initialize hash calculator FIRST
        self.hash_calculator = HashCalculator()

        # Universal file type detector
        self.file_type_detector = FileTypeDetector(file_path)

        # Initialize parsers
        self.pe_parser = PEParser(file_path)
        self.elf_parser = ELFParser(file_path)
        self.zip_parser = ZIPParser(file_path)
        self.installer_parser = InstallerParser(file_path)
        self.nsis_parser = NSISParser(file_path)
        self.strings_parser = StringsParser(file_path)
        self.packer_detector = PackerDetector(file_path)
        self.config_extractor = ConfigExtractor(file_path)
        self.yara_parser = YaraParser(file_path)
        self.magic_carver = MagicCarver(file_path, use_binwalk=use_binwalk, verbose=verbose)
        self.zlib_parser = ZlibParser(file_path)
        self.key_reconstructor = KeyReconstructor(file_path)
        self.decryption_engine = DecryptionEngine(file_path)
        self.entropy_detector = EntropyDetector(file_path)
        self.attck_mapper = ATTACKMapper()
        self.filesystem_extractor = FilesystemExtractor()
        self.indicator_detector = IndicatorDetector()

        # Track discovered keys and extracted files
        self.discovered_keys: List[Dict[str, Any]] = []
        self.extracted_files: List[Dict[str, Any]] = []
        self.file_type_info: Dict[str, Any] = {}
        self._nsis_detected = False
        self._is_pass1_analysis = parent_context.get('pass') == 1 if parent_context else False

    def analyze(self, depth: int = 0) -> StaticReport:
        """Run complete static analysis with context-aware entropy decisions."""
        self._log(f"Starting static analysis of {self.file_path.name} (depth {depth})")

        # Prevent infinite recursion
        file_hash = self.hash_calculator.calculate_all(self.file_path).get('md5', '')
        if file_hash in self._analyzed_files:
            self._log(f"Skipping already analyzed file: {self.file_path.name}")
            return self._create_empty_report()
        self._analyzed_files.add(file_hash)

        # ============================================================
        # STEP 0: Detect file type FIRST (before entropy decisions)
        # ============================================================
        self._log("=" * 60)
        self._log("STEP 0: File type detection")
        self._log("=" * 60)

        file_type_info = self.file_type_detector.detect()
        self.file_type_info = file_type_info
        file_type = file_type_info.get('type', 'unknown')
        self._log(f"Detected file type: {file_type} (confidence: {file_type_info.get('confidence', 'low')})")

        # ============================================================
        # STEP 0.5: Context-aware entropy check
        # ============================================================
        overall_entropy = self.entropy_detector._calculate_overall_entropy()
        self._log(f"Overall entropy: {overall_entropy:.2f}")

        # Determine if we should skip carving based on context
        skip_carving = self._should_skip_carving(file_type, overall_entropy)

        if skip_carving:
            self._log(f"*** SKIPPING CARVING: Context-aware decision for {file_type} ***")
            self.use_binwalk = False
        else:
            self._log(f"*** ENABLING CARVING: Context-aware decision for {file_type} ***")

        # ============================================================
        # STEP 1: Force NSIS detection (MUST RUN BEFORE ANYTHING ELSE)
        # ============================================================
        nsis_detected = self._force_nsis_detection()
        if nsis_detected:
            self._log("=" * 60)
            self._log("*** DETECTED NSIS INSTALLER ***")
            self._log("=" * 60)
            self._nsis_detected = True
            self.file_type_info = {'type': 'nsis_installer', 'confidence': 'high'}

            if self.extract_installers and depth < self.max_recursion_depth:
                self._log("*** EXTRACTING NSIS INSTALLER CONTENTS ***")
                return self._analyze_installer(depth, 'nsis_installer')
            else:
                self._log("NSIS extraction disabled or max depth reached")

        # ============================================================
        # STEP 2: Handle other installer types
        # ============================================================
        if file_type in ['inno_installer', 'msi_installer']:
            if self.extract_installers and depth < self.max_recursion_depth:
                self._log(f"Detected {file_type} - extracting and analyzing contents")
                return self._analyze_installer(depth, file_type)

        # ============================================================
        # STEP 3: File info
        # ============================================================
        file_info = self._get_file_info()

        # In analyze() method, find the PE parsing section and replace with:

        # ============================================================
        # STEP 4: Handle based on file type
        # ============================================================
        pe_data = {}
        elf_data = {}
        zip_data = {}
        net_strings = []   # <-- Add this
        net_imports = []   # <-- Add this

        if file_type in ['pe_file', 'pe_native', 'pe_dotnet']:
            self._log(f"Parsing as PE file: {self.file_path.name}")
            pe_data = self.pe_parser.parse()
            self.errors.extend(self.pe_parser.get_errors())

            # ============================================================
            # NEW: Use .NET P/Invoke imports if available
            # ============================================================
            net_imports = pe_data.get('net_imports', [])
            net_strings = pe_data.get('net_strings', [])
            net_types = pe_data.get('net_types', [])
            net_methods = pe_data.get('net_methods', [])

            if net_imports:
                self._log(f"Found {len(net_imports)} .NET P/Invoke imports")
                # Convert to ImportInfo objects
                from .models.report import ImportInfo
                for net_imp in net_imports:
                    # Create a fake address for P/Invoke imports
                    import_info = ImportInfo(
                        dll=net_imp.get('dll', ''),
                        function=net_imp.get('function', ''),
                        address='0x0',  # P/Invoke doesn't have a fixed address
                        hint=0
                    )
                    # Add to the imports list
                    if 'imports' not in pe_data:
                        pe_data['imports'] = []
                    pe_data['imports'].append(import_info)
                pe_data['net_imports'] = net_imports

            if net_strings:
                self._log(f"Found {len(net_strings)} .NET user strings")

            if net_types:
                self._log(f"Found {len(net_types)} .NET types")

        elif file_type == 'elf_file':
            self._log(f"Parsing as ELF file: {self.file_path.name}")
            elf_data = self.elf_parser.parse()
            self.errors.extend(self.elf_parser.get_errors())
        elif file_type == 'zip_file':
            self._log(f"Parsing as ZIP file: {self.file_path.name}")
            zip_data = self.zip_parser.parse()
            self.errors.extend(self.zip_parser.get_errors())

        # ============================================================
        # STEP 5: Calculate hashes
        # ============================================================
        hashes = self.hash_calculator.calculate_all(self.file_path)

        # ============================================================
        # STEP 6: Calculate imphash if PE is valid
        # ============================================================
        imphash = None
        if self.pe_parser.pe:
            imphash = self.hash_calculator.calculate_imphash(self.pe_parser.pe)

        # ============================================================
        # STEP 7: Extract strings (universal)
        # ============================================================
        strings = self.strings_parser.extract(include_floss=not self.no_floss)
        self.errors.extend(self.strings_parser.get_errors())
        all_strings = strings.get('standard', []) + strings.get('floss', [])

        # ============================================================
        # NEW: Merge .NET strings with all_strings for detection
        # ============================================================
        if net_strings:
            all_strings.extend(net_strings)
            # Also add to strings for reporting
            strings['dotnet_strings'] = net_strings

        # ============================================================
        # STEP 8: Detect packers
        # ============================================================
        packer_data = self.packer_detector.detect()
        self.errors.extend(self.packer_detector.get_errors())

        if not packer_data['detected'] and pe_data.get('sections'):
            section_packer = self.packer_detector.detect_with_sections(pe_data['sections'])
            if section_packer['detected']:
                packer_data = section_packer

        # ============================================================
        # STEP 9: Detect indicators
        # ============================================================
        sections = pe_data.get('sections', [])
        imports = pe_data.get('imports', [])
        indicators = self.indicator_detector.analyze(imports, sections, all_strings)
        suspicious_strings = self.strings_parser.find_suspicious(all_strings)

        # ============================================================
        # STEP 10: Extract configuration
        # ============================================================
        config_data = self.config_extractor.extract()
        self.errors.extend(self.config_extractor.get_errors())

        # ============================================================
        # STEP 11: YARA scan
        # ============================================================
        yara_data = self.yara_parser.scan()
        self.errors.extend(self.yara_parser.get_errors())

        # ============================================================
        # STEP 12: Key Discovery
        # ============================================================
        self.discovered_keys = self.key_reconstructor.find_keys()
        self.errors.extend(self.key_reconstructor.get_errors())
        if self.discovered_keys:
            self._log(f"Discovered {len(self.discovered_keys)} potential keys with algorithm context")

        # ============================================================
        # STEP 13: Magic carving (respects self.use_binwalk set above)
        # ============================================================
        carved_data = self.magic_carver.carve()
        self.errors.extend(self.magic_carver.get_errors())

        # ============================================================
        # STEP 14: Recursive analysis of embedded files (with limits)
        # ============================================================
        embedded_files = self._extract_and_analyze_embedded_files(depth + 1)

        # ============================================================
        # STEP 15: Entropy analysis
        # ============================================================
        entropy_analysis = self.entropy_detector.analyze(sections, all_strings)
        self._log(f"Entropy analysis: {len(entropy_analysis.high_entropy_sections)} high entropy sections")

        # ============================================================
        # STEP 16: ATT&CK mapping
        # ============================================================
        attck_mappings = self.attck_mapper.map_all(
            strings=all_strings,
            imports=imports,
            yara_data=yara_data,
            entropy_findings=entropy_analysis.high_entropy_sections + entropy_analysis.suspicious_entropy,
            config=config_data
        )
        self._log(f"Generated {len(attck_mappings)} ATT&CK mappings with justification")

        # ============================================================
        # STEP 17: Build report
        # ============================================================
        report = StaticReport(
            filename=self.file_path.name,
            size_bytes=file_info['size_bytes'],
            size_mb=file_info['size_mb'],
            extension=self.file_path.suffix,
            file_type=file_type,
            file_type_info=file_type_info,
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
            errors=self.errors,
            nsis_detected=self._nsis_detected
        )

        self._log("Analysis complete")
        return report

    def _should_skip_carving(self, file_type: str, entropy: float) -> bool:
        """
        Context-aware decision on whether to skip carving.

        Strategy:
        - Known installers (NSIS, Inno, MSI): NEVER skip (they contain embedded files)
        - Known archives (ZIP, GZip): NEVER skip (they contain files)
        - PE files: NEVER skip (may contain resources, overlay data)
        - Known encrypted extensions (.3w, .enc): ALWAYS skip (try decryption)
        - Unknown files with very high entropy (>7.8): Skip (likely encrypted)
        - Unknown files with moderate entropy: Allow carving
        """
        # ============================================================
        # NEVER skip for installers - they contain embedded files
        # ============================================================
        if file_type in ['nsis_installer', 'inno_installer', 'msi_installer']:
            self._log(f"  Installer type '{file_type}' - enabling carving")
            return False

        # ============================================================
        # NEVER skip for archives
        # ============================================================
        if file_type in ['zip_file', 'gzip_file', 'archive_zip', 'archive_gzip']:
            self._log(f"  Archive type '{file_type}' - enabling carving")
            return False

        # ============================================================
        # NEVER skip for PE files (even with high entropy - may be packed)
        # ============================================================
        if file_type in ['pe_file', 'pe_native', 'pe_dotnet']:
            self._log(f"  PE file with entropy {entropy:.2f} - enabling carving for resources")
            return False

        # ============================================================
        # ALWAYS skip for known encrypted extensions
        # ============================================================
        ext = self.file_path.suffix.lower()
        if ext in ['.3w', '.enc', '.dat', '.crypt']:
            self._log(f"  Encrypted extension '{ext}' - skipping carving")
            return True

        # ============================================================
        # Check if it has a known compression header (don't skip)
        # ============================================================
        if self.magic_carver.data and len(self.magic_carver.data) > 10:
            compression_headers = [
                b'\x78\x9C', b'\x78\xDA', b'\x78\x01',  # zlib
                b'\x1F\x8B',  # gzip
                b'PK\x03\x04',  # zip
                b'7z\xBC\xAF\x27\x1C',  # 7z
                b'Rar!',  # RAR
            ]
            for header in compression_headers:
                if self.magic_carver.data[:len(header)] == header:
                    self._log(f"  Found compression header - enabling carving")
                    return False

        # ============================================================
        # For unknown files, only skip if very high entropy
        # ============================================================
        if file_type == 'unknown' and entropy > 7.8:
            self._log(f"  Unknown file with very high entropy {entropy:.2f} - skipping carving")
            return True

        # ============================================================
        # For all other cases, allow carving
        # ============================================================
        return False

    def _force_nsis_detection(self) -> bool:
        """Force NSIS detection by scanning the file content."""
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read(1048576)  # 1MB

            data_str = data.decode('utf-8', errors='ignore')

            # Check for NSIS signatures
            nsis_signatures = [
                'Nullsoft.NSIS.exehead',
                'NullsoftInst',
                'Nullsoft.NSIS',
                'Nullsoft Install System'
            ]

            for sig in nsis_signatures:
                if sig in data_str:
                    self._log(f"  Found NSIS signature: {sig}")
                    return True

            # Check for NSIS manifest
            if '<assembly xmlns="urn:schemas-microsoft-com:asm.v1"' in data_str:
                if 'Nullsoft.NSIS' in data_str:
                    self._log("  Found NSIS manifest")
                    return True

        except Exception as e:
            self._log(f"NSIS detection error: {e}")

        return False

    def _analyze_installer(self, depth: int, installer_type: str) -> StaticReport:
        """
        Analyze an installer with two-pass approach:
        Pass 1: Extract all files, discover keys from all extracted files
        Pass 2: Use discovered keys to decrypt encrypted payloads
        """
        self._log("=" * 60)
        self._log(f"*** EXTRACTING {installer_type.upper()} INSTALLER ***")
        self._log("=" * 60)

        # Extract the installer contents
        extracted_files = self.installer_parser.extract_all()
        self.errors.extend(self.installer_parser.errors)

        for err in self.installer_parser.errors:
            self._log(f"Installer parser: {err}")

        if not extracted_files:
            self._log("*** NO FILES EXTRACTED FROM INSTALLER ***")
            return self._analyze_as_binary(depth)

        self._log("=" * 60)
        self._log(f"*** EXTRACTED {len(extracted_files)} FILES FROM INSTALLER ***")
        self._log("=" * 60)

        for f in extracted_files:
            self._log(f"  - {f.get('name')} ({f.get('type')}, {f.get('size', 0)} bytes)")

        self._extracted_installer_files = extracted_files

        # ============================================================
        # PASS 1: Collect ALL keys from ALL files (no decryption yet)
        # ============================================================
        self._log("=" * 60)
        self._log("PASS 1: Collecting keys from all extracted files")
        self._log("=" * 60)

        all_collected_keys = []
        file_analyses = []
        encrypted_payloads = []

        for extracted in extracted_files:
            file_path = extracted.get('path')
            file_name = extracted.get('name', 'unknown')
            file_type = extracted.get('type', 'unknown')

            if not file_path or not file_path.exists():
                self._log(f"  Skipping {file_name} - file not found")
                continue

            # Check if this is an encrypted payload (based on name or type)
            is_encrypted_payload = self._is_encrypted_payload(file_name, file_type, file_path)

            if is_encrypted_payload:
                encrypted_payloads.append({
                    'name': file_name,
                    'path': file_path,
                    'size': extracted.get('size', 0),
                    'type': file_type
                })
                self._log(f"  Identified encrypted payload: {file_name}")
                continue

            # For normal files, analyze for keys
            self._log(f"  Analyzing {file_name} for keys...")

            # Quick key-only analysis (no recursive extraction, no carving)
            sub_analyzer = StaticAnalyzer(
                file_path,
                verbose=self.verbose,
                no_floss=True,
                max_recursion_depth=0,
                use_binwalk=False,
                parent_context={
                    'parent_file': self.file_path.name,
                    'installer_type': installer_type,
                    'depth': depth,
                    'pass': 1
                },
                extract_installers=False
            )

            # Extract strings and find keys
            strings_data = sub_analyzer.strings_parser.extract(include_floss=False)
            all_strings = strings_data.get('standard', [])

            # Find keys with algorithm context
            keys = sub_analyzer.key_reconstructor.find_keys()

            # Store keys with source file
            for key in keys:
                key['source_file'] = file_name
                all_collected_keys.append(key)

            self._log(f"    Found {len(keys)} keys in {file_name}")

            file_analyses.append({
                'name': file_name,
                'path': file_path,
                'type': file_type,
                'keys': keys,
                'size': extracted.get('size', 0)
            })

        # Deduplicate keys
        seen_keys = set()
        unique_keys = []
        for key in all_collected_keys:
            key_id = f"{key.get('algorithm', '')}_{key.get('key', '')[:20]}"
            if key_id not in seen_keys:
                seen_keys.add(key_id)
                unique_keys.append(key)
        all_collected_keys = unique_keys

        self._log(f"Total unique keys collected: {len(all_collected_keys)}")

        # Store keys in global cache
        StaticAnalyzer._global_key_cache[self.file_path.name] = all_collected_keys

        # ============================================================
        # PASS 2: Decrypt encrypted payloads with collected keys
        # ============================================================
        if encrypted_payloads and all_collected_keys:
            self._log("=" * 60)
            self._log(f"PASS 2: Trying to decrypt {len(encrypted_payloads)} encrypted payloads")
            self._log("=" * 60)

            for payload in encrypted_payloads:
                payload_path = payload.get('path')
                payload_name = payload.get('name')

                if not payload_path or not payload_path.exists():
                    self._log(f"  Warning: {payload_name} not found at {payload_path}")
                    continue

                try:
                    with open(payload_path, 'rb') as f:
                        encrypted_data = f.read()

                    self._log(f"  Reading {len(encrypted_data)} bytes from {payload_name}")

                    # Check entropy of the payload
                    from .detectors.entropy_detector import EntropyDetector
                    payload_entropy = EntropyDetector._calculate_entropy(None, encrypted_data)
                    self._log(f"  Payload entropy: {payload_entropy:.2f}")

                    # Try all RC4 keys first
                    rc4_keys = [k for k in all_collected_keys if k.get('algorithm') == 'rc4']

                    # Also try any keys that look like RC4 keys (15 bytes, alphanumeric)
                    potential_rc4_keys = []
                    for k in all_collected_keys:
                        key_str = k.get('key', '')
                        if len(key_str) == 15 and key_str.isalnum():
                            potential_rc4_keys.append(k)

                    # Combine and deduplicate
                    all_rc4_keys = rc4_keys + potential_rc4_keys
                    seen = set()
                    unique_rc4_keys = []
                    for k in all_rc4_keys:
                        key_str = k.get('key', '')
                        if key_str not in seen:
                            seen.add(key_str)
                            unique_rc4_keys.append(k)

                    self._log(f"  Trying {len(unique_rc4_keys)} RC4 keys on {payload_name}")

                    decryption_success = False
                    decrypted_data = None
                    used_key = None

                    for key_info in unique_rc4_keys[:50]:  # Limit to top 50 keys
                        key_data = key_info.get('key', '')
                        if not key_data:
                            continue

                        # Try as string
                        try:
                            key_bytes = key_data.encode('ascii')
                            decrypted = self.decryption_engine.decrypt_rc4(encrypted_data, key_bytes)

                            if decrypted and len(decrypted) > 1024:
                                # Check if decrypted data looks valid
                                if decrypted[:2] == b'MZ' or decrypted[:4] == b'PK\x03\x04':
                                    self._log(f"  *** SUCCESS: Decrypted {payload_name} with key: {key_data} ***")
                                    self._log(f"  Decrypted size: {len(decrypted)} bytes, magic: {decrypted[:4].hex()}")
                                    decryption_success = True
                                    decrypted_data = decrypted
                                    used_key = key_data
                                    StaticAnalyzer._decrypted_payloads[payload_name] = decrypted
                                    break
                        except Exception as e:
                            continue

                    if decryption_success and decrypted_data:
                        # Write decrypted data to temp file and analyze it
                        import tempfile
                        suffix = '.exe' if decrypted_data[:2] == b'MZ' else '.bin'
                        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                            tmp.write(decrypted_data)
                            tmp_path = Path(tmp.name)

                        self._log(f"Analyzing decrypted payload: {tmp_path.name}")

                        # Analyze the decrypted payload with the discovered keys
                        payload_analyzer = StaticAnalyzer(
                            tmp_path,
                            verbose=self.verbose,
                            no_floss=self.no_floss,
                            max_recursion_depth=1,  # Don't recurse too deep
                            use_binwalk=False,  # Don't carve decrypted data
                            extract_installers=False,
                            parent_context={
                                'parent_file': self.file_path.name,
                                'decrypted_from': payload_name,
                                'rc4_key': used_key,
                                'pass': 2
                            }
                        )
                        # Propagate all collected keys
                        payload_analyzer.discovered_keys = all_collected_keys.copy()
                        if hasattr(payload_analyzer.decryption_engine, '_candidate_keys'):
                            payload_analyzer.decryption_engine._candidate_keys = all_collected_keys.copy()

                        payload_report = payload_analyzer.analyze(depth=depth + 1)

                        # Clean up
                        tmp_path.unlink(missing_ok=True)

                        # Clean up the original encrypted file
                        try:
                            payload_path.unlink(missing_ok=True)
                        except:
                            pass

                        return payload_report

                    else:
                        self._log(f"  Failed to decrypt {payload_name} with available keys")

                except Exception as e:
                    self._log(f"  Error decrypting {payload_name}: {e}")

        # ============================================================
        # PASS 3: Analyze remaining files normally
        # ============================================================
        self._log("=" * 60)
        self._log("PASS 3: Analyzing remaining extracted files")
        self._log("=" * 60)

        embedded_analyses = []

        for file_info in file_analyses:
            file_path = file_info['path']
            file_name = file_info['name']
            file_type = file_info['type']

            self._log(f"Analyzing extracted file: {file_name} ({file_type})")

            sub_analyzer = StaticAnalyzer(
                file_path,
                verbose=self.verbose,
                no_floss=self.no_floss,
                max_recursion_depth=self.max_recursion_depth - 1,
                use_binwalk=False,  # Don't carve extracted files (they're already extracted)
                parent_context={
                    'parent_file': self.file_path.name,
                    'installer_type': installer_type,
                    'depth': depth,
                    'pass': 2
                },
                extract_installers=self.extract_installers
            )

            # Propagate all collected keys
            sub_analyzer.discovered_keys = all_collected_keys.copy()
            if hasattr(sub_analyzer.decryption_engine, '_candidate_keys'):
                sub_analyzer.decryption_engine._candidate_keys = all_collected_keys.copy()

            sub_report = sub_analyzer.analyze(depth=depth + 1)

            # Clean up temporary file
            try:
                file_path.unlink(missing_ok=True)
            except:
                pass

            embedded_analyses.append({
                'name': file_name,
                'type': file_type,
                'report': sub_report.to_dict(),
                'keys_used': len(all_collected_keys)
            })

        # Combine results into a single report
        main_report_dict = None

        # Look for D3D11InstallHelper.dll first (contains the RC4 key)
        for analysis in embedded_analyses:
            if 'D3D11InstallHelper' in analysis['name']:
                main_report_dict = analysis['report']
                self._log(f"Found D3D11InstallHelper.dll as main payload")
                break

        # Look for DLL files
        if not main_report_dict:
            for analysis in embedded_analyses:
                if '.dll' in analysis['name'].lower():
                    main_report_dict = analysis['report']
                    self._log(f"Found DLL as main payload: {analysis['name']}")
                    break

        # Look for the largest executable
        if not main_report_dict:
            for analysis in embedded_analyses:
                if analysis.get('type') == 'pe_file':
                    main_report_dict = analysis['report']
                    self._log(f"Found PE as main payload: {analysis['name']}")
                    break

        if not main_report_dict and embedded_analyses:
            main_report_dict = embedded_analyses[0]['report']
            self._log("Using first extracted file as main report")

        if main_report_dict:
            return self._dict_to_static_report(main_report_dict)

        return self._analyze_as_binary(depth)

    def _is_encrypted_payload(self, file_name: str, file_type: str, file_path: Path) -> bool:
        """Determine if a file is likely an encrypted payload."""
        # Check extension
        name_lower = file_name.lower()
        if name_lower.endswith(('.3w', '.enc', '.crypt', '.dat')):
            return True

        # Check if it's a large unknown file
        if file_type == 'unknown':
            try:
                size = file_path.stat().st_size
                if size > 100000:  # > 100KB
                    # Check entropy
                    with open(file_path, 'rb') as f:
                        data = f.read(4096)
                        from .detectors.entropy_detector import EntropyDetector
                        entropy = EntropyDetector._calculate_entropy(None, data)
                        if entropy > 7.5:
                            return True
            except:
                pass

        return False

    def _dict_to_static_report(self, report_dict: Dict[str, Any]) -> StaticReport:
        """Convert a dictionary back to a StaticReport with proper object reconstruction."""
        from .models.report import (
            StaticReport, SectionInfo, ImportInfo, ExportInfo, StringInfo,
            PackerInfo, IndicatorInfo, YaraResult, EntropyAnalysis, ATTACKMapping
        )

        packer_dict = report_dict.get('packer', {})
        packer_info = PackerInfo(
            detected=packer_dict.get('detected', False),
            packers=packer_dict.get('packers', []),
            confidence=packer_dict.get('confidence', 'none')
        )

        strings_dict = report_dict.get('strings', {})
        string_info = StringInfo(
            standard=strings_dict.get('standard', []),
            floss=strings_dict.get('floss', []),
            decoded=strings_dict.get('decoded', []),
            deobfuscated=strings_dict.get('deobfuscated', [])
        )

        indicators_dict = report_dict.get('indicators', {})
        indicator_info = IndicatorInfo(
            suspicious_imports=indicators_dict.get('suspicious_imports', []),
            suspicious_strings=indicators_dict.get('suspicious_strings', []),
            high_entropy_sections=indicators_dict.get('high_entropy_sections', []),
            anti_debug=indicators_dict.get('anti_debug', []),
            anti_vm=indicators_dict.get('anti_vm', []),
            ransomware_indicators=indicators_dict.get('ransomware_indicators', []),
            anti_sandbox=indicators_dict.get('anti_sandbox', []),
            anti_vm_strings=indicators_dict.get('anti_vm_strings', []),
            anti_sandbox_strings=indicators_dict.get('anti_sandbox_strings', []),
            sleep_functions=indicators_dict.get('sleep_functions', [])
        )

        yara_dict = report_dict.get('yara', {})
        yara_result = YaraResult(
            matches=yara_dict.get('matches', []),
            matched_rules=yara_dict.get('matched_rules', []),
            packer_detected=yara_dict.get('packer_detected', False),
            packers=yara_dict.get('packers', []),
            attck_mapping=yara_dict.get('attck_mapping', [])
        )

        entropy_dict = report_dict.get('entropy_analysis', {})
        entropy_analysis = EntropyAnalysis(
            high_entropy_sections=entropy_dict.get('high_entropy_sections', []),
            suspicious_entropy=entropy_dict.get('suspicious_entropy', []),
            packed_sections=entropy_dict.get('packed_sections', []),
            encrypted_data=entropy_dict.get('encrypted_data', []),
            overall_entropy=entropy_dict.get('overall_entropy'),
            justification=entropy_dict.get('justification', ''),
            crypto_indicators=entropy_dict.get('crypto_indicators', [])
        )

        attck_mappings = []
        for mapping_dict in report_dict.get('attck_mappings', []):
            attck_mappings.append(ATTACKMapping(
                technique=mapping_dict.get('technique', ''),
                name=mapping_dict.get('name', ''),
                source=mapping_dict.get('source', ''),
                evidence=mapping_dict.get('evidence', ''),
                confidence=mapping_dict.get('confidence', ''),
                justification=mapping_dict.get('justification', '')
            ))

        sections = []
        for section_dict in report_dict.get('sections', []):
            sections.append(SectionInfo(
                name=section_dict.get('name', ''),
                virtual_address=section_dict.get('virtual_address', ''),
                virtual_size=section_dict.get('virtual_size', 0),
                raw_size=section_dict.get('raw_size', 0),
                entropy=section_dict.get('entropy', 0),
                characteristics=section_dict.get('characteristics', ''),
                is_executable=section_dict.get('is_executable', False),
                is_writable=section_dict.get('is_writable', False),
                is_readable=section_dict.get('is_readable', False),
                md5=section_dict.get('md5', ''),
                sha1=section_dict.get('sha1', ''),
                ssdeep=section_dict.get('ssdeep')
            ))

        imports = []
        for import_dict in report_dict.get('imports', []):
            imports.append(ImportInfo(
                dll=import_dict.get('dll', ''),
                function=import_dict.get('function', ''),
                address=import_dict.get('address', ''),
                hint=import_dict.get('hint', 0)
            ))

        exports = []
        for export_dict in report_dict.get('exports', []):
            exports.append(ExportInfo(
                name=export_dict.get('name', ''),
                address=export_dict.get('address', ''),
                ordinal=export_dict.get('ordinal', 0)
            ))

        return StaticReport(
            filename=report_dict.get('filename', ''),
            size_bytes=report_dict.get('size_bytes', 0),
            size_mb=report_dict.get('size_mb', 0),
            extension=report_dict.get('extension', ''),
            file_type=report_dict.get('file_type', 'unknown'),
            file_type_info=report_dict.get('file_type_info', {}),
            md5=report_dict.get('md5', ''),
            sha1=report_dict.get('sha1', ''),
            sha256=report_dict.get('sha256', ''),
            ssdeep=report_dict.get('ssdeep'),
            tlsh=report_dict.get('tlsh'),
            imphash=report_dict.get('imphash'),
            is_dotnet=report_dict.get('is_dotnet', False),
            metadata=report_dict.get('metadata', {}),
            sections=sections,
            imports=imports,
            exports=exports,
            resources=report_dict.get('resources', []),
            strings=string_info,
            packer=packer_info,
            indicators=indicator_info,
            embedded_files=report_dict.get('embedded_files', []),
            discovered_keys=report_dict.get('discovered_keys', []),
            yara=yara_result,
            entropy_analysis=entropy_analysis,
            attck_mappings=attck_mappings,
            config=report_dict.get('config', {}),
            nsis_detected=report_dict.get('nsis_detected', False),
            analysis_timestamp=report_dict.get('analysis_timestamp', ''),
            errors=report_dict.get('errors', [])
        )

    def _analyze_as_binary(self, depth: int) -> StaticReport:
        """Fall back to binary analysis when file type is unknown or extraction fails."""
        self._log("Falling back to binary analysis")

        file_info = self._get_file_info()
        hashes = self.hash_calculator.calculate_all(self.file_path)

        strings = self.strings_parser.extract(include_floss=not self.no_floss)
        self.errors.extend(self.strings_parser.get_errors())

        config_data = self.config_extractor.extract()
        yara_data = self.yara_parser.scan()
        carved_data = self.magic_carver.carve()
        entropy_analysis = self.entropy_detector.analyze([], [])

        return StaticReport(
            filename=self.file_path.name,
            size_bytes=file_info['size_bytes'],
            size_mb=file_info['size_mb'],
            extension=self.file_path.suffix,
            file_type='binary_blob',
            file_type_info={'type': 'binary_blob', 'confidence': 'low'},
            md5=hashes.get('md5', ''),
            sha1=hashes.get('sha1', ''),
            sha256=hashes.get('sha256', ''),
            strings=StringInfo(**strings),
            config=config_data,
            yara=YaraResult(**yara_data),
            entropy_analysis=entropy_analysis,
            errors=self.errors,
            nsis_detected=self._nsis_detected
        )

    def _extract_and_analyze_embedded_files(self, depth: int) -> List[Dict[str, Any]]:
        """Extract embedded files and analyze them recursively."""
        if depth > self.max_recursion_depth:
            self._log(f"Reached maximum recursion depth ({self.max_recursion_depth})")
            return []

        embedded_results = []
        all_embedded = self.magic_carver.carved_data.get('embedded_files', [])

        if all_embedded:
            self._log(f"Found {len(all_embedded)} embedded files")
        else:
            self._log("No embedded files found")
            return []

        # Limit to prevent explosion
        MAX_EMBEDDED_TO_ANALYZE = 10
        if len(all_embedded) > MAX_EMBEDDED_TO_ANALYZE:
            self._log(f"Limiting embedded file analysis to {MAX_EMBEDDED_TO_ANALYZE} files")
            all_embedded = all_embedded[:MAX_EMBEDDED_TO_ANALYZE]

        prioritized = self._prioritize_embedded_files(all_embedded)

        for entry in prioritized:
            offset = entry.get('offset', 0)
            file_type = entry.get('type', 'unknown')
            data = entry.get('data', b'')

            if offset == 0 or len(data) < 1024:
                continue

            self._log(f"Processing {file_type} at offset {offset} ({len(data)} bytes)")

            if file_type in ['zlib_data', 'gzip_file']:
                decompressed = self._decompress_zlib_data(data, offset)
                if decompressed and len(decompressed) > 1024:
                    self._log(f"Decompressed {len(decompressed)} bytes from offset {offset}")

                    files = self.filesystem_extractor.extract_files_from_data(decompressed, offset)
                    self._log(f"Extracted {len(files)} files from zlib data")

                    for file_info in files:
                        file_data = file_info.get('data', b'')
                        if len(file_data) < 1024:
                            continue

                        file_type_detected = file_info.get('type', 'unknown')
                        filename = file_info.get('filename', f'extracted_{file_type_detected}.bin')

                        result = self._analyze_embedded_data(
                            data=file_data,
                            file_type=file_type_detected,
                            offset=file_info.get('offset', offset),
                            depth=depth,
                            original_type=f'zlib_extracted_{filename}'
                        )
                        if result:
                            embedded_results.append(result)
                continue

            if file_type == 'pe_file' and offset > 0:
                self._log(f"Analyzing PE at offset {offset}")
                result = self._analyze_embedded_data(
                    data=data,
                    file_type='pe_file',
                    offset=offset,
                    depth=depth,
                    original_type='binwalk_extracted'
                )
                if result:
                    embedded_results.append(result)
                continue

        return embedded_results

    def _decompress_zlib_data(self, data: bytes, offset: int) -> Optional[bytes]:
        """Decompress zlib data with multiple approaches."""
        decompressed = self.zlib_parser.decompress(data)
        if decompressed and len(decompressed) > 1024:
            return decompressed

        if hasattr(self.magic_carver, 'data') and self.magic_carver.data:
            larger_data = self.magic_carver.data[offset:offset + 65536]
            decompressed = self.zlib_parser.decompress(larger_data)
            if decompressed and len(decompressed) > 1024:
                return decompressed

        for i in range(min(1024, len(data))):
            if data[i:i+2] in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
                sub_data = data[i:]
                decompressed = self.zlib_parser.decompress(sub_data)
                if decompressed and len(decompressed) > 1024:
                    self._log(f"Found zlib header at offset {i}")
                    return decompressed

        return None

    def _prioritize_embedded_files(self, files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize embedded files by type and size."""
        priority_map = {
            'pe_file': 100,
            'elf_file': 90,
            'zip_file': 80,
            'gzip_file': 70,
            'zlib_data': 60,
            'json_data': 30,
            'xml_data': 30,
            'plaintext': 20,
            'unknown': 10,
        }

        return sorted(
            files,
            key=lambda x: (
                priority_map.get(x.get('type', 'unknown'), 0),
                x.get('size', 0)
            ),
            reverse=True
        )

    def _analyze_embedded_data(self, data: bytes, file_type: str, offset: int,
                               depth: int, original_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Analyze embedded data using a temporary file and StaticAnalyzer."""
        try:
            ext = self._get_extension_for_type(file_type)

            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                tmp.write(data)
                tmp_path = Path(tmp.name)

            hashes = self.hash_calculator.calculate_all(tmp_path)

            analyzer = StaticAnalyzer(
                tmp_path,
                verbose=self.verbose,
                no_floss=self.no_floss,
                max_recursion_depth=self.max_recursion_depth,
                use_binwalk=self.use_binwalk,
                extract_installers=self.extract_installers
            )

            analyzer.discovered_keys = self.discovered_keys.copy()
            if hasattr(analyzer.decryption_engine, '_candidate_keys'):
                analyzer.decryption_engine._candidate_keys = self.discovered_keys.copy()

            sub_report = analyzer.analyze(depth=depth)

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
                'discovered_keys': sub_report.discovered_keys,
                'full_report': sub_report.to_dict()
            }

        except Exception as e:
            self.errors.append(f"Error analyzing embedded file at offset {offset}: {e}")
            return None

    def _get_extension_for_type(self, file_type: str) -> str:
        """Get appropriate file extension for a file type."""
        ext_map = {
            'pe_file': '.exe',
            'elf_file': '.elf',
            'zip_file': '.zip',
            'gzip_file': '.gz',
            'zlib_data': '.bin',
            'json_data': '.json',
            'xml_data': '.xml',
            'plaintext': '.txt',
            'jpeg_image': '.jpg',
            'png_image': '.png',
            'pdf_file': '.pdf',
            'riff_file': '.wav',
            'unknown': '.bin',
        }
        return ext_map.get(file_type, '.bin')

    def _create_empty_report(self) -> StaticReport:
        """Create an empty report for skipped files."""
        return StaticReport(
            filename=self.file_path.name,
            size_bytes=0,
            size_mb=0,
            extension='',
            file_type='unknown',
            file_type_info={},
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

    def _combine_reports(self, analyses: List[Dict[str, Any]]) -> StaticReport:
        """Combine multiple analysis reports."""
        if not analyses:
            return self._create_empty_report()

        first = analyses[0]
        report_dict = first.get('report', {})

        # Collect all keys
        all_keys = []
        for analysis in analyses:
            all_keys.extend(analysis.get('report', {}).get('discovered_keys', []))

        # Deduplicate keys
        seen = set()
        unique_keys = []
        for key in all_keys:
            key_id = key.get('key', '')[:20]
            if key_id not in seen:
                seen.add(key_id)
                unique_keys.append(key)

        report_dict['discovered_keys'] = unique_keys
        report_dict['filename'] = self.file_path.name

        return StaticReport(**report_dict)

    def _log(self, message: str):
        """Print verbose messages if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {message}")
