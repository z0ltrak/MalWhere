"""Ghidra headless analysis engine for native PE/ELF files."""

import subprocess
import json
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from .base_engine import AnalysisEngine
from ..models.report import StaticReport, StringInfo, PackerInfo, IndicatorInfo


class GhidraEngine(AnalysisEngine):
    """Ghidra headless analysis engine for native PE/ELF."""

    SUPPORTED_TYPES = ['pe_native', 'pe_file', 'elf_file']

    def __init__(self, verbose: bool = False, timeout: int = 600):
        """Initialize the engine and locate the ghidra-headless binary, if installed.

        Args:
            verbose: Enable verbose progress logging.
            timeout: Timeout in seconds for the ghidra-headless subprocess.
        """
        self.verbose = verbose
        self.timeout = timeout
        self.ghidra_bin = shutil.which('ghidra-headless')
        self.errors: List[str] = []
        self.script_dir = Path(__file__).parent.parent / 'ghidra_scripts'

    def supports_file(self, file_type: str) -> bool:
        """Check if this engine supports the given file type.

        Args:
            file_type: Detected file type string.

        Returns:
            True if file_type is supported and ghidra-headless is installed.
        """
        return file_type in self.SUPPORTED_TYPES and self.ghidra_bin is not None

    def get_name(self) -> str:
        return "Ghidra Headless"

    def analyze(self, file_path: Path, depth: int = 0) -> StaticReport:
        """Run Ghidra headless analysis on a native PE/ELF file.

        Args:
            file_path: Path to the file to analyze.
            depth: Current recursion depth, used only for logging.

        Returns:
            The completed StaticReport, or an empty report tagged with an
            error if Ghidra isn't available, times out, or fails.
        """
        self._log(f"Running Ghidra analysis on {file_path.name} (depth {depth})")

        if not self.ghidra_bin:
            self.errors.append("Ghidra headless not found")
            return self._create_empty_report(file_path, "Ghidra not available")

        if not self.script_dir.exists():
            self.script_dir.mkdir(parents=True, exist_ok=True)
            self._create_ghidra_script()

        with tempfile.TemporaryDirectory(prefix='ghidra_') as tmpdir:
            project_dir = Path(tmpdir) / 'project'
            project_dir.mkdir()

            cmd = [
                self.ghidra_bin,
                str(project_dir),
                'malwhere_analysis',
                '-import', str(file_path),
                '-scriptPath', str(self.script_dir),
                '-postScript', 'ghidra_analysis.py',
                '-deleteProject'
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )

                if proc.returncode != 0:
                    self.errors.append(f"Ghidra failed: {proc.stderr[:200]}")
                    return self._create_empty_report(file_path, "Ghidra analysis failed")

                output_file = Path('/workspace/ghidra_results.json')
                if output_file.exists():
                    with open(output_file) as f:
                        data = json.load(f)
                    output_file.unlink()
                    return self._build_report_from_ghidra(file_path, data)
                else:
                    self.errors.append("Ghidra output file not found")
                    return self._create_empty_report(file_path, "No output from Ghidra")

            except subprocess.TimeoutExpired:
                self.errors.append(f"Ghidra timed out after {self.timeout}s")
                return self._create_empty_report(file_path, "Ghidra timeout")
            except Exception as e:
                self.errors.append(f"Ghidra error: {e}")
                return self._create_empty_report(file_path, str(e))

    def _create_ghidra_script(self):
        """Create the Ghidra analysis script."""
        script_content = '''# ghidra_analysis.py - MalWhere Ghidra Script
import json
import re
from datetime import datetime

class Analyzer:
    def __init__(self, program):
        self.program = program
        self.listing = program.getListing()
        self.memory = program.getMemory()
        self.results = {
            'file_info': {},
            'exports': [],
            'functions': [],
            'strings': [],
            'xor_decrypted': [],
            'rc4_keys': [],
            'c2_indicators': [],
            'suspicious_imports': [],
            'call_graph': []
        }

    def analyze(self):
        self._analyze_file_info()
        self._analyze_exports()
        self._analyze_functions()
        self._analyze_strings()
        self._analyze_xor_strings()
        self._analyze_rc4()
        self._analyze_c2()
        self._analyze_call_graph()
        return self.results

    def _analyze_file_info(self):
        info = self.program.getExecutableInfo()
        self.results['file_info'] = {
            'name': self.program.getName(),
            'format': str(self.program.getLanguage()),
            'entry_point': str(self.program.getEntryPoint())
        }

    def _analyze_strings(self):
        strings = self.listing.getDefinedData(True)
        for s in strings:
            if s.getDataType().getName() == "string":
                try:
                    text = s.getBytes().decode('utf-8', errors='ignore').rstrip('\\x00')
                    if len(text) >= 4:
                        self.results['strings'].append({
                            'string': text,
                            'offset': s.getAddress().getOffset()
                        })
                except Exception:
                    pass

    def _analyze_xor_strings(self):
        # Try common XOR keys
        xor_keys = [0x5A, 0x1E, 0x2F, 0x3F, 0x4F, 0x5F, 0x6F, 0x7F]
        data_items = self.listing.getDefinedData(True)

        for item in data_items:
            if item.getDataType().getName() == "string":
                continue
            try:
                data = item.getBytes()
                if len(data) < 10:
                    continue
                for key in xor_keys:
                    decoded = bytes([b ^ key for b in data])
                    try:
                        s = decoded.decode('ascii', errors='ignore')
                        if len(s) >= 10 and s.isalnum():
                            self.results['xor_decrypted'].append({
                                'xor_key': hex(key),
                                'decrypted': s,
                                'offset': item.getAddress().getOffset()
                            })
                    except Exception:
                        pass
            except Exception:
                pass

    def _analyze_rc4(self):
        # Look for RC4 patterns
        func_manager = self.program.getFunctionManager()
        funcs = func_manager.getFunctions(True)
        for func in funcs:
            if 'S[' in str(func.getBody()) and '256' in str(func.getBody()):
                # Extract potential key
                instructions = self.listing.getInstructions(func.getBody(), True)
                for ins in instructions:
                    if 'data' in ins.toString():
                        match = re.search(r'[0-9a-fA-F]{4,}', ins.toString())
                        if match:
                            try:
                                hex_str = match.group()
                                key_bytes = bytes.fromhex(hex_str)
                                key = key_bytes.decode('ascii', errors='ignore')
                                if len(key) >= 10 and key.isalnum():
                                    self.results['rc4_keys'].append({
                                        'function': func.getName(),
                                        'key': key,
                                        'address': str(func.getEntryPoint())
                                    })
                                    break
                            except Exception:
                                pass

    def _analyze_exports(self):
        for exp in self.listing.getExports():
            self.results['exports'].append({
                'name': exp.getName(),
                'address': str(exp.getAddress())
            })

    def _analyze_c2(self):
        # Look for IP addresses and domains in data
        text = str(self.memory.getAllBytes())
        # Simple patterns
        ip_pattern = re.compile(r'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}')
        for match in ip_pattern.finditer(text):
            ip = match.group()
            if not ip.startswith('1.'):
                self.results['c2_indicators'].append({
                    'type': 'ip',
                    'value': ip
                })

        domain_pattern = re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]*\\.[a-zA-Z]{2,}')
        for match in domain_pattern.finditer(text):
            domain = match.group()
            if not any(noise in domain for noise in ['.dll', '.exe', '.sys']):
                self.results['c2_indicators'].append({
                    'type': 'domain',
                    'value': domain
                })

    def _analyze_call_graph(self):
        func_manager = self.program.getFunctionManager()
        funcs = func_manager.getFunctions(True)
        for func in funcs:
            calls = self.listing.getCallsFrom(func.getBody())
            if calls:
                call_info = {
                    'from': func.getName(),
                    'calls': []
                }
                for call in calls:
                    dest = func_manager.getFunctionAt(call.getAddress())
                    if dest:
                        call_info['calls'].append(dest.getName())
                if call_info['calls']:
                    self.results['call_graph'].append(call_info)

def main():
    program = getCurrentProgram()
    analyzer = Analyzer(program)
    results = analyzer.analyze()
    results['timestamp'] = datetime.now().isoformat()

    with open('/workspace/ghidra_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print("Analysis complete")

if __name__ == '__main__':
    main()
'''
        script_file = self.script_dir / 'ghidra_analysis.py'
        script_file.write_text(script_content)

    def _build_report_from_ghidra(self, file_path: Path, data: Dict[str, Any]) -> StaticReport:
        """Build a StaticReport from the Ghidra post-script's JSON results.

        Args:
            file_path: Path to the analyzed file, for basic file info.
            data: Parsed ghidra_results.json content.

        Returns:
            A StaticReport with strings, exports, config IOCs, and discovered keys.
        """
        from ..models.report import StaticReport, StringInfo, PackerInfo, IndicatorInfo, YaraResult, EntropyAnalysis

        strings = data.get('strings', [])
        standard_strings = [s['string'] for s in strings if len(s.get('string', '')) >= 4]

        discovered_keys = []
        for item in data.get('xor_decrypted', []):
            discovered_keys.append({
                'type': 'xor_decrypted',
                'key': item['decrypted'],
                'xor_key': item['xor_key'],
                'offset': item['offset'],
                'source': 'ghidra',
                'confidence': 'high'
            })

        for item in data.get('rc4_keys', []):
            discovered_keys.append({
                'type': 'rc4_key',
                'key': item['key'],
                'function': item['function'],
                'source': 'ghidra',
                'confidence': 'high'
            })

        config = {
            'ips': [],
            'domains': [],
            'urls': []
        }
        for item in data.get('c2_indicators', []):
            if item['type'] == 'ip':
                config['ips'].append(item['value'])
            elif item['type'] == 'domain':
                config['domains'].append(item['value'])

        exports = []
        for exp in data.get('exports', []):
            exports.append({
                'name': exp['name'],
                'address': exp['address']
            })

        return StaticReport(
            filename=file_path.name,
            size_bytes=file_path.stat().st_size,
            size_mb=file_path.stat().st_size / (1024 * 1024),
            extension=file_path.suffix,
            file_type='pe_native',
            file_type_info={'analyzer': 'ghidra'},
            strings=StringInfo(standard=standard_strings[:5000]),
            exports=exports,
            config=config,
            discovered_keys=discovered_keys,
            packer=PackerInfo(),
            indicators=IndicatorInfo(),
            yara=YaraResult(),
            entropy_analysis=EntropyAnalysis()
        )

    def _create_empty_report(self, file_path: Path, error: str) -> StaticReport:
        """Build a minimal StaticReport carrying only basic file info and an error.

        Args:
            file_path: Path to the file, for basic file info.
            error: Error message to record.

        Returns:
            A StaticReport with file_type='unknown' and no analysis content.
        """
        from ..models.report import StaticReport
        return StaticReport(
            filename=file_path.name,
            size_bytes=file_path.stat().st_size,
            size_mb=file_path.stat().st_size / (1024 * 1024),
            extension=file_path.suffix,
            file_type='unknown',
            errors=[error]
        )

    def _log(self, message: str):
        if self.verbose:
            print(f"[*] {self.get_name()}: {message}")
