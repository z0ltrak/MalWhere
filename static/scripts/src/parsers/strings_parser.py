"""Strings extraction module for static analysis."""

import json
import subprocess
import re
from typing import List, Dict, Any
from pathlib import Path
from ..deobfuscators.string_deobfuscator import StringDeobfuscator
from ..detectors.crypto_detector import CryptoDetector


class StringsParser:
    """Extract and analyze strings from PE files."""

    SUSPICIOUS_PATTERNS = [
        (r'https?://[^\s]+', 'URL'),
        (r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?', 'Domain'),
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP Address'),
        (r'[A-Fa-f0-9]{32}', 'MD5 Hash'),
        (r'[A-Fa-f0-9]{40}', 'SHA1 Hash'),
        (r'[A-Fa-f0-9]{64}', 'SHA256 Hash'),
        (r'HKEY_[A-Z_]+\\[^\\]+', 'Registry Path'),
        (r'[A-Za-z]:\\[^\\]+\\[^\\]+', 'Windows Path'),
        (r'\\\\.*\\\\[^\\]+\\\\[^\\]+', 'UNC Path'),
        (r'[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}', 'GUID/Mutex'),
        (r'(?i)ransom|encrypt|decrypt|bitcoin|lock|pay|key', 'Ransomware Indicator'),
        (r'(?i)steal|password|cookie|credential|log|dump', 'Stealer Indicator'),
        (r'(?i)inject|injector|load|loader|dropper', 'Loader Indicator'),
        (r'(?i)cmd\.exe|powershell|wscript|cscript|rundll32', 'Execution Indicator'),
        (r'(?i)admin|uac|bypass|elevat', 'Privilege Escalation'),
        (r'(?i)sandbox|debug|virtual|vmware|vbox|xen|hyper-v', 'VM/DBG Detection'),
        (r'(?i)wine|getversion|getproductinfo', 'Environment Detection'),
        (r'(?i)svchost|explorer|winlogon|lsass|services', 'Process Spoofing'),
        (r'[A-Za-z0-9+/]{16,}={0,2}', 'Base64 Pattern'),
        (r'expand 32-byte k', 'ChaCha20 encryption (T1486)'),
        (r'expand 16-byte k', 'ChaCha20 encryption (T1486)'),
        (r'RC4', 'RC4 encryption (T1486)'),
        (r'AES', 'AES encryption (T1486)'),
        (r'RSA', 'RSA encryption (T1486)'),
        (r'XOR', 'XOR encryption (T1140)'),
        (r'SHA-?256', 'SHA-256 hashing (T1486)'),
        (r'MD5', 'MD5 hashing (T1486)'),
    ]


    def __init__(self, file_path: Path, timeout: int = 300, verbose: bool = False):
        """Initialize the strings parser."""
        self.file_path = file_path
        self.timeout = timeout
        self.verbose = verbose
        self.errors: List[str] = []
        self.deobfuscator = StringDeobfuscator()
        self.crypto_detector = CryptoDetector()

    def extract(self, include_floss: bool = True) -> Dict[str, List[str]]:
        """Extract strings using strings command and optionally FLOSS."""
        result = {
            'standard': self._extract_standard_strings(),
            'floss': [],
            'decoded': []
        }

        if include_floss:
            floss_result = self._extract_floss_strings()
            result['floss'] = floss_result['stack_strings']
            result['decoded'] = floss_result['decoded_strings']

        # Previously omitted 'pattern_decoded' (single-byte XOR bruteforce
        # results) from this merge entirely -- its output was computed but
        # then silently discarded before reaching the report or the ATT&CK
        # mapper, making that whole code path dead weight.
        deobfuscated = self.deobfuscator.deobfuscate(result['standard'])
        result['deobfuscated'] = deobfuscated.get('xor_decoded', []) + \
                                deobfuscated.get('pattern_decoded', []) + \
                                deobfuscated.get('base64_decoded', []) + \
                                deobfuscated.get('hex_decoded', [])

        return result

    def _extract_standard_strings(self) -> List[str]:
        """Extract strings using the standard strings command."""
        try:
            result = subprocess.run(
                ['strings', '-n', '6', str(self.file_path)],
                capture_output=True, text=True, timeout=60
            )
            strings = [s for s in result.stdout.split('\n') if len(s) > 0]
            return strings[:5000]
        except subprocess.TimeoutExpired:
            self.errors.append("strings command timed out")
            return []
        except Exception as e:
            self.errors.append(f"Error extracting strings: {e}")
            return []

    def _extract_floss_strings(self) -> Dict[str, List[str]]:
        """Extract deobfuscated strings using FLOSS.

        Previously used `--no-static`/`--json` as single hyphenated
        tokens -- neither exists in the installed FLOSS version (3.1.1);
        its real CLI takes `--no static` (a value-taking flag, needs a
        `--` separator before the positional sample path or argparse
        swallows the path as another value) and `-j`/`--json` (which
        WAS valid, it just never got read because argument parsing
        failed before that point). Every one of the 4 old fallback
        attempts either hit this same broken `--no-static` token or (the
        4th, flag-free one) silently became FLOSS's slowest possible
        invocation -- full static+stack+tight+decoded analysis -- run as
        a last resort on every single file, every single time, its
        result then discarded because the surrounding retry logic still
        logged "FLOSS all approaches failed" whenever text-mode parsing
        didn't find anything (also just fixed by trusting JSON, which
        now actually gets reached). FLOSS only supports PE for
        string-decoding/stackstrings -- skip it entirely for non-PE data
        instead of letting it fail on, say, a BMP resource.
        """
        result = {'stack_strings': [], 'decoded_strings': []}

        import shutil
        if not shutil.which('floss'):
            self.errors.append("FLOSS not installed")
            return result

        if not self._looks_like_pe():
            self._log("Skipping FLOSS: not a PE file (FLOSS only supports PE for string decoding)")
            return result

        # Fast mode first (skip static strings -- the `strings` command
        # already covers those; FLOSS's real value is stack/tight/decoded
        # strings). Full mode only as a fallback if that finds nothing.
        approaches = [
            (['floss', '--no', 'static', '--json', '--', str(self.file_path)], 60),
            (['floss', '--json', '--', str(self.file_path)], 90),
        ]

        for cmd, timeout in approaches:
            try:
                self._log(f"Trying FLOSS with: {' '.join(cmd)} (timeout: {timeout}s)")

                proc = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=timeout
                )

                if proc.returncode == 0 and proc.stdout:
                    try:
                        data = json.loads(proc.stdout)
                        strings_data = data.get('strings', {})

                        stack_strings = strings_data.get('stack_strings', [])
                        result['stack_strings'] = [
                            s.get('string', str(s)) if isinstance(s, dict) else str(s)
                            for s in stack_strings
                        ][:1000]

                        decoded_strings = strings_data.get('decoded_strings', [])
                        result['decoded_strings'] = [
                            s.get('string', str(s)) if isinstance(s, dict) else str(s)
                            for s in decoded_strings
                        ][:1000]

                        if result['stack_strings'] or result['decoded_strings']:
                            self._log(f"FLOSS succeeded with {len(result['stack_strings'])} stack strings")
                            return result

                    except json.JSONDecodeError:
                        self._parse_floss_text_output(proc.stdout, result)
                        if result['stack_strings'] or result['decoded_strings']:
                            return result

            except subprocess.TimeoutExpired:
                self.errors.append(f"FLOSS timed out with: {' '.join(cmd)}")
                continue
            except Exception as e:
                self.errors.append(f"FLOSS error: {str(e)[:100]}")
                continue

        self._log("FLOSS found no stack/decoded strings -- using standard strings only")
        return result

    def _looks_like_pe(self) -> bool:
        """Cheap MZ-header check -- FLOSS only supports PE for string decoding."""
        try:
            with open(self.file_path, 'rb') as f:
                return f.read(2) == b'MZ'
        except Exception:
            return False

    def _log(self, message: str) -> None:
        """Verbose-gated progress logging -- NOT an error, don't append to self.errors."""
        if self.verbose:
            print(f"[*] StringsParser: {message}")

    def _parse_floss_text_output(self, text_output: str, result: Dict[str, List[str]]) -> None:
        """Parse FLOSS text output as fallback."""
        lines = text_output.split('\n')
        capture_stack = False
        capture_decoded = False

        for line in lines:
            if 'Stack Strings' in line:
                capture_stack = True
                capture_decoded = False
                continue
            elif 'Decoded Strings' in line:
                capture_stack = False
                capture_decoded = True
                continue
            elif line.strip().startswith('---') or line.strip().startswith('['):
                continue

            if capture_stack and line.strip():
                parts = line.split(':', 1)
                result['stack_strings'].append(parts[1].strip() if len(parts) == 2 else line.strip())
            elif capture_decoded and line.strip():
                result['decoded_strings'].append(line.strip())

        result['stack_strings'] = result['stack_strings'][:1000]
        result['decoded_strings'] = result['decoded_strings'][:1000]

    def find_suspicious(self, strings: List[str]) -> List[Dict[str, str]]:
        """Find suspicious patterns in strings."""
        found = []
        for s in strings:
            for pattern, description in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, s):
                    found.append({
                        'string': s[:50] + '...' if len(s) > 50 else s,
                        'description': description
                    })
                    break
        return found[:100]

    def get_errors(self) -> List[str]:
        """Get extraction errors."""
        return self.errors

    def find_crypto_patterns(self, strings: List[str]) -> List[Dict[str, str]]:
        """Find cryptographic algorithm patterns in strings."""
        return self.crypto_detector.detect_in_strings(strings)

    def find_potential_keys(self, strings: List[str]) -> List[Dict[str, str]]:
        """Find potential encryption keys in strings."""
        return self.crypto_detector.detect_keys(strings)
