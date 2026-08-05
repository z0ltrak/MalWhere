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


    def __init__(self, file_path: Path, timeout: int = 300):
        """Initialize the strings parser."""
        self.file_path = file_path
        self.timeout = timeout
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

        deobfuscated = self.deobfuscator.deobfuscate(result['standard'])
        result['deobfuscated'] = deobfuscated.get('xor_decoded', []) + \
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
        """Extract deobfuscated strings using FLOSS."""
        result = {'stack_strings': [], 'decoded_strings': []}

        # Check if FLOSS is installed
        import shutil
        if not shutil.which('floss'):
            self.errors.append("FLOSS not installed")
            return result

        # Try multiple approaches with different timeouts
        approaches = [
            # Approach 1: Fastest - only stack strings
            (['floss', '--no-static', '--json', str(self.file_path)], 60),
            # Approach 2: Moderate - stack + decoded
            (['floss', '--json', str(self.file_path)], 120),
            # Approach 3: Fallback - text mode (no JSON parsing)
            (['floss', '--no-static', str(self.file_path)], 90),
            # Approach 4: Simplest - just run with defaults
            (['floss', str(self.file_path)], 60),
        ]

        for cmd, timeout in approaches:
            try:
                self.errors.append(f"Trying FLOSS with: {' '.join(cmd)} (timeout: {timeout}s)")

                proc = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=timeout
                )

                if proc.returncode == 0 and proc.stdout:
                    # Try JSON parsing first
                    if '--json' in cmd:
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
                                self.errors.append(f"FLOSS JSON succeeded with {len(result['stack_strings'])} strings")
                                return result

                        except json.JSONDecodeError:
                            # Fall through to text parsing
                            pass

                    # Text parsing
                    self._parse_floss_text_output(proc.stdout, result)
                    if result['stack_strings'] or result['decoded_strings']:
                        self.errors.append(f"FLOSS text succeeded with {len(result['stack_strings'])} strings")
                        return result

            except subprocess.TimeoutExpired:
                self.errors.append(f"FLOSS timed out with: {' '.join(cmd)}")
                continue
            except Exception as e:
                self.errors.append(f"FLOSS error: {str(e)[:100]}")
                continue

        # If we get here, all approaches failed
        self.errors.append("FLOSS all approaches failed - using standard strings only")
        return result

    def _extract_floss_text_fallback(self, result: Dict[str, List[str]]) -> None:
        """Fallback to text mode if JSON is not supported."""
        try:
            proc = subprocess.run(
                ['floss', str(self.file_path)],
                capture_output=True, text=True, timeout=self.timeout
            )
            self._parse_floss_text_output(proc.stdout, result)
        except Exception as e:
            self.errors.append(f"FLOSS text fallback failed: {e}")

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
