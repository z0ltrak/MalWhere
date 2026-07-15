"""Strings extraction module for static analysis"""
import subprocess
import re
from typing import List, Dict, Any, Optional
from pathlib import Path


"""Extract and analyze strings from PE files"""
class StringsParser:

    # Suspicious patterns for string analysis
    SUSPICIOUS_PATTERNS = [
        # URLs and domains
        (r'https?://[^\s]+', 'URL'),
        (r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?', 'Domain'),
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP Address'),

        # Crypto
        (r'[A-Fa-f0-9]{32}', 'MD5 Hash'),
        (r'[A-Fa-f0-9]{40}', 'SHA1 Hash'),
        (r'[A-Fa-f0-9]{64}', 'SHA256 Hash'),

        # Registry
        (r'HKEY_[A-Z_]+\\[^\\]+', 'Registry Path'),

        # File paths
        (r'[A-Za-z]:\\[^\\]+\\[^\\]+', 'Windows Path'),
        (r'\\\\.*\\\\[^\\]+\\\\[^\\]+', 'UNC Path'),

        # Mutexes/GUIDs
        (r'[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}', 'GUID/Mutex'),

        # Malware keywords
        (r'(?i)ransom|encrypt|decrypt|bitcoin|lock|pay|key', 'Ransomware Indicator'),
        (r'(?i)steal|password|cookie|credential|log|dump', 'Stealer Indicator'),
        (r'(?i)inject|injector|load|loader|dropper', 'Loader Indicator'),
        (r'(?i)cmd\.exe|powershell|wscript|cscript|rundll32', 'Execution Indicator'),
        (r'(?i)admin|uac|bypass|elevat', 'Privilege Escalation'),

        # Anti-debug/VM
        (r'(?i)sandbox|debug|virtual|vmware|vbox|xen|hyper-v', 'VM/DBG Detection'),
        (r'(?i)wine|getversion|getproductinfo', 'Environment Detection'),

        # Process names
        (r'(?i)svchost|explorer|winlogon|lsass|services', 'Process Spoofing'),

        # Base64
        (r'[A-Za-z0-9+/]{16,}={0,2}', 'Base64 Pattern'),
    ]


    def __init__(self, file_path: Path, timeout: int = 120):
        self.file_path = file_path
        self.timeout = timeout
        self.errors: List[str] = []


    """Extract strings using strings command and optionally FLOSS"""
    def extract(self, include_floss: bool = True) -> Dict[str, List[str]]:
        result = {
            'standard': self._extract_standard_strings(),
            'floss': [],
            'decoded': []
        }

        if include_floss:
            floss_result = self._extract_floss_strings()
            result['floss'] = floss_result['stack_strings']
            result['decoded'] = floss_result['decoded_strings']

        return result


    """Extract strings using the standard strings command"""
    def _extract_standard_strings(self) -> List[str]:
        try:
            result = subprocess.run(
                ['strings', '-n', '6', str(self.file_path)],
                capture_output=True, text=True, timeout=self.timeout
            )
            strings = [s for s in result.stdout.split('\n') if len(s) > 0]
            return strings[:5000]  # Limit for performance
        except subprocess.TimeoutExpired:
            self.errors.append("strings command timed out")
            return []
        except Exception as e:
            self.errors.append(f"Error extracting strings: {e}")
            return []


    """Extract deobfuscated strings using FLOSS"""
    def _extract_floss_strings(self) -> Dict[str, List[str]]:
        result = {'stack_strings': [], 'decoded_strings': []}

        try:
            proc = subprocess.run(
                ['floss', str(self.file_path), '--no-static'],
                capture_output=True, text=True, timeout=self.timeout
            )

            # Parse FLOSS output
            lines = proc.stdout.split('\n')
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

            # Limit results
            result['stack_strings'] = result['stack_strings'][:1000]
            result['decoded_strings'] = result['decoded_strings'][:1000]

        except subprocess.TimeoutExpired:
            self.errors.append("FLOSS command timed out")
        except Exception as e:
            self.errors.append(f"Error running FLOSS: {e}")

        return result


    """Find suspicious patterns in strings"""
    def find_suspicious(self, strings: List[str]) -> List[Dict[str, str]]:
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


    """Get extraction errors"""
    def get_errors(self) -> List[str]:
        return self.errors
