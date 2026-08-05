"""Configuration extraction from PE files."""

import re
import struct
from typing import List, Dict, Any
from pathlib import Path


class ConfigExtractor:
    """Extract configuration data from PE files."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = None
        self.errors: List[str] = []
        self.DOMAIN_PATTERN = r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b'

    def extract(self) -> Dict[str, Any]:
        """Extract configuration data from the file."""
        result = {
            'ips': [],
            'domains': [],
            'urls': [],
            'emails': [],
            'registry_paths': [],
            'file_paths': [],
            'mutexes': [],
            'encryption_keys': [],
            'patterns': []
        }

        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()

            # Extract strings (ASCII)
            ascii_strings = self._extract_ascii_strings()

            # Find IP addresses
            result['ips'] = self._find_ips(ascii_strings)

            # Find domains
            result['domains'] = self._find_domains(ascii_strings)

            # Find URLs
            result['urls'] = self._find_urls(ascii_strings)

            # Find emails
            result['emails'] = self._find_emails(ascii_strings)

            # Find registry paths
            result['registry_paths'] = self._find_registry(ascii_strings)

            # Find file paths
            result['file_paths'] = self._find_file_paths(ascii_strings)

            # Find mutexes/GUIDs
            result['mutexes'] = self._find_mutexes(ascii_strings)

            # Find potential encryption keys (hex patterns)
            result['encryption_keys'] = self._find_hex_patterns()

        except Exception as e:
            self.errors.append(f"Config extraction error: {e}")

        return result

    def _extract_ascii_strings(self) -> List[str]:
        """Extract ASCII strings from binary data."""
        strings = []
        current = []

        for byte in self.data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= 4:  # Minimum string length
                    strings.append(''.join(current))
                current = []

        if len(current) >= 4:
            strings.append(''.join(current))

        return strings

    def _find_ips(self, strings: List[str]) -> List[str]:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = set()
        for s in strings:
            matches = re.findall(ip_pattern, s)
            for ip in matches:
                parts = ip.split('.')
                if all(0 <= int(p) <= 255 for p in parts):
                    # Skip version strings (like 1.1.2.2, 17.9.0.0)
                    if ip.startswith('1.') and len(ip) <= 7:
                        continue
                    if ip.startswith('17.9.') or ip.startswith('1.1.'):
                        continue
                    ips.add(ip)
        return list(ips)[:20]

    def _find_domains(self, strings: List[str]) -> List[str]:
        """Find domain names in strings with noise filtering."""
        domains = set()

        # Noise patterns to ignore
        NOISE_PATTERNS = [
            r'^[a-z]{1,3}\.[a-z]{1,3}$',      # 2-3 letter random domains (e.g., "tb.kf")
            r'^[0-9]+\.[0-9]+\.[0-9]+',        # Version strings (e.g., "1.1.2.2")
            r'^[a-z]+\.[a-z]{1,2}$',           # Short domain (e.g., "i.xo", "g.kx")
            r'(?i)system\.',                   # System.* namespaces
            r'(?i)runtime\.',                  # Runtime.* namespaces
            r'(?i)microsoft\.',                # Microsoft.* namespaces
            r'(?i)collections\.',              # Collections.* namespaces
            r'(?i)configuration\.',            # Configuration.* namespaces
            r'(?i)diagnostics\.',              # Diagnostics.* namespaces
            r'(?i)management\.',               # Management.* namespaces
            r'(?i)net\.',                      # Net.* namespaces
            r'(?i)security\.',                 # Security.* namespaces
            r'(?i)threading\.',                # Threading.* namespaces
            r'(?i)xml\.',                      # XML.* namespaces
            r'(?i)io\.',                       # IO.* namespaces
            r'(?i)text\.',                     # Text.* namespaces
            r'(?i)windows\.',                  # Windows.* namespaces
            r'(?i)aspnet\.',                   # ASP.NET namespaces
            r'(?i)system\.',                   # System.* namespaces
        ]

        for s in strings:
            matches = re.findall(self.DOMAIN_PATTERN, s)
            for domain in matches:
                domain_lower = domain.lower()

                # Skip obvious noise
                if domain.endswith('.exe') or domain.endswith('.dll'):
                    continue
                if domain.startswith('www') or domain.startswith('http'):
                    continue

                # Skip noise patterns
                is_noise = False
                for pattern in NOISE_PATTERNS:
                    if re.match(pattern, domain_lower):
                        is_noise = True
                        break
                if is_noise:
                    continue

                domains.add(domain_lower)

        return list(domains)[:20]

    def _find_urls(self, strings: List[str]) -> List[str]:
        """Find URLs in strings."""
        url_pattern = r'https?://[^\s]+'
        urls = set()
        for s in strings:
            matches = re.findall(url_pattern, s)
            urls.update(matches)
        return list(urls)[:20]

    def _find_emails(self, strings: List[str]) -> List[str]:
        """Find email addresses in strings."""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = set()
        for s in strings:
            matches = re.findall(email_pattern, s)
            emails.update(matches)
        return list(emails)[:10]

    def _find_registry(self, strings: List[str]) -> List[str]:
        """Find registry paths in strings."""
        registry_pattern = r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*'
        paths = set()
        for s in strings:
            matches = re.findall(registry_pattern, s)
            paths.update(matches)
        return list(paths)[:20]

    def _find_file_paths(self, strings: List[str]) -> List[str]:
        """Find file paths in strings."""
        path_pattern = r'[A-Za-z]:\\[^\\]+\\[^\\]+(?:\\[^\\]+)*'
        unc_pattern = r'\\\\[^\\]+\\[^\\]+(?:\\[^\\]+)*'
        paths = set()
        for s in strings:
            matches = re.findall(path_pattern, s)
            paths.update(matches)
            matches = re.findall(unc_pattern, s)
            paths.update(matches)
        return list(paths)[:20]

    def _find_mutexes(self, strings: List[str]) -> List[str]:
        """Find mutexes/GUIDs in strings."""
        guid_pattern = r'[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}'
        mutexes = set()
        for s in strings:
            matches = re.findall(guid_pattern, s)
            mutexes.update(matches)
        return list(mutexes)[:20]

    def _find_hex_patterns(self) -> List[Dict[str, Any]]:
        """Find potential encryption keys (hex patterns)."""
        patterns = []
        # Look for 32, 64, and 128 character hex strings
        hex_patterns = [
            (r'\b[A-Fa-f0-9]{32}\b', 'MD5 key'),
            (r'\b[A-Fa-f0-9]{64}\b', 'SHA256 key'),
            (r'\b[A-Fa-f0-9]{128}\b', 'SHA512 key'),
            (r'\b[A-Fa-f0-9]{40}\b', 'SHA1 key'),
        ]

        # Search in binary data for hex strings
        for pattern, description in hex_patterns:
            matches = re.findall(pattern.encode(), self.data)
            for match in matches:
                try:
                    patterns.append({
                        'hex': match.decode(),
                        'length': len(match),
                        'description': description
                    })
                except:
                    pass

        return patterns[:20]

    def get_errors(self) -> List[str]:
        """Get extraction errors."""
        return self.errors
