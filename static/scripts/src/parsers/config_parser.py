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
            'patterns': [],
            'xor_recovered_iocs': [],
        }

        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()

            # Extract strings (ASCII)
            ascii_strings = self._extract_ascii_strings()

            # Find IP addresses
            result['ips'] = self._find_ips(ascii_strings)

            # Find IPs hidden behind single-byte XOR obfuscation -- a
            # generic recovery technique (256 keys is exhaustive, no
            # sample-specific key needed), not something scoped to any
            # one family. Found auditing RoningLoader's diamondage.exe:
            # its C2 address is 202.95.11.173, single-byte XOR'd with
            # 0x61, invisible to plain ASCII string extraction but
            # trivially recoverable this way.
            xor_ips = self._find_xor_obfuscated_ips()
            for hit in xor_ips:
                if hit['ip'] not in result['ips']:
                    result['ips'].append(hit['ip'])
            result['xor_recovered_iocs'] = xor_ips

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

    # Cap the exhaustive 256-key scan to files where it stays fast --
    # bytes.translate() is C-speed so even a few MB is well under a
    # second per key, but there's no reason to run it against a 50MB+
    # binary when the C2-config region it's meant to catch is always tiny.
    _XOR_SCAN_MAX_SIZE = 10_000_000

    # A key whose decode produces more than this many dotted-quad-shaped
    # regex matches gets discarded outright, not just filtered hit-by-hit.
    # Verified this is necessary, not just extra caution: on a real sample,
    # key 0x2e (0x00 XORs to '.', i.e. this key turns any run of null
    # padding into literal dots) decoded a repeating table of small
    # integers into an unbroken chain of 8 "IPs" -- 9.8.6.8, 4.7.5.7,
    # 2.7.3.7, ... -- every single one individually passing the boundary
    # check below, because the null bytes that make it a "clean boundary"
    # are exactly what's generating the fake dots in the first place. A
    # real embedded C2 string is isolated; a cascade of matches from one
    # key is structural noise. The true positive this method is built
    # for (RoningLoader's C2 address) produced exactly 1 match for its key.
    _XOR_MAX_MATCHES_PER_KEY = 2

    def _find_xor_obfuscated_ips(self) -> List[Dict[str, Any]]:
        """Brute-force all 256 single-byte XOR keys looking for an IPv4
        address that decodes cleanly -- i.e. immediately bounded by bytes
        that are either 0x00 or equal to the XOR key itself (both are what
        zero-padding around the string looks like once XOR'd: 0x00 stays
        0x00 if it's outside the XOR'd region, or becomes the key's own
        byte value if it's zero-padding *inside* the XOR'd region), AND
        that key doesn't also decode a run of other dotted-quad-shaped
        matches nearby (see _XOR_MAX_MATCHES_PER_KEY) -- packed/compiled
        code XOR'd with the "wrong" key routinely decodes into
        coincidental-looking dotted-quads, and without both filters this
        produces constant false-positive noise.
        """
        if not self.data or len(self.data) > self._XOR_SCAN_MAX_SIZE:
            return []

        ip_re = re.compile(rb'(?:\d{1,3}\.){3}\d{1,3}')
        found: Dict[str, int] = {}

        for key in range(1, 256):
            table = bytes(b ^ key for b in range(256))
            xored = self.data.translate(table)
            raw_matches = list(ip_re.finditer(xored))
            if len(raw_matches) > self._XOR_MAX_MATCHES_PER_KEY:
                continue

            for m in raw_matches:
                ip = m.group().decode()
                parts = ip.split('.')
                if not all(0 <= int(p) <= 255 for p in parts):
                    continue
                # Same junk filter _find_ips applies to plaintext hits.
                if ip.startswith('1.') and len(ip) <= 7:
                    continue
                if ip.startswith('17.9.') or ip.startswith('1.1.') or ip.startswith('0.'):
                    continue

                start, end = m.span()
                raw_before = self.data[start - 1] if start > 0 else 0
                raw_after = self.data[end] if end < len(self.data) else 0
                clean_boundary = raw_before in (0, key) and raw_after in (0, key)

                if clean_boundary and ip not in found:
                    found[ip] = key

        return [{'ip': ip, 'xor_key': f'0x{key:02x}'} for ip, key in found.items()][:10]

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
                except Exception:
                    pass

        return patterns[:20]

    def get_errors(self) -> List[str]:
        """Get extraction errors."""
        return self.errors
