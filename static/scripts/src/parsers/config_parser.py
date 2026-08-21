"""Configuration extraction from PE files."""

import re
import struct
from collections import Counter
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
        """Extract configuration data (IPs, domains, URLs, emails, registry/file paths, mutexes, keys) from the file.

        Returns:
            Dict with ips, domains, urls, emails, registry_paths, file_paths,
            mutexes, encryption_keys, patterns, and xor_recovered_iocs lists.
        """
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

            ascii_strings = self._extract_ascii_strings()
            result['ips'] = self._find_ips(ascii_strings)

            # Single-byte XOR is exhaustive (256 keys, no sample-specific
            # key needed) and generic across families, not scoped to one.
            xor_ips = self._find_xor_obfuscated_ips()
            for hit in xor_ips:
                if hit['ip'] not in result['ips']:
                    result['ips'].append(hit['ip'])
            result['xor_recovered_iocs'] = xor_ips

            result['domains'] = self._find_domains(ascii_strings)
            result['urls'] = self._find_urls(ascii_strings)
            result['emails'] = self._find_emails(ascii_strings)
            result['registry_paths'] = self._find_registry(ascii_strings)
            result['file_paths'] = self._find_file_paths(ascii_strings)
            result['mutexes'] = self._find_mutexes(ascii_strings)
            result['encryption_keys'] = self._find_hex_patterns()

        except Exception as e:
            self.errors.append(f"Config extraction error: {e}")

        return result

    def _extract_ascii_strings(self) -> List[str]:
        """Extract ASCII strings from binary data.

        Returns:
            Printable-ASCII runs of at least 4 characters.
        """
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

    # X.509 certificate-attribute/extension OID arcs ("2.5.4.*",
    # "2.5.29.*") are complete, correctly-bounded dotted-decimal tokens
    # that appear verbatim in almost any Authenticode-signed PE's
    # embedded certificate -- among the most standardized OID prefixes
    # there are, so treated as never a real C2 IP.
    _OID_IP_PREFIXES = ('2.5.4.', '2.5.29.')

    def _find_ips(self, strings: List[str]) -> List[str]:
        """Find IPv4 addresses in strings, filtering out version numbers and OID fragments.

        Args:
            strings: Extracted ASCII strings.

        Returns:
            Up to 20 candidate IPs.
        """
        # Negative lookaround excludes matches that are a 4-group window
        # sliced out of a longer dotted-decimal chain (e.g. an OID like
        # "2.16.840.1.101.3.4.2.4"), which \b alone can't catch since it
        # only checks one adjacent character, not whether more
        # digits-and-dots continue past it.
        ip_pattern = r'(?<!\d\.)\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\.\d)'
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
                    if ip.startswith(self._OID_IP_PREFIXES):
                        continue
                    # PE/.NET assembly version numbers (MAJOR.MINOR.
                    # BUILD.REVISION) are dotted-quads too, and their
                    # trailing fields are conventionally 0 far more often
                    # than a real C2 IP's octets are.
                    if sum(1 for p in parts[1:] if p == '0') >= 2:
                        continue
                    ips.add(ip)
        return list(ips)[:20]

    # Cap the exhaustive 256-key scan to files where it stays fast --
    # there's no reason to run it against a 50MB+ binary when the
    # C2-config region it's meant to catch is always tiny.
    _XOR_SCAN_MAX_SIZE = 10_000_000

    # A key whose decode produces more than this many dotted-quad-shaped
    # matches is discarded outright: a repeating null-padding or
    # structural-table region routinely decodes into a cascade of
    # coincidental "IPs" under the wrong key, while a real embedded C2
    # string is isolated (typically exactly 1 match for its true key).
    _XOR_MAX_MATCHES_PER_KEY = 2

    def _find_xor_obfuscated_ips(self) -> List[Dict[str, Any]]:
        """Brute-force all 256 single-byte XOR keys for an IPv4 address
        that decodes cleanly: immediately bounded by bytes that are
        either 0x00 or equal to the XOR key itself (both are what
        zero-padding looks like once XOR'd), and whose key doesn't also
        decode a cascade of other dotted-quad matches nearby (see
        _XOR_MAX_MATCHES_PER_KEY) -- without both filters, packed/
        compiled code XOR'd with the "wrong" key produces constant
        false-positive noise.

        Returns:
            One dict per recovered IP with its XOR key, deduplicated.
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
                # Stricter than _find_ips's plaintext threshold (2+ zero
                # octets): brute-forcing 256 keys against arbitrary binary
                # is a much higher false-positive-risk source than one
                # targeted regex pass, so even a single zero octet is
                # treated as the same null-padding signature
                # _XOR_MAX_MATCHES_PER_KEY guards against (a real .NET
                # assembly version tuple like "3.2.0.2" explains this
                # shape far better than a C2 address does).
                if sum(1 for p in parts[1:] if p == '0') >= 1:
                    continue
                # A repeating non-zero byte in a structural padding/
                # alignment table decodes to a near-identical octet run
                # just as readily as null-padding does. A real routable
                # IP essentially never has 3 of its 4 octets numerically
                # identical.
                if max(Counter(parts).values()) >= 3:
                    continue

                start, end = m.span()
                raw_before = self.data[start - 1] if start > 0 else 0
                raw_after = self.data[end] if end < len(self.data) else 0
                clean_boundary = raw_before in (0, key) and raw_after in (0, key)

                if clean_boundary and ip not in found:
                    found[ip] = key

        return [{'ip': ip, 'xor_key': f'0x{key:02x}'} for ip, key in found.items()][:10]

    # Curated allowlist of real TLDs (not the full ~1500-entry IANA list):
    # gTLDs/ccTLDs actually seen in malware C2 infrastructure plus major
    # country/region ccTLDs, so a dotted string with a fabricated "TLD"
    # (.editors, .misc, .system -- misparsed from .NET/C++ identifiers)
    # is rejected outright rather than relying on a namespace denylist.
    _VALID_TLDS = frozenset({
        'com', 'net', 'org', 'info', 'biz', 'name', 'pro', 'mobi', 'asia',
        'tel', 'xxx', 'coop', 'museum', 'aero', 'jobs', 'travel',
        'xyz', 'top', 'club', 'online', 'site', 'live', 'life', 'click',
        'link', 'icu', 'buzz', 'work', 'host', 'space', 'store', 'tech',
        'dev', 'app', 'cloud', 'email', 'download', 'win', 'bid', 'loan',
        'men', 'date', 'review', 'science', 'party', 'trade', 'accountant',
        'stream', 'gdn', 'vip', 'fun', 'rest', 'cyou', 'monster', 'sbs',
        'io', 'co', 'me', 'cc', 'tv', 'ws', 'to', 'sh', 'nu', 'la', 'fm',
        'ac', 'gg', 'je', 'im', 'is', 'li', 'ai', 'gl',
        'onion',
        'us', 'uk', 'de', 'fr', 'nl', 'ru', 'cn', 'jp', 'kr', 'in', 'br',
        'au', 'ca', 'es', 'it', 'pl', 'se', 'no', 'fi', 'dk', 'ch', 'at',
        'be', 'cz', 'gr', 'pt', 'ro', 'hu', 'ua', 'by', 'kz', 'tr', 'ir',
        'sa', 'ae', 'il', 'eg', 'za', 'ng', 'ke', 'mx', 'ar', 'cl', 'pe',
        've', 'id', 'vn', 'th', 'my', 'ph', 'sg', 'hk', 'tw', 'nz', 'ie',
        'lu', 'mc', 'sm', 'va', 'ad', 'mt', 'cy', 'ee', 'lv', 'lt', 'si',
        'sk', 'bg', 'hr', 'rs', 'ba', 'mk', 'al', 'md', 'ge', 'am', 'az',
        'uz', 'tm', 'kg', 'tj', 'mn', 'np', 'lk', 'bd', 'pk', 'af', 'iq',
        'sy', 'jo', 'lb', 'kw', 'qa', 'bh', 'om', 'ye', 'ly', 'tn', 'dz',
        'ma', 'sd', 'et', 'gh', 'tz', 'ug', 'zm', 'zw', 'mz', 'ao', 'cm',
        'ci', 'sn', 'ml', 'bf', 'ne', 'td', 'cf', 'cg', 'cd', 'ga', 'gq',
        'gw', 'gm', 'lr', 'sl', 'tg', 'bj', 'mr', 'dj', 'so', 'er', 'rw',
        'bi', 'mw', 'na', 'bw', 'ls', 'sz', 'mg', 'mu', 'sc', 'km', 'cv',
        'st', 'tk', 'ga',
    })

    # Filename/debug/source-code extensions that the domain regex can
    # mis-tokenize as a fake TLD when they follow a real one, or are
    # themselves short enough to slip past other checks (e.g. "sdk.sample").
    _NON_DOMAIN_EXTENSIONS = (
        '.exe', '.dll', '.sys', '.ocx', '.drv', '.cpl', '.pdb', '.obj',
        '.lib', '.rs', '.c', '.cpp', '.cc', '.h', '.hpp', '.cs', '.py',
        '.go', '.java', '.rc', '.sample', '.config',
    )

    def _find_domains(self, strings: List[str]) -> List[str]:
        """Find domain names in strings with noise filtering.

        Three independent filters catch distinct classes of false
        positive from .NET/C++ identifiers mis-tokenized as domains:
        known non-domain extensions (source/debug file references like
        wtf8.rs), a TLD allowlist (rejects fabricated "TLDs" like
        .editors, .misc), and compound-identifier casing (a lowercase-
        then-uppercase transition, checked pre-lowercase, flags a code
        identifier like MyApplication rather than a real domain).

        Args:
            strings: Extracted strings from the sample.

        Returns:
            Up to 20 candidate domain names, lowercased.
        """
        domains = set()

        # Cheap first-pass exact-prefix noise patterns, anchored
        # (re.match) so a real domain merely containing "microsoft."
        # mid-string (crl.microsoft.com) isn't discarded. The TLD
        # allowlist and casing check below catch namespace noise that
        # doesn't start at the string's first label.
        NOISE_PATTERNS = [
            r'^[a-z]{1,3}\.[a-z]{1,3}$',      # 2-3 letter random domains (e.g., "tb.kf")
            r'^[0-9]+\.[0-9]+\.[0-9]+',        # Version strings (e.g., "1.1.2.2")
            r'^[a-z]+\.[a-z]{1,2}$',           # Short domain (e.g., "i.xo", "g.kx")
            # 1-2 char first label ("0.na") is essentially never a real
            # second-level domain; real domains overwhelmingly have 3+ chars.
            r'^[a-z0-9]{1,2}\.[a-z]{2,}$',
            # A <=3-char first label mixing in a digit/hyphen ("w1d.gg")
            # is the same noise class, past the length-2 cutoff. Pure
            # 3-letter labels (a real brand like "ibm.com") are untouched.
            r'^(?=[a-z0-9-]{1,3}\.)[a-z0-9-]*[0-9-][a-z0-9-]*\.[a-z]{2,}$',

            r'(?i)system\.',                   # System.* namespaces
            r'(?i)runtime\.',                  # Runtime.* namespaces
            r'(?i)microsoft\.',                # Microsoft.* namespaces
            r'(?i)collections\.',              # Collections.* namespaces
            r'(?i)configuration\.',            # Configuration.* namespaces
            r'(?i)diagnostics\.',              # Diagnostics.* namespaces
            r'(?i)management\.',               # Management.* namespaces
            r'(?i)security\.',                 # Security.* namespaces
            r'(?i)threading\.',                # Threading.* namespaces
            r'(?i)xml\.',                      # XML.* namespaces
            r'(?i)windows\.',                  # Windows.* namespaces
            r'(?i)aspnet\.',                   # ASP.NET namespaces
        ]

        for s in strings:
            matches = re.findall(self.DOMAIN_PATTERN, s)
            for domain in matches:
                domain_lower = domain.lower()

                # Skip obvious noise
                if domain_lower.endswith(self._NON_DOMAIN_EXTENSIONS):
                    continue
                if domain.startswith('www') or domain.startswith('http'):
                    continue

                is_noise = False
                for pattern in NOISE_PATTERNS:
                    if re.match(pattern, domain_lower):
                        is_noise = True
                        break
                if is_noise:
                    continue

                # Reject fabricated TLDs (real domains only, not code paths)
                tld = domain_lower.rsplit('.', 1)[-1]
                if tld not in self._VALID_TLDS:
                    continue

                # Reject compound-identifier casing (checked pre-lowercase)
                if re.search(r'[a-z][A-Z]', domain):
                    continue

                domains.add(domain_lower)

        return list(domains)[:20]

    def _find_urls(self, strings: List[str]) -> List[str]:
        """Find URLs in strings.

        Args:
            strings: Extracted ASCII strings.

        Returns:
            Up to 20 candidate URLs.
        """
        url_pattern = r'https?://[^\s]+'
        urls = set()
        for s in strings:
            matches = re.findall(url_pattern, s)
            urls.update(matches)
        return list(urls)[:20]

    def _find_emails(self, strings: List[str]) -> List[str]:
        """Find email addresses in strings.

        Args:
            strings: Extracted ASCII strings.

        Returns:
            Up to 10 candidate email addresses.
        """
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = set()
        for s in strings:
            matches = re.findall(email_pattern, s)
            emails.update(matches)
        return list(emails)[:10]

    def _find_registry(self, strings: List[str]) -> List[str]:
        """Find registry paths in strings.

        Args:
            strings: Extracted ASCII strings.

        Returns:
            Up to 20 candidate registry paths.
        """
        registry_pattern = r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*'
        paths = set()
        for s in strings:
            matches = re.findall(registry_pattern, s)
            paths.update(matches)
        return list(paths)[:20]

    def _find_file_paths(self, strings: List[str]) -> List[str]:
        """Find Windows and UNC file paths in strings.

        Args:
            strings: Extracted ASCII strings.

        Returns:
            Up to 20 candidate file paths.
        """
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
        """Find mutexes/GUIDs in strings.

        Args:
            strings: Extracted ASCII strings.

        Returns:
            Up to 20 candidate mutex/GUID strings.
        """
        guid_pattern = r'[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}'
        mutexes = set()
        for s in strings:
            matches = re.findall(guid_pattern, s)
            mutexes.update(matches)
        return list(mutexes)[:20]

    def _find_hex_patterns(self) -> List[Dict[str, Any]]:
        """Find potential encryption keys as hex-encoded patterns in the raw binary.

        Returns:
            Up to 20 candidate hex-encoded keys with their inferred type.
        """
        patterns = []
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
