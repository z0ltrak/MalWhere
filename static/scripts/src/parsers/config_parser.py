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

    # Certificate-attribute and certificate-extension OID arcs -- X.509's
    # "2.5.4.*" (id-at-*: commonName, countryName, ...) and "2.5.29.*"
    # (id-ce-*: subjectAltName, basicConstraints, ...) are complete,
    # correctly-bounded 4-part dotted-decimal tokens in their own right
    # (not a chain fragment the lookaround below would catch), and appear
    # verbatim as strings in essentially any Authenticode-signed PE's
    # embedded certificate. Found on RoningLoader's own resubmitted
    # components (11a6cb1d..., 1668cc75...): a real C2 IP starting "2.5."
    # is not impossible in principle, but these two exact arcs are among
    # the most standardized OID prefixes there are.
    _OID_IP_PREFIXES = ('2.5.4.', '2.5.29.')

    def _find_ips(self, strings: List[str]) -> List[str]:
        # Negative lookaround excludes matches that are actually a 4-group
        # window sliced out of a *longer* dotted-decimal chain -- found on
        # the same RoningLoader components: "101.3.4.2" turned out to be
        # a mid-string fragment of the real OID "2.16.840.1.101.3.4.2.4"
        # (a NIST hash-algorithm identifier), which \b alone doesn't catch
        # since \b only checks one adjacent character's word/non-word
        # class, not whether more digits-and-dots continue past it. A
        # real embedded IP is never itself a fragment of a longer
        # dotted-decimal run.
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
                    # General case of the same problem: PE/.NET assembly
                    # version numbers (MAJOR.MINOR.BUILD.REVISION, e.g.
                    # "3.2.0.0", "6.0.0.0") are dotted-quads too, and the
                    # trailing fields are conventionally 0 far more often
                    # than a real embedded C2 IP's octets are (verified
                    # against all 30 known-real C2 IPs across the two
                    # validated families with numeric IOCs: zero of them
                    # have 2+ zero octets outside the first position).
                    if sum(1 for p in parts[1:] if p == '0') >= 2:
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
                # Stricter than _find_ips's plaintext-scan threshold
                # (2+ zero octets): a brute-force XOR decode is a much
                # higher false-positive-risk source than a direct string
                # match to begin with -- 256 candidate keys tried against
                # arbitrary binary, not one targeted regex pass -- so even
                # a single zero octet here is treated as the same
                # null-padding signature this method is already known to
                # be vulnerable to (see _XOR_MAX_MATCHES_PER_KEY's comment
                # above). Found on a resubmitted AsyncRAT payload: key
                # 0x2e -- the exact key already documented as the false-
                # positive-cascade culprit -- decoded a single match,
                # "3.2.0.2", that a real .NET assembly version tuple
                # shape explains far better than a real C2 address does.
                if sum(1 for p in parts[1:] if p == '0') >= 1:
                    continue
                # A second instance of the same root cause, one step more
                # general: a repeating *non-zero* byte in a structural
                # padding/alignment table (e.g. \x1c\x00\x00\x00 repeated)
                # decodes to a repeating near-identical octet run just as
                # readily as a null-padded one does -- found immediately
                # after the fix above, on a *different* resubmitted
                # AsyncRAT payload: key 0x32 decoded "222.222.222.232" from
                # exactly such a table. A real routable IP essentially
                # never has 3 of its 4 octets numerically identical; a
                # decode artifact from repeating source bytes routinely
                # does.
                if max(Counter(parts).values()) >= 3:
                    continue

                start, end = m.span()
                raw_before = self.data[start - 1] if start > 0 else 0
                raw_after = self.data[end] if end < len(self.data) else 0
                clean_boundary = raw_before in (0, key) and raw_after in (0, key)

                if clean_boundary and ip not in found:
                    found[ip] = key

        return [{'ip': ip, 'xor_key': f'0x{key:02x}'} for ip, key in found.items()][:10]

    # Curated allowlist of real TLDs. Not the full ~1500-entry IANA list --
    # covers the gTLDs/ccTLDs actually seen in malware C2 infrastructure
    # (abused cheap/free ccTLDs like .tk/.ml/.cf, common bulletproof-hosting
    # gTLDs like .xyz/.top/.icu, plus the major country/region ccTLDs) so a
    # dotted string with a fabricated "TLD" (.editors, .misc, .system,
    # .dllfailed, .sample -- all seen misparsed from .NET/C++ identifiers)
    # gets rejected outright rather than relying on a namespace denylist.
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

        Three independent filters, each catching a distinct class of false
        positive seen in practice (.NET/C++ identifiers mis-tokenized by the
        dotted-string regex as domains):
          1. Known non-domain extensions -- rejects source/debug file
             references like d3d11install.pdb, wtf8.rs.
          2. TLD allowlist -- rejects fabricated "TLDs" like .editors, .misc,
             .system, .dllfailed, .sample (see _VALID_TLDS above).
          3. Compound-identifier casing -- .NET/C++ namespaces and type
             names are essentially always PascalCase/camelCase compounds
             (MyApplication, SettingsDesigner); real embedded C2 domains are
             not. A lowercase-then-uppercase transition inside the matched
             substring (checked on the ORIGINAL case, before normalizing to
             lowercase) is a strong signal of a code identifier rather than
             a domain literal.
        """
        domains = set()

        # Legacy exact-prefix noise patterns (anchored: re.match, not
        # re.search) -- kept as a cheap first pass, but the TLD allowlist
        # and casing check below are what actually catch namespace noise
        # that doesn't start at the string's first label (e.g.
        # "KMicrosoft.VisualStudio.Editors" is rejected by the fabricated
        # ".editors" TLD, not by this list). Kept anchored so a real domain
        # that merely contains "microsoft." mid-string (crl.microsoft.com)
        # isn't discarded here.
        NOISE_PATTERNS = [
            r'^[a-z]{1,3}\.[a-z]{1,3}$',      # 2-3 letter random domains (e.g., "tb.kf")
            r'^[0-9]+\.[0-9]+\.[0-9]+',        # Version strings (e.g., "1.1.2.2")
            r'^[a-z]+\.[a-z]{1,2}$',           # Short domain (e.g., "i.xo", "g.kx")
            # A 1-2 char, possibly-numeric first label ("0.na", "9r.dk") is
            # essentially never a real second-level domain -- it's noise
            # that only started surviving once the TLD allowlist below grew
            # to include the (very real) short ccTLDs these happened to
            # collide with. Real domains overwhelmingly have a first label
            # of 3+ chars, so this is a safe, targeted cut.
            r'^[a-z0-9]{1,2}\.[a-z]{2,}$',
            # A first label of 3 chars or fewer that mixes in a digit or
            # hyphen ("w1d.gg", "s-.mz") is the same class of noise as the
            # pattern above, just past the length-2 cutoff -- no real
            # domain a malware author would hand-type looks like this. Pure
            # 3-letter labels (a real brand TLD like "ibm.com") are left
            # alone; only the digit/hyphen mix is targeted.
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

                # Skip noise patterns. Anchored (re.match, not re.search) so
                # a real domain that merely contains e.g. "microsoft." mid-
                # string (crl.microsoft.com) isn't discarded here -- the TLD
                # allowlist and casing check below are what catch namespace
                # noise; this list only needs to catch the exact-prefix case.
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
