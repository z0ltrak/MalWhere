import re
from typing import List, Dict, Any


class CryptoDetector:
    """Detect cryptographic algorithms and constants."""

    CRYPTO_PATTERNS = [
        # ChaCha20
        (r'expand 32-byte k', 'ChaCha20 (T1486)'),
        (r'expand 16-byte k', 'ChaCha20 (T1486)'),
        (r'chacha20', 'ChaCha20 (T1486)'),

        # RC4
        (r'RC4', 'RC4 encryption (T1486)'),
        (r'ARC4', 'RC4 encryption (T1486)'),

        # AES
        (r'AES', 'AES encryption (T1486)'),
        (r'Rijndael', 'AES encryption (T1486)'),

        # RSA
        (r'RSA', 'RSA encryption (T1486)'),
        (r'RSAParameters', 'RSA encryption (T1486)'),

        # SHA
        (r'SHA-256', 'SHA-256 hashing (T1486)'),
        (r'SHA256', 'SHA-256 hashing (T1486)'),
        (r'SHA-1', 'SHA-1 hashing (T1486)'),
        (r'SHA1', 'SHA-1 hashing (T1486)'),
        (r'MD5', 'MD5 hashing (T1486)'),

        # XOR
        (r'XOR', 'XOR encryption (T1140)'),

        # Base64
        (r'Base64', 'Base64 encoding (T1132)'),

        # Zlib
        (r'zlib', 'Zlib compression (T1560.001)'),
        (r'deflate', 'Deflate compression (T1560.001)'),

        # GZip
        (r'GZip', 'GZip compression (T1560.001)'),
        (r'gzip', 'GZip compression (T1560.001)'),
    ]

    # Known key patterns
    KEY_PATTERNS = [
        (r'[0-9a-fA-F]{32}', 'MD5 hash / 16-byte key'),
        (r'[0-9a-fA-F]{40}', 'SHA1 hash / 20-byte key'),
        (r'[0-9a-fA-F]{64}', 'SHA256 hash / 32-byte key'),
        (r'[0-9a-fA-F]{128}', 'SHA512 hash / 64-byte key'),
    ]

    def detect_in_strings(self, strings: List[str]) -> List[Dict[str, str]]:
        """Detect crypto patterns in strings."""
        found = []
        for s in strings:
            for pattern, description in self.CRYPTO_PATTERNS:
                if re.search(pattern, s, re.IGNORECASE):
                    found.append({
                        'string': s[:100],
                        'pattern': pattern,
                        'description': description,
                        'confidence': 'high'
                    })
                    break
        return found

    def detect_keys(self, strings: List[str]) -> List[Dict[str, str]]:
        """Detect potential keys in strings."""
        found = []
        for s in strings:
            for pattern, description in self.KEY_PATTERNS:
                matches = re.findall(pattern, s)
                for match in matches:
                    found.append({
                        'key': match,
                        'pattern': pattern,
                        'description': description,
                        'confidence': 'medium'
                    })
        return found[:20]

    def detect_all(self, strings: List[str]) -> Dict[str, List[Dict]]:
        """Run all crypto detection."""
        return {
            'crypto_algorithms': self.detect_in_strings(strings),
            'potential_keys': self.detect_keys(strings),
        }
