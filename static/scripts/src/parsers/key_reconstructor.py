import math
import re
from typing import List, Dict, Any, Optional
from pathlib import Path


class KeyReconstructor:
    """Reconstruct encryption keys from binary data."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = None
        self.errors: List[str] = []
        self.keys: List[Dict[str, Any]] = []

    def find_keys(self) -> List[Dict[str, Any]]:
        """Find all potential keys."""
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()

            # RC4 keys
            self.keys.extend(self._find_rc4_keys())

            # ChaCha20 keys
            self.keys.extend(self._find_chacha20_keys())

            # XOR keys
            self.keys.extend(self._find_xor_keys())

            # RSA keys
            self.keys.extend(self._find_rsa_keys())

            # Find keys from .rdata constants
            self.keys.extend(self._find_rdata_keys())

        except Exception as e:
            self.errors.append(f"Key reconstruction error: {e}")

        return self.keys

    def _find_rc4_keys(self) -> List[Dict[str, Any]]:
        """Find potential RC4 keys."""
        keys = []
        # Look for 16-32 byte printable strings with high entropy
        for i in range(0, len(self.data) - 16):
            for length in [16, 20, 24, 28, 32]:
                if i + length > len(self.data):
                    continue
                chunk = self.data[i:i+length]
                try:
                    decoded = chunk.decode('ascii', errors='ignore')
                    # Check if printable and high entropy
                    if self._is_printable(decoded) and self._is_high_entropy(chunk):
                        keys.append({
                            'type': 'rc4',
                            'offset': i,
                            'length': length,
                            'key': chunk.hex(),
                            'key_ascii': decoded,
                            'confidence': 'high'
                        })
                except:
                    pass
        return keys[:10]

    def _find_chacha20_keys(self) -> List[Dict[str, Any]]:
        """Find ChaCha20 keys (32 bytes)."""
        keys = []
        for i in range(0, len(self.data) - 32):
            chunk = self.data[i:i+32]
            if self._is_high_entropy(chunk):
                # Check if it's not all zeros or ones
                if len(set(chunk)) > 10:
                    keys.append({
                        'type': 'chacha20',
                        'offset': i,
                        'length': 32,
                        'key': chunk.hex(),
                        'confidence': 'medium'
                    })
        return keys[:10]

    def _find_xor_keys(self) -> List[Dict[str, Any]]:
        """Find XOR keys (3-8 bytes)."""
        keys = []
        for i in range(0, len(self.data) - 3):
            for length in [3, 4, 5, 6, 7, 8]:
                if i + length > len(self.data):
                    continue
                chunk = self.data[i:i+length]
                try:
                    decoded = chunk.decode('ascii')
                    if decoded.isprintable() and len(set(decoded)) > 1:
                        # Check if this might be the "bdf" key pattern from WhiteSnakeStealer
                        if decoded.lower() in ['bdf', 'xor', 'key', 'secret']:
                            keys.append({
                                'type': 'xor',
                                'offset': i,
                                'length': length,
                                'key': decoded,
                                'key_hex': chunk.hex(),
                                'confidence': 'high'
                            })
                        else:
                            keys.append({
                                'type': 'xor',
                                'offset': i,
                                'length': length,
                                'key': decoded,
                                'key_hex': chunk.hex(),
                                'confidence': 'medium'
                            })
                except:
                    pass
        return keys[:10]

    def _find_rdata_keys(self) -> List[Dict[str, Any]]:
        """Find keys in .rdata section with better extraction."""
        keys = []
        for i in range(0, len(self.data) - 60):
            chunk = self.data[i:i+60]
            try:
                decoded = chunk.decode('ascii', errors='ignore')

                # Look for patterns like "dkwk239c0v023kx" (RoningLoader RC4 key)
                # or "bdf" with "nooo:" prefix
                if re.search(r'[a-zA-Z0-9]{10,}', decoded):
                    # Extract the actual key string
                    key_match = re.search(r'[a-zA-Z0-9]{10,}', decoded)
                    if key_match:
                        key_str = key_match.group(0)
                        if len(key_str) >= 10:
                            keys.append({
                                'type': 'rdata_key',
                                'offset': i,
                                'length': len(chunk),
                                'key': chunk[:32].hex(),
                                'key_ascii': key_str,
                                'confidence': 'high'
                            })
            except:
                pass
        return keys[:5]

    def _find_rsa_keys(self) -> List[Dict[str, Any]]:
        """Find RSA public/private keys."""
        keys = []
        rsa_patterns = [
            (b'-----BEGIN RSA PRIVATE KEY-----', 'rsa_private'),
            (b'-----BEGIN PUBLIC KEY-----', 'rsa_public'),
            (b'-----BEGIN CERTIFICATE-----', 'certificate'),
        ]
        for pattern, key_type in rsa_patterns:
            start = self.data.find(pattern)
            if start != -1:
                end = self.data.find(b'-----END', start)
                if end != -1:
                    end += 128  # Include end marker
                    keys.append({
                        'type': key_type,
                        'offset': start,
                        'length': end - start,
                        'key': self.data[start:end].decode('ascii', errors='ignore'),
                        'confidence': 'high'
                    })
        return keys

    def _is_printable(self, s: str) -> bool:
        """Check if string is printable ASCII."""
        return all(32 <= ord(c) <= 126 for c in s)

    def _is_high_entropy(self, data: bytes) -> bool:
        """Check if data has high entropy."""
        if len(data) < 8:
            return False
        try:
            freq = {b: data.count(b) for b in set(data)}
            entropy = -sum((count/len(data)) * math.log2(count/len(data))
                           for count in freq.values())
            return entropy > 5.5
        except:
            return False

    def get_errors(self) -> List[str]:
        """Get reconstruction errors."""
        return self.errors
