from typing import Optional, List, Dict, Any
from pathlib import Path


class DecryptionEngine:
    """Decrypt data using discovered keys."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = None
        self.errors: List[str] = []

    def decrypt_rc4(self, data: bytes, key: bytes) -> Optional[bytes]:
        """RC4 decrypt using key."""
        try:
            # Simple RC4 implementation (no external dependency)
            S = list(range(256))
            j = 0
            for i in range(256):
                j = (j + S[i] + key[i % len(key)]) & 0xFF
                S[i], S[j] = S[j], S[i]

            i = j = 0
            result = bytearray(len(data))
            for k in range(len(data)):
                i = (i + 1) & 0xFF
                j = (j + S[i]) & 0xFF
                S[i], S[j] = S[j], S[i]
                result[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF]
            return bytes(result)
        except Exception as e:
            self.errors.append(f"RC4 decryption error: {e}")
            return None

    def decrypt_xor(self, data: bytes, key: bytes) -> Optional[bytes]:
        """XOR decrypt using key."""
        try:
            result = bytearray()
            for i, byte in enumerate(data):
                result.append(byte ^ key[i % len(key)])
            return bytes(result)
        except Exception as e:
            self.errors.append(f"XOR decryption error: {e}")
            return None

    def decrypt_xor_string(self, s: str, key: str) -> Optional[str]:
        """XOR decrypt a string."""
        try:
            key_bytes = key.encode()
            result = []
            for i, c in enumerate(s):
                result.append(chr(ord(c) ^ key_bytes[i % len(key_bytes)]))
            return ''.join(result)
        except Exception as e:
            self.errors.append(f"XOR string decryption error: {e}")
            return None

    def try_all_keys(self, data: bytes, keys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Try all keys on data."""
        results = []
        for key_info in keys:
            key_type = key_info.get('type', '')
            key_data = key_info.get('key', '')

            if key_type == 'rc4':
                if len(key_data) >= 16:
                    key_bytes = bytes.fromhex(key_data) if len(key_data) > 32 else key_data.encode()
                    decrypted = self.decrypt_rc4(data, key_bytes[:32])
                    if decrypted and self._is_plaintext(decrypted):
                        results.append({
                            'key_type': key_type,
                            'key': key_info,
                            'decrypted': decrypted,
                            'size': len(decrypted)
                        })
            elif key_type == 'xor':
                key_bytes = key_data.encode()
                decrypted = self.decrypt_xor(data, key_bytes)
                if decrypted and self._is_plaintext(decrypted):
                    results.append({
                        'key_type': key_type,
                        'key': key_info,
                        'decrypted': decrypted,
                        'size': len(decrypted)
                    })
        return results

    def _is_plaintext(self, data: bytes) -> bool:
        """Check if decrypted data looks like plaintext."""
        if len(data) < 16:
            return False
        printable = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
        return printable / len(data) > 0.7

    def get_errors(self) -> List[str]:
        """Get decryption errors."""
        return self.errors
