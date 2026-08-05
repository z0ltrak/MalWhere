import base64
import re
from typing import List, Dict, Any, Optional


class StringDeobfuscator:
    """Deobfuscate strings using various techniques."""

    def __init__(self):
        self.decoded_strings = []
        self.errors: List[str] = []

    def deobfuscate(self, strings: List[str]) -> Dict[str, List[str]]:
        """Run all deobfuscation techniques."""
        result = {
            'xor_decoded': [],
            'base64_decoded': [],
            'rc4_decoded': [],
            'hex_decoded': [],
        }

        for s in strings:
            # XOR decode (like WhiteSnakeStealer's "hy" class)
            xor_result = self._try_xor_decode(s)
            if xor_result:
                result['xor_decoded'].append(xor_result)

            # Base64 decode
            b64_result = self._try_base64_decode(s)
            if b64_result:
                result['base64_decoded'].append(b64_result)

            # Hex decode
            hex_result = self._try_hex_decode(s)
            if hex_result:
                result['hex_decoded'].append(hex_result)

        return result

    def _try_xor_decode(self, s: str) -> Optional[str]:
        """Try to XOR decode a string."""
        # Try common keys (from WhiteSnakeStealer "bdf" pattern)
        common_keys = [
            'bdf',       # WhiteSnakeStealer
            'nooo:',     # WhiteSnakeStealer prefix
            'xor', 'key', 'secret',
            'dkwk239c0v023kx',  # RoningLoader RC4 key
        ]

        for key in common_keys:
            try:
                key_bytes = key.encode()
                result = []
                for i, c in enumerate(s):
                    # Try different XOR patterns
                    key_byte = key_bytes[i % len(key_bytes)]
                    decoded_char = chr(ord(c) ^ key_byte)
                    result.append(decoded_char)

                decoded = ''.join(result)
                if self._is_plaintext(decoded) and len(decoded) > 4:
                    return decoded
            except:
                continue

        return None

    def _try_base64_decode(self, s: str) -> Optional[str]:
        """Try to Base64 decode a string."""
        try:
            # Standard Base64
            decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
            if self._is_plaintext(decoded) and len(decoded) > 4:
                return decoded
        except:
            pass

        try:
            # URL-safe Base64
            decoded = base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
            if self._is_plaintext(decoded) and len(decoded) > 4:
                return decoded
        except:
            pass

        return None

    def _try_hex_decode(self, s: str) -> Optional[str]:
        """Try to decode hex string."""
        try:
            # Check if it's valid hex
            if re.match(r'^[0-9a-fA-F]+$', s) and len(s) % 2 == 0:
                decoded = bytes.fromhex(s).decode('utf-8', errors='ignore')
                if self._is_plaintext(decoded) and len(decoded) > 4:
                    return decoded
        except:
            pass
        return None

    def _is_plaintext(self, s: str) -> bool:
        """Check if string looks like plaintext."""
        if len(s) < 4:
            return False
        printable = sum(1 for c in s if 32 <= ord(c) <= 126 or c in '\t\n\r')
        return printable / len(s) > 0.7

    def get_errors(self) -> List[str]:
        """Get deobfuscation errors."""
        return self.errors
