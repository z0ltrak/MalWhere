"""String deobfuscator with automatic pattern discovery."""

import base64
import re
import math
from typing import List, Dict, Any, Optional, Set


class StringDeobfuscator:
    """Deobfuscate strings using automatic pattern discovery."""

    def __init__(self):
        self.decoded_strings = []
        self.errors: List[str] = []
        self._discovered_keys: Set[str] = set()

    def deobfuscate(self, strings: List[str], discovered_keys: List[Dict[str, Any]] = None) -> Dict[str, List[str]]:
        """Run all deobfuscation techniques with discovered keys."""
        result = {
            'xor_decoded': [],
            'base64_decoded': [],
            'rc4_decoded': [],
            'hex_decoded': [],
            'pattern_decoded': [],
        }

        # Use discovered keys if provided
        keys = []
        if discovered_keys:
            for key_info in discovered_keys:
                if key_info.get('type') in ['xor', 'printable_key', 'pattern_key']:
                    keys.append(key_info.get('key', ''))

        # Try XOR decryption with discovered keys
        for s in strings:
            # 1. Try XOR with discovered keys
            for key in keys:
                xor_result = self._try_xor_with_key(s, key)
                if xor_result:
                    result['xor_decoded'].append(xor_result)
                    break

            # 2. Try auto-XOR pattern detection (like WhiteSnakeStealer "bdf" pattern)
            xor_pattern = self._try_xor_pattern_detection(s)
            if xor_pattern:
                result['pattern_decoded'].append(xor_pattern)

            # 3. Try Base64 decode
            b64_result = self._try_base64_decode(s)
            if b64_result:
                result['base64_decoded'].append(b64_result)

            # 4. Try Hex decode
            hex_result = self._try_hex_decode(s)
            if hex_result:
                result['hex_decoded'].append(hex_result)

        return result

    def _try_xor_with_key(self, s: str, key: str) -> Optional[str]:
        """Try XOR decryption with a specific key."""
        try:
            key_bytes = key.encode()
            result = []
            for i, c in enumerate(s):
                decoded_char = chr(ord(c) ^ key_bytes[i % len(key_bytes)])
                result.append(decoded_char)

            decoded = ''.join(result)
            if self._is_plaintext(decoded) and len(decoded) > 4:
                return decoded
        except:
            pass
        return None

    def _try_xor_pattern_detection(self, s: str) -> Optional[str]:
        """Try to detect XOR pattern automatically (like WhiteSnakeStealer's "bdf" + "nooo:")."""
        # Try common XOR key lengths
        for key_len in [3, 4, 5, 6, 7, 8]:
            # Try all possible first bytes (ASCII printable)
            for first_byte in range(32, 127):
                try:
                    # Build key with pattern detection
                    key = bytearray([first_byte])

                    # Try to determine rest of key from pattern
                    # Look for "nooo:" prefix after XOR
                    for i in range(1, key_len):
                        # Try common patterns (bdf pattern)
                        if i == 1:
                            key.append(0x62)  # 'b'
                        elif i == 2:
                            key.append(0x64)  # 'd'
                        else:
                            key.append(0x66)  # 'f'

                    result = []
                    for i, c in enumerate(s):
                        decoded_char = chr(ord(c) ^ key[i % len(key)])
                        result.append(decoded_char)

                    decoded = ''.join(result)

                    # Check if it starts with "nooo:" (WhiteSnakeStealer pattern)
                    if decoded.startswith('nooo:'):
                        # Remove prefix and return
                        return decoded[5:]  # Remove "nooo:" prefix

                    # Check if it's plaintext
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

    def _is_plaintext(self, s: str, threshold: float = 0.7) -> bool:
        """Check if string looks like plaintext."""
        if len(s) < 4:
            return False
        printable = sum(1 for c in s if 32 <= ord(c) <= 126 or c in '\t\n\r')
        return printable / len(s) > threshold

    def get_errors(self) -> List[str]:
        """Get deobfuscation errors."""
        return self.errors
