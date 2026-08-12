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

            # 2. Try single-byte XOR bruteforce (fully generic)
            xor_pattern = self._try_single_byte_xor_bruteforce(s)
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
        except Exception:
            pass
        return None

    def _try_single_byte_xor_bruteforce(self, s: str) -> Optional[str]:
        """Bruteforce single-byte XOR over all 256 key values.

        Previously this tried a hardcoded multi-byte key pattern
        (first byte brute-forced, remaining bytes fixed to the literal
        ASCII values 'b'/'d'/'f') and only accepted a result that started
        with the literal prefix "nooo:" -- a real, verified finding for
        one specific sample (WhiteSnakeStealer's own string-obfuscation
        scheme, see manual_wsnakestealer_report.md), but hardcoded as if
        it were generic pattern detection. It could structurally never
        find any other key. Genuine multi-byte XOR key discovery needs a
        crib or repeated-byte statistics a single short string doesn't
        provide -- KeyReconstructor already does that properly at the
        binary-section level, and its output reaches _try_xor_with_key()
        above. This just covers the one thing a lone string realistically
        can self-validate: a single-byte key, brute-forced generically.
        """
        # Skip strings that already look like plaintext -- nothing to
        # decode, and bruteforcing them risks scrambling valid text into
        # different-but-still-printable-looking text (a false "decode").
        if self._is_plaintext(s):
            return None

        for key_byte in range(1, 256):  # skip 0: XOR with 0 is a no-op
            try:
                decoded = ''.join(chr(ord(c) ^ key_byte) for c in s)
                if decoded != s and self._is_plaintext(decoded) and len(decoded) > 4:
                    return decoded
            except Exception:
                continue

        return None

    def _try_base64_decode(self, s: str) -> Optional[str]:
        """Try to Base64 decode a string."""
        try:
            # Standard Base64
            decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
            if self._is_plaintext(decoded) and len(decoded) > 4:
                return decoded
        except Exception:
            pass

        try:
            # URL-safe Base64
            decoded = base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
            if self._is_plaintext(decoded) and len(decoded) > 4:
                return decoded
        except Exception:
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
        except Exception:
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
