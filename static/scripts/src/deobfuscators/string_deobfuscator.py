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
        """Run all deobfuscation techniques against a list of extracted strings.

        Args:
            strings: Extracted strings to attempt to deobfuscate.
            discovered_keys: Candidate keys from KeyReconstructor, used for XOR decryption.

        Returns:
            Dict of decoded strings by technique: xor_decoded, base64_decoded, rc4_decoded, hex_decoded, pattern_decoded.
        """
        result = {
            'xor_decoded': [],
            'base64_decoded': [],
            'rc4_decoded': [],
            'hex_decoded': [],
            'pattern_decoded': [],
        }

        # Type names must match what KeyReconstructor actually emits (see
        # decryption_engine.py's _key_to_bytes for the same concern).
        # Capped to the top 50 by confidence: this runs per-string, so an
        # uncapped 300 keys x thousands of strings would reintroduce the
        # quadratic blowup fixed in KeyReconstructor's own perf pass.
        _USABLE_KEY_TYPES = {
            'plaintext_all_strings', 'xor_single_byte', 'xor_sub_key',
            'printable_ascii', 'rc4_ksa_key',
        }
        _CONF_ORDER = {'high': 0, 'medium': 1, 'low': 2}
        keys = []
        if discovered_keys:
            candidates = [
                k for k in discovered_keys
                if k.get('type') in _USABLE_KEY_TYPES and k.get('key')
            ]
            candidates.sort(key=lambda k: _CONF_ORDER.get(k.get('confidence', 'low'), 2))
            keys = [k['key'] for k in candidates[:50]]

        # Even with a tightened per-trial threshold, tens of thousands of
        # trials (~50 keys x thousands of strings) still produce a
        # residual handful of chance false positives. Same corroboration
        # principle as this pipeline's ATT&CK confidence scoring: a key
        # that decodes only ONE string is indistinguishable from chance;
        # one that decodes 2+ DIFFERENT strings is real evidence.
        hits_by_key: Dict[str, List[str]] = {}
        for s in strings:
            for key in keys:
                xor_result = self._try_xor_with_key(s, key)
                if xor_result:
                    hits_by_key.setdefault(key, []).append(xor_result)
                    break

        for key, decoded_strings in hits_by_key.items():
            if len(set(decoded_strings)) >= 2:
                result['xor_decoded'].extend(decoded_strings)

        for s in strings:
            xor_pattern = self._try_single_byte_xor_bruteforce(s)
            if xor_pattern:
                result['pattern_decoded'].append(xor_pattern)

            b64_result = self._try_base64_decode(s)
            if b64_result:
                result['base64_decoded'].append(b64_result)

            hex_result = self._try_hex_decode(s)
            if hex_result:
                result['hex_decoded'].append(hex_result)

        return result

    def _try_xor_with_key(self, s: str, key: str) -> Optional[str]:
        """Try XOR decryption with a specific discovered key.

        `s` is already printable (from `strings` output), so a wrong key
        is just as likely to produce printable-looking noise as real
        plaintext. With up to 50 keys tried per string, the default 0.7
        printable threshold (fine for a single hypothesis) produces real
        false-positive flooding at that volume, so this uses a higher
        printable-ratio bar and longer minimum length -- not a change to
        _is_plaintext's default, which single-hypothesis callers
        (base64/hex decode, the single-byte bruteforce) still use unmodified.

        Args:
            s: A printable string extracted via `strings`.
            key: A discovered candidate key to try.

        Returns:
            The decoded string if it passes the tightened plaintext/alnum
            checks, else None.
        """
        try:
            key_bytes = key.encode()
            result = []
            for i, c in enumerate(s):
                decoded_char = chr(ord(c) ^ key_bytes[i % len(key_bytes)])
                result.append(decoded_char)

            decoded = ''.join(result)
            if len(decoded) < 10 or not self._is_plaintext(decoded, threshold=0.95):
                return None

            # A wrong key produces symbol/punctuation-heavy noise from
            # already-printable input; genuine content is letter/digit-dominant.
            alnum_ratio = sum(1 for c in decoded if c.isalnum()) / len(decoded)
            if alnum_ratio < 0.6:
                return None

            return decoded
        except Exception:
            pass
        return None

    def _try_single_byte_xor_bruteforce(self, s: str) -> Optional[str]:
        """Bruteforce single-byte XOR over all 256 key values.

        Genuine multi-byte XOR key discovery needs a crib or repeated-byte
        statistics a single short string doesn't provide -- that's
        KeyReconstructor's job at the binary-section level, reaching
        _try_xor_with_key() above. This only covers what a lone string can
        self-validate: a single-byte key, brute-forced generically.

        Args:
            s: A candidate string to bruteforce.

        Returns:
            The decoded string if a key produces plaintext, else None.
        """
        # Already-plaintext strings have nothing to decode, and
        # bruteforcing them risks a false "decode" into different-but-
        # still-printable-looking text.
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

    _BASE64_SHAPE = re.compile(r'^[A-Za-z0-9+/]{8,}={0,2}$')
    _BASE64_URLSAFE_SHAPE = re.compile(r'^[A-Za-z0-9\-_]{8,}={0,2}$')

    def _try_base64_decode(self, s: str) -> Optional[str]:
        """Try to Base64 decode a string.

        Requires base64-shaped input first, then strict decoding
        (`validate=True`) and strict UTF-8 -- a real base64-encoded
        string decodes to valid UTF-8 or it isn't one; silently
        stripping invalid characters/bytes accepts far too much
        symbol-heavy noise as a "successful" decode.

        Args:
            s: A candidate string to decode.

        Returns:
            The decoded string if it's base64-shaped and decodes to valid UTF-8 plaintext, else None.
        """
        if len(s) % 4 == 0 and self._BASE64_SHAPE.match(s):
            try:
                decoded = base64.b64decode(s, validate=True).decode('utf-8', errors='strict')
                if self._is_plaintext(decoded) and len(decoded) > 4:
                    return decoded
            except Exception:
                pass

        if len(s) % 4 == 0 and self._BASE64_URLSAFE_SHAPE.match(s):
            try:
                decoded = base64.urlsafe_b64decode(s).decode('utf-8', errors='strict')
                if self._is_plaintext(decoded) and len(decoded) > 4:
                    return decoded
            except Exception:
                pass

        return None

    def _try_hex_decode(self, s: str) -> Optional[str]:
        """Try to decode hex string.

        Args:
            s: A candidate string to decode.

        Returns:
            The decoded string if it decodes to valid UTF-8 plaintext, else None.
        """
        try:
            if re.match(r'^[0-9a-fA-F]{8,}$', s) and len(s) % 2 == 0:
                # Strict UTF-8: a real hex-encoded string decodes cleanly
                # or it isn't one (same reasoning as _try_base64_decode above).
                decoded = bytes.fromhex(s).decode('utf-8', errors='strict')
                if self._is_plaintext(decoded) and len(decoded) > 4:
                    return decoded
        except Exception:
            pass
        return None

    def _is_plaintext(self, s: str, threshold: float = 0.7) -> bool:
        """Check if string looks like plaintext.

        Args:
            s: String to check.
            threshold: Minimum fraction of printable characters required.

        Returns:
            True if the printable ratio exceeds threshold.
        """
        if len(s) < 4:
            return False
        printable = sum(1 for c in s if 32 <= ord(c) <= 126 or c in '\t\n\r')
        return printable / len(s) > threshold

    def get_errors(self) -> List[str]:
        """Get deobfuscation errors."""
        return self.errors
