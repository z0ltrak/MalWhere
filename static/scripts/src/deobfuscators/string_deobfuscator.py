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

        # Use discovered keys if provided. The type filter previously
        # checked for 'xor'/'printable_key'/'pattern_key' -- none of which
        # KeyReconstructor has ever actually produced (same stale-type-name
        # bug already fixed in decryption_engine.py's _key_to_bytes; see
        # that commit for the real type names). This filter was therefore
        # always empty regardless of what got passed in -- and separately,
        # nothing ever passed discovered_keys here at all until analyzer.py
        # was reordered to run key discovery before string extraction.
        # Capped to the top 50 (by confidence) to bound cost: this runs
        # per-string, so an uncapped 300 keys x thousands of strings would
        # reintroduce the kind of quadratic blowup fixed in
        # KeyReconstructor's own perf pass.
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

        # Try XOR decryption with discovered keys. Even with the tightened
        # per-trial threshold in _try_xor_with_key, ~50 keys x hundreds-to-
        # thousands of strings is tens of thousands of trials -- enough
        # combinatorial volume that a residual handful of chance false
        # positives is still expected even at a strict per-trial rate.
        # Same corroboration principle used throughout this pipeline's
        # ATT&CK confidence scoring: a key that only ever "successfully"
        # decodes ONE string out of everything it was tried against is
        # indistinguishable from chance; a key that consistently produces
        # plausible output across multiple DIFFERENT strings is real
        # evidence the key itself is genuine. Collect all hits per key
        # first, keep only keys with 2+ distinct decoded strings.
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
        """Try XOR decryption with a specific discovered key.

        `s` comes from the standard `strings` command output, which only
        ever extracts already-printable runs -- so unlike the generic
        single-byte bruteforce (which skips already-plaintext input
        outright, since there nothing to recover), every input here starts
        printable, and XOR is just as likely to produce printable-looking
        noise as printable-looking real plaintext for a wrong key. With up
        to 50 candidate keys tried per string, the default 0.7 threshold
        (fine for a single hypothesis) produces real false-positive
        flooding at that volume -- confirmed directly: wiring real
        discovered keys in here initially took WhiteSnake's deobfuscated
        count from a baseline of 87 to 871, almost all short runs of
        control characters that happened to clear 70% printable by chance.
        Tightened for this specific multi-hypothesis context: a higher
        printable-ratio bar and a longer minimum length, both of which cut
        per-trial false-accept probability -- not a change to
        _is_plaintext's default, which single-hypothesis callers
        (base64/hex decode, the single-byte bruteforce) still use unmodified.
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

            # Printable-but-noisy (heavy on symbols/punctuation, sparse on
            # actual letters and digits) is exactly what a wrong key
            # produces from already-printable input -- genuine decoded
            # content (paths, URLs, words) is letter/digit-dominant.
            alnum_ratio = sum(1 for c in decoded if c.isalnum()) / len(decoded)
            if alnum_ratio < 0.6:
                return None

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

    _BASE64_SHAPE = re.compile(r'^[A-Za-z0-9+/]{8,}={0,2}$')
    _BASE64_URLSAFE_SHAPE = re.compile(r'^[A-Za-z0-9\-_]{8,}={0,2}$')

    def _try_base64_decode(self, s: str) -> Optional[str]:
        """Try to Base64 decode a string.

        Previously ran base64.b64decode(s) against EVERY extracted string
        with no pre-filter for whether s even looks like base64, and threw
        away the strictness base64 already offers: no `validate=True` (so
        non-base64-alphabet characters get silently stripped rather than
        rejected) and `errors='ignore'` on the UTF-8 decode (so invalid
        byte sequences get silently dropped instead of failing). Together
        these accepted a lot of non-base64 input as a "successful" decode
        -- confirmed directly: this was the source of 87 of WhiteSnake's
        94 baseline "deobfuscated" strings, nearly all short symbol-heavy
        noise, not real content. Now requires base64-shaped input first,
        strict decoding, and strict UTF-8 (a real base64-encoded string
        decodes to valid UTF-8 or it isn't one).
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
        """Try to decode hex string."""
        try:
            # Check if it's valid hex
            if re.match(r'^[0-9a-fA-F]{8,}$', s) and len(s) % 2 == 0:
                # Strict UTF-8: a real hex-encoded string decodes cleanly
                # or it isn't one -- errors='ignore' previously let
                # invalid byte sequences silently drop instead of failing,
                # same class of issue fixed in _try_base64_decode above.
                decoded = bytes.fromhex(s).decode('utf-8', errors='strict')
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
