"""Decryption engine that tries discovered keys automatically with algorithm context."""

from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
import math
import base64
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..constants import HIGH_ENTROPY_THRESHOLD, SKIP_CARVING_THRESHOLD


class DecryptionEngine:
    """Decrypt data using discovered keys with algorithm context and entropy detection."""

    # Algorithm-specific validation rules
    ALGORITHM_RULES = {
        'chacha20': {
            'min_key_size': 16,
            'max_key_size': 32,
            'valid_key_sizes': [16, 32],
            'min_entropy': 4.5,
        },
        'rc4': {
            'min_key_size': 5,
            'max_key_size': 32,
            'valid_key_sizes': [5, 8, 10, 15, 16, 24, 32],
            'min_entropy': 3.5,
        },
        'aes': {
            'min_key_size': 16,
            'max_key_size': 32,
            'valid_key_sizes': [16, 24, 32],
            'min_entropy': 4.0,
        },
        'xor': {
            'min_key_size': 1,
            'max_key_size': 8,
            'valid_key_sizes': [1, 2, 3, 4, 5, 6, 7, 8],
            'min_entropy': 2.0,
        },
    }

    # Common keys that should be skipped
    COMMON_KEYS = {
        b'password', b'12345678', b'abcdefgh', b'00000000',
        b'FFFFFFFF', b'key', b'secret', b'changeme',
        b'admin', b'guest', b'default', b'none',
        b'test', b'12345', b'qwerty', b'abc123',
        b'password123', b'letmein', b'welcome', b'monkey',
    }

    # Entropy thresholds -- see src/constants.py
    HIGH_ENTROPY_THRESHOLD = HIGH_ENTROPY_THRESHOLD
    SKIP_CARVING_THRESHOLD = SKIP_CARVING_THRESHOLD

    def __init__(self, file_path: Path, verbose: bool = False):
        """Initialize the decryption engine.

        Args:
            file_path: Path to the sample (kept for context; decryption itself operates on passed-in bytes).
            verbose: Enable verbose progress logging.
        """
        self.file_path = file_path
        self.verbose = verbose
        self.data = None
        self.errors: List[str] = []
        self._rc4_cache = {}
        self._candidate_keys: List[Dict[str, Any]] = []
        self._successful_keys: List[Dict[str, Any]] = []
        self._cache = {}

    def _log(self, msg: str) -> None:
        """Verbose-gated progress logging -- NOT an error, don't append to self.errors."""
        if self.verbose:
            print(f"[*] DecryptionEngine: {msg}")

    def detect_encrypted_data(self, data: bytes) -> Dict[str, Any]:
        """Detect if data is likely encrypted and determine the algorithm.

        Args:
            data: Candidate data to check.

        Returns:
            Dict with is_encrypted, entropy, confidence, suggested_algorithm, reason.
        """
        if not data or len(data) < 1024:
            return {'is_encrypted': False, 'reason': 'data_too_small', 'entropy': 0.0}

        entropy = self._calculate_entropy(data)
        result = {
            'is_encrypted': False,
            'entropy': entropy,
            'confidence': 'low',
            'suggested_algorithm': None,
            'reason': ''
        }

        if entropy > self.SKIP_CARVING_THRESHOLD:
            result['is_encrypted'] = True
            result['confidence'] = 'high'
            result['suggested_algorithm'] = 'rc4'
            result['reason'] = f'Very high entropy ({entropy:.2f})'
            return result

        if entropy > self.HIGH_ENTROPY_THRESHOLD:
            if data[:2] == b'MZ':  # could be a packed PE, not encrypted
                result['is_encrypted'] = False
                result['reason'] = f'PE file with high entropy ({entropy:.2f}) - likely packed'
                return result

            result['is_encrypted'] = True
            result['confidence'] = 'medium'
            result['suggested_algorithm'] = 'rc4'
            result['reason'] = f'High entropy ({entropy:.2f})'
            return result

        if data[:2] == b'MZ':
            result['reason'] = f'PE file with normal entropy ({entropy:.2f})'
        elif data[:4] == b'PK\x03\x04':
            result['reason'] = f'ZIP file with normal entropy ({entropy:.2f})'
        elif data[:4] == b'\x7fELF':
            result['reason'] = f'ELF file with normal entropy ({entropy:.2f})'
        else:
            result['reason'] = f'Normal entropy ({entropy:.2f})'

        return result

    def try_decrypt_with_candidates(self, data: bytes) -> Optional[bytes]:
        """Detect whether data is encrypted, then try each candidate key against it.

        Returns:
            Decrypted data if successful, None otherwise.
        """
        detection = self.detect_encrypted_data(data)

        if not detection['is_encrypted']:
            self._log(f"Data doesn't appear encrypted: {detection['reason']}")
            return None

        self._log(f"Data appears encrypted: {detection['reason']}")
        self._log(f"Trying {len(self._candidate_keys)} candidate keys")

        for key_info in self._candidate_keys[:50]:
            key_data = key_info.get('key', '')
            if not key_data:
                continue

            for key_bytes in self._key_to_bytes_variants(key_data):
                if len(key_bytes) < 5:
                    continue

                decrypted = self._decrypt_rc4(data, key_bytes)
                if decrypted and self._is_valid_data(decrypted):
                    self._log(f"Success with RC4 key: {key_data[:20]}...")
                    self._successful_keys.append({
                        'algorithm': 'rc4',
                        'key': key_data,
                        'source': key_info.get('source_file', 'unknown')
                    })
                    return decrypted

                decrypted = self._decrypt_xor(data, key_bytes)
                if decrypted and self._is_valid_data(decrypted):
                    self._log(f"Success with XOR key: {key_data[:20]}...")
                    self._successful_keys.append({
                        'algorithm': 'xor',
                        'key': key_data,
                        'source': key_info.get('source_file', 'unknown')
                    })
                    return decrypted

        self._log("No candidate key successfully decrypted the data")
        return None

    def decrypt_with_key(self, data: bytes, key: bytes, algorithm: str,
                         nonce_or_iv: Optional[bytes] = None) -> Optional[bytes]:
        """Decrypt data using the specified algorithm and key.

        nonce_or_iv is optional -- ChaCha20/AES-CBC need one but this
        engine has no way to discover a real one from the sample.
        Defaults to zero bytes: it will only succeed against payloads
        actually encrypted with a zero nonce/IV, but that's a real,
        honest limitation rather than silently running the wrong algorithm.

        Args:
            data: Ciphertext to decrypt.
            key: Candidate key bytes.
            algorithm: 'rc4', 'chacha20', 'aes', 'xor', or 'base64'.
            nonce_or_iv: Nonce/IV for ChaCha20/AES, defaulting to zero bytes if not given.

        Returns:
            Decrypted bytes if the key validated and decryption ran without error, else None.
        """
        if not key or len(key) == 0:
            return None

        validation = self.validate_key(key, algorithm)
        if not validation.get('valid', False):
            self._log(f"Key validation failed for {algorithm}: {validation.get('reason')}")
            return None

        cache_key = f"{algorithm}_{key.hex()}_{len(data)}_{(nonce_or_iv or b'').hex()}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            decrypted = None
            if algorithm == 'rc4':
                decrypted = self._decrypt_rc4(data, key)
            elif algorithm == 'chacha20':
                decrypted = self._decrypt_chacha20(data, key, nonce_or_iv)
            elif algorithm == 'aes':
                decrypted = self._decrypt_aes(data, key, nonce_or_iv)
            elif algorithm == 'xor':
                decrypted = self._decrypt_xor(data, key)
            elif algorithm == 'base64':
                decrypted = self._decode_base64(data, key)
            else:
                decrypted = self._decrypt_rc4(data, key)  # fallback

            if decrypted:
                self._cache[cache_key] = decrypted
                if self._is_valid_data(decrypted):
                    self._successful_keys.append({
                        'algorithm': algorithm,
                        'key': key.hex(),
                        'decrypted_size': len(decrypted),
                        'entropy': self._calculate_entropy(decrypted)
                    })
                return decrypted

        except Exception as e:
            self.errors.append(f"Decryption error for {algorithm}: {e}")

        return None

    def decrypt_with_candidates(self, data: bytes, candidates: List[Dict[str, Any]],
                                max_tries: int = 50) -> List[Dict[str, Any]]:
        """Try multiple key candidates on data, sorted by priority, stopping early only on a confirmed PE.

        Args:
            data: Ciphertext to decrypt.
            candidates: Key candidates (from KeyReconstructor), sorted by _candidate_priority before trying.
            max_tries: Maximum number of candidates to actually attempt.

        Returns:
            One result dict per successful decryption (or a single
            {'already_valid': True} entry if data was already valid).
        """
        results = []
        tried = 0

        if self._is_valid_data(data):
            return [{'decrypted': data, 'already_valid': True}]

        sorted_candidates = sorted(candidates, key=self._candidate_priority, reverse=True)

        for candidate in sorted_candidates:
            if tried >= max_tries:
                break

            # Some KeyReconstructor candidate types (high_entropy_binary,
            # chacha20_key_candidate) only populate 'key_hex', not 'key'.
            key_data = candidate.get('key', '') or candidate.get('key_hex', '')
            algorithm = candidate.get('algorithm', 'rc4')

            if not key_data:
                continue

            key_bytes = self._key_to_bytes(key_data, candidate.get('type', ''))
            if not key_bytes:
                continue

            if len(key_bytes) < 3:
                continue

            if key_bytes.lower() in self.COMMON_KEYS:
                continue

            tried += 1
            decrypted = self.decrypt_with_key(data, key_bytes, algorithm)

            if decrypted and self._is_valid_data(decrypted):
                results.append({
                    'algorithm': algorithm,
                    'key': key_data,
                    'key_bytes': key_bytes.hex(),
                    'decrypted': decrypted,
                    'size': len(decrypted),
                    'entropy': self._calculate_entropy(decrypted),
                    'candidate': candidate
                })
                # Keep trying other keys; only stop early on a confirmed PE.
                if decrypted[:2] == b'MZ':
                    self._log(f"Found valid PE using {algorithm} key: {key_data[:20]}...")
                    break

        return results

    def _key_to_bytes(self, key_data: str, key_type: str) -> Optional[bytes]:
        """Convert a key string to bytes based on KeyReconstructor's candidate type.

        Type names must match what key_reconstructor.py actually emits --
        hex/base64-encoded candidates need decoding first, not a literal
        ASCII encode of the encoded string itself.

        Args:
            key_data: The key as a string (encoded form, depending on key_type).
            key_type: KeyReconstructor candidate type, e.g. 'hex_encoded', 'base64_encoded'.

        Returns:
            Decoded key bytes.
        """
        try:
            if key_type in ('hex_encoded', 'high_entropy_binary', 'chacha20_key_candidate'):
                return bytes.fromhex(key_data)
            elif key_type == 'base64_encoded':
                return base64.b64decode(key_data)
            elif key_type in ('plaintext_all_strings', 'xor_single_byte', 'xor_sub_key',
                              'printable_ascii', 'rc4_ksa_key'):
                return key_data.encode('ascii', errors='ignore')
            else:
                return key_data.encode('ascii', errors='ignore')  # unknown/future type: best-effort ASCII
        except Exception:
            return key_data.encode('ascii', errors='ignore')

    def _key_to_bytes_variants(self, key_data: str) -> List[bytes]:
        """Try multiple ways (raw ASCII, hex, UTF-8) to convert a key string to bytes.

        Args:
            key_data: The key as a string.

        Returns:
            Every successfully-decoded byte variant (not deduplicated).
        """
        variants = []

        try:
            variants.append(key_data.encode('ascii'))
        except Exception:
            pass

        try:
            if len(key_data) % 2 == 0:
                variants.append(bytes.fromhex(key_data))
        except Exception:
            pass

        try:
            variants.append(key_data.encode('utf-8'))
        except Exception:
            pass

        return variants

    def validate_key(self, key: bytes, algorithm: str) -> Dict[str, Any]:
        """Validate if a key is likely valid for the given algorithm.

        Args:
            key: Candidate key bytes.
            algorithm: Algorithm the key is intended for; looked up in ALGORITHM_RULES.

        Returns:
            Dict with 'valid' bool, a 'reason' if invalid, and 'entropy' if valid.
        """
        if not key or len(key) == 0:
            return {'valid': False, 'reason': 'empty_key'}

        if len(key) < 3:
            return {'valid': False, 'reason': 'key_too_short'}

        rules = self.ALGORITHM_RULES.get(algorithm, {})
        if rules:
            valid_sizes = rules.get('valid_key_sizes', [])
            if valid_sizes and len(key) not in valid_sizes:
                min_size = rules.get('min_key_size', 0)
                max_size = rules.get('max_key_size', 0)
                if not (min_size <= len(key) <= max_size):
                    return {'valid': False, 'reason': f'invalid_key_size_{len(key)}'}

            min_entropy = rules.get('min_entropy', 0)
            entropy = self._calculate_entropy(key)
            if entropy < min_entropy:
                return {'valid': False, 'reason': 'low_entropy', 'entropy': entropy}

        if key.lower() in self.COMMON_KEYS:
            return {'valid': False, 'reason': 'common_key'}

        return {'valid': True, 'entropy': self._calculate_entropy(key)}

    def _decrypt_rc4(self, data: bytes, key: bytes) -> Optional[bytes]:
        """RC4 decrypt using key.

        Args:
            data: Ciphertext to decrypt.
            key: RC4 key bytes.

        Returns:
            Decrypted bytes, or None on error.
        """
        try:
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

    def _decrypt_chacha20(self, data: bytes, key: bytes, nonce: Optional[bytes] = None) -> Optional[bytes]:
        """Real ChaCha20 decrypt via the `cryptography` library.

        Requires a 32-byte key (ChaCha20 has no variable key size) and a
        16-byte nonce (`cryptography`'s API: 4-byte LE block counter +
        12-byte RFC7539 nonce, concatenated). We have no way to discover
        the real per-payload nonce from static analysis alone, so this
        defaults to all-zero -- correct only for payloads that happen to
        use a zero nonce. That's an honest, narrower capability, not the
        previous silent "run RC4 instead" behavior.

        Args:
            data: Ciphertext to decrypt.
            key: 32-byte ChaCha20 key.
            nonce: 16-byte nonce, defaulting to all-zero if not given.

        Returns:
            Decrypted bytes, or None if the key size is wrong or decryption errors.
        """
        if len(key) != 32:
            self._log(f"ChaCha20 requires a 32-byte key, got {len(key)} -- skipping")
            return None
        try:
            nonce = (nonce or b'\x00' * 16).ljust(16, b'\x00')[:16]
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()
        except Exception as e:
            self.errors.append(f"ChaCha20 decryption error: {e}")
            return None

    def _decrypt_aes(self, data: bytes, key: bytes, iv: Optional[bytes] = None) -> Optional[bytes]:
        """Real AES decrypt via the `cryptography` library.

        Tries ECB first (needs only the key, no IV to guess), then CBC
        with the given IV (or all-zero if none discovered) as a
        best-effort fallback -- same "correct but narrower than a full
        implementation would be" tradeoff as ChaCha20 above: this cannot
        recover payloads encrypted with a real random IV we never
        discovered, but it no longer silently no-ops either.

        Args:
            data: Ciphertext to decrypt.
            key: 16/24/32-byte AES key.
            iv: CBC initialization vector, defaulting to all-zero if not given.

        Returns:
            The ECB attempt's output (whether or not CBC also succeeded),
            or None if the key size is wrong or there's no data to decrypt.
        """
        if len(key) not in (16, 24, 32):
            self._log(f"AES requires a 16/24/32-byte key, got {len(key)} -- skipping")
            return None

        block_size = 16
        truncated = data[: len(data) - (len(data) % block_size)]
        if not truncated:
            return None

        try:
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            decryptor = cipher.decryptor()
            ecb_result = decryptor.update(truncated) + decryptor.finalize()
            if self._is_valid_data(ecb_result):
                return ecb_result
        except Exception as e:
            self.errors.append(f"AES-ECB decryption error: {e}")
            ecb_result = None

        try:
            cbc_iv = (iv or b'\x00' * block_size).ljust(block_size, b'\x00')[:block_size]
            cipher = Cipher(algorithms.AES(key), modes.CBC(cbc_iv))
            decryptor = cipher.decryptor()
            cbc_result = decryptor.update(truncated) + decryptor.finalize()
            if self._is_valid_data(cbc_result):
                return cbc_result
        except Exception as e:
            self.errors.append(f"AES-CBC decryption error: {e}")
            cbc_result = None

        # Neither produced recognizably valid output -- return the ECB
        # attempt (block-cipher default) so callers relying on entropy
        # comparisons still have something to inspect, same contract as
        # the other _decrypt_* methods (they return their best attempt,
        # validity is checked by the caller via _is_valid_data).
        return ecb_result

    def _decrypt_xor(self, data: bytes, key: bytes) -> Optional[bytes]:
        """XOR decrypt using key.

        Args:
            data: Ciphertext to decrypt.
            key: Repeating XOR key bytes.

        Returns:
            Decrypted bytes, or None on error.
        """
        try:
            if not key:
                return None
            result = bytearray()
            for i, byte in enumerate(data):
                result.append(byte ^ key[i % len(key)])
            return bytes(result)
        except Exception as e:
            self.errors.append(f"XOR decryption error: {e}")
            return None

    def _decode_base64(self, data: bytes, key: bytes) -> Optional[bytes]:
        """Base64 decode data (key is unused; accepted for a uniform _decrypt_* signature).

        Args:
            data: Base64-encoded data to decode.
            key: Unused.

        Returns:
            Decoded bytes, or None on error.
        """
        try:
            return base64.b64decode(data)
        except Exception:
            return None

    def _candidate_priority(self, candidate: Dict[str, Any]) -> float:
        """Calculate a priority score for a key candidate, higher tried first.

        Args:
            candidate: A key candidate dict (algorithm, confidence, entropy, source).

        Returns:
            A priority score combining algorithm, confidence tier, entropy, and source.
        """
        score = 0.0

        algorithm = candidate.get('algorithm', '')
        if algorithm in ['chacha20', 'rc4']:
            score += 10.0
        elif algorithm in ['aes']:
            score += 8.0
        elif algorithm in ['xor']:
            score += 3.0
        else:
            score += 1.0

        confidence = candidate.get('confidence', '')
        if confidence == 'high':
            score += 5.0
        elif confidence == 'medium':
            score += 3.0
        elif confidence == 'low':
            score += 1.0

        entropy = candidate.get('entropy', 0)
        score += entropy * 0.5

        source = candidate.get('source', '')
        if '.rdata' in source:
            score += 3.0

        return score

    # Reflective loaders commonly prepend a stub (shellcode, a loader
    # header) before the actual PE they carry -- verified on a real
    # sample: roning's RC4-encrypted payload decrypts correctly with its
    # known key, but the resulting PE's MZ header sits at offset 4841, not
    # 0. A correct decryption was never recognized as one because every
    # validity check here only ever looked at the very start of the
    # buffer. Search a bounded window instead of just offset 0.
    MAX_EMBEDDED_PE_SEARCH = 8192

    def _find_embedded_pe_offset(self, data: bytes) -> Optional[int]:
        """Find a real PE header within the first MAX_EMBEDDED_PE_SEARCH bytes.

        Requires the full e_lfanew/PE\\0\\0 structure to line up, not just
        the 2-byte 'MZ' match -- a coincidental 'MZ' in random decryption
        garbage is plausible in an 8KB window; a *matching* PE signature
        at the offset it points to is not.

        Args:
            data: Candidate decrypted bytes to search.

        Returns:
            The offset of a real embedded PE header, or None if none found.
        """
        search_limit = min(len(data) - 4, self.MAX_EMBEDDED_PE_SEARCH)
        start = 0
        while True:
            idx = data.find(b'MZ', start, search_limit)
            if idx == -1:
                return None
            try:
                pe_offset = idx + struct.unpack('<I', data[idx + 0x3C:idx + 0x40])[0]
                if pe_offset + 4 < len(data) and data[pe_offset:pe_offset + 4] == b'PE\x00\x00':
                    return idx
            except Exception:
                pass
            start = idx + 1

    def _is_valid_data(self, data: bytes) -> bool:
        """Check if decrypted data looks like a real, recognizable file worth keeping.

        Args:
            data: Candidate decrypted bytes.

        Returns:
            True if data parses as (or contains) a PE, ZIP, zlib, GZip,
            JSON, XML, or sufficiently-printable plaintext file.
        """
        if len(data) < 1024:
            return False

        if data[:2] == b'MZ':
            try:
                import pefile
                from io import BytesIO
                pe = pefile.PE(data=BytesIO(data))
                return True
            except Exception:
                try:
                    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
                    if pe_offset + 4 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                        return True
                except Exception:
                    pass
                return False

        if self._find_embedded_pe_offset(data) is not None:
            return True

        if data[:4] == b'PK\x03\x04':
            return True

        if data[:2] in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
            return True

        if data[:2] == b'\x1F\x8B':
            return True

        try:
            import json
            json.loads(data[:1024].decode('utf-8', errors='ignore'))
            return True
        except Exception:
            pass

        if data[:5] == b'<?xml':
            return True

        printable = sum(1 for b in data[:512] if 32 <= b <= 126 or b in [9, 10, 13])
        if printable / min(len(data), 512) > 0.8:
            return True

        return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy.

        Args:
            data: Bytes to measure.

        Returns:
            Entropy in bits/byte (0.0 to 8.0).
        """
        if len(data) < 2:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)

        return entropy

    def get_successful_keys(self) -> List[Dict[str, Any]]:
        """Get keys that successfully decrypted data."""
        return self._successful_keys

    def get_errors(self) -> List[str]:
        """Get decryption errors."""
        return self.errors

    def decrypt_rc4(self, data: bytes, key: bytes) -> Optional[bytes]:
        """Public wrapper for RC4 decryption.

        Args:
            data: Ciphertext to decrypt.
            key: RC4 key bytes.

        Returns:
            Decrypted bytes, or None on error.
        """
        return self._decrypt_rc4(data, key)

    def decrypt_xor(self, data: bytes, key: bytes) -> Optional[bytes]:
        """Public wrapper for XOR decryption.

        Args:
            data: Ciphertext to decrypt.
            key: Repeating XOR key bytes.

        Returns:
            Decrypted bytes, or None on error.
        """
        return self._decrypt_xor(data, key)
