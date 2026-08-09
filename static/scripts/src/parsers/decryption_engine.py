"""
Decryption engine that tries discovered keys automatically with algorithm context.
TFM 2025-2026 - Universidad Complutense de Madrid
"""

from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
import math
import base64
import struct


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

    # Entropy thresholds
    HIGH_ENTROPY_THRESHOLD = 7.5
    SKIP_CARVING_THRESHOLD = 7.8

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = None
        self.errors: List[str] = []
        self._rc4_cache = {}
        self._candidate_keys: List[Dict[str, Any]] = []
        self._successful_keys: List[Dict[str, Any]] = []
        self._cache = {}

    def detect_encrypted_data(self, data: bytes) -> Dict[str, Any]:
        """
        Detect if data is likely encrypted and determine the algorithm.

        Returns:
            Dict with:
                - is_encrypted: bool
                - entropy: float
                - confidence: 'high', 'medium', 'low'
                - suggested_algorithm: str
                - reason: str
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

        # Very high entropy = likely encrypted
        if entropy > self.SKIP_CARVING_THRESHOLD:
            result['is_encrypted'] = True
            result['confidence'] = 'high'
            result['suggested_algorithm'] = 'rc4'
            result['reason'] = f'Very high entropy ({entropy:.2f})'
            return result

        # High entropy = possibly encrypted/obfuscated
        if entropy > self.HIGH_ENTROPY_THRESHOLD:
            # Check if it might be a PE file with high entropy (could be packed)
            if data[:2] == b'MZ':
                result['is_encrypted'] = False
                result['reason'] = f'PE file with high entropy ({entropy:.2f}) - likely packed'
                return result

            result['is_encrypted'] = True
            result['confidence'] = 'medium'
            result['suggested_algorithm'] = 'rc4'
            result['reason'] = f'High entropy ({entropy:.2f})'
            return result

        # Check for common file headers
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
        """
        Try to decrypt data using discovered keys.
        First checks if data is encrypted, then tries candidate keys.

        Returns:
            Decrypted data if successful, None otherwise
        """
        # First, detect if data is likely encrypted
        detection = self.detect_encrypted_data(data)

        if not detection['is_encrypted']:
            self.errors.append(f"Data doesn't appear encrypted: {detection['reason']}")
            return None

        self.errors.append(f"Data appears encrypted: {detection['reason']}")
        self.errors.append(f"Trying {len(self._candidate_keys)} candidate keys")

        # Try all candidate keys
        for key_info in self._candidate_keys[:50]:  # Limit to 50 keys
            key_data = key_info.get('key', '')
            if not key_data:
                continue

            # Try both hex and string forms
            for key_bytes in self._key_to_bytes_variants(key_data):
                if len(key_bytes) < 5:
                    continue

                # Try RC4
                decrypted = self._decrypt_rc4(data, key_bytes)
                if decrypted and self._is_valid_data(decrypted):
                    self.errors.append(f"Success with RC4 key: {key_data[:20]}...")
                    self._successful_keys.append({
                        'algorithm': 'rc4',
                        'key': key_data,
                        'source': key_info.get('source_file', 'unknown')
                    })
                    return decrypted

                # Try XOR
                decrypted = self._decrypt_xor(data, key_bytes)
                if decrypted and self._is_valid_data(decrypted):
                    self.errors.append(f"Success with XOR key: {key_data[:20]}...")
                    self._successful_keys.append({
                        'algorithm': 'xor',
                        'key': key_data,
                        'source': key_info.get('source_file', 'unknown')
                    })
                    return decrypted

        self.errors.append("No candidate key successfully decrypted the data")
        return None

    def decrypt_with_key(self, data: bytes, key: bytes, algorithm: str) -> Optional[bytes]:
        """Decrypt data using the specified algorithm and key."""
        if not key or len(key) == 0:
            return None

        # Validate key for the algorithm
        validation = self.validate_key(key, algorithm)
        if not validation.get('valid', False):
            self.errors.append(f"Key validation failed for {algorithm}: {validation.get('reason')}")
            return None

        # Check cache
        cache_key = f"{algorithm}_{key.hex()}_{len(data)}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            decrypted = None
            if algorithm == 'rc4':
                decrypted = self._decrypt_rc4(data, key)
            elif algorithm == 'chacha20':
                decrypted = self._decrypt_chacha20(data, key)
            elif algorithm == 'aes':
                decrypted = self._decrypt_aes(data, key)
            elif algorithm == 'xor':
                decrypted = self._decrypt_xor(data, key)
            elif algorithm == 'base64':
                decrypted = self._decode_base64(data, key)
            else:
                # Try RC4 as fallback
                decrypted = self._decrypt_rc4(data, key)

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
        """Try multiple key candidates on data."""
        results = []
        tried = 0

        # First, check if data is already valid
        if self._is_valid_data(data):
            return [{'decrypted': data, 'already_valid': True}]

        # Sort candidates by priority (algorithm confidence, entropy)
        sorted_candidates = sorted(candidates, key=self._candidate_priority, reverse=True)

        for candidate in sorted_candidates:
            if tried >= max_tries:
                break

            # Extract key and algorithm
            key_data = candidate.get('key', '')
            algorithm = candidate.get('algorithm', 'rc4')

            if not key_data:
                continue

            # Convert key to bytes based on type
            key_bytes = self._key_to_bytes(key_data, candidate.get('type', ''))
            if not key_bytes:
                continue

            # Skip keys that are too short
            if len(key_bytes) < 3:
                continue

            # Skip common keys
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
                # Keep trying other keys to find the best one
                # Only stop if we find a PE/executable
                if decrypted[:2] == b'MZ':
                    self.errors.append(f"Found valid PE using {algorithm} key: {key_data[:20]}...")
                    break

        return results

    def _key_to_bytes(self, key_data: str, key_type: str) -> Optional[bytes]:
        """Convert key string to bytes based on type."""
        try:
            if key_type in ['hex_key', 'roning_rc4_key']:
                # Hex string
                return bytes.fromhex(key_data)
            elif key_type == 'base64_key':
                # Base64 decoded
                return base64.b64decode(key_data)
            elif key_type in ['printable_key', 'rdata_key', 'pattern_key', 'string_key']:
                # ASCII string
                return key_data.encode('ascii', errors='ignore')
            elif key_type == 'binary_key_hex':
                # Already hex
                return bytes.fromhex(key_data)
            else:
                # Try as ASCII
                return key_data.encode('ascii', errors='ignore')
        except:
            # Try as ASCII as fallback
            return key_data.encode('ascii', errors='ignore')

    def _key_to_bytes_variants(self, key_data: str) -> List[bytes]:
        """Try multiple ways to convert a key string to bytes."""
        variants = []

        # Try as raw string
        try:
            variants.append(key_data.encode('ascii'))
        except:
            pass

        # Try as hex
        try:
            if len(key_data) % 2 == 0:
                variants.append(bytes.fromhex(key_data))
        except:
            pass

        # Try as UTF-8
        try:
            variants.append(key_data.encode('utf-8'))
        except:
            pass

        return variants

    def validate_key(self, key: bytes, algorithm: str) -> Dict[str, Any]:
        """Validate if a key is likely valid for the given algorithm."""
        if not key or len(key) == 0:
            return {'valid': False, 'reason': 'empty_key'}

        # Check minimum length
        if len(key) < 3:
            return {'valid': False, 'reason': 'key_too_short'}

        # Check algorithm-specific rules
        rules = self.ALGORITHM_RULES.get(algorithm, {})
        if rules:
            # Check key size
            valid_sizes = rules.get('valid_key_sizes', [])
            if valid_sizes and len(key) not in valid_sizes:
                # Allow if it's within range
                min_size = rules.get('min_key_size', 0)
                max_size = rules.get('max_key_size', 0)
                if not (min_size <= len(key) <= max_size):
                    return {'valid': False, 'reason': f'invalid_key_size_{len(key)}'}

            # Check entropy
            min_entropy = rules.get('min_entropy', 0)
            entropy = self._calculate_entropy(key)
            if entropy < min_entropy:
                return {'valid': False, 'reason': 'low_entropy', 'entropy': entropy}

        # Check if key is too common
        if key.lower() in self.COMMON_KEYS:
            return {'valid': False, 'reason': 'common_key'}

        return {'valid': True, 'entropy': self._calculate_entropy(key)}

    def _decrypt_rc4(self, data: bytes, key: bytes) -> Optional[bytes]:
        """RC4 decrypt using key."""
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

    def _decrypt_chacha20(self, data: bytes, key: bytes) -> Optional[bytes]:
        """ChaCha20 decrypt using key (simplified - requires actual implementation)."""
        # This is a placeholder - full ChaCha20 implementation would be here
        # For now, try RC4 as a fallback
        self.errors.append("ChaCha20 decryption not fully implemented, trying RC4 fallback")
        return self._decrypt_rc4(data, key)

    def _decrypt_aes(self, data: bytes, key: bytes) -> Optional[bytes]:
        """AES decrypt using key (simplified - requires actual implementation)."""
        # This is a placeholder - full AES implementation would be here
        self.errors.append("AES decryption not fully implemented")
        return None

    def _decrypt_xor(self, data: bytes, key: bytes) -> Optional[bytes]:
        """XOR decrypt using key."""
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
        """Base64 decode (key is used as separator)."""
        try:
            return base64.b64decode(data)
        except:
            return None

    def _candidate_priority(self, candidate: Dict[str, Any]) -> float:
        """Calculate priority score for a key candidate."""
        score = 0.0

        # Algorithm confidence
        algorithm = candidate.get('algorithm', '')
        if algorithm in ['chacha20', 'rc4']:
            score += 10.0
        elif algorithm in ['aes']:
            score += 8.0
        elif algorithm in ['xor']:
            score += 3.0
        else:
            score += 1.0

        # Key confidence
        confidence = candidate.get('confidence', '')
        if confidence == 'high':
            score += 5.0
        elif confidence == 'medium':
            score += 3.0
        elif confidence == 'low':
            score += 1.0

        # Entropy
        entropy = candidate.get('entropy', 0)
        score += entropy * 0.5

        # Source
        source = candidate.get('source', '')
        if '.rdata' in source:
            score += 3.0

        return score

    def _is_valid_data(self, data: bytes) -> bool:
        """Check if data is valid and worth keeping."""
        if len(data) < 1024:
            return False

        # Check for PE
        if data[:2] == b'MZ':
            try:
                import pefile
                from io import BytesIO
                pe = pefile.PE(data=BytesIO(data))
                return True
            except:
                # Check if it looks like a PE even if pefile fails
                try:
                    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
                    if pe_offset + 4 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                        return True
                except:
                    pass
                return False

        # Check for ZIP
        if data[:4] == b'PK\x03\x04':
            return True

        # Check for zlib
        if data[:2] in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
            return True

        # Check for GZip
        if data[:2] == b'\x1F\x8B':
            return True

        # Check for valid JSON
        try:
            import json
            json.loads(data[:1024].decode('utf-8', errors='ignore'))
            return True
        except:
            pass

        # Check for valid XML
        if data[:5] == b'<?xml':
            return True

        # Check for plaintext
        printable = sum(1 for b in data[:512] if 32 <= b <= 126 or b in [9, 10, 13])
        if printable / min(len(data), 512) > 0.8:
            return True

        return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
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
        """Public wrapper for RC4 decryption."""
        return self._decrypt_rc4(data, key)

    def decrypt_xor(self, data: bytes, key: bytes) -> Optional[bytes]:
        """Public wrapper for XOR decryption."""
        return self._decrypt_xor(data, key)
