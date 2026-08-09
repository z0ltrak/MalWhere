"""
key_reconstructor.py — malwhere pipeline v3

Generic encryption key discovery from binary samples.
Designed to work on unknown malware without hardcoded assumptions.

Performance fixes from v3.1:
- Added _find_all_printable_strings() to catch plaintext keys at any offset
- Scans .rdata/.data sections with step=1 but limited to first 1MB (fast)
- Lower entropy threshold (2.5) for plaintext keys
- Generic - works for any malware, no hardcoded keys

Design principle: GENERIC first, specific never.
No hardcoded offsets, key values, or family-specific logic.
"""

import math
import re
import base64
import struct
from typing import List, Dict, Any, Optional, Set
from pathlib import Path


# ---- Tunable thresholds ----
MIN_PRINTABLE_RATIO = 0.95      # v2 was 0.80 — main FP source
MIN_KEY_ENTROPY = 4.0           # v2 was 3.5
XOR_STEP = 1                    # scan every Nth byte position
PRINTABLE_STEP = 1              # same for printable key scan
MAX_CANDIDATES_PER_TECHNIQUE = 100  # hard cap per technique
MAX_TOTAL_KEYS = 300            # hard cap on dedup output

XOR_KEY_LENGTHS = [8, 10, 12, 15, 16, 20, 24, 32]

# DATA sections only for XOR bruteforce (skip .text, .code)
XOR_SCAN_SECTIONS = {'.rdata', '.data', '.rsrc', 'data', '<file>'}

COMMON_NON_KEY_PATTERNS = [
    re.compile(r'^[A-Za-z\s]{8,}$'),
    re.compile(r'This program'),
    re.compile(r'cannot be run'),
    re.compile(r'DOS mode'),
    re.compile(r'^[0-9\.\-\s]+$'),
    re.compile(r'^[A-Z][a-z]+\s[A-Z][a-z]+'),
]

CHACHA20_CONSTANT = b'expand 32-byte k'
SALSA20_CONSTANT  = b'expand 16-byte k'
RC4_KSA_MIN_UNIQUE = 200

ALGORITHM_KEY_SIZES = {
    'rc4':     [5, 8, 10, 12, 15, 16, 20, 24, 32],
    'aes':     [16, 24, 32],
    'chacha20':[32],
    'salsa20': [32],
    'xor':     [1, 2, 4, 8, 16],
    'des':     [8],
    '3des':    [16, 24],
}


class KeyReconstructor:
    """Generic encryption key discovery from binary data."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data: Optional[bytes] = None
        self.errors: List[str] = []
        self.keys: List[Dict[str, Any]] = []
        self._sections: List[Dict[str, Any]] = []
        self._detected_algorithms: Set[str] = set()
        self._algorithm_key_sizes: Dict[str, List[int]] = {}

    # ------------------------------------------------------------------ #
    # Public entry point                                                   #
    # ------------------------------------------------------------------ #

    def find_keys(self) -> List[Dict[str, Any]]:
        """Run all key discovery techniques. Returns up to MAX_TOTAL_KEYS candidates."""
        try:
            self.data = self.file_path.read_bytes()
        except Exception as e:
            self.errors.append(f"Failed to read file: {e}")
            return []

        # Skip tiny files
        if len(self.data) < 64:
            return []

        self._load_sections()
        self._detect_encryption_algorithms()
        self._log(f"Algorithms detected: {self._detected_algorithms}")

        candidates: List[Dict[str, Any]] = []

        # 0. ALL PRINTABLE STRINGS (NEW - catches plaintext keys at any offset)
        plaintext_all = self._find_all_printable_strings()
        candidates.extend(plaintext_all[:MAX_CANDIDATES_PER_TECHNIQUE])
        if plaintext_all:
            self._log(f"Found {len(plaintext_all)} printable string candidates")
            # Log first few to see if we caught anything interesting
            for i, key in enumerate(plaintext_all[:3]):
                self._log(f"  Printable candidate: '{key.get('key', '')[:30]}' (len={key.get('length')})")

        # 1. Single-byte XOR bruteforce (most important, most expensive — capped)
        xor_results = self._find_xor_single_byte_keys()
        candidates.extend(xor_results[:MAX_CANDIDATES_PER_TECHNIQUE])

        # 2. Sub-key extraction from top XOR candidates only
        top_xor = [c for c in xor_results if c.get('confidence') == 'high'][:20]
        candidates.extend(self._extract_sub_keys(top_xor)[:MAX_CANDIDATES_PER_TECHNIQUE])

        # 3. Plaintext keys (existing - step=4)
        candidates.extend(self._find_printable_keys()[:MAX_CANDIDATES_PER_TECHNIQUE])

        # 4. Base64 keys
        candidates.extend(self._find_base64_keys()[:MAX_CANDIDATES_PER_TECHNIQUE])

        # 5. Hex-encoded keys
        candidates.extend(self._find_hex_keys()[:MAX_CANDIDATES_PER_TECHNIQUE])

        # 6. High-entropy binary regions (AES/ChaCha20)
        candidates.extend(self._find_high_entropy_regions()[:MAX_CANDIDATES_PER_TECHNIQUE])

        # 7. ChaCha20/Salsa20 constants
        candidates.extend(self._find_chacha_constants())

        # 8. RC4 KSA
        candidates.extend(self._find_rc4_ksa()[:MAX_CANDIDATES_PER_TECHNIQUE])

        # Filter by detected algorithms, deduplicate, hard-cap
        candidates = self._filter_by_algorithm(candidates)
        self.keys = self._deduplicate(candidates)
        self._log(f"Total keys after filtering: {len(self.keys)}")

        for i, key in enumerate(self.keys[:5]):
            self._log(f"  Top {i+1}: '{key.get('key', key.get('key_hex',''))[:30]}' "
                      f"({key.get('confidence')}, {key.get('algorithm','?')})")

        return self.keys

    # ------------------------------------------------------------------ #
    # NEW: All printable strings (catches plaintext keys at any offset)   #
    # ------------------------------------------------------------------ #

    def _find_all_printable_strings(self) -> List[Dict[str, Any]]:
        """
        Find ALL printable strings of key-like lengths in .rdata/.data.
        This catches plaintext keys that might be fragmented or at non-4-byte-aligned offsets.
        Generic - works for any file, not malware-specific.

        Performance: Only scans first 1MB of each data section (keys are usually near start).
        """
        candidates = []
        seen = set()

        # Key lengths to consider (common for crypto keys)
        key_lengths = [8, 10, 12, 15, 16, 20, 24, 32]

        # Only scan data sections
        for section in self._sections:
            # Skip sections that are unlikely to contain keys
            skip_sections = ('.text', '.code', 'code', '.plt', '.pdata', '.reloc', '.fptable')
            if section['name'].lower() in skip_sections:
                continue

            data = section['data']
            base_offset = section['offset']

            # Limit to first 1MB of each section (keys are usually near the beginning)
            # This keeps performance reasonable even with step=1
            scan_limit = min(len(data), 1024 * 1024)
            data = data[:scan_limit]

            self._log(f"  Scanning {section['name']} ({len(data)} bytes) for printable strings")

            for key_len in key_lengths:
                if len(data) < key_len:
                    continue

                # Scan EVERY byte (step=1) - but limited to 1MB sections
                for i in range(0, len(data) - key_len + 1):
                    if len(candidates) >= MAX_CANDIDATES_PER_TECHNIQUE * 2:
                        break

                    chunk = data[i:i + key_len]

                    # Check if it's printable ASCII (slightly lower threshold for plaintext)
                    if not self._is_printable_bytes(chunk, 0.85):
                        continue

                    decoded_str = chunk.decode('ascii', errors='replace')

                    # Skip if it's common text
                    if self._is_common_text(decoded_str):
                        continue

                    # Skip if it's all the same character
                    if len(set(decoded_str)) < 4:
                        continue

                    # Check entropy - needs SOME randomness to be a key
                    entropy = self._entropy(chunk)
                    if entropy < 2.5:  # Lower threshold for plaintext keys
                        continue

                    # Skip strings that are just sequential characters (lookup tables)
                    if self._is_sequential(decoded_str):
                        continue

                    # Skip if it's just numbers (likely version info)
                    if re.match(r'^[0-9\.]+$', decoded_str):
                        continue

                    key_id = f"plain_all_{decoded_str[:20]}"
                    if key_id in seen:
                        continue
                    seen.add(key_id)

                    # Determine algorithm from length
                    algorithm = self._determine_algorithm_from_length(key_len)

                    # Higher confidence for 15-byte keys (RC4 common length)
                    confidence = 'high' if key_len == 15 else 'medium'

                    candidates.append({
                        'type': 'plaintext_all_strings',
                        'key': decoded_str,
                        'key_hex': chunk.hex(),
                        'length': key_len,
                        'section': section['name'],
                        'offset': base_offset + i,
                        'entropy': round(entropy, 3),
                        'confidence': confidence,
                        'description': f"Printable string ({key_len} bytes): '{decoded_str[:30]}'",
                        'attck_id': 'T1027',
                        'algorithm': algorithm,
                    })

        return candidates

    # ------------------------------------------------------------------ #
    # Algorithm detection                                                  #
    # ------------------------------------------------------------------ #

    def _detect_encryption_algorithms(self) -> None:
        """Quick string scan for algorithm indicators."""
        self._detected_algorithms = set()
        self._algorithm_key_sizes = {}

        try:
            # Fast: collect strings from data sections only
            strings = []
            for s in self._sections:
                if s['name'].lower() in XOR_SCAN_SECTIONS:
                    data = s['data']
                    current = []
                    for byte in data:
                        if 32 <= byte <= 126:
                            current.append(chr(byte))
                        else:
                            if len(current) >= 6:
                                strings.append(''.join(current))
                            current = []

            text = ' '.join(strings).lower()

            if any(k in text for k in ['rc4', 'arc4', 'streamcipher']):
                self._detected_algorithms.add('rc4')
            if any(k in text for k in ['aes', 'rijndael']):
                self._detected_algorithms.add('aes')
            if 'chacha' in text or CHACHA20_CONSTANT in (self.data or b''):
                self._detected_algorithms.add('chacha20')
            if SALSA20_CONSTANT in (self.data or b''):
                self._detected_algorithms.add('salsa20')

        except Exception as e:
            self._log(f"Algorithm detection error: {e}")

        # Default: search for all common types
        if not self._detected_algorithms:
            self._detected_algorithms = {'rc4', 'aes', 'xor'}

        for algo in self._detected_algorithms:
            self._algorithm_key_sizes[algo] = ALGORITHM_KEY_SIZES.get(algo, [16, 32])

    # ------------------------------------------------------------------ #
    # Section loading                                                      #
    # ------------------------------------------------------------------ #

    def _load_sections(self) -> None:
        """Load PE sections. Falls back to whole file scan."""
        try:
            import pefile
            pe = pefile.PE(data=self.data)
            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
                self._sections.append({
                    'name': name,
                    'data': section.get_data(),
                    'offset': section.PointerToRawData,
                })
            pe.close()
        except Exception:
            self._sections.append({
                'name': '<file>',
                'data': self.data,
                'offset': 0,
            })

    # ------------------------------------------------------------------ #
    # Technique 1 — Single-byte XOR bruteforce                            #
    # ------------------------------------------------------------------ #

    def _find_xor_single_byte_keys(self) -> List[Dict[str, Any]]:
        """
        Bruteforce single-byte XOR on data sections with step=4.
        Finds keys like RONINGLOADER's 0x5A-obfuscated RC4 key.
        Capped at MAX_CANDIDATES_PER_TECHNIQUE.
        """
        candidates = []
        seen = set()

        # Only scan data sections — not executable sections
        data_sections = [
            s for s in self._sections
            if s['name'].lower() in XOR_SCAN_SECTIONS
        ]

        # Use algorithm-aware key lengths
        valid_lengths = set()
        for algo in self._detected_algorithms:
            valid_lengths.update(self._algorithm_key_sizes.get(algo, []))
        if not valid_lengths:
            valid_lengths = set(XOR_KEY_LENGTHS)
        # Always include 15 (common RC4 key length)
        valid_lengths.add(15)

        for section in data_sections:
            data = section['data']
            base_offset = section['offset']

            for xor_byte in range(1, 256):
                for key_len in sorted(valid_lengths):
                    if len(data) < key_len:
                        continue

                    # Step = 4 for performance (was 1 in v2)
                    for i in range(0, len(data) - key_len + 1, 4):
                        if len(candidates) >= MAX_CANDIDATES_PER_TECHNIQUE * 3:
                            break

                        chunk = data[i:i + key_len]
                        decoded = bytes(b ^ xor_byte for b in chunk)

                        # Tighter printability check (0.95 vs 0.80 in v2)
                        if not self._is_printable_bytes(decoded, MIN_PRINTABLE_RATIO):
                            continue

                        decoded_str = decoded.decode('ascii', errors='replace')

                        if self._is_common_text(decoded_str):
                            continue

                        entropy = self._entropy(chunk)
                        if entropy < MIN_KEY_ENTROPY:
                            continue

                        if len(set(decoded_str)) < max(4, key_len // 4):
                            continue

                        key_id = f"xor1_{decoded_str[:20]}"
                        if key_id in seen:
                            continue
                        seen.add(key_id)

                        algorithm = self._determine_algorithm_from_length(key_len)
                        candidates.append({
                            'type': 'xor_single_byte',
                            'key': decoded_str,
                            'key_hex': chunk.hex(),
                            'key_decoded_hex': decoded.hex(),
                            'xor_byte': hex(xor_byte),
                            'length': key_len,
                            'section': section['name'],
                            'offset': base_offset + i,
                            'entropy_obfuscated': round(entropy, 3),
                            'confidence': 'high' if entropy > 4.5 else 'medium',
                            'description': (
                                f"Byte sequence XORed with 0x{xor_byte:02X} → "
                                f"printable ASCII: '{decoded_str}'"
                            ),
                            'attck_id': 'T1027',
                            'algorithm': algorithm,
                        })

        return candidates

    # ------------------------------------------------------------------ #
    # Technique 1b — Sub-key extraction                                   #
    # ------------------------------------------------------------------ #

    def _extract_sub_keys(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract sub-keys from high-confidence XOR-decrypted strings.
        Limited to top candidates to avoid explosion.
        """
        sub_keys = []
        seen = set()

        for candidate in candidates:
            key_str = candidate.get('key', '')
            if not key_str or len(key_str) < 8:
                continue

            # Extract all alphanumeric sequences of key-like lengths
            for match in re.finditer(r'[a-zA-Z0-9]{10,32}', key_str):
                sub = match.group()
                key_id = f"sub_{sub[:20]}"
                if key_id in seen:
                    continue

                entropy = self._entropy(sub.encode())
                if entropy < MIN_KEY_ENTROPY:
                    continue

                if len(set(sub)) < 5:
                    continue

                if self._is_common_text(sub):
                    continue

                seen.add(key_id)
                algorithm = self._determine_algorithm_from_length(len(sub))
                sub_keys.append({
                    'type': 'xor_sub_key',
                    'key': sub,
                    'key_hex': sub.encode().hex(),
                    'length': len(sub),
                    'parent_key': key_str[:50],
                    'entropy': round(entropy, 3),
                    'confidence': 'high' if len(sub) == 15 else 'medium',
                    'description': f"Sub-key from XOR-decrypted string: '{sub}'",
                    'algorithm': algorithm,
                })

                if len(sub_keys) >= MAX_CANDIDATES_PER_TECHNIQUE:
                    break

        return sub_keys

    # ------------------------------------------------------------------ #
    # Technique 2 — Plaintext printable keys (step=4)                     #
    # ------------------------------------------------------------------ #

    def _find_printable_keys(self) -> List[Dict[str, Any]]:
        """Find unobfuscated printable ASCII key strings with step=4."""
        candidates = []
        seen = set()

        valid_lengths = set()
        for algo in self._detected_algorithms:
            valid_lengths.update(self._algorithm_key_sizes.get(algo, []))
        if not valid_lengths:
            valid_lengths = set(XOR_KEY_LENGTHS)

        for section in self._sections:
            data = section['data']
            base_offset = section['offset']

            for key_len in sorted(valid_lengths):
                if len(data) < key_len:
                    continue

                for i in range(0, len(data) - key_len + 1, 4):
                    if len(candidates) >= MAX_CANDIDATES_PER_TECHNIQUE:
                        break

                    chunk = data[i:i + key_len]
                    if not self._is_printable_bytes(chunk, MIN_PRINTABLE_RATIO):
                        continue

                    decoded_str = chunk.decode('ascii', errors='replace')
                    if self._is_common_text(decoded_str):
                        continue

                    if len(set(decoded_str)) < max(4, key_len // 4):
                        continue

                    entropy = self._entropy(chunk)
                    if entropy < MIN_KEY_ENTROPY:
                        continue

                    key_id = f"plain_{decoded_str[:20]}"
                    if key_id in seen:
                        continue
                    seen.add(key_id)

                    algorithm = self._determine_algorithm_from_length(key_len)
                    candidates.append({
                        'type': 'printable_ascii',
                        'key': decoded_str,
                        'key_hex': chunk.hex(),
                        'length': key_len,
                        'section': section['name'],
                        'offset': base_offset + i,
                        'entropy': round(entropy, 3),
                        'confidence': 'medium',
                        'description': f"Plaintext key candidate ({key_len} bytes): '{decoded_str}'",
                        'attck_id': 'T1027',
                        'algorithm': algorithm,
                    })

        return candidates

    # ------------------------------------------------------------------ #
    # Technique 3 — Base64 keys                                           #
    # ------------------------------------------------------------------ #

    def _find_base64_keys(self) -> List[Dict[str, Any]]:
        """Find Base64-encoded blobs decoding to key-sized data."""
        candidates = []
        seen = set()

        try:
            text = self.data.decode('ascii', errors='ignore')
        except Exception:
            return candidates

        pattern = re.compile(r'[A-Za-z0-9+/]{24,88}={0,2}')
        for match in pattern.finditer(text):
            if len(candidates) >= MAX_CANDIDATES_PER_TECHNIQUE:
                break
            b64_str = match.group()
            try:
                decoded = base64.b64decode(b64_str)
            except Exception:
                continue

            if len(decoded) not in (8, 10, 12, 15, 16, 20, 24, 32, 48, 64):
                continue

            entropy = self._entropy(decoded)
            if entropy < MIN_KEY_ENTROPY:
                continue

            key_id = f"b64_{b64_str[:20]}"
            if key_id in seen:
                continue
            seen.add(key_id)

            algorithm = self._determine_algorithm_from_length(len(decoded))
            candidates.append({
                'type': 'base64_encoded',
                'key': b64_str,
                'key_decoded_hex': decoded.hex(),
                'decoded_length': len(decoded),
                'offset': match.start(),
                'entropy_decoded': round(entropy, 3),
                'confidence': 'medium',
                'description': f"Base64 → {len(decoded)} bytes, entropy {entropy:.2f}",
                'attck_id': 'T1027',
                'algorithm': algorithm,
            })

        return candidates

    # ------------------------------------------------------------------ #
    # Technique 4 — Hex-encoded keys                                      #
    # ------------------------------------------------------------------ #

    def _find_hex_keys(self) -> List[Dict[str, Any]]:
        """Find hex-encoded key strings (32/40/64 char)."""
        candidates = []
        seen = set()

        try:
            text = self.data.decode('ascii', errors='ignore')
        except Exception:
            return candidates

        for char_len, byte_len, desc in [
            (32, 16, 'AES-128'),
            (40, 20, 'SHA1-size'),
            (64, 32, 'AES-256'),
        ]:
            if len(candidates) >= MAX_CANDIDATES_PER_TECHNIQUE:
                break
            pattern = re.compile(
                rf'(?<![0-9a-fA-F])[0-9a-fA-F]{{{char_len}}}(?![0-9a-fA-F])'
            )
            for match in pattern.finditer(text):
                hex_str = match.group()
                try:
                    raw = bytes.fromhex(hex_str)
                except Exception:
                    continue

                entropy = self._entropy(raw)
                if entropy < MIN_KEY_ENTROPY:
                    continue

                key_id = f"hex_{hex_str[:20]}"
                if key_id in seen:
                    continue
                seen.add(key_id)

                algorithm = self._determine_algorithm_from_length(byte_len)
                candidates.append({
                    'type': 'hex_encoded',
                    'key': hex_str,
                    'key_bytes_hex': raw.hex(),
                    'decoded_length': byte_len,
                    'offset': match.start(),
                    'entropy': round(entropy, 3),
                    'confidence': 'medium',
                    'description': f"Hex key {char_len} chars = {byte_len} bytes ({desc})",
                    'attck_id': 'T1027',
                    'algorithm': algorithm,
                })

        return candidates

    # ------------------------------------------------------------------ #
    # Technique 5 — High-entropy binary regions                           #
    # ------------------------------------------------------------------ #

    def _find_high_entropy_regions(self) -> List[Dict[str, Any]]:
        """Scan for high-entropy binary regions (AES/ChaCha20 keys)."""
        candidates = []
        seen = set()

        data_sections = [
            s for s in self._sections
            if s['name'].lower() not in ('.text', '.code', 'code', '.plt')
        ]

        for section in data_sections:
            data = section['data']
            base_offset = section['offset']

            for key_len in (16, 32):
                threshold = 7.2

                for i in range(0, len(data) - key_len, 16):  # step=16
                    if len(candidates) >= MAX_CANDIDATES_PER_TECHNIQUE:
                        break

                    chunk = data[i:i + key_len]
                    if self._is_printable_bytes(chunk, 0.8):
                        continue

                    entropy = self._entropy(chunk)
                    if entropy < threshold:
                        continue

                    if chunk.count(0) / key_len > 0.25:
                        continue

                    key_id = f"hent_{chunk.hex()[:16]}"
                    if key_id in seen:
                        continue
                    seen.add(key_id)

                    algorithm = self._determine_algorithm_from_length(key_len)
                    candidates.append({
                        'type': 'high_entropy_binary',
                        'key_hex': chunk.hex(),
                        'length': key_len,
                        'section': section['name'],
                        'offset': base_offset + i,
                        'entropy': round(entropy, 3),
                        'confidence': 'low',
                        'description': f"High-entropy binary {key_len}B region (entropy {entropy:.2f})",
                        'attck_id': 'T1027',
                        'algorithm': algorithm,
                    })

        return candidates

    # ------------------------------------------------------------------ #
    # Technique 6 — ChaCha20/Salsa20 constants                           #
    # ------------------------------------------------------------------ #

    def _find_chacha_constants(self) -> List[Dict[str, Any]]:
        """Detect ChaCha20/Salsa20 sigma constants."""
        candidates = []
        for constant, algo in [
            (CHACHA20_CONSTANT, 'ChaCha20'),
            (SALSA20_CONSTANT, 'Salsa20'),
        ]:
            pos = 0
            while True:
                pos = self.data.find(constant, pos)
                if pos == -1:
                    break
                candidates.append({
                    'type': 'crypto_constant',
                    'algorithm': algo.lower(),
                    'constant': constant.decode('ascii'),
                    'offset': pos,
                    'confidence': 'high',
                    'description': f"{algo} sigma constant at offset {pos}",
                    'attck_id': 'T1486',
                })
                # Look for 32-byte key near constant
                for delta in (-32, 16, 32):
                    ko = pos + delta
                    if 0 <= ko <= len(self.data) - 32:
                        kb = self.data[ko:ko + 32]
                        entropy = self._entropy(kb)
                        if entropy > 6.5 and kb.count(0) < 6:
                            candidates.append({
                                'type': 'chacha20_key_candidate',
                                'algorithm': algo.lower(),
                                'key_hex': kb.hex(),
                                'offset': ko,
                                'entropy': round(entropy, 3),
                                'confidence': 'medium',
                                'description': f"Possible {algo} 32B key near constant",
                                'attck_id': 'T1486',
                            })
                pos += 1
        return candidates

    # ------------------------------------------------------------------ #
    # Technique 7 — RC4 KSA detection                                     #
    # ------------------------------------------------------------------ #

    def _find_rc4_ksa(self) -> List[Dict[str, Any]]:
        """Detect RC4 S-box arrays and nearby keys."""
        candidates = []

        for section in self._sections:
            data = section['data']
            base_offset = section['offset']
            if len(data) < 256:
                continue

            for i in range(0, len(data) - 256, 32):  # step=32 (was 16)
                if len(candidates) >= MAX_CANDIDATES_PER_TECHNIQUE:
                    break
                chunk = data[i:i + 256]
                if len(set(chunk)) < RC4_KSA_MIN_UNIQUE:
                    continue

                for delta in (-32, -16, 256):
                    ko = i + delta
                    if ko < 0 or ko + 32 > len(data):
                        continue
                    for klen in (8, 10, 15, 16, 20, 32):
                        kb = data[ko:ko + klen]
                        if not self._is_printable_bytes(kb, MIN_PRINTABLE_RATIO):
                            continue
                        key_str = kb.decode('ascii', errors='replace')
                        if self._is_common_text(key_str):
                            continue
                        algorithm = self._determine_algorithm_from_length(klen)
                        candidates.append({
                            'type': 'rc4_ksa_key',
                            'key': key_str,
                            'key_hex': kb.hex(),
                            'sbox_offset': base_offset + i,
                            'key_offset': base_offset + ko,
                            'confidence': 'medium',
                            'description': f"RC4 S-box at {base_offset+i}, key nearby: '{key_str}'",
                            'attck_id': 'T1027',
                            'algorithm': algorithm,
                        })

        return candidates

    # ------------------------------------------------------------------ #
    # Algorithm-aware filtering                                            #
    # ------------------------------------------------------------------ #

    def _filter_by_algorithm(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score and filter candidates based on detected algorithms."""
        if not candidates:
            return candidates

        filtered = []
        for c in candidates:
            algo = c.get('algorithm', 'unknown')
            key_len = len(c.get('key', '') or c.get('key_hex', '') or '')

            if algo in self._detected_algorithms:
                valid_sizes = self._algorithm_key_sizes.get(algo, [])
                if not valid_sizes or key_len in valid_sizes:
                    c['confidence'] = 'high'
                    filtered.append(c)
                    continue

            # Try to assign best algorithm from length
            for a in self._detected_algorithms:
                sizes = self._algorithm_key_sizes.get(a, [])
                if key_len in sizes:
                    c['algorithm'] = a
                    filtered.append(c)
                    break
            else:
                # Keep if it's a crypto constant or has explicit algorithm
                if c.get('type') in ('crypto_constant', 'chacha20_key_candidate'):
                    filtered.append(c)
                elif algo != 'unknown':
                    filtered.append(c)

        return filtered

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _determine_algorithm_from_length(self, length: int) -> str:
        if length == 15:             return 'rc4'
        elif length in (16, 24, 32): return 'aes'
        elif length in (5, 8, 10, 12, 20): return 'rc4'
        elif length <= 8:            return 'xor'
        return 'unknown'

    def _is_printable_bytes(self, data: bytes, min_ratio: float) -> bool:
        if not data:
            return False
        printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
        return (printable / len(data)) >= min_ratio

    def _is_common_text(self, s: str) -> bool:
        for pattern in COMMON_NON_KEY_PATTERNS:
            if pattern.search(s):
                return True
        if s and max(s.count(c) for c in set(s)) > len(s) * 0.5:
            return True
        return False

    def _is_sequential(self, s: str) -> bool:
        """Check if a string is sequential characters (like lookup tables)."""
        if len(s) < 5:
            return False
        # Check for sequential ASCII pattern
        sequential_count = 0
        for i in range(len(s) - 1):
            if ord(s[i+1]) - ord(s[i]) == 1:
                sequential_count += 1
            else:
                sequential_count = 0
            if sequential_count >= 4:
                return True
        return False

    def _entropy(self, data) -> float:
        if isinstance(data, str):
            data = data.encode('ascii', errors='replace')
        if len(data) < 2:
            return 0.0
        freq: Dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def _deduplicate(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate and sort by confidence. Hard cap at MAX_TOTAL_KEYS."""
        conf_order = {'high': 0, 'medium': 1, 'low': 2}
        seen = set()
        unique = []

        sorted_cands = sorted(
            candidates,
            key=lambda x: (
                conf_order.get(x.get('confidence', 'low'), 2),
                -(x.get('entropy', x.get('entropy_obfuscated', 0.0)) or 0.0)
            )
        )

        for c in sorted_cands:
            key_str = c.get('key', '')
            dedup_id = (key_str or c.get('key_hex', '') or c.get('key_decoded_hex', ''))[:32]
            if dedup_id and dedup_id not in seen:
                seen.add(dedup_id)
                unique.append(c)
            if len(unique) >= MAX_TOTAL_KEYS:
                break

        return unique

    def _log(self, msg: str) -> None:
        self.errors.append(f"KeyReconstructor: {msg}")

    def get_errors(self) -> List[str]:
        return self.errors
