"""Entropy detection for obfuscated/encrypted sections."""

import math
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..models.report import EntropyFinding, EntropyAnalysis
from ..constants import HIGH_ENTROPY_THRESHOLD


class EntropyDetector:
    """Detect obfuscated/encrypted sections using entropy analysis."""

    # Entropy thresholds -- see src/constants.py
    HIGH_ENTROPY_THRESHOLD = HIGH_ENTROPY_THRESHOLD
    SUSPICIOUS_ENTROPY_THRESHOLD = 6.0

    # Known packed section names
    PACKED_SECTION_NAMES = [
        '.UPX', 'UPX0', 'UPX1', '.upx',
        '.aspack', 'ASPack',
        '.mpress', 'MPRESS',
        'PEC2', 'PEC3', 'PECompact', '.pecompact',
        'Themida', '.themida',
        'VMProtect', 'VMP',
    ]

    # Crypto indicator keywords
    CRYPTO_KEYWORDS = [
        'encrypt', 'decrypt', 'RC4', 'AES', 'RSA', 'ChaCha20',
        'XOR', 'Base64', 'key', 'salt', 'iv', 'nonce',
        'cipher', 'crypto', 'crypt', 'hash', 'SHA', 'MD5',
        'expand 32-byte k', 'expand 16-byte k'
    ]

    def __init__(self, file_path: Path):
        """Initialize entropy detector."""
        self.file_path = file_path
        self.data = None

    def analyze(self, sections: List, strings: List[str]) -> EntropyAnalysis:
        """Analyze entropy of sections and data."""

        high_entropy = []
        suspicious = []
        packed = []
        encrypted = []

        # 1. Analyze sections (treat as objects, not dicts)
        for section in sections:

            entropy = section.entropy
            name = section.name

            # Check for packed section names
            if any(p in name for p in self.PACKED_SECTION_NAMES):
                packed.append(EntropyFinding(
                    name=name,
                    entropy=entropy,
                    threshold='N/A',
                    likely=f'Packer detected: {name}',
                    confidence='high',
                    justification=self._generate_packer_justification(name)
                ))

            # Check entropy levels
            if entropy > self.HIGH_ENTROPY_THRESHOLD:
                high_entropy.append(EntropyFinding(
                    name=name,
                    entropy=entropy,
                    threshold=f'>{self.HIGH_ENTROPY_THRESHOLD:.1f}',
                    likely='Strongly encrypted or packed',
                    confidence='high',
                    justification=self._generate_high_entropy_justification(name, entropy)
                ))
            elif entropy > self.SUSPICIOUS_ENTROPY_THRESHOLD:
                suspicious.append(EntropyFinding(
                    name=name,
                    entropy=entropy,
                    threshold=f'{self.SUSPICIOUS_ENTROPY_THRESHOLD:.1f}-{self.HIGH_ENTROPY_THRESHOLD:.1f}',
                    likely='Possibly packed or obfuscated',
                    confidence='medium',
                    justification=self._generate_suspicious_entropy_justification(name, entropy)
                ))

        # 2. Calculate overall entropy
        overall_entropy = self._calculate_overall_entropy()

        # 3. Find crypto indicators in strings
        crypto_indicators = self._find_crypto_indicators(strings)

        # 4. Generate overall justification
        overall_justification = self._generate_overall_entropy_justification(
            overall_entropy, high_entropy, suspicious
        )

        # 5. Check if data is encrypted (if overall entropy > 7.5)
        if overall_entropy and overall_entropy > self.HIGH_ENTROPY_THRESHOLD:
            encrypted.append(EntropyFinding(
                name='OVERALL_FILE',
                entropy=overall_entropy,
                threshold=f'>{self.HIGH_ENTROPY_THRESHOLD:.1f}',
                likely='File appears encrypted or heavily packed',
                confidence='high',
                justification=f"Overall file entropy is {overall_entropy:.2f}, which exceeds the {self.HIGH_ENTROPY_THRESHOLD:.1f} threshold. This strongly indicates the entire file or large portions are encrypted or packed."
            ))

        return EntropyAnalysis(
            high_entropy_sections=high_entropy,
            suspicious_entropy=suspicious,
            packed_sections=packed,
            encrypted_data=encrypted,
            overall_entropy=overall_entropy,
            justification=overall_justification,
            crypto_indicators=crypto_indicators
        )

    def _calculate_overall_entropy(self) -> Optional[float]:
        """Calculate overall entropy of the file."""
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()
                return self._calculate_entropy(self.data)
        except Exception:
            return None

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)

        return entropy

    def _find_crypto_indicators(self, strings: List[str]) -> List[Dict[str, str]]:
        """Find strings indicating crypto operations."""
        indicators = []
        seen = set()

        for s in strings:
            if len(s) < 4:
                continue
            s_lower = s.lower()
            for keyword in self.CRYPTO_KEYWORDS:
                if keyword.lower() in s_lower:
                    key = f"{keyword}_{s[:20]}"
                    if key not in seen:
                        indicators.append({
                            'string': s[:50] + ('...' if len(s) > 50 else ''),
                            'indicator': keyword,
                            'confidence': 'medium'
                        })
                        seen.add(key)
                    break  # Only match first keyword per string

        return indicators[:20]  # Limit output

    def _generate_packer_justification(self, name: str) -> str:
        """Generate justification for packer detection."""
        return f"Section name '{name}' matches known packer signatures. This strongly indicates the binary has been packed to evade detection and hinder analysis."

    def _generate_high_entropy_justification(self, name: str, entropy: float) -> str:
        """Generate justification for high entropy section."""
        return f"Section '{name}' has entropy {entropy:.2f} (>7.5). This is characteristic of encrypted or packed data. Typical compiled code sections have entropy between 5.5-6.5. Values above 7.5 are uncommon for standard executables and strongly suggest the presence of encrypted content or packing."

    def _generate_suspicious_entropy_justification(self, name: str, entropy: float) -> str:
        """Generate justification for suspicious entropy section."""
        return f"Section '{name}' has entropy {entropy:.2f} (6.0-7.5). This is moderately high and may indicate obfuscated or compressed data. While this could be legitimate (e.g., resource data), in the context of malware it often suggests packing or string obfuscation."

    def _generate_overall_entropy_justification(self, overall_entropy: Optional[float],
                                               high_entropy: List,
                                               suspicious: List) -> str:
        """Generate justification for overall entropy."""
        if overall_entropy is None:
            return "Unable to calculate overall file entropy."

        if overall_entropy > 7.5:
            return f"Overall file entropy is {overall_entropy:.2f}, which is very high. This indicates the file likely contains encrypted, packed, or heavily obfuscated data. Found {len(high_entropy)} sections with entropy >7.5 and {len(suspicious)} sections with entropy 6.0-7.5."
        elif overall_entropy > 6.0:
            return f"Overall file entropy is {overall_entropy:.2f}, which is moderately high. This suggests the presence of obfuscated or compressed data. Found {len(high_entropy)} sections with entropy >7.5 and {len(suspicious)} sections with entropy 6.0-7.5."
        else:
            return f"Overall file entropy is {overall_entropy:.2f}, which is within the normal range for executables (typically 5.5-6.5). No significant entropy anomalies detected."
