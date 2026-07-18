"""Packer detection module for static analysis."""

import json
import os
import subprocess
import shutil
from typing import Dict, List, Any
from pathlib import Path


class PackerDetector:
    """Detect packers using multiple methods."""

    PACKER_SECTIONS = {
        '.UPX': 'UPX',
        '.upx': 'UPX',
        'UPX0': 'UPX',
        'UPX1': 'UPX',
        '.UPX0': 'UPX',
        '.UPX1': 'UPX',
        '.aspack': 'ASPack',
        '.MPRESS': 'MPRESS',
        '.mpress': 'MPRESS',
        'PEC2': 'PEC2',
        'PEC3': 'PEC3',
        'PECompact': 'PECompact',
        '.pecompact': 'PECompact',
        'Themida': 'Themida',
        '.themida': 'Themida',
    }

    def __init__(self, file_path: Path, timeout: int = 60):
        self.file_path = file_path
        self.timeout = timeout
        self.errors: List[str] = []
        self.result = {
            'detected': False,
            'packers': [],
            'confidence': 'none'
        }
        self._die_binary = None

    def detect(self) -> Dict[str, Any]:
        """Run all packer detection methods."""
        self._detect_with_die()

        if not self.result['detected']:
            self._detect_heuristic()

        return self.result

    def _find_die_binary(self) -> None:
        """Find the DIE binary name in the system."""
        # Prefer diec (headless) over die
        for binary in ['diec', 'die']:
            if shutil.which(binary):
                self._die_binary = binary
                return
        self._die_binary = None

    def _detect_with_die(self) -> None:
        """Detect packers using Detect-It-Easy."""
        if self._die_binary is None:
            self._find_die_binary()

        if self._die_binary is None:
            self.errors.append("DIE not found in PATH")
            return

        try:
            # Set environment to use offscreen rendering
            env = os.environ.copy()
            env['QT_QPA_PLATFORM'] = 'offscreen'

            # Build command - use text output instead of JSON for reliability
            cmd = [self._die_binary, str(self.file_path)]

            # If using 'die' (GUI version), add headless flag
            if self._die_binary == 'die':
                cmd.insert(1, '-h')

            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=self.timeout,
                env=env
            )

            # Parse text output directly (more reliable)
            if result.stdout:
                self._parse_die_text_output(result.stdout)
            elif result.stderr:
                self.errors.append(f"DIE error: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            self.errors.append("DIE command timed out")
        except Exception as e:
            self.errors.append(f"Error detecting packer with DIE: {e}")

    def _parse_die_text_output(self, text_output: str) -> None:
        """Parse DIE text output for packer detection."""
        lines = text_output.strip().split('\n')
        packers = []

        for line in lines:
            # Look for packer or compiler information
            line_lower = line.lower()
            if 'packer' in line_lower or 'compiler' in line_lower:
                # Try to extract meaningful info
                clean_line = line.strip()
                # Remove common prefixes
                for prefix in ['[', '(', '{']:
                    if clean_line.startswith(prefix):
                        clean_line = clean_line[1:]
                for suffix in [']', ')', '}']:
                    if clean_line.endswith(suffix):
                        clean_line = clean_line[:-1]

                packers.append({
                    'name': clean_line.strip(),
                    'version': 'N/A',
                    'type': 'packer' if 'packer' in line_lower else 'compiler',
                    'confidence': 'medium'
                })

        if packers:
            self.result['detected'] = True
            self.result['packers'] = packers
            self.result['confidence'] = 'medium'

    def _parse_die_output(self, die_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Parse DIE JSON output for packer detection."""
        packers = []

        if 'detects' in die_data:
            for detect in die_data['detects']:
                detect_type = detect.get('type', '').lower()
                if 'packer' in detect_type or 'compiler' in detect_type:
                    packers.append({
                        'name': detect.get('name', 'Unknown'),
                        'version': detect.get('version', 'N/A'),
                        'type': detect.get('type', 'packer'),
                        'confidence': detect.get('confidence', 'medium')
                    })

        if not packers and 'result' in die_data:
            for result_item in die_data['result']:
                if isinstance(result_item, dict):
                    for key, value in result_item.items():
                        if 'packer' in key.lower() or 'compiler' in key.lower():
                            packers.append({
                                'name': str(value),
                                'version': 'N/A',
                                'type': 'packer',
                                'confidence': 'high'
                            })

        if not packers:
            for key, value in die_data.items():
                if 'packer' in key.lower() and isinstance(value, str):
                    packers.append({
                        'name': value,
                        'version': 'N/A',
                        'type': 'packer',
                        'confidence': 'medium'
                    })
                elif 'compiler' in key.lower() and isinstance(value, str):
                    packers.append({
                        'name': value,
                        'version': 'N/A',
                        'type': 'compiler',
                        'confidence': 'medium'
                    })

        return packers

    def _detect_heuristic(self) -> None:
        """Fallback heuristic-based packer detection."""
        indicators = [{
            'name': 'Possible Packer',
            'reason': 'Heuristic detection based on PE characteristics',
            'confidence': 'low'
        }]

        self.result['detected'] = True
        self.result['packers'] = indicators
        self.result['confidence'] = 'low'

    def detect_with_sections(self, sections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect packers using section information."""
        indicators = []

        for section in sections:
            name = section.get('name', '')
            if name in self.PACKER_SECTIONS:
                indicators.append({
                    'name': self.PACKER_SECTIONS[name],
                    'reason': f'Section name: {name}',
                    'confidence': 'high'
                })

        high_entropy = [s for s in sections if s.get('entropy', 0) > 7.5]
        if len(high_entropy) > 2:
            indicators.append({
                'name': 'Unknown Packer',
                'reason': f'{len(high_entropy)} high-entropy sections (>7.5)',
                'confidence': 'medium'
            })

        if len(sections) <= 3 and len(sections) > 0:
            indicators.append({
                'name': 'Possible Packer',
                'reason': f'Low section count: {len(sections)}',
                'confidence': 'low'
            })

        if indicators:
            return {
                'detected': True,
                'packers': indicators,
                'confidence': 'medium'
            }

        return self.result

    def get_errors(self) -> List[str]:
        """Get detection errors."""
        return self.errors
