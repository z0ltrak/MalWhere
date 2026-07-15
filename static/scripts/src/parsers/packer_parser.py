"""Packer detection module for static analysis"""
import json
import subprocess
from typing import Dict, List, Any, Optional
from pathlib import Path


"""Detect packers using multiple methods"""
class PackerDetector:

    # Known packer section names
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

    def __init__(self, file_path: Path, timeout: int = 30):
        self.file_path = file_path
        self.timeout = timeout
        self.errors: List[str] = []
        self.result = {
            'detected': False,
            'packers': [],
            'confidence': 'none'
        }


    """Run all packer detection methods"""
    def detect(self) -> Dict[str, Any]:
        # Try DIE first (most accurate)
        self._detect_with_die()

        # If not detected, try heuristic detection
        if not self.result['detected']:
            self._detect_heuristic()

        return self.result


    """Detect packers using Detect-It-Easy"""
    def _detect_with_die(self) -> None:
        try:
            result = subprocess.run(
                ['diec', '-j', str(self.file_path)],
                capture_output=True, text=True, timeout=self.timeout
            )

            if result.returncode == 0 and result.stdout:
                die_data = json.loads(result.stdout)
                packers = []

                # Parse DIE output
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

                if packers:
                    self.result['detected'] = True
                    self.result['packers'] = packers
                    self.result['confidence'] = 'high'

        except subprocess.TimeoutExpired:
            self.errors.append("DIE command timed out")
        except json.JSONDecodeError:
            self.errors.append("DIE returned invalid JSON")
        except FileNotFoundError:
            self.errors.append("DIE not found in PATH")
        except Exception as e:
            self.errors.append(f"Error detecting packer with DIE: {e}")


    """Fallback heuristic-based packer detection"""
    def _detect_heuristic(self) -> None:
        indicators = []

        # This is a placeholder - the actual implementation would need
        # to access PE sections. The full implementation will be in the
        # main analyzer that has access to the PE data.
        indicators.append({
            'name': 'Possible Packer',
            'reason': 'Heuristic detection requires PE parsing',
            'confidence': 'low'
        })

        if indicators:
            self.result['detected'] = True
            self.result['packers'] = indicators
            self.result['confidence'] = 'low'


    """Detect packers using section information"""
    def detect_with_sections(self, sections: List[Dict[str, Any]]) -> Dict[str, Any]:
        indicators = []

        # Check section names
        for section in sections:
            name = section.get('name', '')
            if name in self.PACKER_SECTIONS:
                indicators.append({
                    'name': self.PACKER_SECTIONS[name],
                    'reason': f'Section name: {name}',
                    'confidence': 'high'
                })

        # Check for high entropy sections
        high_entropy = [s for s in sections if s.get('entropy', 0) > 7.5]
        if len(high_entropy) > 2:
            indicators.append({
                'name': 'Unknown Packer',
                'reason': f'{len(high_entropy)} high-entropy sections (>7.5)',
                'confidence': 'medium'
            })

        # Check section count (packed files often have few sections)
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


    """Get detection errors"""
    def get_errors(self) -> List[str]:
        return self.errors
