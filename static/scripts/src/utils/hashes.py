"""Hash calculation utilities."""

import hashlib
from pathlib import Path
from typing import Dict

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False


class HashCalculator:
    """Calculate various hashes for files."""

    def calculate_all(self, file_path: Path) -> Dict[str, str]:
        """Calculate all hash types for a file."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

                result = {
                    'md5': hashlib.md5(data).hexdigest(),
                    'sha1': hashlib.sha1(data).hexdigest(),
                    'sha256': hashlib.sha256(data).hexdigest(),
                }

                # SSDeep fuzzy hash
                if SSDEEP_AVAILABLE:
                    try:
                        result['ssdeep'] = ssdeep.hash(data)
                    except Exception:
                        result['ssdeep'] = 'N/A'
                else:
                    result['ssdeep'] = 'N/A'

                # TLSH hash
                if TLSH_AVAILABLE:
                    try:
                        result['tlsh'] = tlsh.hash(data)
                    except Exception:
                        result['tlsh'] = 'N/A'
                else:
                    result['tlsh'] = 'N/A'

                return result

        except Exception as e:
            return {
                'md5': 'ERROR',
                'sha1': 'ERROR',
                'sha256': 'ERROR',
                'ssdeep': 'ERROR',
                'tlsh': 'ERROR',
                'error': str(e)
            }

    def calculate_section_hash(self, data: bytes, hash_type: str = 'md5') -> str:
        """Calculate hash of section data."""
        if hash_type == 'md5':
            return hashlib.md5(data).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
