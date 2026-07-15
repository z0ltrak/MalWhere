"""Hash calculation utilities"""
import hashlib
from pathlib import Path
from typing import Dict, Optional

try:
    import ssdeep
except ImportError:
    ssdeep = None


"""Calculate various hashes for files"""
class HashCalculator:

    """Calculate all hash types"""
    def calculate_all(self, file_path: Path) -> Dict[str, str]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

                result = {
                    'md5': hashlib.md5(data).hexdigest(),
                    'sha1': hashlib.sha1(data).hexdigest(),
                    'sha256': hashlib.sha256(data).hexdigest(),
                }

                # SSDeep fuzzy hash
                if ssdeep:
                    try:
                        result['ssdeep'] = ssdeep.hash(data)
                    except Exception:
                        result['ssdeep'] = 'N/A'
                else:
                    result['ssdeep'] = 'N/A'

                return result

        except Exception as e:
            return {
                'md5': 'ERROR',
                'sha1': 'ERROR',
                'sha256': 'ERROR',
                'ssdeep': 'ERROR',
                'error': str(e)
            }


    """Calculate hash of section data"""
    def calculate_section_hash(self, data: bytes, hash_type: str = 'md5') -> str:
        if hash_type == 'md5':
            return hashlib.md5(data).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
