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
        """Calculate all hash types for a file.

        Args:
            file_path: Path to the file to hash.

        Returns:
            Dict with md5, sha1, sha256, ssdeep, and tlsh (each 'N/A' if
            the optional library isn't installed), or all 'ERROR' plus an 'error' key on failure.
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

                result = {
                    'md5': hashlib.md5(data).hexdigest(),
                    'sha1': hashlib.sha1(data).hexdigest(),
                    'sha256': hashlib.sha256(data).hexdigest(),
                }

                if SSDEEP_AVAILABLE:
                    try:
                        result['ssdeep'] = ssdeep.hash(data)
                    except Exception:
                        result['ssdeep'] = 'N/A'
                else:
                    result['ssdeep'] = 'N/A'

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

    def calculate_imphash(self, pe) -> str:
        """Calculate import hash (imphash) for a PE file.

        Args:
            pe: A loaded pefile.PE object.

        Returns:
            The imphash, or 'N/A' if the PE has no import directory or hashing failed.
        """
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return pe.get_imphash()
        except Exception:
            pass
        return 'N/A'

    def calculate_section_hash(self, data: bytes, hash_type: str = 'md5') -> str:
        """Calculate hash of section data.

        Args:
            data: Bytes to hash.
            hash_type: 'md5', 'sha1', or 'sha256'.

        Returns:
            The hex digest.

        Raises:
            ValueError: If hash_type isn't recognized.
        """
        if hash_type == 'md5':
            return hashlib.md5(data).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
