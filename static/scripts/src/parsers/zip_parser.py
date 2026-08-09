"""ZIP file parsing module."""

import zipfile
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional


class ZIPParser:
    """Parser for ZIP archives."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.errors: List[str] = []
        self.zip_data = {}

    def parse(self) -> Dict[str, Any]:
        """Parse ZIP file and extract metadata."""
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()

                self.zip_data = {
                    'is_zip': True,
                    'file_count': len(file_list),
                    'files': file_list[:100],  # Limit output
                    'metadata': self._get_metadata(zip_ref)
                }

                return self.zip_data

        except zipfile.BadZipFile as e:
            self.errors.append(f"Invalid ZIP file: {e}")
            return {'error': str(e)}
        except Exception as e:
            self.errors.append(f"Error parsing ZIP: {e}")
            return {'error': str(e)}

    def _get_metadata(self, zip_ref: zipfile.ZipFile) -> Dict[str, Any]:
        """Get ZIP file metadata."""
        metadata = {
            'comment': None,
            'compressed_size': 0,
            'uncompressed_size': 0,
            'files': []
        }

        try:
            if zip_ref.comment:
                metadata['comment'] = zip_ref.comment.decode('utf-8', errors='ignore')[:200]
        except:
            pass

        try:
            for info in zip_ref.infolist():
                metadata['compressed_size'] += info.compress_size
                metadata['uncompressed_size'] += info.file_size

                # Check for suspicious files
                is_suspicious = self._is_suspicious_filename(info.filename)

                metadata['files'].append({
                    'filename': info.filename,
                    'size': info.file_size,
                    'compressed_size': info.compress_size,
                    'is_suspicious': is_suspicious
                })

                if len(metadata['files']) >= 100:
                    break

        except Exception as e:
            self.errors.append(f"Error getting ZIP metadata: {e}")

        return metadata

    def _is_suspicious_filename(self, filename: str) -> bool:
        """Check if a filename is suspicious."""
        suspicious_patterns = [
            '.exe', '.dll', '.sys', '.com', '.scr', '.pif',
            'install', 'setup', 'update', 'patch', 'crack',
            'password', 'keygen', 'crack', 'loader',
            'ransom', 'encrypt', 'decrypt'
        ]

        filename_lower = filename.lower()
        for pattern in suspicious_patterns:
            if pattern in filename_lower:
                return True

        # Check for double extensions
        if filename.count('.') > 1:
            return True

        return False

    def extract_all(self, extract_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Extract all files from ZIP archive."""
        extracted = []

        try:
            with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                if not extract_dir:
                    extract_dir = Path(tempfile.mkdtemp(prefix='zip_extract_'))
                else:
                    extract_dir.mkdir(parents=True, exist_ok=True)

                zip_ref.extractall(extract_dir)

                # Collect extracted files
                for file_path in extract_dir.rglob('*'):
                    if file_path.is_file():
                        extracted.append({
                            'name': file_path.name,
                            'path': file_path,
                            'size': file_path.stat().st_size,
                            'type': self._get_file_type(file_path)
                        })

        except Exception as e:
            self.errors.append(f"Error extracting ZIP: {e}")

        return extracted

    def _get_file_type(self, file_path: Path) -> str:
        """Get file type from file content."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(256)

            if data[:2] == b'MZ':
                return 'pe_file'
            if data[:4] == b'\x7fELF':
                return 'elf_file'
            if data[:4] == b'PK\x03\x04':
                return 'zip_file'
            if file_path.suffix.lower() in ['.exe', '.dll', '.sys']:
                return 'pe_file'

            return 'unknown'

        except:
            return 'unknown'

    def get_errors(self) -> List[str]:
        """Get parsing errors."""
        return self.errors
