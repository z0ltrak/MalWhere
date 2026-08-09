"""Universal installer parser supporting multiple installer formats."""

import tempfile
import subprocess
import shutil
import struct
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


class InstallerParser:
    """Parse and extract various installer formats."""

    def __init__(self, file_path: Path, timeout: int = 120):
        self.file_path = file_path
        self.timeout = timeout
        self.errors: List[str] = []
        self.extracted_files: List[Dict[str, Any]] = []
        self.data = None
        self.installer_type = None

    def parse(self) -> Dict[str, Any]:
        """Parse installer and return metadata."""
        try:
            with open(self.file_path, 'rb') as f:
                # Read more data for better detection
                self.data = f.read(1048576)  # 1MB
        except:
            self.errors.append("Failed to read file")

        # Detect installer type
        installer_type = self._detect_type()
        self.installer_type = installer_type

        return {
            'type': installer_type,
            'is_installer': installer_type is not None,
            'extracted_files': len(self.extracted_files) if self.extracted_files else 0
        }

    def extract_all(self) -> List[Dict[str, Any]]:
        """Extract all files from the installer."""
        # Force detection by reading the file directly
        self.installer_type = self._detect_type()

        if not self.installer_type:
            self.errors.append("Unknown installer type")
            return []

        if self.installer_type == 'nsis_installer':
            return self._extract_nsis()
        elif self.installer_type == 'inno_installer':
            return self._extract_inno()
        elif self.installer_type == 'msi_installer':
            return self._extract_msi()
        else:
            self.errors.append(f"Unsupported installer type: {self.installer_type}")
            return []

    def _detect_type(self) -> Optional[str]:
        """Detect installer type with more thorough reading."""
        try:
            # Read directly from file - this is more reliable
            with open(self.file_path, 'rb') as f:
                file_data = f.read(1048576)  # 1MB
        except Exception as e:
            self.errors.append(f"Failed to read file for detection: {e}")
            return None

        # Convert to string for searching
        data_str = file_data.decode('utf-8', errors='ignore')

        # NSIS - check for signatures that might be far into the file
        nsis_signatures = [
            'Nullsoft.NSIS.exehead',
            'NullsoftInst',
            'Nullsoft.NSIS',
            'Nullsoft Install System',
        ]
        for sig in nsis_signatures:
            if sig in data_str:
                self.errors.append(f"Detected NSIS installer: {sig}")
                return 'nsis_installer'

        # Also check for the NSIS manifest XML pattern
        if '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">' in data_str:
            if 'Nullsoft.NSIS' in data_str or 'Nullsoft Install System' in data_str:
                self.errors.append("Detected NSIS installer via manifest")
                return 'nsis_installer'

        # Inno Setup
        if 'Inno Setup' in data_str:
            return 'inno_installer'

        # MSI
        if self.file_path.suffix.lower() == '.msi':
            return 'msi_installer'

        return None

    def _extract_nsis(self) -> List[Dict[str, Any]]:
        """Extract NSIS installer."""
        from .nsis_parser import NSISParser

        nsis_parser = NSISParser(self.file_path, self.timeout)

        # Check if 7z is available
        if shutil.which('7z'):
            self.errors.append("Using 7z for NSIS extraction")
            files = nsis_parser.extract_all()
            self.errors.extend(nsis_parser.get_errors())
            if files:
                self.extracted_files = files
                return files

        # Try 7za
        if shutil.which('7za'):
            self.errors.append("Using 7za for NSIS extraction")
            files = nsis_parser._extract_with_7za()
            self.errors.extend(nsis_parser.get_errors())
            if files:
                self.extracted_files = files
                return files

        # Try manual extraction as fallback
        self.errors.append("7z not found, using manual extraction")
        files = nsis_parser._extract_nsis_manually()
        self.errors.extend(nsis_parser.get_errors())
        self.extracted_files = files
        return files

    def _extract_inno(self) -> List[Dict[str, Any]]:
        """Extract Inno Setup installer."""
        self.errors.append("Extracting Inno Setup installer...")

        if shutil.which('innoextract'):
            temp_dir = Path(tempfile.mkdtemp(prefix='inno_extract_'))

            try:
                cmd = ['innoextract', '-d', str(temp_dir), str(self.file_path)]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )

                if result.returncode != 0:
                    self.errors.append(f"InnoExtract failed: {result.stderr[:200]}")
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return []

                # Collect extracted files
                files = []
                for file_path in temp_dir.rglob('*'):
                    if file_path.is_file():
                        files.append({
                            'name': file_path.name,
                            'path': file_path,
                            'size': file_path.stat().st_size,
                            'type': self._get_file_type(file_path)
                        })

                self.extracted_files = files
                return files

            except subprocess.TimeoutExpired:
                self.errors.append("InnoExtract timed out")
            except Exception as e:
                self.errors.append(f"InnoExtract error: {e}")

            shutil.rmtree(temp_dir, ignore_errors=True)

        return []

    def _extract_msi(self) -> List[Dict[str, Any]]:
        """Extract MSI installer."""
        self.errors.append("Extracting MSI installer...")

        if shutil.which('msiexec'):
            temp_dir = Path(tempfile.mkdtemp(prefix='msi_extract_'))

            try:
                # Use msiexec to extract
                cmd = [
                    'msiexec',
                    '/a',
                    str(self.file_path),
                    '/qn',
                    f'TARGETDIR={temp_dir}'
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )

                # Collect extracted files
                files = []
                for file_path in temp_dir.rglob('*'):
                    if file_path.is_file():
                        files.append({
                            'name': file_path.name,
                            'path': file_path,
                            'size': file_path.stat().st_size,
                            'type': self._get_file_type(file_path)
                        })

                self.extracted_files = files
                return files

            except subprocess.TimeoutExpired:
                self.errors.append("MSI extraction timed out")
            except Exception as e:
                self.errors.append(f"MSI extraction error: {e}")

            shutil.rmtree(temp_dir, ignore_errors=True)

        return []

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
        """Get extraction errors."""
        return self.errors
