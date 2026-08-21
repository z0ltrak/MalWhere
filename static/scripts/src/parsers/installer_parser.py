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
        """Initialize the installer parser.

        Args:
            file_path: Path to the installer file.
            timeout: Timeout in seconds for extraction subprocesses.
        """
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
                self.data = f.read(1048576)  # 1MB
        except Exception:
            self.errors.append("Failed to read file")

        installer_type = self._detect_type()
        self.installer_type = installer_type

        return {
            'type': installer_type,
            'is_installer': installer_type is not None,
            'extracted_files': len(self.extracted_files) if self.extracted_files else 0
        }

    def extract_all(self) -> List[Dict[str, Any]]:
        """Extract all files from the installer.

        Returns:
            One dict per extracted file (name, path, size, type), or
            empty if the installer type couldn't be detected or extraction failed.
        """
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
        """Detect installer type with more thorough reading.

        Returns:
            'nsis_installer', 'inno_installer', or 'msi_installer', or None if undetected.
        """
        try:
            with open(self.file_path, 'rb') as f:
                file_data = f.read(1048576)  # 1MB
        except Exception as e:
            self.errors.append(f"Failed to read file for detection: {e}")
            return None

        data_str = file_data.decode('utf-8', errors='ignore')

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

        if '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">' in data_str:
            if 'Nullsoft.NSIS' in data_str or 'Nullsoft Install System' in data_str:
                self.errors.append("Detected NSIS installer via manifest")
                return 'nsis_installer'

        if 'Inno Setup' in data_str:
            return 'inno_installer'

        if self.file_path.suffix.lower() == '.msi':
            return 'msi_installer'

        return None

    def _extract_nsis(self) -> List[Dict[str, Any]]:
        """Extract an NSIS installer via 7z, 7za, or manual extraction as fallbacks.

        Returns:
            One dict per extracted file.
        """
        from .nsis_parser import NSISParser

        nsis_parser = NSISParser(self.file_path, self.timeout)

        if shutil.which('7z'):
            self.errors.append("Using 7z for NSIS extraction")
            files = nsis_parser.extract_all()
            self.errors.extend(nsis_parser.get_errors())
            if files:
                self.extracted_files = files
                return files

        if shutil.which('7za'):
            self.errors.append("Using 7za for NSIS extraction")
            files = nsis_parser._extract_with_7za()
            self.errors.extend(nsis_parser.get_errors())
            if files:
                self.extracted_files = files
                return files

        self.errors.append("7z not found, using manual extraction")
        files = nsis_parser._extract_nsis_manually()
        self.errors.extend(nsis_parser.get_errors())
        self.extracted_files = files
        return files

    def _extract_inno(self) -> List[Dict[str, Any]]:
        """Extract an Inno Setup installer via innoextract.

        Returns:
            One dict per extracted file, or empty if innoextract is unavailable or fails.
        """
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
        """Extract an MSI installer via msiexec's administrative install.

        Returns:
            One dict per extracted file, or empty if msiexec is unavailable or fails.
        """
        self.errors.append("Extracting MSI installer...")

        if shutil.which('msiexec'):
            temp_dir = Path(tempfile.mkdtemp(prefix='msi_extract_'))

            try:
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
        """Get file type from file content.

        Args:
            file_path: Path to the file to check.

        Returns:
            A file type string, or 'unknown' if unrecognized.
        """
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

        except Exception:
            return 'unknown'

    def get_errors(self) -> List[str]:
        """Get extraction errors."""
        return self.errors
