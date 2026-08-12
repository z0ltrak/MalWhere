"""Dedicated NSIS installer parser with 7z extraction support."""

import struct
import tempfile
import zlib
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


class NSISParser:
    """Parse NSIS installer files."""

    def __init__(self, file_path: Path, timeout: int = 120):
        self.file_path = file_path
        self.data = None
        self.errors: List[str] = []
        self.nsis_data = None
        self.timeout = timeout
        self.extracted_files: List[Dict[str, Any]] = []

    def parse(self) -> Dict[str, Any]:
        """Parse NSIS installer structure."""
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()
        except Exception as e:
            self.errors.append(f"Error reading NSIS file: {e}")
            return {}

        # Check if it's NSIS
        if not self._is_nsis():
            self.errors.append("Not an NSIS installer")
            return {}

        # Parse NSIS data
        self.nsis_data = self._parse_nsis()

        return {
            'is_nsis': True,
            'version': self.nsis_data.get('version', 'unknown'),
            'files': len(self.nsis_data.get('files', [])),
            'data_blocks': len(self.nsis_data.get('data_blocks', [])),
            'extracted_files': len(self.extracted_files)
        }

    def _is_nsis(self) -> bool:
        """Check if file is an NSIS installer."""
        if not self.data:
            return False

        # Check for NSIS signature
        if b'Nullsoft.NSIS.exehead' in self.data:
            return True

        # Check for NSIS manifest
        if b'Nullsoft.NSIS' in self.data:
            return True

        # Check for NSIS installer pattern
        if b'NullsoftInst' in self.data:
            return True

        return False

    def _parse_nsis(self) -> Dict[str, Any]:
        """Parse NSIS installer structure."""
        result = {
            'version': 'unknown',
            'files': [],
            'data_blocks': [],
            'strings': []
        }

        # Extract version
        version_pattern = b'Nullsoft.NSIS.exeheadv'
        pos = self.data.find(version_pattern)
        if pos != -1:
            version_start = pos + len(version_pattern)
            if version_start + 10 < len(self.data):
                version = self.data[version_start:version_start+10].split(b'\x00')[0]
                result['version'] = version.decode('utf-8', errors='ignore')

        return result

    def extract_all(self) -> List[Dict[str, Any]]:
        """Extract all files from NSIS installer."""
        self.extracted_files = []

        # Try 7z first (most reliable)
        if shutil.which('7z'):
            self.errors.append("Using 7z for NSIS extraction")
            result = self._extract_with_7z()
            if result:
                self.errors.append(f"7z extracted {len(result)} files")
                self.extracted_files = result
                return result
            else:
                self.errors.append("7z extraction returned no files")

        # Try 7za
        if shutil.which('7za'):
            self.errors.append("Using 7za for NSIS extraction")
            result = self._extract_with_7za()
            if result:
                self.errors.append(f"7za extracted {len(result)} files")
                self.extracted_files = result
                return result
            else:
                self.errors.append("7za extraction returned no files")

        # Try manual extraction as fallback
        self.errors.append("7z not found, trying manual extraction...")
        result = self._extract_nsis_manually()
        if result:
            self.errors.append(f"Manual extraction extracted {len(result)} files")
            self.extracted_files = result
            return result

        self.errors.append("All extraction methods failed")
        return []

    def _extract_with_7z(self) -> List[Dict[str, Any]]:
        """Extract using 7z."""
        temp_dir = Path(tempfile.mkdtemp(prefix='nsis_extract_'))

        try:
            # 7z command to extract NSIS installer
            cmd = ['7z', 'x', '-y', str(self.file_path), f'-o{temp_dir}']

            self.errors.append(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            self.errors.append(f"7z return code: {result.returncode}")

            if result.stdout:
                self.errors.append(f"7z stdout: {result.stdout[:200]}...")
            if result.stderr:
                self.errors.append(f"7z stderr: {result.stderr[:200]}...")

            if result.returncode != 0:
                self.errors.append(f"7z extraction failed with code {result.returncode}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return []

            # Collect extracted files
            files = []
            for file_path in temp_dir.rglob('*'):
                if file_path.is_file():
                    file_type = self._get_file_type(file_path)
                    files.append({
                        'name': file_path.name,
                        'path': file_path,
                        'size': file_path.stat().st_size,
                        'type': file_type,
                        'is_executable': file_type in ['pe_file', 'batch_script']
                    })
                    self.errors.append(f"Extracted: {file_path.name} ({file_type}, {file_path.stat().st_size} bytes)")

            self.errors.append(f"Extracted {len(files)} files with 7z")
            return files

        except subprocess.TimeoutExpired:
            self.errors.append("7z extraction timed out")
        except Exception as e:
            self.errors.append(f"7z extraction error: {e}")

        shutil.rmtree(temp_dir, ignore_errors=True)
        return []

    def _extract_with_7za(self) -> List[Dict[str, Any]]:
        """Extract using 7za."""
        return self._extract_with_tool('7za')

    def _extract_with_tool(self, tool: str) -> List[Dict[str, Any]]:
        """Extract using a specified tool."""
        temp_dir = Path(tempfile.mkdtemp(prefix='nsis_extract_'))

        try:
            # 7z command to extract NSIS installer
            cmd = [tool, 'x', '-y', str(self.file_path), f'-o{temp_dir}']

            self.errors.append(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if result.returncode != 0:
                self.errors.append(f"{tool} extraction failed: {result.stderr[:200]}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return []

            # Collect extracted files
            files = []
            for file_path in temp_dir.rglob('*'):
                if file_path.is_file():
                    file_type = self._get_file_type(file_path)
                    files.append({
                        'name': file_path.name,
                        'path': file_path,
                        'size': file_path.stat().st_size,
                        'type': file_type,
                        'is_executable': file_type in ['pe_file', 'batch_script']
                    })

            self.errors.append(f"Extracted {len(files)} files with {tool}")
            return files

        except subprocess.TimeoutExpired:
            self.errors.append(f"{tool} extraction timed out")
        except Exception as e:
            self.errors.append(f"{tool} extraction error: {e}")

        shutil.rmtree(temp_dir, ignore_errors=True)
        return []

    def _extract_nsis_manually(self) -> List[Dict[str, Any]]:
        """Manual extraction of NSIS installer."""
        self.errors.append("Performing manual NSIS extraction...")

        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()

            # Look for zlib compressed data blocks
            zlib_blocks = self._find_zlib_blocks(data)

            files = []
            for i, (offset, size) in enumerate(zlib_blocks):
                compressed = data[offset:offset+size]

                # Try to decompress
                try:
                    decompressed = zlib.decompress(compressed)
                    if len(decompressed) > 1024:
                        # Identify file type
                        file_type = self._identify_file_type(decompressed)

                        # Create temporary file
                        ext = self._get_extension(file_type)
                        tmp_path = Path(tempfile.mktemp(suffix=ext))
                        tmp_path.write_bytes(decompressed)

                        files.append({
                            'name': f'extracted_block_{i}{ext}',
                            'path': tmp_path,
                            'size': len(decompressed),
                            'type': file_type,
                            'is_executable': file_type == 'pe_file'
                        })
                except Exception as e:
                    self.errors.append(f"Failed to decompress block {i}: {e}")

            self.errors.append(f"Manually extracted {len(files)} files")
            return files

        except Exception as e:
            self.errors.append(f"Manual NSIS extraction error: {e}")
            return []

    def _find_zlib_blocks(self, data: bytes) -> List[Tuple[int, int]]:
        """Find zlib compressed blocks in data."""
        blocks = []
        zlib_headers = [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']

        offset = 0
        while offset < len(data) - 10:
            found = False
            for header in zlib_headers:
                pos = data.find(header, offset)
                if pos != -1:
                    # Try to find the end of zlib data
                    size = self._find_zlib_end(data, pos)
                    if size > 1024:
                        blocks.append((pos, size))
                        offset = pos + size
                        found = True
                        break
            if not found:
                offset += 1

        return blocks

    def _find_zlib_end(self, data: bytes, start: int) -> int:
        """Find the end of zlib compressed data."""
        # Try to decompress and see how far it goes
        for size in [1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144]:
            try:
                if start + size > len(data):
                    return len(data) - start
                zlib.decompress(data[start:start+size])
            except zlib.error:
                if size > 1024:
                    return size - 1024
                break

        return 65536  # Default

    def _identify_file_type(self, data: bytes) -> str:
        """Identify file type from data."""
        if data[:2] == b'MZ':
            return 'pe_file'
        if data[:4] == b'\x7fELF':
            return 'elf_file'
        if data[:4] == b'PK\x03\x04':
            return 'zip_file'
        if data[:2] in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
            return 'zlib_data'
        if data[:2] == b'\x1F\x8B':
            return 'gzip_file'
        if data[:10] == b'@echo off' or data[:2] == b'::':
            return 'batch_script'
        if data[:5] == b'<?xml':
            return 'xml_data'
        if data[:1] == b'{' or data[:1] == b'[':
            return 'json_data'
        return 'unknown'

    def _get_extension(self, file_type: str) -> str:
        """Get file extension for file type."""
        ext_map = {
            'pe_file': '.exe',
            'elf_file': '.elf',
            'zip_file': '.zip',
            'gzip_file': '.gz',
            'zlib_data': '.bin',
            'batch_script': '.bat',
            'xml_data': '.xml',
            'json_data': '.json',
            'unknown': '.bin'
        }
        return ext_map.get(file_type, '.bin')

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
            if file_path.suffix.lower() in ['.bat', '.cmd']:
                return 'batch_script'

            return 'unknown'

        except Exception:
            return 'unknown'

    def get_errors(self) -> List[str]:
        """Get parsing errors."""
        return self.errors
