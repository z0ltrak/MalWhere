"""Extract multiple files from decompressed data (NSIS installer payloads)."""

import struct
import re
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path


class FilesystemExtractor:
    """Extract files from decompressed data (NSIS installer file system)."""

    # Common file signatures
    FILE_SIGNATURES = [
        (b'MZ', 'pe_file', 4096),           # PE executable
        (b'PK\x03\x04', 'zip_file', 65536),  # ZIP
        (b'\x1F\x8B', 'gzip_file', 65536),   # GZip
        (b'\x78\x9C', 'zlib_data', 65536),   # Zlib
        (b'\x78\xDA', 'zlib_data', 65536),   # Zlib
        (b'\x78\x01', 'zlib_data', 65536),   # Zlib
        (b'{\n', 'json_data', 65536),        # JSON
        (b'<?xml', 'xml_data', 65536),       # XML
    ]

    # Generic NSIS/installer boilerplate only, no sample-specific strings.
    # _is_nsis_file_system() below also has 2 independent structural
    # fallbacks (file-path scanning, file-table pattern matching).
    NSIS_SIGNATURES = [
        b'Nullsoft.NSIS',
        b'NSIS',
        b'installer',
    ]

    def __init__(self):
        self.errors: List[str] = []
        self.extracted_files: List[Dict[str, Any]] = []

    def extract_files_from_data(self, data: bytes, base_offset: int = 0) -> List[Dict[str, Any]]:
        """Extract multiple files from decompressed data.

        Args:
            data: Decompressed data to extract files from.
            base_offset: Offset of `data` within the original file, added to each extracted file's reported offset.

        Returns:
            One dict per extracted file (filename, data, size, offset, type).
        """
        self.extracted_files = []
        self.errors = []

        if len(data) < 1024:
            self.errors.append("Data too small to extract files")
            return []

        if self._is_nsis_file_system(data):
            self.errors.append("Detected NSIS file system structure")
            nsis_files = self._extract_nsis_files(data, base_offset)
            if nsis_files:
                return nsis_files

        if self._is_single_file(data):
            self.errors.append("Detected single file")
            return self._extract_single_file(data, base_offset)

        files = self._scan_for_files(data, base_offset)
        if len(files) > 1:
            self.errors.append(f"Found {len(files)} files by signature scanning")
            return files

        self.errors.append("Treating as single file")
        return self._extract_single_file(data, base_offset)

    def _is_nsis_file_system(self, data: bytes) -> bool:
        """Check if data contains an NSIS file system structure.

        Args:
            data: Data to check.

        Returns:
            True if an NSIS signature, 3+ file paths, or a file table pattern is found.
        """
        if len(data) < 1024:
            return False

        search_data = data[:8192]

        for sig in self.NSIS_SIGNATURES:
            if sig in search_data:
                return True

        file_paths = self._find_file_paths(search_data)
        if len(file_paths) >= 3:
            return True

        if self._find_nsis_file_table(search_data) != -1:
            return True

        return False

    def _find_file_paths(self, data: bytes) -> List[str]:
        """Find potential file paths in data.

        Args:
            data: Data to search.

        Returns:
            Up to 50 candidate file paths.
        """
        paths = set()

        path_patterns = [
            rb'[A-Za-z]:\\[^\\]+\\[^\\]+\.(?:exe|dll|sys|dat|bin|tmp|bat|cmd|ps1)',
            rb'[A-Za-z0-9_\-\. ]+\.(?:exe|dll|sys|dat|bin|tmp|bat|cmd|ps1)',
            rb'[A-Za-z0-9_\-\. ]+\.(?:dll|exe)',
        ]

        for pattern in path_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            for match in matches:
                try:
                    path = match.decode('utf-8', errors='ignore')
                    path = path.strip()
                    if len(path) > 5 and len(path) < 260:
                        paths.add(path)
                except Exception:
                    pass

        return list(paths)[:50]

    def _find_nsis_file_table(self, data: bytes) -> int:
        """Find the NSIS file table offset.

        Args:
            data: Data to search.

        Returns:
            The offset of a chunk matching 3+ file-table patterns, or -1 if none found.
        """
        patterns = [
            rb'Files:',
            rb'File:',
            rb'Name:\s*[A-Za-z0-9_\-\. ]+\.',
            rb'Size:\s*\d+',
            rb'Offset:\s*\d+',
        ]

        for i in range(0, min(16384, len(data) - 200), 4):
            chunk = data[i:i+200]
            found_count = 0
            for pattern in patterns:
                if re.search(pattern, chunk, re.IGNORECASE):
                    found_count += 1
            if found_count >= 3:
                return i

        return -1

    def _is_single_file(self, data: bytes) -> bool:
        """Check if data is a single file (PE, ZIP, or script).

        Args:
            data: Data to check.

        Returns:
            True if data looks like exactly one file rather than a container.
        """
        if data[:2] == b'MZ':
            try:
                pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
                if pe_offset + 4 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    return True
            except Exception:
                pass

        if data[:2] == b'MZ' and b'.dll' in data[:4096].lower():
            return True

        if data[:4] == b'PK\x03\x04':
            return True

        if data[:10].lower() in [b'@echo off', b'powershell', b'#!', b'::']:
            return True

        return False

    def _extract_nsis_files(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Extract files from an NSIS file system, falling back to signature scanning/pattern matching.

        Args:
            data: NSIS file system data.
            base_offset: Offset of `data` within the original file.

        Returns:
            One dict per extracted file.
        """
        files = []

        file_table_offset = self._find_nsis_file_table(data)
        if file_table_offset != -1:
            self.errors.append(f"Found file table at offset {file_table_offset}")
            file_entries = self._parse_nsis_file_table(data, file_table_offset)
            for entry in file_entries:
                if entry.get('size', 0) > 1024:
                    file_data = data[entry['offset']:entry['offset'] + entry['size']]
                    if len(file_data) > 1024:
                        files.append({
                            'filename': entry.get('name', f'nsis_file_{len(files)}.bin'),
                            'data': file_data,
                            'size': len(file_data),
                            'offset': base_offset + entry['offset'],
                            'type': self._detect_file_type(file_data)
                        })
                        self.errors.append(f"Extracted {entry.get('name', 'unknown')} ({len(file_data)} bytes)")

        if not files:
            self.errors.append("No NSIS file table found, scanning for signatures")
            files = self._scan_for_files(data, base_offset)

        if not files:
            files = self._extract_nsis_by_pattern(data, base_offset)

        return files

    def _parse_nsis_file_table(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """Parse NSIS file table entries.

        Args:
            data: NSIS file system data.
            offset: Offset of the file table within `data`.

        Returns:
            One dict per parsed entry (name, size, offset).
        """
        entries = []
        current_offset = offset

        while current_offset < offset + 8192 and current_offset < len(data) - 100:
            chunk = data[current_offset:current_offset+200]

            name_match = re.search(rb'([A-Za-z0-9_\-\. ]+\.(?:exe|dll|sys|dat|bin|tmp|bat|cmd|ps1))', chunk)
            if name_match:
                name = name_match.group(1).decode('utf-8', errors='ignore').strip()

                size_match = re.search(rb'(\d+)\s*(?:bytes|Bytes|size|Size)', chunk)
                if size_match:
                    try:
                        size = int(size_match.group(1))
                        file_offset = current_offset + len(name_match.group(0)) + len(size_match.group(0)) + 20
                        if file_offset < len(data):
                            entries.append({
                                'name': name,
                                'size': size,
                                'offset': file_offset
                            })
                            current_offset = file_offset + size
                            continue
                    except Exception:
                        pass

            current_offset += 1

        return entries

    def _extract_nsis_by_pattern(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Extract files from NSIS data using filename pattern matching, as a last-resort fallback.

        Args:
            data: NSIS file system data.
            base_offset: Offset of `data` within the original file.

        Returns:
            One dict per matched filename with recoverable file data.
        """
        files = []

        patterns = [
            (rb'[A-Za-z0-9_\-\. ]+\.dll', 'dll'),
            (rb'[A-Za-z0-9_\-\. ]+\.exe', 'exe'),
            (rb'[A-Za-z0-9_\-\. ]+\.sys', 'sys'),
            (rb'[A-Za-z0-9_\-\. ]+\.dat', 'dat'),
            (rb'[A-Za-z0-9_\-\. ]+\.bin', 'bin'),
            (rb'[A-Za-z0-9_\-\. ]+\.bat', 'bat'),
            (rb'[A-Za-z0-9_\-\. ]+\.ps1', 'ps1'),
        ]

        for pattern, file_type in patterns:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                try:
                    filename = match.group().decode('utf-8', errors='ignore').strip()
                    if len(filename) > 5:
                        file_offset = match.end()
                        file_data = self._find_file_data_at_offset(data, file_offset)
                        if file_data and len(file_data) > 1024:
                            files.append({
                                'filename': filename,
                                'data': file_data,
                                'size': len(file_data),
                                'offset': base_offset + file_offset,
                                'type': self._detect_file_type(file_data)
                            })
                except Exception:
                    pass

        return files

    def _find_file_data_at_offset(self, data: bytes, offset: int) -> Optional[bytes]:
        """Find file data starting near an offset, preferring a recognized signature within the next 1000 bytes.

        Args:
            data: Data to search.
            offset: Starting offset to search from.

        Returns:
            A chunk of file data, or None if offset is past the end of data.
        """
        if offset >= len(data):
            return None

        for i in range(offset, min(offset + 1000, len(data))):
            for sig, file_type, max_size in self.FILE_SIGNATURES:
                if data[i:i+len(sig)] == sig:
                    size = min(max_size, len(data) - i)
                    return data[i:i+size]

        size = min(8192, len(data) - offset)
        return data[offset:offset+size]

    def _scan_for_files(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Scan for files by looking for known magic-byte signatures.

        Args:
            data: Data to scan.
            base_offset: Offset of `data` within the original file.

        Returns:
            One dict per matched signature with recognizable file data.
        """
        files = []
        seen_offsets = set()

        for signature, file_type, max_size in self.FILE_SIGNATURES:
            offset = data.find(signature)
            while offset != -1:
                if offset in seen_offsets:
                    offset = data.find(signature, offset + 1)
                    continue
                seen_offsets.add(offset)

                size = min(max_size, len(data) - offset)
                file_data = data[offset:offset+size]

                if len(file_data) > 1024:
                    file_type_detected = self._detect_file_type(file_data)
                    if file_type_detected != 'unknown':
                        files.append({
                            'filename': f'{file_type}_{offset}.bin',
                            'data': file_data,
                            'size': len(file_data),
                            'offset': base_offset + offset,
                            'type': file_type_detected
                        })
                        self.errors.append(f"Found {file_type_detected} at offset {offset}")

                offset = data.find(signature, offset + 1)

        return files

    def _detect_file_type(self, data: bytes) -> str:
        """Detect file type from magic bytes.

        Args:
            data: Data to check.

        Returns:
            A file type string, or 'unknown' if no signature matched.
        """
        if len(data) < 4:
            return 'unknown'

        if data[:2] == b'MZ':
            try:
                pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
                if pe_offset + 4 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    return 'pe_file'
            except Exception:
                pass

        # Check for DLL (PE with .dll in strings)
        if data[:2] == b'MZ' and b'.dll' in data[:4096].lower():
            return 'pe_file'

        if data[:4] == b'PK\x03\x04':
            return 'zip_file'

        if data[:2] == b'\x1F\x8B':
            return 'gzip_file'

        if data[:2] in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
            return 'zlib_data'

        if data[:1] == b'{' or data[:1] == b'[':
            try:
                import json
                json.loads(data[:1024].decode('utf-8', errors='ignore'))
                return 'json_data'
            except Exception:
                pass

        if data[:5] == b'<?xml':
            return 'xml_data'

        if data[:10].lower() == b'@echo off' or data[:2] == b'::':
            return 'batch_script'

        if data[:10].lower() == b'powershell' or data[:2] == b'#!':
            return 'powershell_script'

        return 'unknown'

    def _extract_single_file(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Extract data as a single file.

        Args:
            data: File data.
            base_offset: Offset of `data` within the original file.

        Returns:
            A single-element list with the file's filename, data, size, offset, and type.
        """
        file_type = self._detect_file_type(data)
        filename = f'extracted_{file_type}.bin'

        if file_type == 'pe_file':
            dll_match = re.search(rb'([A-Za-z0-9_\-\.]+\.dll)', data[:4096])
            if dll_match:
                try:
                    filename = dll_match.group(1).decode('utf-8', errors='ignore')
                except Exception:
                    pass

        return [{
            'filename': filename,
            'data': data,
            'size': len(data),
            'offset': base_offset,
            'type': file_type
        }]

    def get_errors(self) -> List[str]:
        """Get extraction errors."""
        return self.errors
