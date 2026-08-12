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

    # NSIS specific signatures -- generic NSIS/installer boilerplate only.
    # Previously included 'Starlabs'/'DiamondAge'/'goldendays'/'diamondage':
    # all RoningLoader-specific product/dropped-file names, not signatures
    # of NSIS itself. _is_nsis_file_system() below already has 2 independent
    # structural fallbacks (file-path scanning, file-table pattern matching)
    # that don't depend on any sample's specific strings -- verified those
    # alone still detect roning's real NSIS payload.
    NSIS_SIGNATURES = [
        b'Nullsoft.NSIS',
        b'NSIS',
        b'installer',
    ]

    def __init__(self):
        self.errors: List[str] = []
        self.extracted_files: List[Dict[str, Any]] = []

    def extract_files_from_data(self, data: bytes, base_offset: int = 0) -> List[Dict[str, Any]]:
        """Extract multiple files from decompressed data."""
        self.extracted_files = []
        self.errors = []

        if len(data) < 1024:
            self.errors.append("Data too small to extract files")
            return []

        # Check if this is an NSIS file system
        if self._is_nsis_file_system(data):
            self.errors.append("Detected NSIS file system structure")
            nsis_files = self._extract_nsis_files(data, base_offset)
            if nsis_files:
                return nsis_files

        # Check if it's a single file (PE, DLL, etc.)
        if self._is_single_file(data):
            self.errors.append("Detected single file")
            return self._extract_single_file(data, base_offset)

        # Try to find multiple files by scanning for signatures
        files = self._scan_for_files(data, base_offset)
        if len(files) > 1:
            self.errors.append(f"Found {len(files)} files by signature scanning")
            return files

        # If we can't find multiple files, treat as single file
        self.errors.append("Treating as single file")
        return self._extract_single_file(data, base_offset)

    def _is_nsis_file_system(self, data: bytes) -> bool:
        """Check if data contains an NSIS file system structure."""
        if len(data) < 1024:
            return False

        # Look for NSIS signatures in the first 8KB
        search_data = data[:8192]

        # Check for NSIS signatures
        for sig in self.NSIS_SIGNATURES:
            if sig in search_data:
                return True

        # Check for multiple file paths with common extensions
        file_paths = self._find_file_paths(search_data)
        if len(file_paths) >= 3:
            return True

        # Check for file table patterns
        if self._find_nsis_file_table(search_data) != -1:
            return True

        return False

    def _find_file_paths(self, data: bytes) -> List[str]:
        """Find potential file paths in data."""
        paths = set()

        # Look for Windows paths with extensions
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
                    # Clean up the path
                    path = path.strip()
                    if len(path) > 5 and len(path) < 260:
                        paths.add(path)
                except Exception:
                    pass

        return list(paths)[:50]

    def _find_nsis_file_table(self, data: bytes) -> int:
        """Find NSIS file table offset."""
        # Look for file table patterns
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
        """Check if data is a single file."""
        # Check for PE
        if data[:2] == b'MZ':
            try:
                pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
                if pe_offset + 4 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    return True
            except Exception:
                pass

        # Check for DLL
        if data[:2] == b'MZ' and b'.dll' in data[:4096].lower():
            return True

        # Check for ZIP
        if data[:4] == b'PK\x03\x04':
            return True

        # Check if it's a script (batch, PowerShell)
        if data[:10].lower() in [b'@echo off', b'powershell', b'#!', b'::']:
            return True

        return False

    def _extract_nsis_files(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Extract files from NSIS file system."""
        files = []

        # Try to find the file table
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

        # If we didn't find NSIS file table, scan for files
        if not files:
            self.errors.append("No NSIS file table found, scanning for signatures")
            files = self._scan_for_files(data, base_offset)

        # If still no files, try to extract based on common NSIS patterns
        if not files:
            files = self._extract_nsis_by_pattern(data, base_offset)

        return files

    def _parse_nsis_file_table(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """Parse NSIS file table entries."""
        entries = []
        current_offset = offset

        # Parse until we hit the end of the table or find a pattern
        while current_offset < offset + 8192 and current_offset < len(data) - 100:
            chunk = data[current_offset:current_offset+200]

            # Look for file name with extension
            name_match = re.search(rb'([A-Za-z0-9_\-\. ]+\.(?:exe|dll|sys|dat|bin|tmp|bat|cmd|ps1))', chunk)
            if name_match:
                name = name_match.group(1).decode('utf-8', errors='ignore').strip()

                # Look for size
                size_match = re.search(rb'(\d+)\s*(?:bytes|Bytes|size|Size)', chunk)
                if size_match:
                    try:
                        size = int(size_match.group(1))
                        # Estimate offset (after the name and size fields)
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
        """Extract files from NSIS data using pattern matching."""
        files = []

        # Look for common file patterns in NSIS installers
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
                        # Try to find the actual file data
                        # Look for the file content after the filename
                        file_offset = match.end()
                        # Try to find the file data by looking for signatures
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
        """Find file data starting at offset."""
        if offset >= len(data):
            return None

        # Look for file signatures within the next 1000 bytes
        for i in range(offset, min(offset + 1000, len(data))):
            for sig, file_type, max_size in self.FILE_SIGNATURES:
                if data[i:i+len(sig)] == sig:
                    # Found a signature, extract from there
                    size = min(max_size, len(data) - i)
                    return data[i:i+size]

        # If no signature found, take a chunk
        size = min(8192, len(data) - offset)
        return data[offset:offset+size]

    def _scan_for_files(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Scan for files by looking for file signatures."""
        files = []
        seen_offsets = set()

        for signature, file_type, max_size in self.FILE_SIGNATURES:
            offset = data.find(signature)
            while offset != -1:
                # Skip if we've seen this offset
                if offset in seen_offsets:
                    offset = data.find(signature, offset + 1)
                    continue
                seen_offsets.add(offset)

                # Extract the data
                size = min(max_size, len(data) - offset)
                file_data = data[offset:offset+size]

                # Only add if it's significant
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
        """Detect file type from magic bytes."""
        if len(data) < 4:
            return 'unknown'

        # Check for PE
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

        # Check for ZIP
        if data[:4] == b'PK\x03\x04':
            return 'zip_file'

        # Check for GZip
        if data[:2] == b'\x1F\x8B':
            return 'gzip_file'

        # Check for zlib
        if data[:2] in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
            return 'zlib_data'

        # Check for JSON
        if data[:1] == b'{' or data[:1] == b'[':
            try:
                import json
                json.loads(data[:1024].decode('utf-8', errors='ignore'))
                return 'json_data'
            except Exception:
                pass

        # Check for XML
        if data[:5] == b'<?xml':
            return 'xml_data'

        # Check for batch script
        if data[:10].lower() == b'@echo off' or data[:2] == b'::':
            return 'batch_script'

        # Check for PowerShell script
        if data[:10].lower() == b'powershell' or data[:2] == b'#!':
            return 'powershell_script'

        return 'unknown'

    def _extract_single_file(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Extract as a single file."""
        file_type = self._detect_file_type(data)
        filename = f'extracted_{file_type}.bin'

        # Try to find a better filename from the data
        if file_type == 'pe_file':
            # Look for DLL name in the data
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
