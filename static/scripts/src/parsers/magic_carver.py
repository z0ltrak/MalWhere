import struct
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path


class MagicCarver:
    """Carve embedded files from binary data using magic bytes."""

    # Common magic bytes
    MAGIC_BYTES = {
        b'MZ': {'type': 'pe_file', 'name': 'PE executable'},
        b'\x7fELF': {'type': 'elf_file', 'name': 'ELF executable'},
        b'PK\x03\x04': {'type': 'zip_file', 'name': 'ZIP archive'},
        b'PK\x01\x02': {'type': 'zip_central', 'name': 'ZIP central directory'},
        b'\x78\x9C': {'type': 'zlib', 'name': 'zlib compressed data'},
        b'\x78\xDA': {'type': 'zlib', 'name': 'zlib compressed data'},
        b'\x78\x01': {'type': 'zlib', 'name': 'zlib compressed data'},
        b'\x1F\x8B': {'type': 'gzip', 'name': 'GZIP compressed data'},
        b'\x50\x4B\x05\x06': {'type': 'zip_eocd', 'name': 'ZIP end of central directory'},
        b'RIFF': {'type': 'riff', 'name': 'RIFF multimedia file'},
        b'\x89PNG': {'type': 'png', 'name': 'PNG image'},
        b'\xFF\xD8\xFF': {'type': 'jpeg', 'name': 'JPEG image'},
        b'%PDF': {'type': 'pdf', 'name': 'PDF document'},
    }


    def __init__(self, file_path: Path):
            self.file_path = file_path
            self.data = None
            self.carved_data = {'pe_files': [], 'compressed_data': [], 'encrypted_data': []}
            self.errors: List[str] = []

    def carve(self) -> Dict[str, List[Dict[str, Any]]]:
        """Carve all embedded files from the binary."""
        result = {
            'embedded_files': [],
            'compressed_data': [],
            'encrypted_data': [],
            'pe_files': [],
            'zip_files': [],
        }

        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()

            # Carve all magic bytes
            for magic, info in self.MAGIC_BYTES.items():
                offsets = self._find_all(self.data, magic)
                for offset in offsets:
                    size = self._determine_size(self.data, offset, info['type'])
                    if size > 0:
                        entry = {
                            'offset': offset,
                            'type': info['type'],
                            'name': info['name'],
                            'size': size,
                            'data': self.data[offset:offset+size]  # Store the actual data
                        }
                        result['embedded_files'].append(entry)

                        # Categorize
                        if info['type'] == 'pe_file':
                            result['pe_files'].append(entry)
                            self.carved_data['pe_files'].append(entry)
                        elif info['type'] in ['zip_file', 'zip_central']:
                            result['zip_files'].append(entry)
                        elif info['type'] == 'zlib':
                            result['compressed_data'].append(entry)
                            self.carved_data['compressed_data'].append(entry)

            # Find encrypted patterns (with actual data)
            for pattern, pattern_type in self.ENCRYPTED_PATTERNS:
                offsets = self._find_all(self.data, pattern)
                for offset in offsets:
                    entry = {
                        'offset': offset,
                        'type': pattern_type,
                        'pattern': pattern.decode('utf-8', errors='ignore'),
                        'size': min(8192, len(self.data) - offset),
                        'data': self.data[offset:offset+8192]
                    }
                    result['encrypted_data'].append(entry)
                    self.carved_data['encrypted_data'].append(entry)

            # Store result in instance for later use
            self.carved_data = result

        except Exception as e:
            self.errors.append(f"Magic carving error: {e}")

        return result

    def _find_all(self, data: bytes, magic: bytes) -> List[int]:
        """Find all occurrences of magic bytes."""
        offsets = []
        start = 0
        while True:
            offset = data.find(magic, start)
            if offset == -1:
                break
            offsets.append(offset)
            start = offset + 1
        return offsets

    def _determine_size(self, data: bytes, offset: int, file_type: str) -> int:
        """Determine size of embedded file based on type."""
        if file_type == 'pe_file':
            return self._get_pe_size(data, offset)
        elif file_type in ['zip_file', 'zip_central']:
            return self._get_zip_size(data, offset)
        elif file_type == 'zlib':
            return self._get_zlib_size(data, offset)
        else:
            # Default: read until next magic or end
            return self._get_next_magic_offset(data, offset)

    def _get_pe_size(self, data: bytes, offset: int) -> int:
        """Get size of PE file from MZ header."""
        if offset + 0x3C >= len(data):
            return 0

        pe_offset = offset + int.from_bytes(data[offset+0x3C:offset+0x40], 'little')
        if pe_offset + 0x54 >= len(data):
            return 0

        # Check PE signature
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return 0

        # Get size_of_image from PE header
        size = int.from_bytes(data[pe_offset+0x50:pe_offset+0x54], 'little')
        return size if size > 0 else 0

    def _get_zip_size(self, data: bytes, offset: int) -> int:
        """Get size of ZIP file (find end of central directory)."""
        # Look for EOCD (0x06054b50) within 65536 bytes
        max_size = min(65536, len(data) - offset)
        for i in range(offset, offset + max_size - 4):
            if data[i:i+4] == b'\x50\x4B\x05\x06':
                # Found EOCD
                return i + 22 - offset
        return 8192  # Default

    def _get_zlib_size(self, data: bytes, offset: int) -> int:
        """Get size of zlib data (try to decompress)."""
        # Zlib data is usually continuous
        max_size = 8192
        return max_size

    def _get_next_magic_offset(self, data: bytes, start_offset: int) -> int:
        """Find next magic byte after start_offset."""
        max_size = 8192
        for i in range(start_offset + 1, min(start_offset + max_size, len(data))):
            for magic in self.MAGIC_BYTES:
                if data[i:i+len(magic)] == magic:
                    return i - start_offset
        return max_size

    def get_errors(self) -> List[str]:
        """Get carving errors."""
        return self.errors
