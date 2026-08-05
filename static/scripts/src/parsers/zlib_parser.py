import zlib
from typing import Optional, List, Dict, Any
from pathlib import Path


class ZlibParser:
    """Parse and decompress zlib-compressed data."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = None
        self.errors: List[str] = []

    def decompress(self, data: bytes) -> Optional[bytes]:
        """Decompress zlib-compressed data."""
        try:
            # Try standard zlib header (0x78 0x9C, 0x78 0xDA, 0x78 0x01)
            for header in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
                offset = data.find(header)
                if offset != -1:
                    try:
                        decompressed = zlib.decompress(data[offset:])
                        if len(decompressed) > 1024:
                            return decompressed
                    except zlib.error:
                        continue

            # Try with negative wbits (raw deflate)
            try:
                # Find likely deflate data
                for offset in self._find_deflate_headers(data):
                    try:
                        decompressed = zlib.decompress(data[offset:], -15)
                        if len(decompressed) > 1024:
                            return decompressed
                    except zlib.error:
                        continue
            except:
                pass

        except Exception as e:
            self.errors.append(f"Zlib decompression error: {e}")

        return None

    def _find_deflate_headers(self, data: bytes) -> List[int]:
        """Find potential deflate headers."""
        offsets = []
        # Look for common deflate patterns
        for i in range(len(data) - 2):
            # BFINAL = 1, BTYPE = 0 (no compression), 1 (fixed), 2 (dynamic)
            if data[i] & 0x01 == 0x01:  # BFINAL
                btype = (data[i] >> 1) & 0x03
                if btype in [0, 1, 2]:
                    offsets.append(i)
        return offsets

    def extract_from_file(self) -> List[Dict[str, Any]]:
        """Extract and decompress zlib data from file."""
        results = []
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()

            # Find all zlib headers
            for header in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
                offset = self.data.find(header)
                while offset != -1:
                    decompressed = self.decompress(self.data[offset:offset+8192])
                    if decompressed:
                        results.append({
                            'offset': offset,
                            'header': header.hex(),
                            'original_size': len(self.data[offset:offset+8192]),
                            'decompressed_size': len(decompressed),
                            'data': decompressed[:10240]  # Sample
                        })
                    offset = self.data.find(header, offset + 1)
        except Exception as e:
            self.errors.append(f"File zlib extraction error: {e}")

        return results

    def get_errors(self) -> List[str]:
        """Get decompression errors."""
        return self.errors
