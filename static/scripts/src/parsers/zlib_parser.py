"""Zlib parser with support for various compression formats."""

import zlib
import struct
from typing import Optional, List, Dict, Any
from pathlib import Path


class ZlibParser:
    """Parse and decompress zlib-compressed data with multiple format support."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = None
        self.errors: List[str] = []

    def decompress(self, data: bytes) -> Optional[bytes]:
        """Decompress zlib-compressed data with multiple format support.

        Args:
            data: Data to decompress.

        Returns:
            Decompressed bytes, or None if every method failed.
        """
        if len(data) < 10:
            self.errors.append("Data too small for decompression")
            return None

        methods = [
            self._decompress_zlib,
            self._decompress_zlib_no_header,
            self._decompress_gzip,
            self._decompress_zlib_offset,
            self._decompress_zlib_multiple,
        ]

        for method in methods:
            try:
                result = method(data)
                if result and len(result) > 1024:
                    self.errors.append(f"Decompression succeeded with {method.__name__}")
                    return result
            except Exception as e:
                self.errors.append(f"{method.__name__} failed: {str(e)[:50]}")
                continue

        result = self._find_and_decompress(data)
        if result:
            return result

        self.errors.append("All decompression methods failed")
        return None

    def _decompress_zlib(self, data: bytes) -> Optional[bytes]:
        """Standard zlib decompression (with header).

        Args:
            data: Data to decompress.

        Returns:
            Decompressed bytes, or None if no valid header/decompression succeeded.
        """
        try:
            for header in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
                offset = data.find(header)
                if offset != -1:
                    decompressed = zlib.decompress(data[offset:])
                    if len(decompressed) > 1024:
                        return decompressed
        except zlib.error:
            pass
        return None

    def _decompress_zlib_no_header(self, data: bytes) -> Optional[bytes]:
        """Raw deflate decompression (no zlib header).

        Args:
            data: Data to decompress.

        Returns:
            Decompressed bytes, or None if no candidate offset decompressed successfully.
        """
        try:
            for offset in self._find_deflate_headers(data):
                try:
                    decompressed = zlib.decompress(data[offset:], -15)
                    if len(decompressed) > 1024:
                        return decompressed
                except zlib.error:
                    continue
        except Exception:
            pass
        return None

    def _decompress_gzip(self, data: bytes) -> Optional[bytes]:
        """GZip decompression.

        Args:
            data: Data to decompress.

        Returns:
            Decompressed bytes, or None if no GZip header/decompression succeeded.
        """
        try:
            offset = data.find(b'\x1F\x8B')
            if offset != -1:
                import gzip
                from io import BytesIO

                with BytesIO(data[offset:]) as f:
                    with gzip.GzipFile(fileobj=f) as gz:
                        decompressed = gz.read()
                        if len(decompressed) > 1024:
                            return decompressed
        except Exception:
            pass
        return None

    def _decompress_zlib_offset(self, data: bytes) -> Optional[bytes]:
        """Try decompressing from various offsets (zlib data may not start at offset 0).

        Args:
            data: Data to decompress.

        Returns:
            Decompressed bytes, or None if no offset decompressed successfully.
        """
        for offset in range(0, min(256, len(data) - 10)):
            chunk = data[offset:offset + 20]
            for header in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
                if chunk.startswith(header):
                    try:
                        decompressed = zlib.decompress(data[offset:])
                        if len(decompressed) > 1024:
                            return decompressed
                    except zlib.error:
                        continue
        return None

    def _decompress_zlib_multiple(self, data: bytes) -> Optional[bytes]:
        """Try decompressing multiple zlib streams concatenated.

        Args:
            data: Data to decompress.

        Returns:
            Concatenated decompressed bytes, or None if nothing decompressed.
        """
        try:
            decompressed = b''
            pos = 0
            while pos < len(data) - 10:
                found = False
                for header in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
                    offset = data.find(header, pos)
                    if offset != -1:
                        try:
                            chunk = zlib.decompress(data[offset:])
                            if chunk:
                                decompressed += chunk
                                pos = offset + len(chunk)
                                found = True
                                break
                        except zlib.error:
                            pos += 1
                            continue
                if not found:
                    break

            if len(decompressed) > 1024:
                return decompressed
        except Exception:
            pass
        return None

    def _find_and_decompress(self, data: bytes) -> Optional[bytes]:
        """Find zlib data within a larger blob and decompress it, trying several chunk sizes.

        Args:
            data: Data to search and decompress.

        Returns:
            Decompressed bytes, or None if nothing decompressed.
        """
        zlib_headers = [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']

        for header in zlib_headers:
            offset = data.find(header)
            if offset != -1:
                self.errors.append(f"Found zlib header at offset {offset}")

                for size in [1024, 2048, 4096, 8192, 16384, 32768, 65536]:
                    try:
                        chunk = data[offset:offset + size]
                        decompressed = zlib.decompress(chunk)
                        if len(decompressed) > 1024:
                            self.errors.append(f"Successfully decompressed {len(decompressed)} bytes")
                            return decompressed
                    except zlib.error:
                        continue
                    except Exception:
                        continue

        return None

    def _find_deflate_headers(self, data: bytes) -> List[int]:
        """Find potential deflate headers.

        Args:
            data: Data to scan.

        Returns:
            Up to 20 candidate offsets with a plausible BFINAL/BTYPE bit pattern.
        """
        offsets = []
        for i in range(len(data) - 2):
            # BFINAL = 1, BTYPE = 0 (no compression), 1 (fixed), 2 (dynamic)
            if data[i] & 0x01 == 0x01:
                btype = (data[i] >> 1) & 0x03
                if btype in [0, 1, 2]:
                    offsets.append(i)
                    if len(offsets) > 20:  # Limit
                        break
        return offsets

    def extract_from_file(self, offset: int, size: int = 0) -> Optional[bytes]:
        """Extract and decompress zlib data from file at specific offset.

        Args:
            offset: Byte offset to read from.
            size: Number of bytes to read; defaults to 64KB if not given.

        Returns:
            Decompressed bytes, or None on read/decompression failure.
        """
        try:
            with open(self.file_path, 'rb') as f:
                f.seek(offset)
                if size > 0:
                    data = f.read(size)
                else:
                    data = f.read(65536)  # Read up to 64KB
                return self.decompress(data)
        except Exception as e:
            self.errors.append(f"File zlib extraction error at offset {offset}: {e}")
            return None

    def get_errors(self) -> List[str]:
        """Get decompression errors."""
        return self.errors
