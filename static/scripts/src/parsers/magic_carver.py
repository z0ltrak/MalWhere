"""
Magic carving with proper binwalk integration and entropy-based skipping.
TFM 2025-2026 - Universidad Complutense de Madrid
"""

import struct
import subprocess
import tempfile
import shutil
import json
import re
import os
import math
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from ..constants import HIGH_ENTROPY_THRESHOLD, SKIP_CARVING_THRESHOLD


class MagicCarver:
    """Carve embedded files using binwalk with entropy-based skipping for encrypted data."""

    # File type priorities (higher = more important to analyze)
    FILE_PRIORITIES = {
        'pe_file': 10,
        'elf_file': 10,
        'zip_file': 8,
        'gzip_file': 8,
        'zlib_data': 7,
        'json_data': 5,
        'xml_data': 5,
        'plaintext': 4,
        'png_image': 3,
        'jpeg_image': 3,
        'riff_file': 3,
        'pdf_file': 3,
        'unknown': 0,
    }

    # Entropy thresholds -- see src/constants.py
    HIGH_ENTROPY_THRESHOLD = HIGH_ENTROPY_THRESHOLD
    SUSPICIOUS_ENTROPY_THRESHOLD = 6.5
    SKIP_CARVING_THRESHOLD = SKIP_CARVING_THRESHOLD  # If overall entropy > this, skip carving entirely

    # Maximum embedded files to extract
    MAX_EMBEDDED_FILES = 20

    # Minimum file size to consider for carving
    MIN_CARVE_SIZE = 1024

    # File types to analyze
    ANALYZE_TYPES = {
        'pe_file': True,
        'elf_file': True,
        'zip_file': True,
        'gzip_file': True,
        'zlib_data': True,
    }

    def __init__(self, file_path: Path, use_binwalk: bool = True, verbose: bool = False):
        self.file_path = file_path
        self.use_binwalk = use_binwalk and shutil.which('binwalk') is not None
        self.verbose = verbose
        self.data = None
        self.carved_data = {
            'pe_files': [],
            'compressed_data': [],
            'encrypted_data': [],
            'binwalk_files': [],
            'all_embedded': []
        }
        self.errors: List[str] = []
        self._binwalk_available = self.use_binwalk
        self._binwalk_output = None

        # Track if we should skip carving
        self._skip_carving = False
        self._overall_entropy = None

    def carve(self) -> Dict[str, List[Dict[str, Any]]]:
        """Carve embedded files with entropy-based skipping."""
        result = {
            'embedded_files': [],
            'compressed_data': [],
            'encrypted_data': [],
            'pe_files': [],
            'zip_files': [],
            'binwalk_files': [],
        }

        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()

            self._log(f"File size: {len(self.data)} bytes")
            self._log(f"Binwalk available: {self._binwalk_available}")

            # ============================================================
            # STEP 1: Calculate overall entropy
            # ============================================================
            self._overall_entropy = self._calculate_entropy(self.data)
            self._log(f"Overall entropy: {self._overall_entropy:.2f}")

            # ============================================================
            # STEP 2: Check if we should skip carving (high entropy = encrypted)
            # ============================================================
            if self._should_skip_carving():
                self._log(f"*** SKIPPING CARVING: File appears encrypted (entropy: {self._overall_entropy:.2f}) ***")
                result['encrypted_data'].append({
                    'entropy': self._overall_entropy,
                    'size': len(self.data),
                    'reason': f'High entropy ({self._overall_entropy:.2f}) - likely encrypted'
                })
                return result

            # ============================================================
            # STEP 3: Check for common file types (not encrypted)
            # ============================================================
            # If it's a PE file, don't carve it
            if self._is_pe_file():
                self._log("File is a PE executable - skipping carving")
                return result

            # If it's a ZIP file, don't carve it
            if self._is_zip_file():
                self._log("File is a ZIP archive - skipping carving")
                return result

            # ============================================================
            # STEP 4: Method 1 - Use binwalk for proper file detection
            # ============================================================
            if self._binwalk_available:
                self._log("Running binwalk scan...")
                binwalk_results = self._carve_with_binwalk()
                self._log(f"Binwalk found {len(binwalk_results)} potential files")

                if binwalk_results:
                    # Log what binwalk found
                    for entry in binwalk_results[:10]:
                        self._log(f"  - {entry.get('type')} at offset {entry.get('offset')}: {entry.get('description', '')[:50]}")

                    # Filter and store results
                    result['binwalk_files'] = binwalk_results
                    result['embedded_files'].extend(binwalk_results)

                    # Categorize binwalk results
                    for entry in binwalk_results:
                        file_type = entry.get('type', 'unknown')
                        if file_type == 'pe_file':
                            result['pe_files'].append(entry)
                        elif file_type in ['zip_file', 'zip_central']:
                            result['zip_files'].append(entry)
                        elif file_type in ['zlib_data', 'gzip_file']:
                            result['compressed_data'].append(entry)
                else:
                    self._log("Binwalk found no embedded files")

            # ============================================================
            # STEP 5: Method 2 - Fallback to magic bytes
            # ============================================================
            if not result['embedded_files']:
                self._log("No embedded files found, trying magic bytes carving...")
                self._carve_magic_bytes(result)

            # ============================================================
            # STEP 6: Limit results to prevent explosion
            # ============================================================
            if len(result['embedded_files']) > self.MAX_EMBEDDED_FILES:
                self._log(f"Limiting embedded files from {len(result['embedded_files'])} to {self.MAX_EMBEDDED_FILES}")
                result['embedded_files'] = result['embedded_files'][:self.MAX_EMBEDDED_FILES]

            # Store for later use
            self.carved_data = result

        except Exception as e:
            self.errors.append(f"Magic carving error: {e}")
            self._log(f"ERROR: {e}")

        return result

    def _should_skip_carving(self) -> bool:
        """Determine if carving should be skipped based on entropy."""
        if self._overall_entropy is None:
            return False

        # Skip if overall entropy is very high (encrypted data)
        if self._overall_entropy > self.SKIP_CARVING_THRESHOLD:
            self._log(f"High entropy ({self._overall_entropy:.2f}) > {self.SKIP_CARVING_THRESHOLD}")
            return True

        # If entropy is high and file is large, likely encrypted
        if self._overall_entropy > self.HIGH_ENTROPY_THRESHOLD and len(self.data) > 1024 * 1024:
            self._log(f"High entropy ({self._overall_entropy:.2f}) and large file ({len(self.data)} bytes)")
            return True

        # Most legitimate executables have entropy between 5.5-6.5
        # If it's in this range and is a PE, don't skip
        if self._is_pe_file() and 5.5 <= self._overall_entropy <= 6.5:
            return False

        return False

    def _is_pe_file(self) -> bool:
        """Check if the file is a PE executable."""
        if not self.data or len(self.data) < 2:
            return False

        if self.data[:2] != b'MZ':
            return False

        try:
            pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
            if pe_offset + 4 < len(self.data) and self.data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                return True
        except Exception:
            pass
        return False

    def _is_zip_file(self) -> bool:
        """Check if the file is a ZIP archive."""
        if not self.data or len(self.data) < 4:
            return False
        return self.data[:4] == b'PK\x03\x04'

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data or len(data) < 2:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)

        return entropy

    def _carve_with_binwalk(self) -> List[Dict[str, Any]]:
        """Use binwalk to detect and extract embedded files."""
        results = []

        try:
            # Run binwalk in scan mode to detect file types
            cmd = [
                'binwalk',
                '--signature',  # Use signatures
                '--terse',      # Terse output
                str(self.file_path)
            ]

            self._log(f"Running: {' '.join(cmd)}")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            self._log(f"Binwalk return code: {proc.returncode}")

            if proc.stdout:
                self._log(f"Binwalk stdout: {len(proc.stdout)} bytes")
                # Print first few lines for debugging
                lines = proc.stdout.split('\n')[:10]
                for line in lines:
                    if line.strip():
                        self._log(f"  {line[:80]}")

            if proc.stderr:
                self._log(f"Binwalk stderr: {proc.stderr[:200]}")

            if proc.returncode == 0 and proc.stdout:
                # Parse the output
                results = self._parse_binwalk_output(proc.stdout)

                # Extract the actual data for interesting files
                for result in results[:self.MAX_EMBEDDED_FILES]:
                    if result.get('offset') is not None:
                        # Extract data from the file
                        data = self._extract_data_at_offset(
                            result['offset'],
                            result.get('size', 0)
                        )
                        if data:
                            result['data'] = data
                            result['size'] = len(data)

            # Try extraction mode if signature scan found nothing
            if not results:
                self._log("Signature scan found nothing, trying extraction mode...")
                results = self._carve_with_binwalk_extraction()

        except subprocess.TimeoutExpired:
            self.errors.append("Binwalk timed out")
            self._log("Binwalk timed out")
        except Exception as e:
            self.errors.append(f"Binwalk error: {e}")
            self._log(f"Binwalk error: {e}")

        return results

    def _carve_with_binwalk_extraction(self) -> List[Dict[str, Any]]:
        """Use binwalk extraction mode to get embedded files."""
        results = []

        try:
            # Run binwalk with extraction
            cmd = [
                'binwalk',
                '-e',  # Extract
                '-M',  # Recursive extraction
                '-dd', '.*',  # Extract all file types
                str(self.file_path)
            ]

            self._log(f"Running extraction: {' '.join(cmd)}")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            self._log(f"Extraction return code: {proc.returncode}")
            self._log(f"Extraction stdout: {len(proc.stdout)} bytes" if proc.stdout else "No stdout")

            if proc.stdout:
                # Parse the extraction output
                lines = proc.stdout.split('\n')
                for line in lines:
                    if 'extracted' in line.lower() or 'extracting' in line.lower():
                        self._log(f"  {line[:100]}")

            # Look for extracted files
            # Binwalk creates directories like: _sample.exe.extracted/
            extraction_dirs = []

            # Check common binwalk extraction directory patterns
            for pattern in [
                f"_{self.file_path.stem}.extracted",
                f"_{self.file_path.name}.extracted",
                f"{self.file_path.stem}.extracted",
            ]:
                for dir_path in self.file_path.parent.glob(pattern):
                    extraction_dirs.append(dir_path)

            # Also check for directories starting with '_'
            for dir_path in self.file_path.parent.glob("_*"):
                if dir_path.is_dir() and '.extracted' in str(dir_path):
                    extraction_dirs.append(dir_path)

            self._log(f"Found extraction directories: {len(extraction_dirs)}")

            for output_dir in extraction_dirs:
                if output_dir.exists():
                    self._log(f"Scanning extraction directory: {output_dir}")
                    # Recursively find all extracted files
                    for extracted_file in output_dir.rglob('*'):
                        if extracted_file.is_file():
                            try:
                                with open(extracted_file, 'rb') as f:
                                    data = f.read()

                                if len(data) > self.MIN_CARVE_SIZE:
                                    # Determine file type
                                    file_type = self._detect_file_type(data)
                                    chunk_entropy = self._calculate_entropy(data)

                                    # Skip high-entropy chunks
                                    if chunk_entropy > self.HIGH_ENTROPY_THRESHOLD:
                                        self._log(f"  Skipping {extracted_file.name} - high entropy ({chunk_entropy:.2f})")
                                        continue

                                    # Skip if it's not interesting
                                    if file_type not in self.ANALYZE_TYPES:
                                        continue

                                    self._log(f"  Found extracted {file_type}: {extracted_file.name} ({len(data)} bytes)")

                                    # Try to find offset from filename
                                    offset = 0
                                    offset_match = re.search(r'(\d+)', extracted_file.name)
                                    if offset_match:
                                        offset = int(offset_match.group(1))

                                    results.append({
                                        'offset': offset,
                                        'type': file_type,
                                        'name': extracted_file.name,
                                        'size': len(data),
                                        'data': data,
                                        'binwalk_extracted': True,
                                        'path': str(extracted_file),
                                        'entropy': chunk_entropy
                                    })
                            except Exception as e:
                                self._log(f"Error reading {extracted_file}: {e}")

                    # Clean up binwalk extraction directory
                    shutil.rmtree(output_dir, ignore_errors=True)
                    self._log(f"Cleaned up {output_dir}")

        except subprocess.TimeoutExpired:
            self.errors.append("Binwalk extraction timed out")
            self._log("Binwalk extraction timed out")
        except Exception as e:
            self.errors.append(f"Binwalk extraction error: {e}")
            self._log(f"Binwalk extraction error: {e}")

        return results

    def _parse_binwalk_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse binwalk output to find interesting files."""
        results = []
        seen_offsets = set()

        self._log(f"Parsing binwalk output...")

        for line in output.split('\n'):
            if not line.strip():
                continue

            # Skip header lines
            if 'DECIMAL' in line or 'HEXADECIMAL' in line or 'DESCRIPTION' in line:
                continue
            if line.startswith('---'):
                continue
            if not line or not line[0].isdigit():
                continue

            # Parse the line - binwalk format: "offset    hex    description"
            parts = line.split()
            if len(parts) < 3:
                continue

            try:
                offset = int(parts[0])  # First column is decimal offset
                hex_offset = parts[1]
                description = ' '.join(parts[2:])

                # Skip offset 0 (main file)
                if offset == 0:
                    self._log(f"  Skipping offset 0 (main file)")
                    continue

                # Skip if we've seen this offset
                if offset in seen_offsets:
                    continue
                seen_offsets.add(offset)

                self._log(f"  Found at offset {offset}: {description[:50]}")

                # Determine file type from description
                file_type = self._determine_type_from_description(description)
                self._log(f"    Type: {file_type}")

                # Skip if it's not interesting
                if file_type == 'ignore':
                    self._log(f"    Ignoring (type: ignore)")
                    continue

                if file_type not in self.ANALYZE_TYPES:
                    self._log(f"    Skipping (type: {file_type} not in ANALYZE_TYPES)")
                    continue

                # Check entropy of the chunk at this offset
                chunk_size = min(4096, len(self.data) - offset)
                chunk = self.data[offset:offset + chunk_size]
                chunk_entropy = self._calculate_entropy(chunk)

                # Skip high-entropy chunks
                if chunk_entropy > self.HIGH_ENTROPY_THRESHOLD:
                    self._log(f"    Skipping - high entropy ({chunk_entropy:.2f})")
                    continue

                # Try to estimate size
                size = self._estimate_size_from_description(description, offset)

                results.append({
                    'offset': offset,
                    'type': file_type,
                    'name': f"binwalk_{file_type}_{offset}.bin",
                    'size': size,
                    'description': description,
                    'binwalk_extracted': False,
                    'entropy': chunk_entropy
                })

                self._log(f"  Added {file_type} at offset {offset}")

            except ValueError as e:
                self._log(f"  Parse error: {e}")
                continue

        self._log(f"Parsed {len(results)} results")
        return results

    def _determine_type_from_description(self, description: str) -> str:
        """Determine file type from binwalk description."""
        desc_lower = description.lower()

        # Check for PE files
        if any(x in desc_lower for x in ['microsoft executable', 'portable executable', 'pe']):
            return 'pe_file'

        # Check for ELF
        if 'elf' in desc_lower:
            return 'elf_file'

        # Check for ZIP
        if 'zip archive' in desc_lower:
            return 'zip_file'

        # Check for GZip
        if 'gzip compressed' in desc_lower:
            return 'gzip_file'

        # Check for zlib
        if 'zlib compressed' in desc_lower:
            return 'zlib_data'

        # Check for images (ignore)
        if any(x in desc_lower for x in ['png', 'jpeg', 'jpg', 'gif', 'bmp', 'tiff']):
            return 'ignore'

        # Check for PDF (ignore)
        if 'pdf' in desc_lower:
            return 'ignore'

        # Check for XML (ignore)
        if 'xml' in desc_lower:
            return 'ignore'

        # Check for HTML (ignore)
        if 'html' in desc_lower:
            return 'ignore'

        # Check for JSON (ignore)
        if 'json' in desc_lower:
            return 'ignore'

        return 'unknown'

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

        # Check for ZIP
        if data[:4] == b'PK\x03\x04':
            return 'zip_file'

        # Check for GZip
        if data[:2] == b'\x1F\x8B':
            return 'gzip_file'

        # Check for zlib
        if data[:2] in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
            return 'zlib_data'

        # Check for ELF
        if data[:4] == b'\x7fELF':
            return 'elf_file'

        return 'unknown'

    def _estimate_size_from_description(self, description: str, offset: int) -> int:
        """Estimate size from description or by scanning."""
        # Try to find size in description
        size_match = re.search(r'size:\s*(\d+)', description, re.IGNORECASE)
        if size_match:
            return int(size_match.group(1))

        # Try to find the next file signature
        if self.data:
            # Look for next known signature
            signatures = [
                b'MZ', b'PK\x03\x04', b'\x1F\x8B', b'\x78\x9C',
                b'\x78\xDA', b'\x78\x01', b'\x89PNG', b'\xFF\xD8'
            ]

            next_offset = len(self.data)
            for i in range(offset + 16, min(offset + 1048576, len(self.data))):
                for sig in signatures:
                    if i + len(sig) <= len(self.data) and self.data[i:i+len(sig)] == sig:
                        next_offset = i
                        break
                if next_offset < len(self.data):
                    break

            if next_offset > offset:
                return next_offset - offset

        # Default: read 64KB
        return min(65536, len(self.data) - offset)

    def _extract_data_at_offset(self, offset: int, size: int = 0) -> Optional[bytes]:
        """Extract data at a specific offset."""
        if not self.data or offset >= len(self.data):
            self._log(f"  No data or offset {offset} >= {len(self.data)}")
            return None

        # Don't read from offset 0 - that's the main file
        if offset == 0:
            self._log(f"  Skipping offset 0 (main file)")
            return None

        # For zlib data, read a larger chunk
        if size == 0 or size < 32768:
            size = 32768

        end_offset = min(offset + size, len(self.data))
        data = self.data[offset:end_offset]
        self._log(f"  Extracted {len(data)} bytes from offset {offset}")

        # Log the first few bytes for debugging
        if len(data) > 16:
            self._log(f"  Magic bytes: {data[:16].hex()}")

        return data

    def _carve_magic_bytes(self, result: Dict[str, List[Dict[str, Any]]]) -> None:
        """Fallback: Carve using magic bytes with limits."""
        magic_bytes = {
            b'MZ': 'pe_file',
            b'PK\x03\x04': 'zip_file',
            b'\x1F\x8B': 'gzip_file',
            b'\x78\x9C': 'zlib_data',
            b'\x78\xDA': 'zlib_data',
            b'\x78\x01': 'zlib_data',
        }

        carved_count = 0
        for magic, file_type in magic_bytes.items():
            offsets = self._find_all(self.data, magic)
            for offset in offsets:
                # Skip offset 0 (main file)
                if offset == 0:
                    continue

                # Skip if we already have this offset
                if any(e.get('offset') == offset for e in result['embedded_files']):
                    continue

                # Check entropy of the chunk
                chunk = self.data[offset:offset + 4096]
                chunk_entropy = self._calculate_entropy(chunk)

                # Skip high-entropy chunks (likely encrypted)
                if chunk_entropy > self.HIGH_ENTROPY_THRESHOLD:
                    self._log(f"  Skipping chunk at offset {offset} - high entropy ({chunk_entropy:.2f})")
                    continue

                size = self._estimate_size_from_description('', offset)
                data = self._extract_data_at_offset(offset, size)
                if data and len(data) > self.MIN_CARVE_SIZE:
                    entry = {
                        'offset': offset,
                        'type': file_type,
                        'name': f"magic_{file_type}_{offset}.bin",
                        'size': len(data),
                        'data': data,
                        'binwalk_extracted': False,
                        'entropy': chunk_entropy
                    }
                    result['embedded_files'].append(entry)
                    carved_count += 1

                    if file_type == 'pe_file':
                        result['pe_files'].append(entry)
                    elif file_type in ['zlib_data', 'gzip_file']:
                        result['compressed_data'].append(entry)

                    if carved_count >= self.MAX_EMBEDDED_FILES:
                        self._log(f"Reached max embedded files ({self.MAX_EMBEDDED_FILES})")
                        return

    # Add to MagicCarver class

    def _should_skip_carving(self) -> bool:
        """
        Determine if carving should be skipped based on file context and entropy.
        This matches the logic in analyzer.py for consistency.
        """
        if self._overall_entropy is None:
            return False

        # ============================================================
        # NEVER skip for installers - they contain embedded files
        # ============================================================
        # Check if this is an NSIS installer
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read(65536)
                data_str = data.decode('utf-8', errors='ignore')
                if 'Nullsoft.NSIS' in data_str or 'NullsoftInst' in data_str:
                    self._log(f"  NSIS installer detected - enabling carving")
                    return False
        except Exception:
            pass

        # ============================================================
        # Check if it's an installer by extension
        # ============================================================
        if self.file_path.suffix.lower() in ['.exe']:
            # Check if it's an installer by name
            name_lower = self.file_path.name.lower()
            if 'install' in name_lower or 'setup' in name_lower:
                self._log(f"  Installer filename detected - enabling carving")
                return False

        # ============================================================
        # ALWAYS skip for known encrypted extensions
        # ============================================================
        ext = self.file_path.suffix.lower()
        if ext in ['.3w', '.enc', '.crypt']:
            self._log(f"  Encrypted extension '{ext}' - skipping carving")
            return True

        # ============================================================
        # NEVER skip for archives
        # ============================================================
        if ext in ['.zip', '.gz', '.gzip', '.7z', '.rar']:
            self._log(f"  Archive extension '{ext}' - enabling carving")
            return False

        # ============================================================
        # NEVER skip for PE files (even with high entropy)
        # ============================================================
        if self._is_pe_file():
            self._log(f"  PE file with entropy {self._overall_entropy:.2f} - enabling carving")
            return False

        # ============================================================
        # Check for compression headers (don't skip)
        # ============================================================
        if self.data and len(self.data) > 10:
            compression_headers = [
                b'\x78\x9C', b'\x78\xDA', b'\x78\x01',  # zlib
                b'\x1F\x8B',  # gzip
                b'PK\x03\x04',  # zip
                b'7z\xBC\xAF\x27\x1C',  # 7z
                b'Rar!',  # RAR
            ]
            for header in compression_headers:
                if self.data[:len(header)] == header:
                    self._log(f"  Found compression header - enabling carving")
                    return False

        # ============================================================
        # For unknown files, only skip if very high entropy
        # ============================================================
        if self._overall_entropy > self.SKIP_CARVING_THRESHOLD:
            self._log(f"  Unknown file with high entropy {self._overall_entropy:.2f} - skipping carving")
            return True

        # ============================================================
        # For all other cases, allow carving
        # ============================================================
        return False

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

    def _log(self, message: str):
        """Log message if verbose."""
        if self.verbose:
            print(f"[*] MagicCarver: {message}")

    def get_errors(self) -> List[str]:
        """Get carving errors."""
        return self.errors

    def get_encrypted_data(self) -> List[Dict[str, Any]]:
        """Get detected encrypted data blocks."""
        return self.carved_data.get('encrypted_data', [])
