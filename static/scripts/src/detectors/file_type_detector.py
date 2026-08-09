"""
Universal File Type Detection Module
TFM 2025-2026 - Universidad Complutense de Madrid

Detects file types using:
1. Magic bytes
2. String signatures
3. PE/ELF parsing
4. Script detection
5. Extension-based detection
6. Heuristics
"""

import struct
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from enum import Enum


class FileCategory(Enum):
    """File type categories."""
    PE_NATIVE = "pe_native"
    PE_DOTNET = "pe_dotnet"
    PE_FILE = "pe_file"
    ELF_FILE = "elf_file"
    INSTALLER_NSIS = "installer_nsis"
    INSTALLER_INNO = "installer_inno"
    INSTALLER_MSI = "installer_msi"
    SCRIPT_POWERSHELL = "script_powershell"
    SCRIPT_BATCH = "script_batch"
    SCRIPT_VBS = "script_vbs"
    SCRIPT_JS = "script_js"
    SCRIPT_PYTHON = "script_python"
    SCRIPT_PHP = "script_php"
    ARCHIVE_ZIP = "archive_zip"
    ARCHIVE_GZIP = "archive_gzip"
    ARCHIVE_7Z = "archive_7z"
    ARCHIVE_RAR = "archive_rar"
    DATA_ZLIB = "zlib_data"
    DATA_JSON = "json_data"
    DATA_XML = "xml_data"
    DATA_PLAINTEXT = "plaintext"
    IMAGE_JPEG = "jpeg_image"
    IMAGE_PNG = "png_image"
    IMAGE_GIF = "gif_image"
    PDF_FILE = "pdf_file"
    UNKNOWN = "unknown"


class FileTypeDetector:
    """
    Universal file type detector using multiple methods.

    Priority order:
    1. Installer signatures (NSIS, Inno, MSI)
    2. Script detection (PowerShell, Batch, VBS, JS)
    3. PE/ELF detection (with .NET detection)
    4. Archive detection (ZIP, GZip, 7z, RAR)
    5. Data detection (JSON, XML, Plaintext)
    6. Extension-based
    7. Heuristics
    """

    # NSIS signatures to check
    NSIS_SIGNATURES = [
        'Nullsoft.NSIS.exehead',
        'NullsoftInst',
        'Nullsoft.NSIS',
        'Nullsoft Install System'
    ]

    # Inno Setup signatures
    INNO_SIGNATURES = [
        'Inno Setup',
        'Inno Setup Messages',
        'Inno Setup Compiler'
    ]

    # PowerShell indicators
    POWERSHELL_INDICATORS = [
        'Write-Host', 'Write-Output', 'Get-', 'Set-',
        'New-', 'Invoke-', 'ConvertTo-', 'ConvertFrom-',
        'Select-', 'Where-', 'ForEach-', 'ForEach-Object',
        'Import-Module', 'Export-Module'
    ]

    # Batch indicators
    BATCH_INDICATORS = [
        '@echo off', 'echo ', 'set ', 'goto ',
        'if ', 'for ', 'call ', 'rem ', 'cls', 'pause'
    ]

    # VBScript indicators
    VBS_INDICATORS = [
        'CreateObject', 'WScript.Shell', 'WScript.Echo',
        'MsgBox', 'InputBox', 'GetObject', 'Run'
    ]

    # JavaScript indicators
    JS_INDICATORS = [
        'document.', 'window.', 'alert(', 'console.log',
        'function()', '=>', 'document.getElementById',
        'eval(', 'JSON.parse', 'fetch('
    ]

    # Python indicators
    PYTHON_INDICATORS = [
        'import ', 'from ', 'def ', 'class ',
        'if __name__', 'print(', 'sys.', 'os.'
    ]

    # PHP indicators
    PHP_INDICATORS = [
        '<?php', '<?=', '$_GET', '$_POST',
        '$_SESSION', '$_COOKIE', 'echo ',
        'function ', 'class '
    ]

    # File signatures for magic byte detection
    FILE_SIGNATURES = {
        b'PK\x03\x04': 'archive_zip',
        b'PK\x05\x06': 'archive_zip',
        b'PK\x07\x08': 'archive_zip',
        b'\x1F\x8B': 'archive_gzip',
        b'7z\xBC\xAF\x27\x1C': 'archive_7z',
        b'Rar!': 'archive_rar',
        b'\x89PNG\r\n\x1A\n': 'image_png',
        b'\xFF\xD8\xFF': 'image_jpeg',
        b'GIF87a': 'image_gif',
        b'GIF89a': 'image_gif',
        b'%PDF': 'pdf_file',
        b'{\n': 'data_json',
        b'{\r': 'data_json',
        b'[': 'data_json',
        b'<?xml': 'data_xml',
    }

    def __init__(self, file_path: Path):
        """
        Initialize the file type detector.

        Args:
            file_path: Path to the file to detect
        """
        self.file_path = file_path
        self.data: Optional[bytes] = None
        self.errors: List[str] = []
        self._log_messages: List[str] = []

    def detect(self) -> Dict[str, Any]:
        """
        Detect file type using multiple methods.

        Returns:
            Dict with keys:
                - type: File type string
                - confidence: 'high', 'medium', 'low'
                - is_dotnet: bool (for PE files)
                - pe_offset: int (for PE files)
                - matched_string: str (for signature matches)
                - error: str (if detection failed)
        """
        try:
            # Read up to 1MB for detection (NSIS signatures can be far in)
            with open(self.file_path, 'rb') as f:
                self.data = f.read(1048576)  # 1MB
        except Exception as e:
            self.errors.append(f"Error reading file: {e}")
            return {'type': 'unknown', 'confidence': 'low', 'error': str(e)}

        # If file is empty
        if not self.data or len(self.data) == 0:
            return {'type': 'unknown', 'confidence': 'low', 'reason': 'empty_file'}

        # =================================================================
        # METHOD 1: Installer detection (MUST run first)
        # =================================================================

        # NSIS installer
        nsis_result = self._detect_nsis()
        if nsis_result:
            return nsis_result

        # Inno Setup installer
        inno_result = self._detect_inno()
        if inno_result:
            return inno_result

        # MSI installer
        msi_result = self._detect_msi()
        if msi_result:
            return msi_result

        # =================================================================
        # METHOD 2: Script detection
        # =================================================================
        script_result = self._detect_script()
        if script_result:
            return script_result

        # =================================================================
        # METHOD 3: PE/ELF detection
        # =================================================================
        pe_result = self._detect_pe()
        if pe_result:
            return pe_result

        elf_result = self._detect_elf()
        if elf_result:
            return elf_result

        # =================================================================
        # METHOD 4: Magic bytes (for archives, images, etc.)
        # =================================================================
        magic_result = self._detect_by_magic()
        if magic_result:
            return magic_result

        # =================================================================
        # METHOD 5: Extension-based detection
        # =================================================================
        ext_result = self._detect_by_extension()
        if ext_result:
            return ext_result

        # =================================================================
        # METHOD 6: Heuristics (plaintext, etc.)
        # =================================================================
        heuristic_result = self._detect_by_heuristics()
        if heuristic_result:
            return heuristic_result

        return {'type': 'unknown', 'confidence': 'low'}

    # ---------------------------------------------------------------------
    # Installer Detection
    # ---------------------------------------------------------------------

    def _detect_nsis(self) -> Optional[Dict[str, Any]]:
        """Detect NSIS installer."""
        if not self.data:
            return None

        # Convert to string for searching
        try:
            data_str = self.data.decode('utf-8', errors='ignore')
        except:
            return None

        for sig in self.NSIS_SIGNATURES:
            if sig in data_str:
                self._log(f"Found NSIS signature: {sig}")
                return {
                    'type': 'installer_nsis',
                    'confidence': 'high',
                    'matched_string': sig
                }

        # Check for NSIS manifest pattern
        if '<assembly' in data_str and 'Nullsoft.NSIS' in data_str:
            self._log("Found NSIS manifest")
            return {
                'type': 'installer_nsis',
                'confidence': 'high',
                'matched_string': 'NSIS manifest'
            }

        return None

    def _detect_inno(self) -> Optional[Dict[str, Any]]:
        """Detect Inno Setup installer."""
        if not self.data:
            return None

        try:
            data_str = self.data.decode('utf-8', errors='ignore')
        except:
            return None

        for sig in self.INNO_SIGNATURES:
            if sig in data_str:
                self._log(f"Found Inno Setup signature: {sig}")
                return {
                    'type': 'installer_inno',
                    'confidence': 'high',
                    'matched_string': sig
                }

        return None

    def _detect_msi(self) -> Optional[Dict[str, Any]]:
        """Detect MSI installer."""
        # Check extension first
        if self.file_path.suffix.lower() == '.msi':
            return {
                'type': 'installer_msi',
                'confidence': 'high',
                'matched_string': '.msi extension'
            }

        # Check for MSI magic: D0 CF 11 E0 A1 B1 1A E1 (COM/OLE)
        if self.data and len(self.data) >= 8:
            if self.data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                # Check for MSI-specific strings
                try:
                    data_str = self.data.decode('utf-16-le', errors='ignore')
                    if 'MSI' in data_str:
                        return {
                            'type': 'installer_msi',
                            'confidence': 'medium',
                            'matched_string': 'MSI OLE header'
                        }
                except:
                    pass

        return None

    # ---------------------------------------------------------------------
    # Script Detection
    # ---------------------------------------------------------------------

    def _detect_script(self) -> Optional[Dict[str, Any]]:
        """Detect script files (PowerShell, Batch, VBS, JS, Python, PHP)."""
        if not self.data or len(self.data) < 10:
            return None

        try:
            text = self.data[:8192].decode('utf-8', errors='ignore')
        except:
            return None

        # PowerShell
        if text.lstrip().startswith('#!') and 'powershell' in text.lower():
            return {'type': 'script_powershell', 'confidence': 'high'}

        ps_count = sum(1 for ind in self.POWERSHELL_INDICATORS if ind in text)
        if ps_count >= 3:
            return {'type': 'script_powershell', 'confidence': 'high'}

        # Batch
        if text.lstrip().startswith('@echo off') or text.lstrip().startswith('::'):
            return {'type': 'script_batch', 'confidence': 'high'}

        batch_count = sum(1 for ind in self.BATCH_INDICATORS if ind in text.lower())
        if batch_count >= 4:
            return {'type': 'script_batch', 'confidence': 'medium'}

        # VBScript
        vbs_count = sum(1 for ind in self.VBS_INDICATORS if ind in text)
        if vbs_count >= 2:
            return {'type': 'script_vbs', 'confidence': 'high'}

        # JavaScript
        js_count = sum(1 for ind in self.JS_INDICATORS if ind in text)
        if js_count >= 2:
            return {'type': 'script_js', 'confidence': 'medium'}

        # Python
        if text.lstrip().startswith('#!') and 'python' in text.lower():
            return {'type': 'script_python', 'confidence': 'high'}

        py_count = sum(1 for ind in self.PYTHON_INDICATORS if ind in text)
        if py_count >= 3:
            return {'type': 'script_python', 'confidence': 'medium'}

        # PHP
        if text.lstrip().startswith('<?php') or '<?=' in text:
            return {'type': 'script_php', 'confidence': 'high'}

        php_count = sum(1 for ind in self.PHP_INDICATORS if ind in text)
        if php_count >= 3:
            return {'type': 'script_php', 'confidence': 'medium'}

        return None

    # ---------------------------------------------------------------------
    # PE/ELF Detection
    # ---------------------------------------------------------------------

    def _detect_pe(self) -> Optional[Dict[str, Any]]:
        """
        Detect PE file and determine if it's .NET.

        Returns:
            Dict with 'type': 'pe_native', 'pe_dotnet', or 'pe_file'
        """
        if not self.data or len(self.data) < 2 or self.data[:2] != b'MZ':
            return None

        try:
            # Read PE offset from DOS header
            pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
            if pe_offset + 4 > len(self.data):
                return {'type': 'pe_file', 'confidence': 'medium'}

            # Check PE magic
            pe_magic = self.data[pe_offset:pe_offset+4]
            if pe_magic != b'PE\x00\x00':
                return None

            # Check if .NET
            is_dotnet = self._is_dotnet_pe()

            if is_dotnet:
                self._log("Detected .NET assembly")
                return {
                    'type': 'pe_dotnet',
                    'confidence': 'high',
                    'is_dotnet': True,
                    'pe_offset': pe_offset
                }
            else:
                self._log("Detected native PE")
                return {
                    'type': 'pe_native',
                    'confidence': 'high',
                    'is_dotnet': False,
                    'pe_offset': pe_offset
                }

        except Exception as e:
            self._log(f"PE detection error: {e}")
            return {'type': 'pe_file', 'confidence': 'medium'}

    def _is_dotnet_pe(self) -> bool:
        """Check if PE is a .NET assembly."""
        if not self.data:
            return False

        try:
            # Method 1: Check COR20 header
            pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
            if pe_offset + 0x60 > len(self.data):
                return False

            # Data directories start at PE offset + 0x60 (for PE32)
            # COR20 is at index 14 (0x0E)
            dir_offset = pe_offset + 0x60 + (14 * 8)
            if dir_offset + 8 > len(self.data):
                return False

            rva, size = struct.unpack('<II', self.data[dir_offset:dir_offset+8])
            if rva != 0 and size != 0:
                return True

            # Method 2: Check for mscoree.dll import
            try:
                text = self.data.decode('utf-8', errors='ignore')
                if 'mscoree.dll' in text.lower():
                    return True
            except:
                pass

            # Method 3: Check for .NET strings
            try:
                text = self.data.decode('utf-8', errors='ignore')
                if any(s in text for s in ['.NET', 'System.', 'mscorlib', 'System.Collections']):
                    return True
            except:
                pass

            # Method 4: Check for .NET assembly attributes
            # These are often in the .text section
            try:
                text = self.data.decode('utf-8', errors='ignore')
                if any(s in text for s in ['AssemblyTitle', 'AssemblyDescription', 'AssemblyCompany']):
                    return True
            except:
                pass

            return False

        except Exception:
            return False

    def _detect_elf(self) -> Optional[Dict[str, Any]]:
        """Detect ELF file."""
        if not self.data or len(self.data) < 4:
            return None

        if self.data[:4] == b'\x7fELF':
            return {
                'type': 'elf_file',
                'confidence': 'high'
            }

        return None

    # ---------------------------------------------------------------------
    # Magic Byte Detection
    # ---------------------------------------------------------------------

    def _detect_by_magic(self) -> Optional[Dict[str, Any]]:
        """Detect file type by magic bytes."""
        if not self.data or len(self.data) < 4:
            return None

        for magic, file_type in self.FILE_SIGNATURES.items():
            if self.data.startswith(magic):
                self._log(f"Magic byte match: {magic.hex()} -> {file_type}")
                return {
                    'type': file_type,
                    'confidence': 'high',
                    'matched_magic': magic.hex()
                }

        # Check for zlib (multiple possible headers)
        if len(self.data) >= 2 and self.data[:2] in [b'\x78\x9C', b'\x78\xDA', b'\x78\x01']:
            return {
                'type': 'zlib_data',
                'confidence': 'high',
                'matched_magic': self.data[:2].hex()
            }

        return None

    # ---------------------------------------------------------------------
    # Extension-Based Detection
    # ---------------------------------------------------------------------

    def _detect_by_extension(self) -> Optional[Dict[str, Any]]:
        """Detect by file extension."""
        ext = self.file_path.suffix.lower()

        # Script extensions
        if ext in ['.ps1', '.psm1', '.psd1']:
            return {'type': 'script_powershell', 'confidence': 'high'}
        if ext in ['.bat', '.cmd']:
            return {'type': 'script_batch', 'confidence': 'high'}
        if ext in ['.vbs', '.vbe']:
            return {'type': 'script_vbs', 'confidence': 'high'}
        if ext in ['.js', '.jse']:
            return {'type': 'script_js', 'confidence': 'high'}
        if ext in ['.py', '.pyw']:
            return {'type': 'script_python', 'confidence': 'high'}
        if ext in ['.php', '.php3', '.php4', '.php5']:
            return {'type': 'script_php', 'confidence': 'high'}

        # Archive extensions
        if ext in ['.zip', '.jar', '.war', '.ear']:
            return {'type': 'archive_zip', 'confidence': 'high'}
        if ext in ['.gz', '.gzip']:
            return {'type': 'archive_gzip', 'confidence': 'high'}
        if ext in ['.7z']:
            return {'type': 'archive_7z', 'confidence': 'high'}
        if ext in ['.rar']:
            return {'type': 'archive_rar', 'confidence': 'high'}

        # PE extensions (but already handled by PE detection)
        if ext in ['.exe', '.dll', '.sys', '.ocx', '.cpl']:
            # Check if we have data and it looks like PE
            if self.data and self.data[:2] == b'MZ':
                return {'type': 'pe_file', 'confidence': 'medium'}

        return None

    # ---------------------------------------------------------------------
    # Heuristic Detection
    # ---------------------------------------------------------------------

    def _detect_by_heuristics(self) -> Optional[Dict[str, Any]]:
        """Detect file type using heuristics."""
        if not self.data or len(self.data) < 32:
            return None

        # Check if it's plaintext
        printable = sum(1 for b in self.data[:512] if 32 <= b <= 126 or b in [9, 10, 13])
        printable_ratio = printable / min(len(self.data), 512)

        if printable_ratio > 0.8:
            # Try to determine if it's JSON or XML
            try:
                text = self.data[:512].decode('utf-8', errors='ignore')
                if text.lstrip().startswith('{') or text.lstrip().startswith('['):
                    return {'type': 'data_json', 'confidence': 'medium'}
                if text.lstrip().startswith('<?xml') or text.lstrip().startswith('<'):
                    if '>' in text and '<' in text:
                        return {'type': 'data_xml', 'confidence': 'medium'}
            except:
                pass

            return {'type': 'plaintext', 'confidence': 'medium'}

        return None

    # ---------------------------------------------------------------------
    # Utility Methods
    # ---------------------------------------------------------------------

    def _log(self, message: str):
        """Log a message."""
        self._log_messages.append(message)

    def get_errors(self) -> List[str]:
        """Get detection errors."""
        return self.errors

    def get_logs(self) -> List[str]:
        """Get detection logs."""
        return self._log_messages

    @classmethod
    def get_file_category(cls, file_type: str) -> FileCategory:
        """
        Get the file category for a file type.

        Args:
            file_type: String file type from detection

        Returns:
            FileCategory enum value
        """
        mapping = {
            'pe_native': FileCategory.PE_NATIVE,
            'pe_dotnet': FileCategory.PE_DOTNET,
            'pe_file': FileCategory.PE_FILE,
            'elf_file': FileCategory.ELF_FILE,
            'installer_nsis': FileCategory.INSTALLER_NSIS,
            'installer_inno': FileCategory.INSTALLER_INNO,
            'installer_msi': FileCategory.INSTALLER_MSI,
            'script_powershell': FileCategory.SCRIPT_POWERSHELL,
            'script_batch': FileCategory.SCRIPT_BATCH,
            'script_vbs': FileCategory.SCRIPT_VBS,
            'script_js': FileCategory.SCRIPT_JS,
            'script_python': FileCategory.SCRIPT_PYTHON,
            'script_php': FileCategory.SCRIPT_PHP,
            'archive_zip': FileCategory.ARCHIVE_ZIP,
            'archive_gzip': FileCategory.ARCHIVE_GZIP,
            'archive_7z': FileCategory.ARCHIVE_7Z,
            'archive_rar': FileCategory.ARCHIVE_RAR,
            'zlib_data': FileCategory.DATA_ZLIB,
            'json_data': FileCategory.DATA_JSON,
            'xml_data': FileCategory.DATA_XML,
            'plaintext': FileCategory.DATA_PLAINTEXT,
            'jpeg_image': FileCategory.IMAGE_JPEG,
            'png_image': FileCategory.IMAGE_PNG,
            'gif_image': FileCategory.IMAGE_GIF,
            'pdf_file': FileCategory.PDF_FILE,
        }
        return mapping.get(file_type, FileCategory.UNKNOWN)

    @classmethod
    def needs_specialized_engine(cls, file_type: str) -> bool:
        """
        Check if a file type needs a specialized engine.

        Args:
            file_type: String file type from detection

        Returns:
            True if the file should use a specialized engine
        """
        specialized_types = [
            'pe_native',
            'pe_file',
            'pe_dotnet',
            'elf_file'
        ]
        return file_type in specialized_types
