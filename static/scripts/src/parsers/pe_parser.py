"""PE file parsing module."""

import hashlib
import pefile
from typing import Optional, List, Dict, Any
from pathlib import Path

from ..models.report import SectionInfo, ImportInfo, ExportInfo
from .config_parser import ConfigExtractor
from .dotnet_parser import DotNetParser


class PEParser:
    """Parser for PE (Portable Executable) files."""

    MACHINE_TYPES = {
        0x14c: 'Intel 386',
        0x8664: 'AMD64',
        0xaa64: 'ARM64',
        0x1c0: 'ARM Little-Endian',
        0x200: 'Intel IA64',
        0x162: 'MIPS R3000',
        0x166: 'MIPS R4000',
        0x184: 'DEC Alpha AXP',
        0x1a2: 'Hitachi SH3',
        0x1a4: 'Hitachi SH4',
    }

    SUBSYSTEM_TYPES = {
        0: 'Unknown',
        1: 'Native',
        2: 'Windows GUI',
        3: 'Windows CUI',
        5: 'OS/2 CUI',
        7: 'POSIX CUI',
        8: 'Native Windows',
        9: 'Windows CE GUI',
        10: 'EFI Application',
        11: 'EFI Boot Service Driver',
        12: 'EFI Runtime Driver',
        13: 'EFI ROM',
        14: 'XBOX',
        16: 'Windows Boot Application'
    }

    def __init__(self, file_path: Path, verbose: bool = False):
        """Initialize the PE parser.

        Args:
            file_path: Path to the PE file to parse.
            verbose: Enable verbose progress logging.
        """
        self.file_path = file_path
        self.verbose = verbose
        self.pe: Optional[pefile.PE] = None
        self.errors: List[str] = []

    def parse(self) -> Dict[str, Any]:
        """Parse PE file and extract metadata.

        Returns:
            Dict with metadata, sections, imports, exports, resources,
            is_dotnet, and (if .NET) net_imports/net_strings/net_types/
            net_methods/net_bcl_calls. {'error': ...} if pefile couldn't open it.
        """
        try:
            self.pe = pefile.PE(str(self.file_path))
        except pefile.PEFormatError as e:
            self.errors.append(f"Invalid PE file: {e}")
            return {'error': str(e)}
        except Exception as e:
            self.errors.append(f"Error parsing PE: {e}")
            return {'error': str(e)}

        is_dotnet = self._is_dotnet()
        net_imports = []
        net_strings = []
        net_types = []
        net_methods = []
        net_bcl_calls = []

        if is_dotnet:
            self._log("Detected .NET assembly, extracting P/Invoke imports...")
            dotnet_parser = DotNetParser(self.file_path, verbose=self.verbose)
            net_data = dotnet_parser.parse()
            net_imports = net_data.get('imports', [])
            net_strings = net_data.get('strings', [])
            net_types = net_data.get('types', [])
            net_methods = net_data.get('methods', [])
            net_bcl_calls = net_data.get('bcl_calls', [])
            self.errors.extend(dotnet_parser.get_errors())
            self._log(f"Extracted {len(net_imports)} P/Invoke imports, "
                     f"{len(net_strings)} strings, "
                     f"{len(net_types)} types, "
                     f"{len(net_bcl_calls)} BCL API calls")

        return {
            'metadata': self._get_metadata(),
            'sections': self._get_sections(),
            'imports': self._get_imports(),
            'exports': self._get_exports(),
            'resources': self._get_resources(),
            'is_dotnet': is_dotnet,
            'net_imports': net_imports,      # P/Invoke imports
            'net_strings': net_strings,      # .NET user strings
            'net_types': net_types,          # .NET type names
            'net_methods': net_methods,      # .NET method names
            'net_bcl_calls': net_bcl_calls,  # fully-qualified BCL API calls
        }

    def _is_dotnet(self) -> bool:
        """Check if the PE is a .NET assembly, via the COR20 header or an mscoree.dll entry point import.

        Returns:
            True if the PE is a .NET assembly.
        """
        if not self.pe:
            return False

        try:
            if hasattr(self.pe, 'OPTIONAL_HEADER') and hasattr(self.pe.OPTIONAL_HEADER, 'DataDirectory'):
                if len(self.pe.OPTIONAL_HEADER.DataDirectory) > 14:
                    entry = self.pe.OPTIONAL_HEADER.DataDirectory[14]
                    if entry.VirtualAddress != 0 and entry.Size != 0:
                        return True
        except Exception:
            pass

        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    if dll_name == 'mscoree.dll':
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode('utf-8', errors='ignore')
                                if func_name in ('_CorExeMain', '_CorDllMain'):
                                    return True
        except Exception:
            pass

        return False

    def _is_nsis_installer(self) -> bool:
        """Check if the file is an NSIS installer.

        Returns:
            True if an NSIS signature is found in the raw bytes or extracted strings.
        """
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read(65536)
                if b'Nullsoft.NSIS.exehead' in data or b'NullsoftInst' in data:
                    return True

            try:
                from ..parsers.strings_parser import StringsParser
                strings_parser = StringsParser(self.file_path)
                strings = strings_parser._extract_standard_strings()
                for s in strings:
                    if 'Nullsoft.NSIS.exehead' in s or 'NullsoftInst' in s:
                        return True
            except Exception:
                pass

            return False
        except Exception:
            return False

    def _get_metadata(self) -> Dict[str, Any]:
        """Extract PE header metadata.

        Returns:
            Dict of FILE_HEADER/OPTIONAL_HEADER fields, or {} if no PE is loaded.
        """
        if not self.pe:
            return {}

        return {
            'machine': {
                'value': hex(self.pe.FILE_HEADER.Machine),
                'description': self.MACHINE_TYPES.get(
                    self.pe.FILE_HEADER.Machine,
                    f'Unknown (0x{self.pe.FILE_HEADER.Machine:x})'
                )
            },
            'number_of_sections': self.pe.FILE_HEADER.NumberOfSections,
            'time_date_stamp': {
                'raw': self.pe.FILE_HEADER.TimeDateStamp,
                'formatted': self._format_timestamp(self.pe.FILE_HEADER.TimeDateStamp)
            },
            'characteristics': hex(self.pe.FILE_HEADER.Characteristics),
            'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
            'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'size_of_code': self.pe.OPTIONAL_HEADER.SizeOfCode,
            'size_of_initialized_data': self.pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'size_of_uninitialized_data': self.pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'subsystem': {
                'value': self.pe.OPTIONAL_HEADER.Subsystem,
                'description': self.SUBSYSTEM_TYPES.get(
                    self.pe.OPTIONAL_HEADER.Subsystem,
                    f'Unknown (0x{self.pe.OPTIONAL_HEADER.Subsystem:x})'
                )
            },
            'dll_characteristics': hex(self.pe.OPTIONAL_HEADER.DllCharacteristics),
            'image_size': self.pe.OPTIONAL_HEADER.SizeOfImage,
            'headers_size': self.pe.OPTIONAL_HEADER.SizeOfHeaders,
            'checksum': self.pe.OPTIONAL_HEADER.CheckSum,
            'is_dll': self.pe.is_dll(),
            'is_driver': self.pe.is_driver()
        }

    def _get_sections(self) -> List[SectionInfo]:
        """Extract section information.

        Returns:
            One SectionInfo per PE section.
        """
        if not self.pe:
            return []

        sections = []
        for section in self.pe.sections:
            try:
                data = section.get_data()
                sections.append(SectionInfo(
                    name=section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    virtual_address=hex(section.VirtualAddress),
                    virtual_size=section.Misc_VirtualSize,
                    raw_size=section.SizeOfRawData,
                    entropy=round(section.get_entropy(), 2),
                    characteristics=hex(section.Characteristics),
                    is_executable=bool(section.Characteristics & 0x20000000),
                    is_writable=bool(section.Characteristics & 0x80000000),
                    is_readable=bool(section.Characteristics & 0x40000000),
                    md5=hashlib.md5(data).hexdigest(),
                    sha1=hashlib.sha1(data).hexdigest()
                ))
            except Exception as e:
                self.errors.append(f"Error processing section: {e}")

        return sections

    def _get_imports(self) -> List[ImportInfo]:
        """Extract imported functions.

        Returns:
            One ImportInfo per named import.
        """
        imports = []
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports

        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        imports.append(ImportInfo(
                            dll=dll_name,
                            function=imp.name.decode('utf-8', errors='ignore'),
                            address=hex(imp.address),
                            hint=imp.hint
                        ))
        except Exception as e:
            self.errors.append(f"Error extracting imports: {e}")

        return imports

    def _get_exports(self) -> List[ExportInfo]:
        """Extract exported functions.

        Returns:
            One ExportInfo per named export.
        """
        exports = []
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports

        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(ExportInfo(
                        name=exp.name.decode('utf-8', errors='ignore'),
                        address=hex(exp.address),
                        ordinal=exp.ordinal
                    ))
        except Exception as e:
            self.errors.append(f"Error extracting exports: {e}")

        return exports

    def _get_resources(self) -> List[Dict[str, Any]]:
        """Extract resource information.

        Returns:
            One dict (type, id, name) per resource entry.
        """
        resources = []
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return resources

        try:
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    type_name = pefile.RESOURCE_TYPE.get(
                        resource_type.id,
                        f'Unknown_{resource_type.id}'
                    )
                    resources.append({
                        'type': type_name,
                        'id': resource_type.id,
                        'name': resource_type.name.decode('utf-8', errors='ignore')
                                if resource_type.name else None
                    })
                except Exception:
                    pass
        except Exception as e:
            self.errors.append(f"Error extracting resources: {e}")

        return resources

    def sections_to_dicts(self, sections: List[SectionInfo]) -> List[Dict[str, Any]]:
        """Convert SectionInfo objects to dictionaries for compatibility.

        Args:
            sections: SectionInfo objects to convert.

        Returns:
            One dict per input SectionInfo.
        """
        return [
            {
                'name': s.name,
                'virtual_address': s.virtual_address,
                'virtual_size': s.virtual_size,
                'raw_size': s.raw_size,
                'entropy': s.entropy,
                'characteristics': s.characteristics,
                'is_executable': s.is_executable,
                'is_writable': s.is_writable,
                'is_readable': s.is_readable,
                'md5': s.md5,
                'sha1': s.sha1,
                'ssdeep': getattr(s, 'ssdeep', None)
            }
            for s in sections
        ]

    @staticmethod
    def _format_timestamp(timestamp: int) -> Optional[str]:
        """Format Unix timestamp to ISO string.

        Args:
            timestamp: Unix timestamp (FILE_HEADER.TimeDateStamp).

        Returns:
            ISO 8601 string, or None if timestamp is falsy.
        """
        if timestamp:
            from datetime import datetime
            return datetime.fromtimestamp(timestamp).isoformat()
        return None

    def _log(self, message: str):
        """Log message if verbose."""
        if self.verbose:
            print(f"[*] PEParser: {message}")

    def get_errors(self) -> List[str]:
        """Get parsing errors."""
        return self.errors
