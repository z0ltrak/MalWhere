"""PE file parsing module"""
import hashlib
import pefile
from typing import Optional, List, Dict, Any
from pathlib import Path

from ..models.report import SectionInfo, ImportInfo, ExportInfo

"""Parser for PE (Portable Executable) files"""
class PEParser:

    # Machine type mapping
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

    # Subsystem types
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

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.pe: Optional[pefile.PE] = None
        self.errors: List[str] = []


    """Parse PE file and extract metadata"""
    def parse(self) -> Dict[str, Any]:
        try:
            self.pe = pefile.PE(str(self.file_path))
        except pefile.PEFormatError as e:
            self.errors.append(f"Invalid PE file: {e}")
            return {'error': str(e)}
        except Exception as e:
            self.errors.append(f"Error parsing PE: {e}")
            return {'error': str(e)}

        return {
            'metadata': self._get_metadata(),
            'sections': self._get_sections(),
            'imports': self._get_imports(),
            'exports': self._get_exports(),
            'resources': self._get_resources()
        }


    """Extract PE header metadata"""
    def _get_metadata(self) -> Dict[str, Any]:
        pe = self.pe
        if not pe:
            return {}

        return {
            'machine': {
                'value': hex(pe.FILE_HEADER.Machine),
                'description': self.MACHINE_TYPES.get(
                    pe.FILE_HEADER.Machine,
                    f'Unknown (0x{pe.FILE_HEADER.Machine:x})'
                )
            },
            'number_of_sections': pe.FILE_HEADER.NumberOfSections,
            'time_date_stamp': {
                'raw': pe.FILE_HEADER.TimeDateStamp,
                'formatted': self._format_timestamp(pe.FILE_HEADER.TimeDateStamp)
            },
            'characteristics': hex(pe.FILE_HEADER.Characteristics),
            'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'size_of_code': pe.OPTIONAL_HEADER.SizeOfCode,
            'size_of_initialized_data': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'size_of_uninitialized_data': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'subsystem': {
                'value': pe.OPTIONAL_HEADER.Subsystem,
                'description': self.SUBSYSTEM_TYPES.get(
                    pe.OPTIONAL_HEADER.Subsystem,
                    f'Unknown (0x{pe.OPTIONAL_HEADER.Subsystem:x})'
                )
            },
            'dll_characteristics': hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            'image_size': pe.OPTIONAL_HEADER.SizeOfImage,
            'headers_size': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'checksum': pe.OPTIONAL_HEADER.CheckSum,
            'is_dll': pe.is_dll(),
            'is_driver': pe.is_driver()
        }


    """Extract section information"""
    def _get_sections(self) -> List[SectionInfo]:
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


    """Extract imported functions"""
    def _get_imports(self) -> List[ImportInfo]:
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


    """Extract exported functions"""
    def _get_exports(self) -> List[ExportInfo]:
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


    """Extract resource information"""
    def _get_resources(self) -> List[Dict[str, Any]]:
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
                except:
                    pass
        except Exception as e:
            self.errors.append(f"Error extracting resources: {e}")

        return resources


    """Format Unix timestamp to ISO string"""
    @staticmethod
    def _format_timestamp(timestamp: int) -> Optional[str]:
        if timestamp:
            from datetime import datetime
            return datetime.fromtimestamp(timestamp).isoformat()
        return None


    """Get parsing errors"""
    def get_errors(self) -> List[str]:
        return self.errors
