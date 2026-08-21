"""ELF file parsing module."""

import struct
from pathlib import Path
from typing import Optional, List, Dict, Any

from ..models.report import SectionInfo, ImportInfo, ExportInfo


class ELFParser:
    """Parser for ELF (Executable and Linkable Format) files."""

    ELF_MAGIC = b'\x7fELF'

    EI_CLASS = {
        1: 'ELF32',
        2: 'ELF64'
    }

    EI_DATA = {
        1: 'Little-endian',
        2: 'Big-endian'
    }

    ETYPES = {
        0: 'ET_NONE',
        1: 'ET_REL',
        2: 'ET_EXEC',
        3: 'ET_DYN',
        4: 'ET_CORE'
    }

    EMACHINES = {
        0x03: 'Intel 386',
        0x3E: 'AMD x86-64',
        0x28: 'ARM',
        0xB7: 'ARM64'
    }

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = None
        self.errors: List[str] = []
        self.elf_data = {}

    def parse(self) -> Dict[str, Any]:
        """Parse ELF file and extract metadata.

        Returns:
            Dict of ELF header fields (and 'sections' if present), or {'error': ...} on failure.
        """
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()
        except Exception as e:
            self.errors.append(f"Error reading ELF file: {e}")
            return {'error': str(e)}

        if not self.data.startswith(self.ELF_MAGIC):
            self.errors.append("Not an ELF file")
            return {'error': 'Not an ELF file'}

        self.elf_data = self._parse_elf_header()

        if self.elf_data.get('e_shnum', 0) > 0:
            sections = self._parse_sections()
            self.elf_data['sections'] = sections

        return self.elf_data

    def _parse_elf_header(self) -> Dict[str, Any]:
        """Parse the ELF header.

        Returns:
            Dict of header fields (class, endianness, type, machine,
            entry point, program/section header offsets and counts).
        """
        header = {}

        try:
            ei_class = self.data[4]
            if ei_class not in self.EI_CLASS:
                self.errors.append(f"Unknown ELF class: {ei_class}")
                return header

            is_64bit = ei_class == 2
            header['class'] = self.EI_CLASS.get(ei_class, 'Unknown')
            header['is_64bit'] = is_64bit

            ei_data = self.data[5]
            header['endianness'] = self.EI_DATA.get(ei_data, 'Unknown')
            header['is_little_endian'] = ei_data == 1

            e_type_offset = 16 if is_64bit else 16
            e_type = struct.unpack('<H' if header['is_little_endian'] else '>H',
                                  self.data[e_type_offset:e_type_offset+2])[0]
            header['type'] = self.ETYPES.get(e_type, f'Unknown (0x{e_type:x})')

            e_machine_offset = 18 if is_64bit else 18
            e_machine = struct.unpack('<H' if header['is_little_endian'] else '>H',
                                     self.data[e_machine_offset:e_machine_offset+2])[0]
            header['machine'] = self.EMACHINES.get(e_machine, f'Unknown (0x{e_machine:x})')

            e_entry_offset = 24 if is_64bit else 24
            e_entry = struct.unpack('<Q' if header['is_little_endian'] and is_64bit else
                                   '>Q' if not header['is_little_endian'] and is_64bit else
                                   '<I' if header['is_little_endian'] else '>I',
                                   self.data[e_entry_offset:e_entry_offset +
                                           (8 if is_64bit else 4)])[0]
            header['entry_point'] = hex(e_entry)

            e_phoff_offset = 32 if is_64bit else 28
            e_phoff = struct.unpack('<Q' if header['is_little_endian'] and is_64bit else
                                   '>Q' if not header['is_little_endian'] and is_64bit else
                                   '<I' if header['is_little_endian'] else '>I',
                                   self.data[e_phoff_offset:e_phoff_offset +
                                           (8 if is_64bit else 4)])[0]
            header['program_header_offset'] = hex(e_phoff)

            e_shoff_offset = 40 if is_64bit else 32
            e_shoff = struct.unpack('<Q' if header['is_little_endian'] and is_64bit else
                                   '>Q' if not header['is_little_endian'] and is_64bit else
                                   '<I' if header['is_little_endian'] else '>I',
                                   self.data[e_shoff_offset:e_shoff_offset +
                                           (8 if is_64bit else 4)])[0]
            header['section_header_offset'] = hex(e_shoff)

            e_shnum_offset = 60 if is_64bit else 48
            e_shnum = struct.unpack('<H' if header['is_little_endian'] else '>H',
                                   self.data[e_shnum_offset:e_shnum_offset+2])[0]
            header['section_count'] = e_shnum

            e_shentsize_offset = 58 if is_64bit else 46
            e_shentsize = struct.unpack('<H' if header['is_little_endian'] else '>H',
                                       self.data[e_shentsize_offset:e_shentsize_offset+2])[0]
            header['section_header_entry_size'] = e_shentsize

            if e_shoff > 0 and e_shnum > 0:
                header['has_section_headers'] = True
            else:
                header['has_section_headers'] = False

        except Exception as e:
            self.errors.append(f"Error parsing ELF header: {e}")

        return header

    def _parse_sections(self) -> List[Dict[str, Any]]:
        """Parse ELF sections using the header offsets already parsed into self.elf_data.

        Returns:
            One dict per parsed section header.
        """
        sections = []

        if not self.elf_data.get('has_section_headers', False):
            return sections

        try:
            is_64bit = self.elf_data['is_64bit']
            is_little_endian = self.elf_data['is_little_endian']
            e_shoff = int(self.elf_data['section_header_offset'], 16)
            e_shnum = self.elf_data['section_count']
            e_shentsize = self.elf_data['section_header_entry_size']

            sh_size = 64 if is_64bit else 40

            for i in range(e_shnum):
                offset = e_shoff + (i * sh_size)
                if offset + sh_size > len(self.data):
                    break

                section = self._parse_section_header(offset, is_64bit, is_little_endian)
                if section:
                    sections.append(section)

        except Exception as e:
            self.errors.append(f"Error parsing sections: {e}")

        return sections

    def _parse_section_header(self, offset: int, is_64bit: bool, is_little_endian: bool) -> Optional[Dict[str, Any]]:
        """Parse a single section header.

        Args:
            offset: Byte offset of the section header in the file.
            is_64bit: Whether the ELF is 64-bit (changes field widths).
            is_little_endian: Byte order to unpack fields with.

        Returns:
            Dict with name, type, address, size, and flags, or None on parse error.
        """
        try:
            sh_name = struct.unpack('<I' if is_little_endian else '>I',
                                   self.data[offset:offset+4])[0]

            sh_type = struct.unpack('<I' if is_little_endian else '>I',
                                   self.data[offset+4:offset+8])[0]

            sh_flags = struct.unpack('<Q' if is_64bit else '<I' if is_little_endian else '>I',
                                    self.data[offset+8:offset+8 + (8 if is_64bit else 4)])[0]

            sh_addr = struct.unpack('<Q' if is_64bit else '<I' if is_little_endian else '>I',
                                   self.data[offset + (16 if is_64bit else 12):
                                           offset + (16 if is_64bit else 12) + (8 if is_64bit else 4)])[0]

            sh_size = struct.unpack('<Q' if is_64bit else '<I' if is_little_endian else '>I',
                                   self.data[offset + (32 if is_64bit else 20):
                                           offset + (32 if is_64bit else 20) + (8 if is_64bit else 4)])[0]

            # Section name from the section header string table
            # This is simplified - in a real implementation we'd need to parse the string table
            section_name = f".section_{sh_type}"

            type_names = {
                0: 'NULL',
                1: 'PROGBITS',
                2: 'SYMTAB',
                3: 'STRTAB',
                4: 'RELA',
                5: 'HASH',
                6: 'DYNAMIC',
                7: 'NOTE',
                8: 'NOBITS',
                9: 'REL',
                10: 'SHLIB',
                11: 'DYNSYM',
                12: 'INIT_ARRAY',
                13: 'FINI_ARRAY',
                14: 'PREINIT_ARRAY',
                15: 'GROUP',
                16: 'SYMTAB_SHNDX'
            }
            type_name = type_names.get(sh_type, f'Unknown (0x{sh_type:x})')

            return {
                'name': section_name,
                'type': type_name,
                'type_value': sh_type,
                'address': hex(sh_addr),
                'size': sh_size,
                'flags': hex(sh_flags)
            }

        except Exception as e:
            self.errors.append(f"Error parsing section header at offset {offset}: {e}")
            return None

    def get_errors(self) -> List[str]:
        """Get parsing errors."""
        return self.errors
