"""Parser modules for static analysis."""

from .pe_parser import PEParser
from .elf_parser import ELFParser
from .zip_parser import ZIPParser
from .installer_parser import InstallerParser
from .nsis_parser import NSISParser
from .strings_parser import StringsParser
from .packer_parser import PackerDetector
from .config_parser import ConfigExtractor
from .yara_parser import YaraParser
from .magic_carver import MagicCarver
from .zlib_parser import ZlibParser
from .key_reconstructor import KeyReconstructor
from .decryption_engine import DecryptionEngine
from .filesystem_extractor import FilesystemExtractor

__all__ = [
    'PEParser',
    'ELFParser',
    'ZIPParser',
    'InstallerParser',
    'NSISParser',
    'StringsParser',
    'PackerDetector',
    'ConfigExtractor',
    'YaraParser',
    'MagicCarver',
    'ZlibParser',
    'KeyReconstructor',
    'DecryptionEngine',
    'FilesystemExtractor'
]
