"""Data models for static analysis results"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


"""PE section information"""
@dataclass
class SectionInfo:
    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: str
    is_executable: bool
    is_writable: bool
    is_readable: bool
    md5: str
    sha1: str
    ssdeep: Optional[str] = None


"""Imported function information"""
@dataclass
class ImportInfo:
    dll: str
    function: str
    address: str
    hint: int


"""Exported function information"""
@dataclass
class ExportInfo:
    name: str
    address: str
    ordinal: int


"""String extraction results"""
@dataclass
class StringInfo:
    standard: List[str] = field(default_factory=list)
    floss: List[str] = field(default_factory=list)
    decoded: List[str] = field(default_factory=list)


"""Packer detection results"""
@dataclass
class PackerInfo:
    detected: bool = False
    packers: List[Dict[str, str]] = field(default_factory=list)
    confidence: str = "none"


"""Suspicious indicators"""
@dataclass
class IndicatorInfo:
    suspicious_imports: List[str] = field(default_factory=list)
    suspicious_strings: List[Dict[str, str]] = field(default_factory=list)
    high_entropy_sections: List[Dict[str, Any]] = field(default_factory=list)
    anti_debug: List[Dict[str, str]] = field(default_factory=list)
    anti_vm: List[Dict[str, str]] = field(default_factory=list)


"""Complete static analysis report"""
@dataclass
class StaticReport:
    # Sample info
    filename: str
    size_bytes: int
    size_mb: float
    extension: str

    # Hashes
    md5: str
    sha1: str
    sha256: str
    ssdeep: Optional[str] = None

    # PE Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Sections
    sections: List[SectionInfo] = field(default_factory=list)

    # Imports/Exports
    imports: List[ImportInfo] = field(default_factory=list)
    exports: List[ExportInfo] = field(default_factory=list)
    resources: List[Dict[str, Any]] = field(default_factory=list)

    # Strings
    strings: StringInfo = field(default_factory=StringInfo)

    # Packer
    packer: PackerInfo = field(default_factory=PackerInfo)

    # Indicators
    indicators: IndicatorInfo = field(default_factory=IndicatorInfo)

    # Metadata
    analysis_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    errors: List[str] = field(default_factory=list)

    """Convert to dictionary for JSON serialization"""
    def to_dict(self) -> Dict[str, Any]:
        import dataclasses
        result = {}
        for key, value in dataclasses.asdict(self).items():
            if value is not None:
                result[key] = value
        return result
