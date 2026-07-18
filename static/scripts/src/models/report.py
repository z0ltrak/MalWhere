"""Data models for static analysis results."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


@dataclass
class SectionInfo:
    """PE section information."""
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


@dataclass
class ImportInfo:
    """Imported function information."""
    dll: str
    function: str
    address: str
    hint: int


@dataclass
class ExportInfo:
    """Exported function information."""
    name: str
    address: str
    ordinal: int


@dataclass
class StringInfo:
    """String extraction results."""
    standard: List[str] = field(default_factory=list)
    floss: List[str] = field(default_factory=list)
    decoded: List[str] = field(default_factory=list)


@dataclass
class PackerInfo:
    """Packer detection results."""
    detected: bool = False
    packers: List[Dict[str, str]] = field(default_factory=list)
    confidence: str = "none"


@dataclass
class IndicatorInfo:
    """Suspicious indicators found during analysis."""
    suspicious_imports: List[str] = field(default_factory=list)
    suspicious_strings: List[Dict[str, str]] = field(default_factory=list)
    high_entropy_sections: List[Dict[str, Any]] = field(default_factory=list)
    anti_debug: List[Dict[str, str]] = field(default_factory=list)
    anti_vm: List[Dict[str, str]] = field(default_factory=list)
    ransomware_indicators: List[Dict[str, str]] = field(default_factory=list)
    anti_sandbox: List[Dict[str, str]] = field(default_factory=list)
    anti_vm_strings: List[Dict[str, str]] = field(default_factory=list)
    anti_sandbox_strings: List[Dict[str, str]] = field(default_factory=list)
    sleep_functions: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class YaraResult:
    """YARA scan results."""
    matches: List[Dict[str, Any]] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    packer_detected: bool = False
    packers: List[Dict[str, str]] = field(default_factory=list)
    attck_mapping: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class StaticReport:
    """Complete static analysis report."""
    filename: str
    size_bytes: int
    size_mb: float
    extension: str
    md5: str
    sha1: str
    sha256: str
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    imphash: Optional[str] = None
    is_dotnet: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[ImportInfo] = field(default_factory=list)
    exports: List[ExportInfo] = field(default_factory=list)
    resources: List[Dict[str, Any]] = field(default_factory=list)
    strings: StringInfo = field(default_factory=StringInfo)
    packer: PackerInfo = field(default_factory=PackerInfo)
    indicators: IndicatorInfo = field(default_factory=IndicatorInfo)
    yara: YaraResult = field(default_factory=YaraResult)
    config: Dict[str, Any] = field(default_factory=dict)  # <-- Added config field
    analysis_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the report to a dictionary for JSON serialization."""
        import dataclasses
        result = {}
        for key, value in dataclasses.asdict(self).items():
            if value is not None:
                result[key] = value
        return result
