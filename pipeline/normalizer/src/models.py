"""Data models for normalized IOC output."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class TaggedValue:
    """A deduplicated value with the set of sources that observed it."""

    value: str
    sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value, "sources": sorted(set(self.sources))}


@dataclass
class HashEntry:
    role: str  # 'primary_sample' | 'dropped_file' | 'cape_payload'
    source: str  # 'static' | 'dynamic'
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    filename: str = ""
    type: str = ""
    cape_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v}


@dataclass
class Observation:
    source: str  # 'static' | 'dynamic'
    source_type: str  # static's 'source' field, or 'dynamic_signature'
    evidence: str
    confidence: str  # 'high' | 'medium' | 'low'
    name: str = ""
    justification: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class TechniqueObservations:
    technique: str
    observations: List[Observation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "observations": [o.to_dict() for o in self.observations],
        }


@dataclass
class DiscardedEntry:
    reason: str
    origin: str  # 'static' | 'dynamic'
    field: str = ""
    raw_value: Any = None
    raw_entry: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, "")}
