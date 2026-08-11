"""Data models for reconciled ATT&CK technique mappings."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MappedTechnique:
    technique_id: str
    technique_name: str
    final_confidence: str  # 'high' | 'medium' | 'low'
    confidence_score: int
    sources: List[str] = field(default_factory=list)
    static_best_confidence: Optional[str] = None
    dynamic_best_confidence: Optional[str] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "final_confidence": self.final_confidence,
            "confidence_score": self.confidence_score,
            "sources": self.sources,
            "static_best_confidence": self.static_best_confidence,
            "dynamic_best_confidence": self.dynamic_best_confidence,
            "evidence": self.evidence,
        }
