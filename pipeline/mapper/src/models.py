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
    # Set by reconcile.apply_cross_level_corroboration when this exact
    # technique_id was promoted using a sibling technique's evidence (its
    # base/parent or another sub-technique under the same base) rather
    # than evidence for this exact ID. Kept separate from sources/
    # static_best_confidence/dynamic_best_confidence, which stay
    # factually accurate to what was directly observed for this id --
    # this field is what makes the promotion auditable.
    cross_level_corroboration: bool = False
    cross_level_sibling: Optional[str] = None

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
            "cross_level_corroboration": self.cross_level_corroboration,
            "cross_level_sibling": self.cross_level_sibling,
        }
