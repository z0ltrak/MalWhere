"""Data models for dynamic (CAPE) analysis results.

ATTACKMapping mirrors static/scripts/src/models/report.py's dataclass of the
same name field-for-field (technique/name/source/evidence/confidence/
justification) so the normalizer can treat static and dynamic evidence
symmetrically. Deliberately not imported from static/ — static/scripts and
dynamic/scripts are independently mounted/built (see docker-compose.yml),
so this package carries its own copy rather than a cross-package import.
"""

from dataclasses import dataclass


@dataclass
class ATTACKMapping:
    technique: str
    name: str
    source: str  # always 'dynamic_signature' for this package
    evidence: str
    confidence: str  # 'high', 'medium', 'low'
    justification: str = ""
