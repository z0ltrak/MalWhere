"""STIX 2.1 exporter for threat intelligence."""

import json
from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path

try:
    import stix2
    from stix2 import (
        Indicator, ObservedData, Relationship, Bundle,
        Identity, ThreatActor, AttackPattern, Malware
    )
except ImportError:
    stix2 = None


class STIXExporter:
    """Export analysis results to STIX 2.1 format."""

    def __init__(self, report_data: Dict[str, Any], sample_hash: str):
        """Initialize the exporter.

        Args:
            report_data: Static analysis report dict to export.
            sample_hash: The sample's SHA-256 hash, used to name the STIX Indicator.
        """
        self.report = report_data
        self.sample_hash = sample_hash
        self.objects = []
        self.errors: List[str] = []

        if stix2 is None:
            self.errors.append("STIX2 library not installed. Run: pip install stix2")

    def export(self) -> Dict[str, Any]:
        """Export the report to a STIX 2.1 bundle.

        Returns:
            Dict with 'bundle' (serialized STIX), 'objects', and 'errors',
            or {'error': ...} if the stix2 library is unavailable or export failed.
        """
        if not stix2:
            return {'error': 'STIX2 library not available'}

        try:
            self._create_identity()
            self._create_indicator()
            self._create_observed_data()
            self._create_threat_actors()
            self._create_attack_patterns()
            self._create_relationships()

            bundle = Bundle(objects=self.objects)
            return {
                'bundle': bundle.serialize(),
                'objects': self.objects,
                'errors': self.errors
            }
        except Exception as e:
            self.errors.append(f"Export error: {e}")
            return {'error': str(e)}

    def _create_identity(self):
        """Create identity for the analysis."""
        identity = Identity(
            name="MalWhere Static Analysis Pipeline",
            description="Automated static analysis for malware samples",
            identity_class="organization",
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc)
        )
        self.objects.append(identity)
        self.identity_id = identity.id

    def _create_indicator(self):
        """Create indicator for the sample."""
        indicator = Indicator(
            name=f"Malware Sample - {self.sample_hash[:8]}",
            description="Suspicious PE file detected by static analysis",
            pattern=f"[file:hashes.'SHA-256' = '{self.sample_hash}']",
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc)
        )
        self.objects.append(indicator)
        self.indicator_id = indicator.id

    def _create_observed_data(self):
        """Create observed data from the analysis results."""
        observed_data = ObservedData(
            first_observed=datetime.now(timezone.utc),
            last_observed=datetime.now(timezone.utc),
            number_observed=1,
            objects={
                "0": {
                    "type": "file",
                    "name": self.report.get('filename', 'unknown.exe'),
                    "hashes": {
                        "MD5": self.report.get('md5', ''),
                        "SHA-1": self.report.get('sha1', ''),
                        "SHA-256": self.report.get('sha256', '')
                    },
                    "size": self.report.get('size_bytes', 0),
                    "pe_sections": len(self.report.get('sections', [])),
                    "imports": len(self.report.get('imports', []))
                }
            }
        )
        self.objects.append(observed_data)

    def _create_threat_actors(self):
        """Create threat actor indicators from strings."""
        suspicious_strings = self.report.get('indicators', {}).get('suspicious_strings', [])
        if suspicious_strings:
            threat_actor = ThreatActor(
                name="Unknown Malware Actor",
                description=f"Sample with {len(suspicious_strings)} suspicious indicators",
                threat_actor_types=["malicious-actor"],
                created=datetime.now(timezone.utc)
            )
            self.objects.append(threat_actor)
            self.threat_actor_id = threat_actor.id

    def _create_attack_patterns(self):
        """Create attack patterns from detected techniques."""
        techniques = []

        # Extract techniques from suspicious imports
        for imp in self.report.get('indicators', {}).get('suspicious_imports', []):
            if 'T1055' in imp:
                techniques.append(('T1055', 'Process Injection'))
            elif 'T1486' in imp:
                techniques.append(('T1486', 'Data Encrypted for Impact'))
            elif 'T1622' in imp:
                techniques.append(('T1622', 'Debugger Evasion'))
            elif 'T1497' in imp:
                techniques.append(('T1497', 'Virtualization/Sandbox Evasion'))
            elif 'T1569' in imp:
                techniques.append(('T1569', 'System Services'))

        for technique_id, technique_name in techniques[:10]:
            attack_pattern = AttackPattern(
                name=technique_name,
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": technique_id
                }],
                created=datetime.now(timezone.utc)
            )
            self.objects.append(attack_pattern)

    def _create_relationships(self):
        """Create relationships between objects."""
        if hasattr(self, 'identity_id') and hasattr(self, 'indicator_id'):
            rel = Relationship(
                relationship_type="created",
                source_ref=self.identity_id,
                target_ref=self.indicator_id,
                created=datetime.now(timezone.utc)
            )
            self.objects.append(rel)

    def save_to_file(self, output_path: Path) -> bool:
        """Save the STIX bundle to a file.

        Args:
            output_path: Destination path for the serialized bundle.

        Returns:
            True if the bundle was exported and written successfully.
        """
        try:
            result = self.export()
            if 'bundle' in result:
                with open(output_path, 'w') as f:
                    f.write(result['bundle'])
                return True
            else:
                self.errors.append("No bundle to save")
                return False
        except Exception as e:
            self.errors.append(f"Error saving: {e}")
            return False


def export_report_to_stix(report_file: Path, output_file: Path) -> None:
    """Convenience function to export a static analysis report JSON file to STIX.

    Args:
        report_file: Path to the static analysis report JSON.
        output_file: Destination path for the serialized STIX bundle.
    """
    with open(report_file, 'r') as f:
        report_data = json.load(f)

    sample_hash = report_data.get('sha256', 'unknown')
    exporter = STIXExporter(report_data, sample_hash)
    result = exporter.export()

    if 'bundle' in result:
        with open(output_file, 'w') as f:
            f.write(result['bundle'])
        print(f"STIX export saved to: {output_file}")
    else:
        print(f"STIX export failed: {result.get('error', 'Unknown error')}")
