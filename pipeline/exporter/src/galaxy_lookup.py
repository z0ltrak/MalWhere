"""Looks up MISP's ATT&CK galaxy cluster tag for a given technique ID.

Confirmed live against a real MISP instance: the "Attack Pattern" galaxy
(id 47, type mitre-attack-pattern) holds ~1266 clusters; each cluster's
MITRE technique ID lives in its GalaxyElement list as
{"key": "external_id", "value": "T1055"}, not a top-level field. The
cluster's own tag_name (e.g. misp-galaxy:mitre-attack-pattern="Process
Injection - T1055") is the string to attach via add_tag/add_attribute_tag
— that's what makes MISP render a real galaxy badge instead of a plain tag.
"""

from typing import Dict, Optional

ATTACK_PATTERN_GALAXY_TYPE = "mitre-attack-pattern"


class AttckGalaxyLookup:
    def __init__(self, misp_client):
        """Initialize the lookup.

        Args:
            misp_client: A connected pymisp.PyMISP client.
        """
        self._misp = misp_client
        self._technique_to_tag: Optional[Dict[str, str]] = None

    def _load(self) -> Dict[str, str]:
        """Fetch and index the MITRE ATT&CK galaxy's clusters by technique ID.

        Returns:
            Dict mapping technique_id -> the cluster's tag_name.

        Raises:
            RuntimeError: If the galaxy listing is malformed, the ATT&CK
                galaxy isn't installed, or it has no clusters.
        """
        galaxies = self._misp.galaxies(pythonify=False)
        if not isinstance(galaxies, list):
            raise RuntimeError(f"Unexpected response listing galaxies: {galaxies}")

        attack_pattern_galaxy = next(
            (g["Galaxy"] for g in galaxies if g.get("Galaxy", {}).get("type") == ATTACK_PATTERN_GALAXY_TYPE),
            None,
        )
        if attack_pattern_galaxy is None:
            raise RuntimeError(
                f"No '{ATTACK_PATTERN_GALAXY_TYPE}' galaxy found on this MISP instance — "
                "is the ATT&CK galaxy installed? (Administration > Import Galaxies, or it "
                "ships enabled by default on most MISP images)"
            )

        full = self._misp.get_galaxy(attack_pattern_galaxy["id"], withCluster=True, pythonify=False)
        clusters = full.get("GalaxyCluster", [])
        if not clusters:
            raise RuntimeError(
                f"'{ATTACK_PATTERN_GALAXY_TYPE}' galaxy exists but has 0 clusters — "
                "it may need re-importing."
            )

        mapping: Dict[str, str] = {}
        for cluster in clusters:
            elements = cluster.get("GalaxyElement", [])
            technique_id = next((e["value"] for e in elements if e.get("key") == "external_id"), None)
            if technique_id:
                mapping[technique_id] = cluster["tag_name"]
        return mapping

    def tag_for(self, technique_id: str) -> Optional[str]:
        """Get the MISP galaxy tag for a technique ID, loading the galaxy on first call.

        Args:
            technique_id: MITRE technique ID, e.g. 'T1055'.

        Returns:
            The cluster's tag_name, or None if the technique isn't in the galaxy.
        """
        if self._technique_to_tag is None:
            self._technique_to_tag = self._load()
        return self._technique_to_tag.get(technique_id)
