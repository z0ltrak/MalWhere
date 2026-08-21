"""Builds a MISPEvent from attck_mapping.json.

Confirmed live against pymisp 2.4.185 + a real MISP instance: add_attribute
returns a single MISPAttribute (not a list) for a single value, and its
.uuid works immediately with add_attribute_tag before the event is ever
pushed — no round-trip to the server needed to tag an attribute.
"""

from typing import Any, Dict, List, Optional

from pymisp import MISPEvent, MISPObject

from .galaxy_lookup import AttckGalaxyLookup

_CONFIDENCE_TAG = {
    "high": 'malwhere:confidence="high"',
    "medium": 'malwhere:confidence="medium"',
    "low": 'malwhere:confidence="low"',
}


class MISPEventBuilder:
    # Same reasoning as StixBundleBuilder.MAX_DESCRIPTION_LENGTH: a
    # defensive cap against a pathological case, not a realistic one.
    MAX_COMMENT_LENGTH = 10000

    def __init__(self, galaxy_lookup: AttckGalaxyLookup, distribution: int = 0):
        """Initialize the event builder.

        Args:
            galaxy_lookup: Lookup for MISP's own ATT&CK galaxy tags.
            distribution: MISP distribution level for the built event.
        """
        self.galaxy_lookup = galaxy_lookup
        self.distribution = distribution
        self.unmapped_techniques: List[str] = []
        # Populated during build() whenever MAX_COMMENT_LENGTH actually
        # truncates real data -- callers should surface these.
        self.truncation_notes: List[str] = []

    def build(self, attck_mapping: Dict[str, Any]) -> MISPEvent:
        """Build a MISPEvent from a reconciled attck_mapping.json.

        Args:
            attck_mapping: Reconciled ATT&CK mapping dict.

        Returns:
            A MISPEvent with file objects, network attributes, and per-technique tagged comments.
        """
        sample = attck_mapping.get("sample", {})
        iocs = attck_mapping.get("iocs", {})
        family = sample.get("family", "unknown")

        event = MISPEvent()
        event.info = f"MalWhere - {family} - automated analysis"
        event.distribution = self.distribution

        self._add_file_objects(event, sample, iocs)
        self._add_network_attributes(event, iocs.get("network_iocs", {}))
        self._add_technique_attributes(event, attck_mapping.get("techniques", []))

        return event

    def _add_file_objects(self, event: MISPEvent, sample: Dict[str, Any], iocs: Dict[str, Any]) -> None:
        """Add MISP file objects for the primary sample and every hash IOC, deduplicated by sha256.

        Args:
            event: MISPEvent to add objects to, mutated in place.
            sample: attck_mapping's sample dict (static/dynamic hashes and filenames).
            iocs: attck_mapping's iocs dict, read for its hashes list.
        """
        def make_file_object(sha256: str, md5: str = "", sha1: str = "", filename: Optional[str] = None) -> Optional[MISPObject]:
            """Build a MISP 'file' object from hash/filename fields.

            Args:
                sha256: File's SHA-256 hash; required.
                md5: File's MD5 hash, if known.
                sha1: File's SHA-1 hash, if known.
                filename: File's name, if known.

            Returns:
                A MISPObject, or None if sha256 wasn't given.
            """
            if not sha256:
                return None
            obj = MISPObject("file")
            obj.add_attribute("sha256", value=sha256)
            if md5:
                obj.add_attribute("md5", value=md5)
            if sha1:
                obj.add_attribute("sha1", value=sha1)
            if filename:
                obj.add_attribute("filename", value=filename)
            return obj

        seen_sha256 = set()

        primary_static = make_file_object(
            sample.get("static_sha256", ""), sample.get("static_md5", ""),
            sample.get("static_sha1", ""), sample.get("static_filename"),
        )
        if primary_static:
            event.add_object(primary_static)
            seen_sha256.add(sample.get("static_sha256"))

        dynamic_sha256 = sample.get("dynamic_sha256", "")
        if dynamic_sha256 and dynamic_sha256 not in seen_sha256:
            obj = make_file_object(dynamic_sha256, sample.get("dynamic_md5", ""), filename=sample.get("dynamic_filename"))
            if obj:
                event.add_object(obj)
                seen_sha256.add(dynamic_sha256)

        for h in iocs.get("hashes", []):
            sha256 = h.get("sha256", "")
            if not sha256 or sha256 in seen_sha256:
                continue
            obj = make_file_object(sha256, h.get("md5", ""), h.get("sha1", ""), h.get("filename"))
            if obj:
                event.add_object(obj)
                seen_sha256.add(sha256)

    def _add_network_attributes(self, event: MISPEvent, network_iocs: Dict[str, Any]) -> None:
        """Add typed network-activity attributes (domain, ip-dst, url) to the event.

        Args:
            event: MISPEvent to add attributes to, mutated in place.
            network_iocs: attck_mapping's iocs.network_iocs dict.
        """
        for d in network_iocs.get("domains", []):
            if d.get("value"):
                event.add_attribute("domain", d["value"], category="Network activity")
        for ip in network_iocs.get("ips", []):
            if ip.get("value"):
                event.add_attribute("ip-dst", ip["value"], category="Network activity")
        for url in network_iocs.get("urls", []):
            if url.get("value"):
                event.add_attribute("url", url["value"], category="Network activity")

    def _add_technique_attributes(self, event: MISPEvent, techniques: List[Dict[str, Any]]) -> None:
        """Add one evidence-carrying comment attribute per technique, tagged with its ATT&CK galaxy and confidence.

        Args:
            event: MISPEvent to add attributes to, mutated in place.
            techniques: Reconciled technique list from attck_mapping.json.
        """
        for t in techniques:
            technique_id = t.get("technique_id", "")
            evidence = t.get("evidence", [])
            justifications = [e.get("justification", "") for e in evidence if e.get("justification")]
            full_comment = f"[{technique_id}] {t.get('technique_name', '')} — " + " | ".join(justifications)
            if len(full_comment) > self.MAX_COMMENT_LENGTH:
                omitted = len(full_comment) - self.MAX_COMMENT_LENGTH
                comment_value = full_comment[: self.MAX_COMMENT_LENGTH] + f" ... [{omitted} more characters truncated]"
                self.truncation_notes.append(f"{technique_id} comment: {omitted} characters truncated (MAX_COMMENT_LENGTH)")
            else:
                comment_value = full_comment

            attr = event.add_attribute("comment", comment_value, category="Other", to_ids=False)
            if isinstance(attr, list):
                attr = attr[0]

            galaxy_tag = self.galaxy_lookup.tag_for(technique_id)
            if galaxy_tag:
                event.add_attribute_tag(galaxy_tag, attr.uuid)
            else:
                self.unmapped_techniques.append(technique_id)

            confidence_tag = _CONFIDENCE_TAG.get(t.get("final_confidence", ""))
            if confidence_tag:
                event.add_attribute_tag(confidence_tag, attr.uuid)
