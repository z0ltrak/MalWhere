"""Builds a connected STIX 2.1 object graph from attck_mapping.json.

Reuses the sound construction patterns from
static/scripts/src/exporters/stix_exporter.py (Identity/Indicator/
AttackPattern/Relationship/Bundle) but fixes its confirmed defects:
  - ObservedData here uses real STIX 2.1 first-class Cyber Observable
    Objects (File/DomainName/IPv4Address/URL) referenced via object_refs,
    not a STIX-2.0-style embedded `objects={"0": {...}}` dict.
  - AttackPattern generation is driven by the already-reconciled
    techniques[] list (real evidence, real confidence), not fragile
    substring matching against import strings.
  - No fabricated ThreatActor with no evidentiary basis — a Malware SDO is
    the graph's central node instead.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from stix2.v21 import (
    AttackPattern,
    Bundle,
    DomainName,
    File,
    Identity,
    Indicator,
    IPv4Address,
    Malware,
    ObservedData,
    Relationship,
    URL,
)


class StixBundleBuilder:
    # AttackPattern.description has no real STIX 2.1 length limit; this is
    # a defensive cap against a pathological case, not a realistic one.
    # Truncation is recorded in truncation_notes rather than happening silently.
    MAX_DESCRIPTION_LENGTH = 10000

    def __init__(self, attck_mapping: Dict[str, Any], max_iocs: int = 100):
        """Initialize the bundle builder.

        Args:
            attck_mapping: Reconciled ATT&CK mapping dict to build a STIX bundle from.
            max_iocs: Cap on hash/network IOCs converted to STIX objects.
        """
        self.mapping = attck_mapping
        self.max_iocs = max_iocs
        self.objects: List[Any] = []
        # Populated during build() whenever a cap (max_iocs or
        # MAX_DESCRIPTION_LENGTH) actually truncates real data -- callers
        # should surface these, not just check bundle size.
        self.truncation_notes: List[str] = []

        self.identity = Identity(name="MalWhere Threat Intelligence Pipeline", identity_class="organization")
        self.objects.append(self.identity)

    def _cid(self) -> str:
        return self.identity.id

    def build(self) -> Bundle:
        """Build the full connected STIX 2.1 bundle from the reconciled ATT&CK mapping.

        Returns:
            A Bundle containing Identity, Malware, observables, ObservedData,
            Indicators, AttackPatterns, and the relationships between them.
        """
        sample = self.mapping.get("sample", {})
        iocs = self.mapping.get("iocs", {})
        techniques = self.mapping.get("techniques", [])

        malware = self._build_malware(sample)
        file_scos = self._build_files(sample, iocs)
        network_scos = self._build_network_scos(iocs.get("network_iocs", {}))
        all_observable_scos = list(file_scos.values()) + network_scos
        self.objects.extend(all_observable_scos)

        observed_data = None
        if all_observable_scos:
            observed_data = ObservedData(
                first_observed=datetime.now(timezone.utc),
                last_observed=datetime.now(timezone.utc),
                number_observed=1,
                object_refs=[o.id for o in all_observable_scos],
                created_by_ref=self._cid(),
            )
            self.objects.append(observed_data)

        indicators = self._build_indicators(file_scos, network_scos)
        self.objects.extend(indicators)
        for ind in indicators:
            self.objects.append(Relationship(ind, "indicates", malware, created_by_ref=self._cid()))
            if observed_data is not None:
                self.objects.append(Relationship(ind, "based-on", observed_data, created_by_ref=self._cid()))

        attack_patterns = self._build_attack_patterns(techniques)
        self.objects.extend(attack_patterns)
        for ap, technique in zip(attack_patterns, techniques):
            description = (
                f"confidence={technique.get('final_confidence')}, "
                f"sources={','.join(technique.get('sources', []))}"
            )
            self.objects.append(
                Relationship(malware, "uses", ap, created_by_ref=self._cid(), description=description)
            )

        return Bundle(objects=self.objects, allow_custom=True)

    def _build_malware(self, sample: Dict[str, Any]) -> Malware:
        """Build the graph's central Malware SDO.

        Args:
            sample: attck_mapping's sample dict.

        Returns:
            A Malware object named after the family, with any other
            detected family names attached as aliases.
        """
        family = sample.get("family", "unknown")
        aliases = [d.get("family") for d in sample.get("family_detections", []) if d.get("family")]
        aliases = sorted(set(a for a in aliases if a.lower() != family.lower()))
        malware = Malware(
            name=family,
            is_family=False,
            malware_types=["unknown"],
            aliases=aliases or None,
            created_by_ref=self._cid(),
        )
        self.objects.append(malware)
        return malware

    def _build_files(self, sample: Dict[str, Any], iocs: Dict[str, Any]) -> Dict[str, File]:
        """Build STIX File objects for the primary sample and every hash IOC, deduplicated by sha256.

        Args:
            sample: attck_mapping's sample dict (static/dynamic hashes and filenames).
            iocs: attck_mapping's iocs dict, read for its hashes list (capped at max_iocs).

        Returns:
            Dict mapping sha256 -> File object.
        """
        files: Dict[str, File] = {}

        def add_file(sha256: str, md5: str = "", sha1: str = "", name: Optional[str] = None) -> None:
            """Add one File object to `files`, keyed by sha256, skipping duplicates/missing hashes.

            Args:
                sha256: File's SHA-256 hash; required, skipped if empty or already added.
                md5: File's MD5 hash, if known.
                sha1: File's SHA-1 hash, if known.
                name: File's name, if known.
            """
            if not sha256 or sha256 in files:
                return
            hashes = {"SHA-256": sha256}
            if md5:
                hashes["MD5"] = md5
            if sha1:
                hashes["SHA-1"] = sha1
            kwargs = {"hashes": hashes}
            if name:
                kwargs["name"] = name
            files[sha256] = File(**kwargs)

        if sample.get("static_sha256"):
            add_file(sample["static_sha256"], sample.get("static_md5", ""), sample.get("static_sha1", ""), sample.get("static_filename"))
        if sample.get("dynamic_sha256"):
            add_file(sample["dynamic_sha256"], sample.get("dynamic_md5", ""), name=sample.get("dynamic_filename"))

        all_hashes = iocs.get("hashes", [])
        if len(all_hashes) > self.max_iocs:
            self.truncation_notes.append(
                f"hashes: {len(all_hashes)} total, only {self.max_iocs} converted to STIX File objects (--max-iocs)"
            )
        for h in all_hashes[: self.max_iocs]:
            add_file(h.get("sha256", ""), h.get("md5", ""), h.get("sha1", ""), h.get("filename"))

        return files

    def _build_network_scos(self, network_iocs: Dict[str, Any]) -> List[Any]:
        """Build STIX Cyber Observable Objects (DomainName/IPv4Address/URL) for network IOCs.

        Args:
            network_iocs: attck_mapping's iocs.network_iocs dict.

        Returns:
            One SCO per valid IOC value, each category capped at max_iocs.
        """
        scos: List[Any] = []

        for label, key, sco_cls in (
            ("domains", "domains", DomainName),
            ("ips", "ips", IPv4Address),
            ("urls", "urls", URL),
        ):
            items = network_iocs.get(key, [])
            if len(items) > self.max_iocs:
                self.truncation_notes.append(
                    f"{label}: {len(items)} total, only {self.max_iocs} converted to STIX objects (--max-iocs)"
                )
            for item in items[: self.max_iocs]:
                value = item.get("value")
                if not value:
                    continue
                try:
                    scos.append(sco_cls(value=value))
                except Exception:
                    pass

        return scos

    def _build_indicators(self, file_scos: Dict[str, File], network_scos: List[Any]) -> List[Indicator]:
        """Build a STIX pattern Indicator for each file hash and network observable, up to max_iocs total.

        Args:
            file_scos: File SCOs from _build_files, keyed by sha256.
            network_scos: Network SCOs from _build_network_scos.

        Returns:
            One Indicator per observable, capped at max_iocs combined.
        """
        indicators: List[Indicator] = []
        count = 0

        for sha256, f in file_scos.items():
            if count >= self.max_iocs:
                break
            pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
            indicators.append(
                Indicator(
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(timezone.utc),
                    created_by_ref=self._cid(),
                )
            )
            count += 1

        for sco in network_scos:
            if count >= self.max_iocs:
                break
            if sco.type == "domain-name":
                pattern = f"[domain-name:value = '{sco.value}']"
            elif sco.type == "ipv4-addr":
                pattern = f"[ipv4-addr:value = '{sco.value}']"
            elif sco.type == "url":
                pattern = f"[url:value = '{sco.value}']"
            else:
                continue
            indicators.append(
                Indicator(
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(timezone.utc),
                    created_by_ref=self._cid(),
                )
            )
            count += 1

        return indicators

    def _build_attack_patterns(self, techniques: List[Dict[str, Any]]) -> List[AttackPattern]:
        """Build a STIX AttackPattern per reconciled technique, with evidence in its description.

        Args:
            techniques: Reconciled technique list from attck_mapping.json.

        Returns:
            One AttackPattern per technique, description truncated at MAX_DESCRIPTION_LENGTH if needed.
        """
        patterns = []
        for t in techniques:
            technique_id = t.get("technique_id", "")
            evidence = t.get("evidence", [])
            justifications = [e.get("justification", "") for e in evidence if e.get("justification")]
            header = (
                f"[confidence={t.get('final_confidence')}, "
                f"sources={','.join(t.get('sources', []))}] "
            )
            full_description = header + " | ".join(justifications)
            if len(full_description) > self.MAX_DESCRIPTION_LENGTH:
                omitted = len(full_description) - self.MAX_DESCRIPTION_LENGTH
                description = full_description[: self.MAX_DESCRIPTION_LENGTH] + f" ... [{omitted} more characters truncated]"
                self.truncation_notes.append(f"{technique_id} justification: {omitted} characters truncated (MAX_DESCRIPTION_LENGTH)")
            else:
                description = full_description
            patterns.append(
                AttackPattern(
                    name=t.get("technique_name", technique_id),
                    description=description,
                    external_references=[
                        {
                            "source_name": "mitre-attack",
                            "external_id": technique_id,
                            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                        }
                    ],
                    created_by_ref=self._cid(),
                    allow_custom=True,
                    x_confidence=t.get("final_confidence"),
                    x_confidence_score=t.get("confidence_score"),
                    x_sources=t.get("sources", []),
                )
            )
        return patterns
