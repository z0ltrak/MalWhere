"""Distills a raw CAPE report.json (tens of MB, mostly raw API call logs)
into a curated, IOC-focused dynamic_report.json.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .confidence import bucket_confidence
from .models import ATTACKMapping

_INJECTION_CATEGORIES = {"injection", "process hollowing", "shellcode"}

# Signature names whose CAPE-community ttps mapping is unreliable enough
# to drop entirely, verified individually against each signature's raw
# evidence and the matching manual report rather than by a blanket
# severity/category rule.
_UNRELIABLE_SIGNATURES = {
    "accesses_public_folder",                   # vague trigger mapped to two unrelated techniques
    "unbacked_process_mitigation_alteration",    # caller addresses resolve to a system DLL, not the sample
    "stealth_window",                            # hidden console window from ordinary silent subprocess use
    "anomalous_deletefile",                      # Akira's own encryption routine renames files, doesn't delete them
}

# Per-technique corrections within an otherwise-kept signature's ttps
# list -- only these specific IDs are wrong, not the whole signature.
_TECHNIQUE_REMAP = {
    # T1129 requires a file-backed module; unbacked_* signatures are, by
    # their own name, about memory NOT backed by a file -- T1620's
    # definition, not T1129's.
    "T1129": "T1620",
    # ATT&CK v14 IDs retired/restructured in v19 (migrated 2026-08); see
    # attck_mapper.py's TECHNIQUE_NAMES for the full mapping rationale.
    "T1022": "T1560",
    "T1562": "T1685",
    "T1562.001": "T1685",
    "T1070.001": "T1685.005",
}

# T1568 is specifically DGA-style algorithmic C2 addressing;
# unbacked_dns_resolution's evidence is about WHERE the DNS call
# originates from, not how the domain was chosen. No clean replacement
# technique, so dropped rather than force-fit.
_TECHNIQUE_DROP = {"T1568"}

# Corrections scoped to one specific signature, not every signature that
# tags the technique -- other signatures legitimately mapping to the same
# technique elsewhere are untouched. Each pair verified against the
# signature's own raw description/data and the matching manual report.
_SIGNATURE_TECHNIQUE_DROP = {
    ("pe_tls_callbacks", "T1055"),                      # TLS callbacks run in the same process, not injection
    ("unbacked_process_creation", "T1106"),             # evidence is about memory location, not Nt*/Zw* API usage
    ("unbacked_crypto_operations", "T1573"),            # signature hedges 4 possible purposes; only 1 supports T1573
    ("registers_vectored_exception_handler", "T1574"),  # VEH is an injection primitive, not DLL-hijack persistence
    ("privilege_elevation_check", "T1082"),             # checking own token's admin status is T1033, not system info
    ("query_fips_reconnaissance", "T1082"),             # narrow crypto policy check; signature hedges its own purpose
    ("infostealer_ftp", "T1003"),                       # reading a saved password from a config file is T1552.001
    ("infostealer_mail", "T1003"),                      # same as above
    ("antiav_servicestop", "T1543"),
    ("antiav_servicestop", "T1543.003"),                # stopping a service is the opposite of creating/modifying one
    ("unbacked_file_dropping", "T1074"),                # a dropped payload isn't evidence of staging for exfiltration
    ("unbacked_bind_shell", "T1090"),                   # a bind shell is inbound access, not traffic relaying
    ("suspicious_iocontrol_codes", "T1542.003"),        # roning's IOCTLs are file-hiding, not boot-sector tampering
    ("persistence_autorun_tasks", "T1053"),             # "autorun at startup" is T1547's definition, not Task Scheduler
    ("suspicious_command_tools", "T1202"),              # generic "ran a command-line tool", no indirection/bypass shown
    ("uses_windows_utilities", "T1202"),                # same as above
    ("antiav_servicestop", "T1489"),                    # roning's own driver restart during install, not disabling a service
    ("per_file_acl_token_check", "T1485"),              # token-query volume matches a write-permission check, not deletion
    ("per_file_acl_token_check", "T1069"),              # token is read on the process's own account, not enumerated for others
    ("unbacked_delay_execution", "T1027"),              # pausing execution isn't obfuscating a file
}


# Known LOLBin/recon command patterns, checked against CAPE's own
# executed_commands -- a generic capability, not a per-sample patch: any
# sample using one of these well-known command patterns is picked up the
# same way, independent of static string detection.
_COMMAND_PATTERN_MAPPING = [
    # (substring to match, case-insensitive, technique, confidence)
    ("netsh wlan show", "T1201", "medium"),
    ("schtasks", "T1053.005", "medium"),
    ("vssadmin", "T1490", "high"),
    ("wbadmin", "T1490", "high"),
    ("wmic shadowcopy", "T1490", "high"),
    ("bcdedit", "T1490", "medium"),
]


class CapeReportParser:
    def __init__(self, report: Dict[str, Any], source_report_path: str, max_list_items: int = 200):
        """Initialize the parser.

        Args:
            report: Raw parsed CAPE report.json.
            source_report_path: Path the report was read from, recorded in the output for provenance.
            max_list_items: Cap on list-valued fields before truncation notes are recorded.
        """
        self.report = report
        self.source_report_path = source_report_path
        self.max_list_items = max_list_items
        self.truncation_notes: List[str] = []

    def _cap(self, items: List[Any], label: str) -> List[Any]:
        """Truncate a list to max_list_items, recording a truncation note if it was cut.

        Args:
            items: List to cap.
            label: Field name to record in the truncation note.

        Returns:
            items, truncated to max_list_items if longer.
        """
        if len(items) > self.max_list_items:
            self.truncation_notes.append(f"{label}: {len(items)} total, {self.max_list_items} shown")
            return items[: self.max_list_items]
        return items

    def parse(self) -> Dict[str, Any]:
        """Distill the raw CAPE report into a curated dynamic_report.json.

        Returns:
            Dict with schema_version, source, target, analysis, signatures,
            attck_mappings, network, dropped_files, host_activity,
            process_tree, process_injection_signatures, and (if any list
            was truncated) truncation_notes.
        """
        r = self.report
        target = r.get("target", {}).get("file", {}) or {}
        info = r.get("info", {}) or {}

        result = {
            "schema_version": "1.0",
            "source": "cape",
            "source_report_path": self.source_report_path,
            "cape_task_id": info.get("id"),
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "target": self._parse_target(target),
            "analysis": self._parse_analysis(r, info),
            "signatures": self._parse_signatures(r),
            "attck_mappings": self._parse_attck_mappings(r),
            "network": self._parse_network(r),
            "dropped_files": self._parse_dropped_files(r),
            "host_activity": self._parse_host_activity(r),
            "process_tree": self._parse_process_tree(r),
            "process_injection_signatures": self._parse_injection_signatures(r),
        }
        if self.truncation_notes:
            result["truncation_notes"] = self.truncation_notes
        return result

    def _parse_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Extract the detonated sample's basic identity.

        Args:
            target: The report's target.file dict.

        Returns:
            Dict with filename, md5, sha1, sha256, size_bytes, file_type.
        """
        return {
            "filename": target.get("name", ""),
            "md5": target.get("md5", ""),
            "sha1": target.get("sha1", ""),
            "sha256": target.get("sha256", ""),
            "size_bytes": target.get("size"),
            "file_type": target.get("type", ""),
        }

    def _parse_analysis(self, r: Dict[str, Any], info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract analysis-run metadata and any AV/signature family detections.

        Args:
            r: Raw CAPE report.
            info: The report's own info dict, for timing/version fields.

        Returns:
            Dict with malscore, malstatus, duration_seconds, started,
            ended, cape_version, and family_detections.
        """
        detections = r.get("detections") or []
        family_detections = []
        for det in detections:
            family = det.get("family")
            if not family:
                continue
            sources = sorted({key for entry in det.get("details", []) for key in entry.keys()})
            family_detections.append({"family": family, "detail_sources": sources})

        return {
            "malscore": r.get("malscore"),
            "malstatus": r.get("malstatus"),
            "duration_seconds": info.get("duration"),
            "started": info.get("started"),
            "ended": info.get("ended"),
            "cape_version": info.get("version"),
            "family_detections": family_detections,
        }

    def _parse_signatures(self, r: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract every fired CAPE signature with its own technique list attached.

        Args:
            r: Raw CAPE report.

        Returns:
            One dict per signature (name, description, severity,
            confidence, categories, ttps, match_count).
        """
        # ttps is keyed by signature name; build a lookup so each signature
        # carries its own technique list alongside description/severity.
        ttps_by_signature: Dict[str, List[str]] = {}
        for entry in r.get("ttps") or []:
            name = entry.get("signature")
            if name:
                ttps_by_signature[name] = entry.get("ttps", [])

        out = []
        for sig in r.get("signatures") or []:
            name = sig.get("name", "")
            out.append(
                {
                    "name": name,
                    "description": sig.get("description", ""),
                    "severity": sig.get("severity"),
                    "confidence": sig.get("confidence"),
                    "categories": sig.get("categories", []),
                    "ttps": ttps_by_signature.get(name, []),
                    "match_count": len(sig.get("data", [])) if isinstance(sig.get("data"), list) else None,
                }
            )
        return out

    def _parse_attck_mappings(self, r: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map CAPE signatures and executed commands to ATT&CK techniques, applying the curation tables above.

        Args:
            r: Raw CAPE report.

        Returns:
            One mapping dict per (technique, signature/command) pair, after
            dropping unreliable signatures/techniques and applying remaps.
        """
        sig_by_name = {s.get("name"): s for s in (r.get("signatures") or [])}
        mappings: List[ATTACKMapping] = []

        for entry in r.get("ttps") or []:
            sig_name = entry.get("signature", "")
            if sig_name in _UNRELIABLE_SIGNATURES:
                continue
            technique_ids = entry.get("ttps", [])
            sig = sig_by_name.get(sig_name, {})
            severity = sig.get("severity") or 1
            confidence_pct = sig.get("confidence") or 50
            tier = bucket_confidence(int(severity), int(confidence_pct))
            categories = sig.get("categories", [])
            justification = (
                f"CAPE signature '{sig_name}' fired "
                f"(severity={severity}, confidence={confidence_pct}%, categories={categories})"
            )
            for technique in technique_ids:
                if technique in _TECHNIQUE_DROP or (sig_name, technique) in _SIGNATURE_TECHNIQUE_DROP:
                    continue
                technique = _TECHNIQUE_REMAP.get(technique, technique)
                mappings.append(
                    ATTACKMapping(
                        technique=technique,
                        name="",
                        source="dynamic_signature",
                        evidence=sig_name,
                        confidence=tier,
                        justification=justification,
                    )
                )

        mappings.extend(self._map_commands_to_attck(r))
        return [m.__dict__ for m in mappings]

    def _map_commands_to_attck(self, r: Dict[str, Any]) -> List[ATTACKMapping]:
        """Check CAPE's raw executed_commands against known LOLBin/recon
        patterns -- see _COMMAND_PATTERN_MAPPING for why this exists.

        Args:
            r: Raw CAPE report.

        Returns:
            One mapping per distinct (technique, command) match.
        """
        commands = r.get("behavior", {}).get("summary", {}).get("executed_commands", []) or []
        mappings: List[ATTACKMapping] = []
        matched_techniques: set = set()

        for command in commands:
            if not isinstance(command, str):
                continue
            command_lower = command.lower()
            for pattern, technique, confidence in _COMMAND_PATTERN_MAPPING:
                if pattern in command_lower and (technique, command) not in matched_techniques:
                    matched_techniques.add((technique, command))
                    mappings.append(
                        ATTACKMapping(
                            technique=technique,
                            name="",
                            source="dynamic_command",
                            evidence=command[:200],
                            confidence=confidence,
                            justification=(
                                f"Executed command '{command[:200]}' matches the known pattern "
                                f"'{pattern}'."
                            ),
                        )
                    )
        return mappings

    def _parse_network(self, r: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network activity (domains, hosts, DNS/HTTP requests, TCP/UDP counts).

        Args:
            r: Raw CAPE report.

        Returns:
            Dict with domains, hosts, dns_requests, http_requests (each
            capped), and tcp_count/udp_count.
        """
        net = r.get("network", {}) or {}
        return {
            "domains": self._cap(net.get("domains", []) or [], "network.domains"),
            "hosts": self._cap(net.get("hosts", []) or [], "network.hosts"),
            "dns_requests": self._cap(net.get("dns", []) or [], "network.dns"),
            "http_requests": self._cap(net.get("http", []) or [], "network.http"),
            "tcp_count": len(net.get("tcp", []) or []),
            "udp_count": len(net.get("udp", []) or []),
        }

    def _parse_dropped_files(self, r: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Merge CAPE's dropped-file and CAPE-payload lists, deduplicated by sha256 with roles pooled.

        Args:
            r: Raw CAPE report.

        Returns:
            One dict per distinct dropped file (name, hashes, size, type, roles), capped.
        """
        by_sha256: Dict[str, Dict[str, Any]] = {}

        def add(entry: Dict[str, Any], role: str) -> None:
            """Add or merge one dropped/payload entry into by_sha256, tracking its role(s)."""
            sha256 = entry.get("sha256", "")
            if sha256 in by_sha256:
                if role not in by_sha256[sha256]["roles"]:
                    by_sha256[sha256]["roles"].append(role)
                return
            by_sha256[sha256] = {
                # CAPE's "name" field is a list, not a string, when the
                # same dropped file was observed under more than one
                # name/path -- flatten to a scalar for downstream consumers.
                "name": "; ".join(entry["name"]) if isinstance(entry.get("name"), list) else entry.get("name", ""),
                "sha256": sha256,
                "md5": entry.get("md5", ""),
                "sha1": entry.get("sha1", ""),
                "size": entry.get("size"),
                "type": entry.get("type", ""),
                "cape_type": entry.get("cape_type", ""),
                "roles": [role],
            }

        for entry in r.get("dropped") or []:
            add(entry, "dropped")
        cape = r.get("CAPE", {}) or {}
        for entry in cape.get("payloads") or []:
            add(entry, "cape_payload")

        return self._cap(list(by_sha256.values()), "dropped_files")

    def _parse_host_activity(self, r: Dict[str, Any]) -> Dict[str, Any]:
        """Extract host-level behavior (mutexes, services, commands, registry writes).

        Args:
            r: Raw CAPE report.

        Returns:
            Dict with mutexes, created_services, started_services,
            commands_executed (each capped), and registry_keys_written
            (items capped, plus total_count/truncated).
        """
        summary = r.get("behavior", {}).get("summary", {}) or {}
        write_keys = summary.get("write_keys", []) or []
        return {
            "mutexes": self._cap(summary.get("mutexes", []) or [], "host_activity.mutexes"),
            "created_services": self._cap(summary.get("created_services", []) or [], "host_activity.created_services"),
            "started_services": self._cap(summary.get("started_services", []) or [], "host_activity.started_services"),
            "commands_executed": self._cap(summary.get("executed_commands", []) or [], "host_activity.commands_executed"),
            "registry_keys_written": {
                "items": self._cap(write_keys, "host_activity.registry_keys_written"),
                "total_count": len(write_keys),
                "truncated": len(write_keys) > self.max_list_items,
            },
        }

    def _parse_process_tree(self, r: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract the process tree, pruned to name/pid/parent_id/module_path/children.

        Args:
            r: Raw CAPE report.

        Returns:
            The pruned process tree, same shape as CAPE's own but with unused fields dropped.
        """
        def prune(node: Dict[str, Any]) -> Dict[str, Any]:
            """Recursively strip a process-tree node down to the fields this pipeline uses."""
            return {
                "name": node.get("name", ""),
                "pid": node.get("pid"),
                "parent_id": node.get("parent_id"),
                "module_path": node.get("module_path", ""),
                "children": [prune(c) for c in node.get("children", []) or []],
            }

        tree = r.get("behavior", {}).get("processtree", []) or []
        return [prune(n) for n in tree]

    def _parse_injection_signatures(self, r: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract signatures categorized (or named) as injection/hollowing/shellcode.

        Args:
            r: Raw CAPE report.

        Returns:
            One dict per matching signature (name, description, severity, categories).
        """
        out = []
        for sig in r.get("signatures") or []:
            categories = {c.lower() for c in sig.get("categories", []) or []}
            name = (sig.get("name") or "").lower()
            if categories & _INJECTION_CATEGORIES or re.search(r"inject|hollow|shellcode", name):
                out.append(
                    {
                        "name": sig.get("name", ""),
                        "description": sig.get("description", ""),
                        "severity": sig.get("severity"),
                        "categories": sig.get("categories", []),
                    }
                )
        return out
