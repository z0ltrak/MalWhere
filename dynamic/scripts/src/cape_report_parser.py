"""Distills a raw CAPE report.json (tens of MB, mostly raw API call logs)
into a curated, IOC-focused dynamic_report.json.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .confidence import bucket_confidence
from .models import ATTACKMapping

_INJECTION_CATEGORIES = {"injection", "process hollowing", "shellcode"}

# Signature names whose CAPE-community ttps mapping is unreliable enough to
# drop entirely, verified individually rather than via a blanket severity/
# category rule. A blanket "exclude severity<=1" or "exclude category
# 'generic'" filter was tried first and rejected: it would have also
# dropped antivm_checks_available_memory -> T1082 and cmdline_terminate ->
# T1059, both of which are genuinely correct matches against real ground
# truth (roning, wsnake) despite sharing the same low severity/category as
# the actually-bad signature below. accesses_public_folder's own evidence
# ("a file was accessed within the Public folder") isn't diagnostic of
# either technique it's mapped to, and mapping one vague trigger to two
# techniques at once (T1548 Abuse Elevation Control, T1036 Masquerading)
# is itself a sign of an overly broad community rule, not a specific
# behavioral match.
_UNRELIABLE_SIGNATURES = {"accesses_public_folder"}

# Per-technique corrections applied within an otherwise-kept signature's
# ttps list (unlike _UNRELIABLE_SIGNATURES, these signatures' OTHER
# technique tags are fine — only these two specific IDs are wrong).
#
# T1129 "Shared Modules" requires the module be backed by an on-disk file
# (MITRE's own T1620 description literally contrasts itself with T1129:
# "vice creating a thread or process backed by a file path on disk (e.g.,
# Shared Modules [T1129])"). CAPE's unbacked_api_resolution/
# unbacked_library_load signatures are — per their own names — about
# exactly the opposite: API/library resolution from memory NOT backed by a
# file. That's T1620's textbook definition, not T1129's.
_TECHNIQUE_REMAP = {"T1129": "T1620"}

# T1568 "Dynamic Resolution" is specifically about C2 infrastructure using
# an algorithm to calculate addressing (DGA-style), per MITRE's own
# description. unbacked_dns_resolution's evidence ("resolved a domain name
# from dynamically allocated (unbacked) memory") is about WHERE the DNS
# call originates from (a fileless-execution signal), not about the C2
# domain being algorithmically calculated — a different concept entirely.
# No clean replacement technique for "DNS call made from unbacked memory"
# specifically, and the same signature already separately maps to the
# correct T1071 for the network/C2 angle — dropped rather than force-fit,
# same precedent as accesses_public_folder and the WhiteSnake Kill Process
# ground-truth finding.
_TECHNIQUE_DROP = {"T1568"}


class CapeReportParser:
    def __init__(self, report: Dict[str, Any], source_report_path: str, max_list_items: int = 200):
        self.report = report
        self.source_report_path = source_report_path
        self.max_list_items = max_list_items
        self.truncation_notes: List[str] = []

    def _cap(self, items: List[Any], label: str) -> List[Any]:
        if len(items) > self.max_list_items:
            self.truncation_notes.append(f"{label}: {len(items)} total, {self.max_list_items} shown")
            return items[: self.max_list_items]
        return items

    def parse(self) -> Dict[str, Any]:
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
        return {
            "filename": target.get("name", ""),
            "md5": target.get("md5", ""),
            "sha1": target.get("sha1", ""),
            "sha256": target.get("sha256", ""),
            "size_bytes": target.get("size"),
            "file_type": target.get("type", ""),
        }

    def _parse_analysis(self, r: Dict[str, Any], info: Dict[str, Any]) -> Dict[str, Any]:
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
                if technique in _TECHNIQUE_DROP:
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
        return [m.__dict__ for m in mappings]

    def _parse_network(self, r: Dict[str, Any]) -> Dict[str, Any]:
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
        by_sha256: Dict[str, Dict[str, Any]] = {}

        def add(entry: Dict[str, Any], role: str) -> None:
            sha256 = entry.get("sha256", "")
            if sha256 in by_sha256:
                if role not in by_sha256[sha256]["roles"]:
                    by_sha256[sha256]["roles"].append(role)
                return
            by_sha256[sha256] = {
                # CAPE's own "name" field is a list, not a string, when the
                # same dropped file was observed written under more than one
                # name/path — confirmed in real data (dropped[].name ==
                # ["report.lock"]). Flatten rather than pass a list through:
                # every downstream consumer (normalizer, STIX/MISP export)
                # expects a scalar string here.
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
        def prune(node: Dict[str, Any]) -> Dict[str, Any]:
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
