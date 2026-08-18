"""Hash/network/host IOC merging and deduplication across static + dynamic
reports, with source provenance tagging.
"""

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from .models import DiscardedEntry, HashEntry, TaggedValue

# Filenames that static string-extraction sometimes misclassifies as domains
# (e.g. "rstrtmgr.dll" — a DLL name that happens to parse as a valid-looking
# hostname, or "wtf8.rs" / "d3d11install.pdb" — Rust source paths and PDB
# debug strings embedded in the binary). Not exhaustive, just the extensions
# actually seen doing this.
_FILENAME_EXTENSIONS = (
    ".dll", ".exe", ".sys", ".ocx", ".drv", ".cpl", ".pdb", ".obj", ".lib",
    ".rs", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".py", ".go", ".java",
    ".rc",
)

# Real domains that show up as normal Windows/sandbox housekeeping rather
# than anything the sample itself chose to contact: NCSI connectivity
# checks, certificate revocation/OCSP lookups, time sync (dynamic
# detonation), and Authenticode certificate-chain infrastructure (CRL/OCSP/
# repository endpoints embedded in any code-signed PE's certificate table --
# static extraction). Reporting these as IOCs is misleading -- a STIX/MISP
# consumer has no way to tell them apart from an actual C2 domain
# otherwise. Kept deliberately small and exact/suffix-matched (not a
# general reputation allowlist): only entries confirmed to be OS/sandbox/
# PKI-generated, not "probably benign" guesses about the sample's own
# behavior. The CA entries were found auditing RoningLoader's 26 resubmitted
# components -- every code-signed one carried its signer's CRL/OCSP chain.
_BENIGN_INFRASTRUCTURE = (
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "www.msftncsi.com",
    "dns.msftncsi.com",
    "crl.microsoft.com",
    "schemas.microsoft.com",
    "ocsp.msocsp.com",
    "ctldl.windowsupdate.com",
    "time.windows.com",
    "teredo.ipv6.microsoft.com",
    # Authenticode certificate-chain infrastructure (CA CRL/OCSP/repository
    # endpoints), not sample-chosen C2.
    "crl.comodoca.com",
    "crt.comodoca.com",
    "secure.comodo.net",
    "crl.usertrust.com",
    "cacerts.digicert.com",
    "crl3.digicert.com",
    "crl.verisign.com",
    "logo.verisign.com",
    "csc3-2010-aia.verisign.com",
    "csc3-2010-crl.verisign.com",
    "repository.certum.pl",
    "crl.certum.pl",
)


def _looks_like_filename(value: str) -> bool:
    return value.lower().endswith(_FILENAME_EXTENSIONS)


def _is_benign_infrastructure(value: str) -> bool:
    value_lower = value.lower()
    return any(value_lower == b or value_lower.endswith("." + b) for b in _BENIGN_INFRASTRUCTURE)


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def merge_hashes(
    static_report: Dict[str, Any], dynamic_report: Optional[Dict[str, Any]]
) -> List[HashEntry]:
    entries: List[HashEntry] = []

    entries.append(
        HashEntry(
            role="primary_sample",
            source="static",
            sha256=static_report.get("sha256", ""),
            md5=static_report.get("md5", ""),
            sha1=static_report.get("sha1", ""),
            filename=static_report.get("filename", ""),
            type=static_report.get("file_type", ""),
        )
    )

    if dynamic_report is None:
        return entries

    target = dynamic_report.get("target", {}) or {}
    entries.append(
        HashEntry(
            role="primary_sample",
            source="dynamic",
            sha256=target.get("sha256", ""),
            md5=target.get("md5", ""),
            sha1=target.get("sha1", ""),
            filename=target.get("filename", ""),
            type=target.get("file_type", ""),
        )
    )

    _ROLE_MAP = {"dropped": "dropped_file", "cape_payload": "cape_payload"}
    for f in dynamic_report.get("dropped_files", []) or []:
        roles = f.get("roles", []) or ["dropped"]
        role = ",".join(_ROLE_MAP.get(r, r) for r in roles)
        entries.append(
            HashEntry(
                role=role,
                source="dynamic",
                sha256=f.get("sha256", ""),
                md5=f.get("md5", ""),
                sha1=f.get("sha1", ""),
                filename=f.get("name", ""),
                type=f.get("type", ""),
                cape_type=f.get("cape_type", ""),
            )
        )

    return entries


def merge_network_iocs(
    static_config: Dict[str, Any], dynamic_report: Optional[Dict[str, Any]]
) -> Tuple[Dict[str, List[TaggedValue]], List[DiscardedEntry]]:
    discarded: List[DiscardedEntry] = []

    domains: Dict[str, TaggedValue] = {}
    ips: Dict[str, TaggedValue] = {}
    urls: Dict[str, TaggedValue] = {}
    emails: Dict[str, TaggedValue] = {}

    def add(bucket: Dict[str, TaggedValue], value: str, source: str) -> None:
        value = value.strip()
        if not value:
            return
        key = value.lower()
        if key not in bucket:
            bucket[key] = TaggedValue(value=value, sources=[])
        bucket[key].sources.append(source)

    for d in static_config.get("domains", []) or []:
        if _looks_like_filename(d):
            discarded.append(
                DiscardedEntry(
                    reason="looks_like_filename_not_domain",
                    origin="static",
                    field="domains",
                    raw_value=d,
                )
            )
            continue
        if _is_benign_infrastructure(d):
            discarded.append(
                DiscardedEntry(
                    reason="known_benign_infrastructure",
                    origin="static",
                    field="domains",
                    raw_value=d,
                )
            )
            continue
        add(domains, d, "static")
    for ip in static_config.get("ips", []) or []:
        add(ips, ip, "static")
    for url in static_config.get("urls", []) or []:
        add(urls, url, "static")
    for email in static_config.get("emails", []) or []:
        add(emails, email, "static")

    if dynamic_report is not None:
        net = dynamic_report.get("network", {}) or {}
        for entry in net.get("domains", []) or []:
            domain = entry.get("domain", "")
            if domain and _looks_like_filename(domain):
                discarded.append(
                    DiscardedEntry(
                        reason="looks_like_filename_not_domain",
                        origin="dynamic",
                        field="domains",
                        raw_value=domain,
                    )
                )
                continue
            if domain and _is_benign_infrastructure(domain):
                discarded.append(
                    DiscardedEntry(
                        reason="known_benign_infrastructure",
                        origin="dynamic",
                        field="domains",
                        raw_value=domain,
                    )
                )
                continue
            if domain:
                add(domains, domain, "dynamic")
            ip = entry.get("ip", "")
            if ip and _is_valid_ip(ip):
                add(ips, ip, "dynamic")
        for entry in net.get("hosts", []) or []:
            ip = entry.get("ip", "")
            if ip and _is_valid_ip(ip):
                add(ips, ip, "dynamic")
        for entry in net.get("http_requests", []) or []:
            url = entry.get("uri") or entry.get("url") or ""
            if url:
                add(urls, url, "dynamic")

    return (
        {
            "domains": [v.to_dict() for v in domains.values()],
            "ips": [v.to_dict() for v in ips.values()],
            "urls": [v.to_dict() for v in urls.values()],
            "emails": [v.to_dict() for v in emails.values()],
        },
        discarded,
    )


def merge_host_iocs(
    static_config: Dict[str, Any], dynamic_report: Optional[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    registry_paths: Dict[str, TaggedValue] = {}
    file_paths: Dict[str, TaggedValue] = {}
    mutexes: Dict[str, TaggedValue] = {}
    encryption_keys: Dict[str, TaggedValue] = {}
    patterns: Dict[str, TaggedValue] = {}

    def add(bucket: Dict[str, TaggedValue], value: str, source: str) -> None:
        value = str(value).strip()
        if not value:
            return
        key = value.lower()
        if key not in bucket:
            bucket[key] = TaggedValue(value=value, sources=[])
        bucket[key].sources.append(source)

    for v in static_config.get("registry_paths", []) or []:
        add(registry_paths, v, "static")
    for v in static_config.get("file_paths", []) or []:
        add(file_paths, v, "static")
    for v in static_config.get("mutexes", []) or []:
        add(mutexes, v, "static")
    for v in static_config.get("encryption_keys", []) or []:
        add(encryption_keys, v, "static")
    for v in static_config.get("patterns", []) or []:
        add(patterns, v, "static")

    if dynamic_report is not None:
        host_activity = dynamic_report.get("host_activity", {}) or {}
        for v in host_activity.get("mutexes", []) or []:
            add(mutexes, v, "dynamic")
        for v in (host_activity.get("registry_keys_written", {}) or {}).get("items", []) or []:
            add(registry_paths, v, "dynamic")

    return {
        "registry_paths": [v.to_dict() for v in registry_paths.values()],
        "file_paths": [v.to_dict() for v in file_paths.values()],
        "mutexes": [v.to_dict() for v in mutexes.values()],
        "encryption_keys": [v.to_dict() for v in encryption_keys.values()],
        "patterns": [v.to_dict() for v in patterns.values()],
    }
