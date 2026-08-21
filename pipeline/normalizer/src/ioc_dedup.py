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
# checks, certificate revocation/OCSP lookups, time sync, and Authenticode
# certificate-chain infrastructure (CRL/OCSP endpoints embedded in any
# code-signed PE's certificate table). Reporting these as IOCs is
# misleading -- a STIX/MISP consumer can't tell them apart from a real C2
# domain otherwise. Kept small and exact/suffix-matched (not a general
# reputation allowlist): only entries confirmed to be OS/sandbox/PKI-
# generated, not guesses about the sample's own behavior.
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


# IPs with no attached hostname (so the domain-based check above can't
# catch them) that showed up identically across multiple unrelated
# families' detonations -- confirmed via ASN lookup, always on port 443,
# never tied to a domain the sample itself looked up. Independent
# malware families do not coincidentally share C2 infrastructure; this
# is the sandbox VM's own background OS traffic leaking into CAPE's
# whole-VM PCAP capture (CAPE has no per-process network attribution).
# Excludes IPs behind an unexplained/unresolvable hostname on the same
# ASN, since domain fronting through a major CDN is a real technique --
# only entries with zero ambiguity (no hostname, or a self-identifying
# reverse-DNS name, plus cross-sample repeat) are listed here.
_BENIGN_INFRASTRUCTURE_IPS = frozenset({
    # Microsoft Corporation (AS8075/AS8068) -- Azure AD / Teams telemetry
    "108.140.32.194", "52.113.196.254",
    "40.126.53.6", "40.126.53.9", "40.126.53.16", "40.126.53.18",
    "20.190.181.2", "20.190.181.3", "20.190.181.23", "20.231.128.66",
    "4.242.235.91",
    # Akamai International B.V. (AS20940) -- Windows Update/Defender CDN
    "96.16.86.160", "96.16.86.208", "96.16.86.210", "96.16.86.212",
    "96.16.86.214", "96.16.86.215", "96.16.86.219",
    # Microsoft Corporation (AS8075) -- Azure Front Door, resolves to
    # self-identifying msedge.net names (confirmed via reverse DNS).
    "104.212.67.104",  # chi26r9c.msedge.net
    "104.212.67.66",   # bna30r9a.msedge.net
    # Cloudflare, Inc. (AS13335), no hostname -- confirmed absent from
    # every monitored process's own API call trace (only present in the
    # whole-VM capture) and absent as a string in either sample binary
    # or manual RE report, ruling out an embedded destination.
    "172.64.154.167",
    "104.18.33.89",
})


def _looks_like_filename(value: str) -> bool:
    """Check if a value looks like a filename rather than a domain.

    Args:
        value: Candidate domain string.

    Returns:
        True if value ends with a known non-domain extension.
    """
    return value.lower().endswith(_FILENAME_EXTENSIONS)


def _is_benign_infrastructure(value: str) -> bool:
    """Check if a domain is known OS/sandbox/PKI housekeeping rather than a real IOC.

    Args:
        value: Candidate domain string.

    Returns:
        True if value exactly matches or is a subdomain of a known benign entry.
    """
    value_lower = value.lower()
    return any(value_lower == b or value_lower.endswith("." + b) for b in _BENIGN_INFRASTRUCTURE)


def _is_benign_infrastructure_ip(value: str) -> bool:
    """Check if an IP is known sandbox-VM background traffic rather than a real IOC.

    Args:
        value: Candidate IP string.

    Returns:
        True if value is in the confirmed-benign IP set.
    """
    return value in _BENIGN_INFRASTRUCTURE_IPS


def _is_valid_ip(value: str) -> bool:
    """Check if a string is a valid IP address.

    Args:
        value: Candidate IP string.

    Returns:
        True if value parses as an IPv4/IPv6 address.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def merge_hashes(
    static_report: Dict[str, Any], dynamic_report: Optional[Dict[str, Any]]
) -> List[HashEntry]:
    """Merge the primary sample's static/dynamic hashes with any dynamically dropped files.

    Args:
        static_report: Static analysis report dict.
        dynamic_report: Curated dynamic_report.json dict, or None if dynamic analysis was skipped.

    Returns:
        One HashEntry per hash: the primary sample (static, and dynamic if
        available) plus every dynamically dropped/CAPE-payload file.
    """
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
    """Merge static/dynamic network IOCs, tagging each by source and filtering known benign infrastructure.

    Args:
        static_config: Static analysis config dict (from ConfigExtractor).
        dynamic_report: Curated dynamic_report.json dict, or None if dynamic analysis was skipped.

    Returns:
        A tuple of (deduplicated IOCs by category, discarded entries with reasons).
    """
    discarded: List[DiscardedEntry] = []

    domains: Dict[str, TaggedValue] = {}
    ips: Dict[str, TaggedValue] = {}
    urls: Dict[str, TaggedValue] = {}
    emails: Dict[str, TaggedValue] = {}

    def add(bucket: Dict[str, TaggedValue], value: str, source: str) -> None:
        """Add value to bucket (keyed lowercase, deduplicated), tagging it with source.

        Args:
            bucket: Dict of lowercase value -> TaggedValue, mutated in place.
            value: Raw IOC value to add.
            source: 'static' or 'dynamic', appended to the entry's sources.
        """
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
                if _is_benign_infrastructure_ip(ip):
                    discarded.append(
                        DiscardedEntry(
                            reason="known_benign_infrastructure",
                            origin="dynamic",
                            field="domains",
                            raw_value=ip,
                        )
                    )
                else:
                    add(ips, ip, "dynamic")
        for entry in net.get("hosts", []) or []:
            ip = entry.get("ip", "")
            hostname = entry.get("hostname", "")
            # CAPE's network.hosts is a whole-VM dump with no per-process
            # attribution, so the same benign domain can resolve to a
            # different IP here than in the domains loop above -- check
            # the hostname here too.
            if hostname and _is_benign_infrastructure(hostname):
                discarded.append(
                    DiscardedEntry(
                        reason="known_benign_infrastructure",
                        origin="dynamic",
                        field="hosts",
                        raw_value=f"{ip} ({hostname})",
                    )
                )
                continue
            if ip and _is_valid_ip(ip):
                if _is_benign_infrastructure_ip(ip):
                    discarded.append(
                        DiscardedEntry(
                            reason="known_benign_infrastructure",
                            origin="dynamic",
                            field="hosts",
                            raw_value=ip,
                        )
                    )
                else:
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
    """Merge static/dynamic host IOCs (registry paths, file paths, mutexes, keys, patterns), tagged by source.

    Args:
        static_config: Static analysis config dict (from ConfigExtractor).
        dynamic_report: Curated dynamic_report.json dict, or None if dynamic analysis was skipped.

    Returns:
        Dict with registry_paths, file_paths, mutexes, encryption_keys, and patterns lists.
    """
    registry_paths: Dict[str, TaggedValue] = {}
    file_paths: Dict[str, TaggedValue] = {}
    mutexes: Dict[str, TaggedValue] = {}
    encryption_keys: Dict[str, TaggedValue] = {}
    patterns: Dict[str, TaggedValue] = {}

    def add(bucket: Dict[str, TaggedValue], value: str, source: str) -> None:
        """Add value to bucket (keyed lowercase, deduplicated), tagging it with source.

        Args:
            bucket: Dict of lowercase value -> TaggedValue, mutated in place.
            value: Raw IOC value to add.
            source: 'static' or 'dynamic', appended to the entry's sources.
        """
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
