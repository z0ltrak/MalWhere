"""Offline-safe MITRE ATT&CK technique name resolution.

3-tier resolution, never blocks on network (malwhere_net is `internal: true`
— no egress — see docker-compose.yml):
  1. --attck-bundle <path>, if given: authoritative names via
     mitreattack-python's MitreAttackData, matching ATTCK_VERSION.
  2. Built-in fallback dict below, covering every technique ID actually
     observed across the 3 validated samples' static+dynamic reports.
  3. Generic "Unknown ATT&CK technique (ID)" placeholder — never fails.
"""

from pathlib import Path
from typing import Optional

# Curated directly from real data: every technique ID observed in
# results/{wsnake,roning,akira}/iocs/normalized_iocs.json as of the initial
# 3-sample validation run.
TECHNIQUE_NAME_FALLBACK = {
    "T1003": "OS Credential Dumping",
    "T1005": "Data from Local System",
    "T1027": "Obfuscated Files or Information",
    "T1027.002": "Obfuscated Files or Information: Software Packing",
    "T1033": "System Owner/User Discovery",
    "T1036": "Masquerading",
    "T1047": "Windows Management Instrumentation",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1069": "Permission Groups Discovery",
    "T1070": "Indicator Removal",
    "T1070.006": "Indicator Removal: Timestomp",
    "T1071": "Application Layer Protocol",
    "T1074": "Data Staged",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1090": "Proxy",
    "T1105": "Ingress Tool Transfer",
    "T1106": "Native API",
    "T1112": "Modify Registry",
    "T1113": "Screen Capture",
    "T1114": "Email Collection",
    "T1129": "Shared Modules",
    "T1135": "Network Share Discovery",
    "T1202": "Indirect Command Execution",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1542.003": "Pre-OS Boot: Bootkit",
    "T1543": "Create or Modify System Process",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1555": "Credentials from Password Stores",
    "T1560": "Archive Collected Data",
    "T1560.001": "Archive Collected Data: Archive via Utility",
    # T1562 retired in ATT&CK v19; T1562.001 promoted to standalone T1685.
    "T1685": "Disable or Modify Tools",
    "T1564": "Hide Artifacts",
    "T1564.003": "Hide Artifacts: Hidden Window",
    "T1568": "Dynamic Resolution",
    "T1573": "Encrypted Channel",
    "T1620": "Reflective Code Loading",
    "T1574": "Hijack Execution Flow",
    "T1622": "Debugger Evasion",
    # Persistence / Defense Evasion coverage extension -- see
    # static/scripts/src/detectors/attck_mapper.py's TECHNIQUE_NAMES for
    # the matching detection-side entries.
    "T1546.010": "Event Triggered Execution: AppInit DLLs",
    "T1547.004": "Boot or Logon Autostart Execution: Winlogon Helper DLL",
    "T1547.005": "Boot or Logon Autostart Execution: Security Support Provider",
    "T1547.002": "Boot or Logon Autostart Execution: Authentication Package",
    "T1546.012": "Event Triggered Execution: Image File Execution Options Injection",
    "T1546.003": "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
    "T1197": "BITS Jobs",
    # Moved out of Indicator Removal (T1070) into the new T1685 parent in
    # ATT&CK v19 (migrated 2026-08, was T1070.001).
    "T1685.005": "Disable or Modify Tools: Clear Windows Event Logs",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1055.012": "Process Injection: Process Hollowing",
    # Credential Access / Collection coverage extension.
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.002": "OS Credential Dumping: Security Account Manager",
    "T1003.004": "OS Credential Dumping: LSA Secrets",
    "T1552.002": "Unsecured Credentials: Credentials in Registry",
    "T1552.004": "Unsecured Credentials: Private Keys",
    "T1555.004": "Credentials from Password Stores: Windows Credential Manager",
    "T1556.002": "Modify Authentication Process: Password Filter DLL",
    "T1040": "Network Sniffing",
    "T1125": "Video Capture",
    "T1114.001": "Email Collection: Local Email Collection",
    "T1039": "Data from Network Shared Drive",
    # Execution / Command and Control coverage extension.
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1559.002": "Inter-Process Communication: Dynamic Data Exchange",
    "T1127.001": "Trusted Developer Utilities Proxy Execution: MSBuild",
    "T1569.002": "System Services: Service Execution",
    "T1102.002": "Web Service: Bidirectional Communication",
    "T1572": "Protocol Tunneling",
    "T1090.002": "Proxy: External Proxy",
    # Discovery coverage extension.
    "T1120": "Peripheral Device Discovery",
    "T1614.001": "System Location Discovery: System Language Discovery",
    "T1049": "System Network Connections Discovery",
    "T1087.001": "Account Discovery: Local Account",
    "T1018": "Remote System Discovery",
    "T1010": "Application Window Discovery",
    "T1518.001": "Software Discovery: Security Software Discovery",
    # Impact coverage extension.
    "T1529": "System Shutdown/Reboot",
    "T1531": "Account Access Removal",
    "T1561.001": "Disk Wipe: Disk Content Wipe",
    "T1496": "Resource Hijacking",
    # Privilege Escalation / Exfiltration coverage extension.
    "T1134.001": "Access Token Manipulation: Token Impersonation/Theft",
    "T1134.002": "Access Token Manipulation: Create Process with Token",
    "T1134.003": "Access Token Manipulation: Make and Impersonate Token",
    "T1546.008": "Event Triggered Execution: Accessibility Features",
    "T1546.009": "Event Triggered Execution: AppCert DLLs",
    "T1547.014": "Boot or Logon Autostart Execution: Active Setup",
    "T1098": "Account Manipulation",
    "T1567.001": "Exfiltration Over Web Service: Exfiltration to Code Repository",
    "T1567.002": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    "T1567.003": "Exfiltration Over Web Service: Exfiltration to Text Storage Sites",
    "T1567.004": "Exfiltration Over Web Service: Exfiltration Over Webhook",
    "T1048.003": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
    # 2nd validation round (2026-08-28), after the CAPE agent-fingerprinting
    # fix restored real dynamic coverage — new technique IDs surfaced across
    # the 3 samples that weren't present in the first, degraded-dynamic run.
    "T1016": "System Network Configuration Discovery",
    "T1041": "Exfiltration Over C2 Channel",
    "T1115": "Clipboard Data",
    "T1123": "Audio Capture",
    "T1132": "Data Encoding",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1201": "Password Policy Discovery",
    "T1518": "Software Discovery",
    "T1555.003": "Credentials from Password Stores: Credentials from Web Browsers",
}

_attck_bundle_cache = None


def _load_bundle_names(bundle_path: Path) -> Optional[dict]:
    """Load and cache technique_id -> name from a local ATT&CK STIX bundle.

    Args:
        bundle_path: Path to an enterprise-attack.json STIX bundle.

    Returns:
        Dict mapping technique_id -> name, or None if the bundle couldn't be loaded/parsed.
    """
    global _attck_bundle_cache
    if _attck_bundle_cache is not None:
        return _attck_bundle_cache
    try:
        from mitreattack.stix20 import MitreAttackData

        data = MitreAttackData(str(bundle_path))
        names = {}
        for technique in data.get_techniques(remove_revoked_deprecated=False):
            for ref in technique.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    names[ref["external_id"]] = technique.get("name", "")
        _attck_bundle_cache = names
        return names
    except Exception:
        return None


def resolve_technique_name(technique_id: str, attck_bundle: Optional[str] = None, verbose: bool = False) -> str:
    """Resolve a technique ID to its name, via the 3-tier fallback described in this module's docstring.

    Args:
        technique_id: MITRE technique ID, e.g. 'T1055'.
        attck_bundle: Optional path to a local enterprise-attack.json STIX bundle for authoritative names.
        verbose: Log a warning when falling back to the generic placeholder.

    Returns:
        The technique's name, or 'Unknown ATT&CK technique (<id>)' if not found anywhere.
    """
    if attck_bundle:
        bundle_path = Path(attck_bundle)
        if bundle_path.exists():
            names = _load_bundle_names(bundle_path)
            if names and technique_id in names:
                return names[technique_id]

    if technique_id in TECHNIQUE_NAME_FALLBACK:
        return TECHNIQUE_NAME_FALLBACK[technique_id]

    if verbose:
        print(f"Warning: no name found for {technique_id}, using placeholder")
    return f"Unknown ATT&CK technique ({technique_id})"
