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
    "T1560.001": "Archive Collected Data: Archive via Utility",
    "T1562": "Impair Defenses",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
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
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
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
}

_attck_bundle_cache = None


def _load_bundle_names(bundle_path: Path) -> Optional[dict]:
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
