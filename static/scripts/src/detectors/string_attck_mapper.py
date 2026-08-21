"""String-based ATT&CK mapping with confidence."""

from typing import List, Dict


class StringATTACKMapper:
    """Map suspicious strings to ATT&CK techniques with confidence."""

    STRING_MAPPING = {
        # HIGH Confidence — Explicit malware indicators
        'akira': {'technique': 'T1486', 'confidence': 'high'},
        'arika': {'technique': 'T1486', 'confidence': 'high'},
        'akira_readme.txt': {'technique': 'T1486', 'confidence': 'high'},
        'WH_KEYBOARD_LL': {'technique': 'T1056.001', 'confidence': 'high'},
        'expand 32-byte k': {'technique': 'T1486', 'confidence': 'high'},
        'expand 16-byte k': {'technique': 'T1486', 'confidence': 'high'},
        'shadowcopy': {'technique': 'T1490', 'confidence': 'high'},
        'vssadmin': {'technique': 'T1490', 'confidence': 'high'},
        'wbadmin': {'technique': 'T1490', 'confidence': 'high'},
        '.onion': {'technique': 'T1071', 'confidence': 'high'},
        'Get-WmiObject Win32_Shadowcopy': {'technique': 'T1490', 'confidence': 'high'},
        'Remove-WmiObject': {'technique': 'T1490', 'confidence': 'high'},
        # Class/field names from the ZIP library actually used, specific
        # enough to be real signal rather than a generic "zip" match.
        'ZipFileEntry': {'technique': 'T1560.001', 'confidence': 'medium'},
        'FilenameInZip': {'technique': 'T1560.001', 'confidence': 'medium'},
        'GZipStream': {'technique': 'T1560.001', 'confidence': 'medium'},

        # MEDIUM Confidence — Suspicious API calls
        'WTSEnumerateProcessesW': {'technique': 'T1057', 'confidence': 'medium'},
        'WTSFreeMemory': {'technique': 'T1057', 'confidence': 'medium'},
        # WNetGetConnectionW removed: resolves a remote UNC path for an
        # already-known local drive letter, not an enumeration API.
        # Restart Manager (Rm*) and TerminateProcess removed from T1489
        # "Service Stop": Rm* identifies/closes processes holding a FILE
        # lock, not a service; TerminateProcess is too generic to map to
        # one technique from string presence alone. Both dropped rather
        # than force-fit, no clean replacement ID for either.
        'RegCreateKeyExW': {'technique': 'T1547.001', 'confidence': 'medium'},
        'RegSetValueExW': {'technique': 'T1547.001', 'confidence': 'medium'},
        'RegOpenKeyExW': {'technique': 'T1547.001', 'confidence': 'medium'},
        'CreateProcessW': {'technique': 'T1059', 'confidence': 'medium'},
        'ShellExecuteW': {'technique': 'T1059', 'confidence': 'medium'},
        'WinExec': {'technique': 'T1059', 'confidence': 'medium'},
        'SetWindowsHookEx': {'technique': 'T1056.001', 'confidence': 'medium'},
        'CopyFromScreen': {'technique': 'T1113', 'confidence': 'medium'},
        'OpenClipboard': {'technique': 'T1115', 'confidence': 'medium'},
        'SetClipboardData': {'technique': 'T1115', 'confidence': 'medium'},
        'GetClipboardData': {'technique': 'T1115', 'confidence': 'medium'},
        'CredEnumerate': {'technique': 'T1555', 'confidence': 'medium'},
        'CredentialBlob': {'technique': 'T1555', 'confidence': 'medium'},
        'NativeCredential': {'technique': 'T1555', 'confidence': 'medium'},
        'ReadProcessMemory': {'technique': 'T1055', 'confidence': 'medium'},
        'VirtualQueryEx': {'technique': 'T1055', 'confidence': 'medium'},
        # OpenProcess removed: has dozens of legitimate non-injection
        # uses (enumeration, termination, memory reads) and, unlike
        # attck_mapper.py's map_imports, this table has no combination
        # check to corroborate it.
        'AdjustTokenPrivileges': {'technique': 'T1134', 'confidence': 'medium'},
        'LookupPrivilegeValue': {'technique': 'T1134', 'confidence': 'medium'},
        'OpenProcessToken': {'technique': 'T1134', 'confidence': 'medium'},
        'GetTickCount': {'technique': 'T1497', 'confidence': 'medium'},
        'QueryPerformanceCounter': {'technique': 'T1497', 'confidence': 'medium'},
        'DeleteFile': {'technique': 'T1070', 'confidence': 'medium'},

        # LOW Confidence — Too generic (only map with other evidence)
        'WriteFile': {'technique': 'T1486', 'confidence': 'low'},
        'CreateFile': {'technique': 'T1070', 'confidence': 'low'},
        'Sleep': {'technique': 'T1497', 'confidence': 'low'},
        # T1497, not T1082: GetSystemInfo's dominant use is CPU-feature/
        # core-count anti-VM checking, not host-identifying recon.
        'GetSystemInfo': {'technique': 'T1497', 'confidence': 'low'},
        'FindFirstFile': {'technique': 'T1083', 'confidence': 'low'},
        'FindNextFile': {'technique': 'T1083', 'confidence': 'low'},
        'IsDebuggerPresent': {'technique': 'T1622', 'confidence': 'low'},

        # --- Persistence / Defense Evasion coverage extension ---
        # Each pattern below is the literal registry key/value, WMI
        # class, or CLI invocation MITRE's own technique page names as
        # the mechanism, kept to the same specificity bar as the rest of
        # this table: presence alone must be real signal, not a generic
        # string unrelated software would also contain.
        'AppInit_DLLs': {'technique': 'T1546.010', 'confidence': 'high'},
        'Winlogon\\Shell': {'technique': 'T1547.004', 'confidence': 'high'},
        'Winlogon\\Userinit': {'technique': 'T1547.004', 'confidence': 'high'},
        'Security Packages': {'technique': 'T1547.005', 'confidence': 'medium'},
        'Authentication Packages': {'technique': 'T1547.002', 'confidence': 'medium'},
        # IFEO's "Debugger" value hijacks execution of a named target
        # binary, commonly a security tool.
        'Image File Execution Options': {'technique': 'T1546.012', 'confidence': 'high'},
        # WMI Event Subscription: these three class names only appear
        # together when a program programmatically creates a permanent
        # WMI event subscription. Combination-aware promotion in
        # map_strings (below) already applies: 2+ corroborating patterns
        # -> high.
        '__EventFilter': {'technique': 'T1546.003', 'confidence': 'medium'},
        '__EventConsumer': {'technique': 'T1546.003', 'confidence': 'medium'},
        '__FilterToConsumerBinding': {'technique': 'T1546.003', 'confidence': 'medium'},
        # bitsadmin.exe is the CLI surface for the same COM
        # (IBackgroundCopyManager) mechanism T1197 describes.
        'bitsadmin': {'technique': 'T1197', 'confidence': 'medium'},

        # Defense Evasion
        # wevtutil's "cl" subcommand, narrower than bare "wevtutil"
        # (which also covers benign query/export). Moved from T1070.001
        # to T1685.005 in ATT&CK v19 (migrated 2026-08).
        'wevtutil cl': {'technique': 'T1685.005', 'confidence': 'high'},
        # scrobj.dll (Squiblydoo): the specific Windows Script Component
        # Runtime DLL this technique abuses via regsvr32, narrower than
        # bare "regsvr32" (a common, legitimate registration tool).
        'scrobj.dll': {'technique': 'T1218.010', 'confidence': 'medium'},
        # Mshta: both patterns together is the actual proxy-execution
        # abuse; the LOLBin name alone has legitimate uses (e.g. real
        # HTA-based help files).
        'mshta.exe': {'technique': 'T1218.005', 'confidence': 'medium'},
        '.hta': {'technique': 'T1218.005', 'confidence': 'medium'},

        # --- Credential Access / Collection coverage extension ---
        # LSASS Memory (T1003.001): duplicates the import-table entry
        # for samples where the call is present as a string but not a
        # plain static import (packed/obfuscated table, or resolved via
        # GetProcAddress). Paired with a direct 'lsass.exe' reference,
        # since MiniDumpWriteDump alone has legitimate crash-reporting uses.
        'MiniDumpWriteDump': {'technique': 'T1003.001', 'confidence': 'medium'},
        'lsass.exe': {'technique': 'T1003.001', 'confidence': 'medium'},
        # SAM (T1003.002): the registry path 'reg save'/similar tools
        # target to dump the local account database offline.
        'hklm\\sam': {'technique': 'T1003.002', 'confidence': 'high'},
        # LSA Secrets (T1003.004): MITRE names this exact registry path.
        'SECURITY\\Policy\\Secrets': {'technique': 'T1003.004', 'confidence': 'high'},
        # Credentials in Registry (T1552.002): specific, well-known
        # third-party credential storage locations, narrower than a bare
        # "password" registry-value scan.
        'SimonTatham\\PuTTY\\Sessions': {'technique': 'T1552.002', 'confidence': 'medium'},
        'RealVNC\\WinVNC4': {'technique': 'T1552.002', 'confidence': 'medium'},
        # Private Keys (T1552.004): PEM/OpenSSH key file markers, MITRE's
        # own file-content signature for this technique.
        '-----BEGIN RSA PRIVATE KEY-----': {'technique': 'T1552.004', 'confidence': 'high'},
        '-----BEGIN PRIVATE KEY-----': {'technique': 'T1552.004', 'confidence': 'high'},
        '-----BEGIN OPENSSH PRIVATE KEY-----': {'technique': 'T1552.004', 'confidence': 'high'},
        '.ppk': {'technique': 'T1552.004', 'confidence': 'medium'},
        # Windows Credential Manager (T1555.004): the vault client DLL,
        # narrower than the generic Cred* APIs covering the older store.
        'VaultCli.dll': {'technique': 'T1555.004', 'confidence': 'medium'},
        # Password Filter DLL (T1556.002): the LSA registry value that
        # registers a password filter DLL to run on every password change.
        'Notification Packages': {'technique': 'T1556.002', 'confidence': 'high'},
        # Network Sniffing (T1040): WinPcap/Npcap's actual packet-capture
        # libraries -- no purpose for ordinary application software.
        'wpcap.dll': {'technique': 'T1040', 'confidence': 'medium'},
        'Packet.dll': {'technique': 'T1040', 'confidence': 'medium'},
        # Video Capture (T1125): the Video for Windows capture API,
        # essentially no legitimate use outside actual camera software.
        'avicap32.dll': {'technique': 'T1125', 'confidence': 'high'},
        # Local Email Collection (T1114.001): Outlook's local storage
        # file extensions.
        '.ost': {'technique': 'T1114.001', 'confidence': 'medium'},
        '.pst': {'technique': 'T1114.001', 'confidence': 'medium'},

        # --- Execution / Command and Control coverage extension ---
        # Scheduled Task (T1053.005): duplicates the dynamic
        # command-pattern check in cape_report_parser.py's
        # _COMMAND_PATTERN_MAPPING for when the string is present
        # statically but wasn't observed executing.
        'schtasks': {'technique': 'T1053.005', 'confidence': 'medium'},
        # PowerShell (T1059.001): -EncodedCommand smuggles a
        # base64-encoded script past logging/AMSI, -WindowStyle Hidden
        # suppresses the console window. Neither is exclusively
        # malicious alone; the combination is what corroborates.
        '-EncodedCommand': {'technique': 'T1059.001', 'confidence': 'medium'},
        '-WindowStyle Hidden': {'technique': 'T1059.001', 'confidence': 'medium'},
        # DDEAUTO is the specific Word/Excel field code that triggers
        # command execution on document open -- the known malicious-
        # document delivery mechanism, unlike plain DDE.
        'DDEAUTO': {'technique': 'T1559.002', 'confidence': 'high'},
        # MSBuild (T1127.001): proxying execution through this trusted,
        # commonly-signed build tool.
        'msbuild.exe': {'technique': 'T1127.001', 'confidence': 'medium'},
        # Service Execution (T1569.002): starts an already-installed
        # service, distinct from T1543.003 (creating the service).
        'sc start': {'technique': 'T1569.002', 'confidence': 'medium'},
        'net start': {'technique': 'T1569.002', 'confidence': 'medium'},

        # Web Service / Bidirectional Communication (T1102.002): using
        # an existing, legitimate web service as a C2 relay.
        'api.telegram.org': {'technique': 'T1102.002', 'confidence': 'high'},
        'pastebin.com/raw': {'technique': 'T1102.002', 'confidence': 'high'},
        'raw.githubusercontent.com': {'technique': 'T1102.002', 'confidence': 'medium'},
        'discord.com/api/webhooks': {'technique': 'T1102.002', 'confidence': 'high'},
        # Protocol Tunneling (T1572): Renci.SshNet is a standard .NET SSH
        # client library; ngrok/serveo.net are specific tunneling services.
        'Renci.SshNet': {'technique': 'T1572', 'confidence': 'high'},
        'ngrok': {'technique': 'T1572', 'confidence': 'medium'},
        'serveo.net': {'technique': 'T1572', 'confidence': 'medium'},
        # External Proxy (T1090.002): Tor's default SOCKS listener port,
        # corroborating the '.onion' pattern above.
        ':9050': {'technique': 'T1090.002', 'confidence': 'medium'},

        # --- Discovery coverage extension ---
        # Security Software Discovery (T1518.001): specific AV/EDR
        # process names and the WMI namespace Windows itself uses to
        # register installed security products.
        'MsMpEng.exe': {'technique': 'T1518.001', 'confidence': 'medium'},
        'avp.exe': {'technique': 'T1518.001', 'confidence': 'medium'},
        'SecurityCenter2': {'technique': 'T1518.001', 'confidence': 'medium'},

        # --- Impact coverage extension ---
        # Disk Content Wipe (T1561.001): raw physical-disk device path,
        # essentially never present in ordinary application strings.
        '\\\\.\\PhysicalDrive': {'technique': 'T1561.001', 'confidence': 'high'},
        # Resource Hijacking (T1496): the Stratum mining-pool protocol
        # scheme, an unambiguous cryptomining indicator.
        'stratum+tcp://': {'technique': 'T1496', 'confidence': 'high'},
        # System Shutdown/Reboot (T1529): complements the ExitWindowsEx
        # import for samples that shell out to shutdown.exe instead.
        'shutdown /r': {'technique': 'T1529', 'confidence': 'medium'},

        # --- Privilege Escalation coverage extension ---
        # Bypass UAC (T1548.002): the "fodhelper" technique's registry
        # path -- a fake ms-settings handler that fodhelper.exe launches
        # without a UAC prompt.
        'ms-settings\\Shell\\Open\\command': {'technique': 'T1548.002', 'confidence': 'high'},
        # Accessibility Features (T1546.008): the classic "sticky keys"
        # backdoor, replacing sethc.exe (launched pre-authentication).
        'sethc.exe': {'technique': 'T1546.008', 'confidence': 'high'},
        # AppCert DLLs (T1546.009): a DLL listed here loads into every
        # process that calls CreateProcess.
        'AppCertDlls': {'technique': 'T1546.009', 'confidence': 'high'},
        # Active Setup (T1547.014): programs listed here execute once
        # per user at first logon after registration.
        'Active Setup\\Installed Components': {'technique': 'T1547.014', 'confidence': 'high'},
        # Account Manipulation (T1098): adds an account to the local
        # Administrators group.
        'net localgroup administrators': {'technique': 'T1098', 'confidence': 'high'},

        # --- Exfiltration coverage extension ---
        'api.github.com': {'technique': 'T1567.001', 'confidence': 'medium'},
        'dropboxapi.com': {'technique': 'T1567.002', 'confidence': 'medium'},
        'storage.googleapis.com': {'technique': 'T1567.002', 'confidence': 'medium'},
        # Pastebin's actual paste-creation (upload) API endpoint,
        # distinct from the read-only pastebin.com/raw pattern above.
        'pastebin.com/api/api_post.php': {'technique': 'T1567.003', 'confidence': 'high'},
    }

    def map_strings(self, strings: List[str]) -> List[Dict[str, str]]:
        """Map strings to ATT&CK techniques with confidence.

        Args:
            strings: Extracted strings from the sample.

        Returns:
            One dict per matched pattern (string excerpt, pattern,
            technique, confidence), deduplicated by (technique, pattern)
            and matching only the first pattern found per string.
        """
        results = []
        seen = set()

        for s in strings:
            s_lower = s.lower()
            for pattern, info in self.STRING_MAPPING.items():
                if pattern.lower() in s_lower:
                    key = f"{info['technique']}_{pattern}"
                    if key not in seen:
                        results.append({
                            'string': s[:50] + ('...' if len(s) > 50 else ''),
                            'pattern': pattern,
                            'technique': info['technique'],
                            'confidence': info['confidence']
                        })
                        seen.add(key)
                    break  # Only match first pattern per string

        return results
