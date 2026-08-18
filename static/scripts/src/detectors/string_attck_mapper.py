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
        # Found auditing WhiteSnake's missing T1560.001: it was in ground
        # truth (a custom ZIP engine, verified via manual RE) but had zero
        # source of static or dynamic evidence anywhere in the pipeline --
        # a pure recall gap, not a mis-mapping. These are class/field names
        # from the ZIP library actually used (confirmed present in
        # wsnake's extracted strings), specific enough to be a real signal
        # rather than a generic "zip" substring match.
        'ZipFileEntry': {'technique': 'T1560.001', 'confidence': 'medium'},
        'FilenameInZip': {'technique': 'T1560.001', 'confidence': 'medium'},
        'GZipStream': {'technique': 'T1560.001', 'confidence': 'medium'},

        # MEDIUM Confidence — Suspicious API calls
        'WTSEnumerateProcessesW': {'technique': 'T1057', 'confidence': 'medium'},
        'WTSFreeMemory': {'technique': 'T1057', 'confidence': 'medium'},
        # WNetGetConnectionW removed: same fix as attck_mapper.py's
        # IMPORT_MAPPING (this table duplicates that one for string-form
        # evidence) -- it resolves a remote UNC path for an ALREADY-KNOWN
        # local drive letter, not an enumeration API. Found auditing a
        # real false positive on Akira, whose manual report shows share
        # targets come from an operator-supplied --share_file argument,
        # not discovery.
        # Restart Manager API (Rm*) was previously mapped to T1489 "Service
        # Stop" -- wrong. These APIs identify/close processes holding a
        # FILE lock (e.g. to delete/replace it), not stop a Windows
        # service; confirmed against real evidence in manual_analysis/
        # wsnake's own notes (rstrtmgr.dll used to unlock a file for
        # deletion, nothing service-related). No single ATT&CK technique
        # cleanly covers "uses Restart Manager to unlock a file" -- same
        # judgment call already made dropping the equivalent manual
        # ground-truth finding rather than force-fitting a wrong ID.
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
        # OpenProcess removed: same fix as attck_mapper.py's map_imports
        # (this table duplicates that one for string-form evidence, but
        # without its coherent-combination check) -- OpenProcess alone
        # has dozens of legitimate non-injection uses (enumeration,
        # termination, memory reads). Found auditing a real false
        # positive on Akira, whose manual report maps this exact code
        # (WTSEnumerateProcessesW + OpenProcess + WaitForSingleObject +
        # CloseHandle, a plain enumerate-and-terminate loop) to
        # T1057/T1685, never T1055.
        'AdjustTokenPrivileges': {'technique': 'T1134', 'confidence': 'medium'},
        'LookupPrivilegeValue': {'technique': 'T1134', 'confidence': 'medium'},
        'OpenProcessToken': {'technique': 'T1134', 'confidence': 'medium'},
        'GetTickCount': {'technique': 'T1497', 'confidence': 'medium'},
        'QueryPerformanceCounter': {'technique': 'T1497', 'confidence': 'medium'},
        # TerminateProcess previously mapped to T1489 "Service Stop" -- also
        # wrong, same root cause as the Rm* fix above. It's a fully generic
        # process-kill API; string presence alone can't tell you the target
        # (an AV process -> T1685, a locked-file holder -> no clean ID,
        # its own child process -> no clean ID). Dropped rather than
        # reassigned, same call already made for the equivalent WhiteSnake
        # ground-truth finding.
        'DeleteFile': {'technique': 'T1070', 'confidence': 'medium'},

        # LOW Confidence — Too generic (only map with other evidence)
        'WriteFile': {'technique': 'T1486', 'confidence': 'low'},
        'CreateFile': {'technique': 'T1070', 'confidence': 'low'},
        'Sleep': {'technique': 'T1497', 'confidence': 'low'},
        # Moved from T1082 (System Information Discovery) to T1497 --
        # same fix as attck_mapper.py's IMPORT_MAPPING, wrong verb:
        # GetSystemInfo's dominant use is CPU-feature/core-count anti-VM
        # checking, not host-identifying recon (that's GetComputerNameW/
        # GetUserNameW's job). Found auditing a real false positive on
        # Akira, whose only use context for this string is anti-VM
        # checking already correctly captured under T1497.
        'GetSystemInfo': {'technique': 'T1497', 'confidence': 'low'},
        'FindFirstFile': {'technique': 'T1083', 'confidence': 'low'},
        'FindNextFile': {'technique': 'T1083', 'confidence': 'low'},
        'IsDebuggerPresent': {'technique': 'T1622', 'confidence': 'low'},

        # --- Persistence / Defense Evasion coverage extension ---
        # Only ~30 technique IDs had a dedicated static rule before this,
        # all justified by evidence in the 3 validated samples -- narrower
        # than the ~474 Windows-relevant techniques in the current MITRE
        # Enterprise matrix (checked directly against the official STIX
        # bundle, not estimated). These are added from MITRE's own
        # technique descriptions instead: each pattern is the literal
        # registry key/value name or WMI class name the technique's own
        # page names as the mechanism, not a guess. None were seen in any
        # of the 3 validated samples (checked after adding, see the
        # commit message) -- kept to the same bar as every other rule
        # here regardless: specific enough that presence alone is real
        # signal, not a generic string a lot of unrelated software would
        # also contain.
        #
        # Persistence — Boot or Logon Autostart Execution family
        # (T1547): each of these boots a DLL via a specific, narrowly-
        # named LSA/Winlogon registry value; MITRE's own page for each
        # names the exact key.
        'AppInit_DLLs': {'technique': 'T1546.010', 'confidence': 'high'},
        'Winlogon\\Shell': {'technique': 'T1547.004', 'confidence': 'high'},
        'Winlogon\\Userinit': {'technique': 'T1547.004', 'confidence': 'high'},
        'Security Packages': {'technique': 'T1547.005', 'confidence': 'medium'},
        'Authentication Packages': {'technique': 'T1547.002', 'confidence': 'medium'},
        # Image File Execution Options Injection: IFEO's own "Debugger"
        # value hijacks execution of a NAMED target binary -- persistence
        # (or a defense-evasion crash-on-launch trick) via a debugger
        # attached to (commonly) a security tool.
        'Image File Execution Options': {'technique': 'T1546.012', 'confidence': 'high'},
        # WMI Event Subscription: these three WMI class names only appear
        # together when a program is programmatically creating a
        # permanent WMI event subscription -- normal software has no
        # reason to reference all three. Combination-aware promotion
        # (map_strings, below) already applies: 2+ corroborating patterns
        # -> high, matching the fileless-persistence pattern MITRE
        # documents.
        '__EventFilter': {'technique': 'T1546.003', 'confidence': 'medium'},
        '__EventConsumer': {'technique': 'T1546.003', 'confidence': 'medium'},
        '__FilterToConsumerBinding': {'technique': 'T1546.003', 'confidence': 'medium'},
        # BITS Jobs: bitsadmin.exe is the CLI surface for the same COM
        # (IBackgroundCopyManager) mechanism MITRE's T1197 page describes.
        'bitsadmin': {'technique': 'T1197', 'confidence': 'medium'},

        # Defense Evasion
        # Clear Windows Event Logs: this exact invocation (wevtutil's
        # "cl" subcommand) is the CLI mechanism MITRE's T1685.005 page
        # names directly -- narrower than bare "wevtutil" (which also
        # covers benign query/export operations). Was T1070.001 under the
        # Indicator Removal parent; moved to a new T1685 "Disable or
        # Modify Tools" parent in ATT&CK v19 (migrated 2026-08).
        'wevtutil cl': {'technique': 'T1685.005', 'confidence': 'high'},
        # Regsvr32 (Squiblydoo): scrobj.dll is the specific legitimate
        # Windows Script Component Runtime DLL this technique abuses to
        # execute a scriptlet via regsvr32 -- narrower and more specific
        # than bare "regsvr32" (a real, common installer/registration
        # tool with legitimate uses this project already avoided treating
        # as suspicious alone, same discipline as dropping bare
        # TerminateProcess above).
        'scrobj.dll': {'technique': 'T1218.010', 'confidence': 'medium'},
        # Mshta: MITRE's own page describes mshta.exe proxying execution
        # of .hta files specifically -- both patterns present together is
        # the actual abuse pattern, not just mentioning the LOLBin name
        # (which alone has legitimate uses, e.g. genuine HTA-based help
        # files).
        'mshta.exe': {'technique': 'T1218.005', 'confidence': 'medium'},
        '.hta': {'technique': 'T1218.005', 'confidence': 'medium'},

        # --- Credential Access / Collection coverage extension ---
        # Same sourcing discipline as the Persistence/Defense Evasion
        # batch: each pattern is the literal registry path, file marker,
        # or DLL MITRE's own technique page names as the mechanism.
        #
        # LSASS Memory (T1003.001): duplicates the import-table entry
        # (attck_mapper.py's IMPORT_MAPPING) for samples where the string
        # is present but the call isn't a plain static import (packed/
        # obfuscated import table, or resolved via GetProcAddress) --
        # same reasoning as WH_KEYBOARD_LL's own string-vs-import
        # duplication above. Corroborating pair: MiniDumpWriteDump alone
        # has legitimate crash-reporting uses, but paired with a direct
        # 'lsass.exe' reference there's no other purpose.
        'MiniDumpWriteDump': {'technique': 'T1003.001', 'confidence': 'medium'},
        'lsass.exe': {'technique': 'T1003.001', 'confidence': 'medium'},
        # SAM (T1003.002): the exact registry path 'reg save'/similar
        # tools target to dump the local account database offline.
        'hklm\\sam': {'technique': 'T1003.002', 'confidence': 'high'},
        # LSA Secrets (T1003.004): MITRE's own page names this exact
        # registry path as where LSA secrets are stored.
        'SECURITY\\Policy\\Secrets': {'technique': 'T1003.004', 'confidence': 'high'},
        # Credentials in Registry (T1552.002): two specific, well-known
        # third-party credential storage locations MITRE's own examples
        # cite -- narrower than a bare "password" registry-value scan,
        # which would be far too generic to trust alone.
        'SimonTatham\\PuTTY\\Sessions': {'technique': 'T1552.002', 'confidence': 'medium'},
        'RealVNC\\WinVNC4': {'technique': 'T1552.002', 'confidence': 'medium'},
        # Private Keys (T1552.004): PEM/OpenSSH key file markers -- MITRE's
        # own page lists exactly these as the file content signature.
        # No legitimate reason malware code would contain these strings
        # unless searching for or handling key files.
        '-----BEGIN RSA PRIVATE KEY-----': {'technique': 'T1552.004', 'confidence': 'high'},
        '-----BEGIN PRIVATE KEY-----': {'technique': 'T1552.004', 'confidence': 'high'},
        '-----BEGIN OPENSSH PRIVATE KEY-----': {'technique': 'T1552.004', 'confidence': 'high'},
        '.ppk': {'technique': 'T1552.004', 'confidence': 'medium'},
        # Windows Credential Manager (T1555.004): the vault client DLL
        # MITRE's page names as the actual mechanism, narrower than the
        # generic Cred* APIs already covering the separate, older store.
        'VaultCli.dll': {'technique': 'T1555.004', 'confidence': 'medium'},
        # Password Filter DLL (T1556.002): the exact LSA registry value
        # that REGISTERS a password filter DLL to run on every password
        # change -- MITRE's page names this as the installation mechanism.
        'Notification Packages': {'technique': 'T1556.002', 'confidence': 'high'},
        # Network Sniffing (T1040): these two DLLs are WinPcap/Npcap's
        # actual packet-capture libraries -- raw packet capture has no
        # purpose for ordinary application software.
        'wpcap.dll': {'technique': 'T1040', 'confidence': 'medium'},
        'Packet.dll': {'technique': 'T1040', 'confidence': 'medium'},
        # Video Capture (T1125): the classic Video for Windows capture
        # API, MITRE's own page cites webcam/video-call API abuse as the
        # mechanism -- essentially no legitimate use outside actual
        # camera-capture software.
        'avicap32.dll': {'technique': 'T1125', 'confidence': 'high'},
        # Local Email Collection (T1114.001): MITRE's page names Outlook's
        # own local storage file extensions directly as the target.
        '.ost': {'technique': 'T1114.001', 'confidence': 'medium'},
        '.pst': {'technique': 'T1114.001', 'confidence': 'medium'},

        # --- Execution / Command and Control coverage extension ---
        # Same sourcing discipline: each pattern is the literal flag,
        # library, or service MITRE's own technique page names.
        #
        # Scheduled Task (T1053.005): duplicates the dynamic command-
        # pattern check in cape_report_parser.py's _COMMAND_PATTERN_MAPPING
        # for when the string is present statically but wasn't (or
        # couldn't be) observed executing in one CAPE run.
        'schtasks': {'technique': 'T1053.005', 'confidence': 'medium'},
        # PowerShell (T1059.001): MITRE's own page names Start-Process and
        # similar cmdlets, but the two strongest real-world indicators are
        # these launch flags -- -EncodedCommand smuggles a base64-encoded
        # script past command-line logging/AMSI scanning, -WindowStyle
        # Hidden suppresses the console window a legitimate interactive
        # script would show. Neither is exclusively malicious alone
        # (some legitimate automation uses -EncodedCommand), the
        # combination is what corroborates.
        '-EncodedCommand': {'technique': 'T1059.001', 'confidence': 'medium'},
        '-WindowStyle Hidden': {'technique': 'T1059.001', 'confidence': 'medium'},
        # Dynamic Data Exchange (T1059.001's sibling T1559.002): DDEAUTO
        # is the specific Word/Excel field code that triggers command
        # execution on document open -- the well-known malicious-document
        # delivery mechanism, not ordinary DDE usage (which uses plain
        # DDE, not DDEAUTO, and doesn't execute commands).
        'DDEAUTO': {'technique': 'T1559.002', 'confidence': 'high'},
        # MSBuild (T1127.001): MITRE's page describes proxying execution
        # through this trusted, commonly-signed build tool.
        'msbuild.exe': {'technique': 'T1127.001', 'confidence': 'medium'},
        # Service Execution (T1569.002): the SCM command-line invocation
        # that starts an already-installed service -- distinct from
        # T1543.003 (already covered), which is about CREATING the
        # service, not executing via it.
        'sc start': {'technique': 'T1569.002', 'confidence': 'medium'},
        'net start': {'technique': 'T1569.002', 'confidence': 'medium'},

        # Web Service / Bidirectional Communication (T1102.002): using an
        # existing, legitimate web service as a C2 relay -- MITRE's page
        # names exactly this pattern (compromised systems leveraging
        # popular websites for C2 instructions). Replaces a dead rule that
        # used to live in attck_mapper.py's map_config, checking
        # config['patterns'] for a 'telegram'/'bot' substring -- that
        # field is only ever populated with hex-key-shaped strings by
        # config_parser.py's _find_hex_patterns(), so the old rule could
        # never actually fire. Moved to real string evidence instead.
        'api.telegram.org': {'technique': 'T1102.002', 'confidence': 'high'},
        'pastebin.com/raw': {'technique': 'T1102.002', 'confidence': 'high'},
        'raw.githubusercontent.com': {'technique': 'T1102.002', 'confidence': 'medium'},
        'discord.com/api/webhooks': {'technique': 'T1102.002', 'confidence': 'high'},
        # Protocol Tunneling (T1572): Renci.SshNet is the standard, widely
        # used .NET SSH client library -- essentially unambiguous when
        # present. ngrok/serveo.net are the specific tunneling services
        # MITRE's own C2 tooling references name.
        'Renci.SshNet': {'technique': 'T1572', 'confidence': 'high'},
        'ngrok': {'technique': 'T1572', 'confidence': 'medium'},
        'serveo.net': {'technique': 'T1572', 'confidence': 'medium'},
        # External Proxy (T1090.002): Tor's default SOCKS listener port,
        # corroborating the existing '.onion' pattern above -- together
        # they distinguish "routes traffic through Tor" from a bare
        # mention of an onion address.
        ':9050': {'technique': 'T1090.002', 'confidence': 'medium'},

        # --- Discovery coverage extension ---
        # Security Software Discovery (T1518.001): MITRE's page describes
        # enumerating installed AV/EDR to shape follow-on behavior --
        # these are specific product process names and the WMI namespace
        # Windows itself uses to register installed security products,
        # not a generic "antivirus" string match.
        'MsMpEng.exe': {'technique': 'T1518.001', 'confidence': 'medium'},
        'avp.exe': {'technique': 'T1518.001', 'confidence': 'medium'},
        'SecurityCenter2': {'technique': 'T1518.001', 'confidence': 'medium'},

        # --- Impact coverage extension ---
        # Disk Content Wipe (T1561.001): the raw physical-disk device
        # path -- MITRE's page describes overwriting a storage device's
        # contents directly, which requires exactly this kind of raw
        # device access rather than going through the normal filesystem
        # API. Essentially never appears in ordinary application strings.
        '\\\\.\\PhysicalDrive': {'technique': 'T1561.001', 'confidence': 'high'},
        # Resource Hijacking (T1496): the Stratum mining-pool protocol
        # scheme -- unambiguous cryptocurrency-mining C2 indicator, no
        # other real-world use for this exact string.
        'stratum+tcp://': {'technique': 'T1496', 'confidence': 'high'},
        # System Shutdown/Reboot (T1529): the exact command-line
        # invocation, complementing the ExitWindowsEx import above for
        # samples that shell out to shutdown.exe instead of calling the
        # API directly.
        'shutdown /r': {'technique': 'T1529', 'confidence': 'medium'},

        # --- Privilege Escalation coverage extension ---
        # Bypass User Account Control (T1548.002): the "fodhelper"
        # technique's registry path -- a fake ms-settings protocol
        # handler that fodhelper.exe (an auto-elevating Windows binary)
        # launches without a UAC prompt. The single most commonly cited
        # UAC bypass in malware analysis literature; narrow enough that
        # legitimate software has no reason to reference it.
        'ms-settings\\Shell\\Open\\command': {'technique': 'T1548.002', 'confidence': 'high'},
        # Accessibility Features (T1546.008): the classic "sticky keys"
        # backdoor -- replacing or hijacking sethc.exe, which Windows
        # launches from the logon screen (before authentication) via a
        # key combination.
        'sethc.exe': {'technique': 'T1546.008', 'confidence': 'high'},
        # AppCert DLLs (T1546.009): MITRE's page names this exact
        # registry value -- a DLL listed here loads into every process
        # that calls CreateProcess, a narrow and specific persistence/
        # privesc registry key with no ordinary application use.
        'AppCertDlls': {'technique': 'T1546.009', 'confidence': 'high'},
        # Active Setup (T1547.014): MITRE's page names this exact
        # registry path -- programs listed here execute once per user at
        # first logon after being registered.
        'Active Setup\\Installed Components': {'technique': 'T1547.014', 'confidence': 'high'},
        # Account Manipulation (T1098): the exact command that adds an
        # account to the local Administrators group -- MITRE's page cites
        # modifying permission groups as a concrete mechanism.
        'net localgroup administrators': {'technique': 'T1098', 'confidence': 'high'},

        # --- Exfiltration coverage extension ---
        # Exfiltration to Code Repository (T1567.001): MITRE's own page
        # cites this exact API endpoint as the example.
        'api.github.com': {'technique': 'T1567.001', 'confidence': 'medium'},
        # Exfiltration to Cloud Storage (T1567.002): well-known cloud
        # storage API hosts -- MITRE's page cites Dropbox/Google Docs by
        # name as the example services.
        'dropboxapi.com': {'technique': 'T1567.002', 'confidence': 'medium'},
        'storage.googleapis.com': {'technique': 'T1567.002', 'confidence': 'medium'},
        # Exfiltration to Text Storage Sites (T1567.003): Pastebin's
        # actual paste-creation API endpoint -- distinct from the
        # read-only pastebin.com/raw pattern already covering T1102.002's
        # C2-retrieval angle, this is the upload/exfil direction
        # specifically.
        'pastebin.com/api/api_post.php': {'technique': 'T1567.003', 'confidence': 'high'},
    }

    def map_strings(self, strings: List[str]) -> List[Dict[str, str]]:
        """Map strings to ATT&CK techniques with confidence."""
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
