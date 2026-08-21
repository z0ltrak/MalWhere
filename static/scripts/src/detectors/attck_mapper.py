"""ATT&CK mapping with justification."""

from typing import List, Dict, Any, Optional
from ..models.report import ATTACKMapping


class ATTACKMapper:
    """Map findings to MITRE ATT&CK techniques with justification."""

    # Import-to-technique mapping
    IMPORT_MAPPING = {
        # Discovery
        'WTSEnumerateProcessesW': 'T1057',
        'WTSFreeMemory': 'T1057',
        'CreateToolhelp32Snapshot': 'T1057',
        'Process32First': 'T1057',
        'Process32Next': 'T1057',
        'GetComputerNameW': 'T1082',
        'GetComputerNameA': 'T1082',
        # T1033 (System Owner/User Discovery), not T1082: T1082 covers
        # OS/hardware info, not usernames.
        'GetUserNameW': 'T1033',
        'GetUserNameA': 'T1033',
        # Peripheral Device Discovery (T1120): enumerates attached
        # hardware via the Setup API.
        'SetupDiGetClassDevsW': 'T1120',
        'SetupDiGetClassDevsA': 'T1120',
        # System Language Discovery (T1614.001): reads the system/UI
        # language, used for geofencing.
        'GetSystemDefaultLangID': 'T1614.001',
        'GetUserDefaultUILanguage': 'T1614.001',
        # System Network Connections Discovery (T1049), distinct from the
        # interface-config APIs already covering T1016.
        'GetTcpTable': 'T1049',
        'GetExtendedTcpTable': 'T1049',
        'GetUdpTable': 'T1049',
        # Local Account Discovery (T1087.001): underlying Win32 API for
        # `net user`.
        'NetUserEnum': 'T1087.001',
        # Remote System Discovery (T1018): underlying Win32 API for
        # `net view`.
        'NetServerEnum': 'T1018',

        # Collection
        'CopyFromScreen': 'T1113',
        'OpenClipboard': 'T1115',
        'SetClipboardData': 'T1115',
        'GetClipboardData': 'T1115',
        'EmptyClipboard': 'T1115',
        'CloseClipboard': 'T1115',
        'SetWindowsHookExW': 'T1056.001',
        'SetWindowsHookExA': 'T1056.001',
        'UnhookWindowsHookEx': 'T1056.001',
        'CallNextHookEx': 'T1056.001',
        'ToUnicodeEx': 'T1056.001',
        'GetAsyncKeyState': 'T1056.001',
        # Simple audio-recording API (T1123); essentially no legitimate
        # non-multimedia use.
        'mciSendStringA': 'T1123',
        'mciSendStringW': 'T1123',

        # Credential Access
        'CredEnumerateW': 'T1555',
        'CredEnumerateA': 'T1555',
        'CredReadW': 'T1555',
        'CredReadA': 'T1555',
        # LSASS memory dump (T1003.001); also used by legitimate crash
        # reporters, so treated as corroborated rather than conclusive
        # alone (see the 'lsass.exe' string pattern in string_attck_mapper.py).
        'MiniDumpWriteDump': 'T1003.001',
        # Windows Credential Manager Vaults (T1555.004), narrower than
        # the generic Cred* APIs above (a separate, older store).
        'VaultOpenVault': 'T1555.004',

        # Data from Network Shared Drive (T1039): the real
        # share-enumeration sequence, all mapped to the same technique.
        'WNetOpenEnumW': 'T1039',
        'WNetOpenEnumA': 'T1039',
        'WNetEnumResourceW': 'T1039',
        'WNetEnumResourceA': 'T1039',
        'WNetCloseEnum': 'T1039',

        # Execution
        'CreateProcessW': 'T1059',
        'CreateProcessA': 'T1059',
        'ShellExecuteW': 'T1059',
        'ShellExecuteA': 'T1059',
        'WinExec': 'T1059',
        'System': 'T1059',

        # Persistence
        'RegCreateKeyExW': 'T1547.001',
        'RegCreateKeyExA': 'T1547.001',
        'RegSetValueExW': 'T1547.001',
        'RegSetValueExA': 'T1547.001',
        'RegOpenKeyExW': 'T1547.001',
        'RegOpenKeyExA': 'T1547.001',
        'RegDeleteKeyW': 'T1547.001',
        'RegDeleteKeyA': 'T1547.001',

        # Privilege Escalation
        'AdjustTokenPrivileges': 'T1134',
        'LookupPrivilegeValueW': 'T1134',
        'LookupPrivilegeValueA': 'T1134',
        'OpenProcessToken': 'T1134',
        'CreateProcessWithTokenW': 'T1134.002',
        # Token Impersonation/Theft (T1134.001) and Make and Impersonate
        # Token (T1134.003) need the combination checks below --
        # ImpersonateLoggedOnUser alone is too generic.

        # Exfiltration Over Unencrypted Non-C2 Protocol (T1048.003):
        # direct FTP upload, distinct from and narrower than the generic
        # WebClient::UploadData already covering T1041's C2-channel case.
        'FtpPutFileW': 'T1048.003',
        'FtpPutFileA': 'T1048.003',

        # Defense Evasion
        'IsDebuggerPresent': 'T1622',
        'CheckRemoteDebuggerPresent': 'T1622',
        'GetTickCount': 'T1497',
        'QueryPerformanceCounter': 'T1497',
        'QueryPerformanceFrequency': 'T1497',
        'Sleep': 'T1497',
        'NtDelayExecution': 'T1497',
        # T1497 (anti-VM check via CPU core count), not T1082
        # (host-identifying recon) -- GetSystemInfo returns CPU
        # architecture/core count, not identity data.
        'GetSystemInfo': 'T1497',
        'SetUnhandledExceptionFilter': 'T1622',
        'UnhandledExceptionFilter': 'T1622',
        'OutputDebugStringW': 'T1622',
        'OutputDebugStringA': 'T1622',

        # Process Manipulation
        'OpenProcess': 'T1055',
        'ReadProcessMemory': 'T1055',
        'WriteProcessMemory': 'T1055',
        'VirtualQueryEx': 'T1055',
        'VirtualAllocEx': 'T1055',
        'CreateRemoteThread': 'T1055',
        'NtCreateThread': 'T1055',
        'QueueUserAPC': 'T1055',

        # Impact
        # Rm*/TerminateProcess -> T1489 "Service Stop" removed: Restart
        # Manager APIs are about file-lock handling, not stopping a
        # service, and TerminateProcess alone is too generic to map to
        # any one technique.
        #
        # System Shutdown/Reboot (T1529): ExitWindowsEx is the real
        # Win32 API for it (the classic post-ransomware-encryption reboot).
        'ExitWindowsEx': 'T1529',
        # Account Access Removal (T1531); also used by legitimate
        # password-management tools, kept at medium for that reason.
        'NetUserChangePassword': 'T1531',

        # Discovery (Network)
        # WNetGetConnectionW/A removed: resolves the UNC path for an
        # already-known local drive letter, not an enumeration API.
        # NetShareEnum (below) is the real T1135 signal.

        # Network -- WSAStartup/WSACleanup/socket/connect/send/recv
        # removed: raw Winsock usage is present in essentially any
        # networked program and too generic to map to one technique.
        # Real C2 evidence (onion URLs, config IPs) is captured
        # separately by map_config()'s T1071 rule below.

        # File System
        'FindFirstFileW': 'T1083',
        'FindFirstFileA': 'T1083',
        'FindNextFileW': 'T1083',
        'FindNextFileA': 'T1083',
        'FindClose': 'T1083',
        'DeleteFileW': 'T1070',
        'DeleteFileA': 'T1070',
        'MoveFileW': 'T1070',
        'MoveFileA': 'T1070',
        'CopyFileW': 'T1070',
        'CopyFileA': 'T1070',
        'WriteFile': 'T1486',  # Low confidence (generic)
        'CreateFileW': 'T1070',  # Low confidence (generic)
        'CreateFileA': 'T1070',  # Low confidence (generic)

        # Network Share
        'NetShareEnum': 'T1135',
    }

    # Fully-qualified .NET BCL API calls -> technique. The managed-code
    # equivalent of IMPORT_MAPPING above, fed by dotnet_parser.py's
    # _extract_bcl_calls() (native import tables are typically just the
    # CLR bootstrap stub for .NET binaries). Entries are chosen to be
    # specific enough that a single occurrence is real signal, excluding
    # common BCL calls (File I/O, Convert, DateTime) and registry/WMI
    # reads that are too common in legitimate .NET software alone.
    DOTNET_API_MAPPING = {
        'Microsoft.Win32.RegistryKey::SetValue': 'T1112',
        'Microsoft.Win32.RegistryKey::CreateSubKey': 'T1112',
        'Microsoft.Win32.RegistryKey::DeleteSubKeyTree': 'T1112',
        'System.Windows.Forms.Clipboard::GetText': 'T1115',
        'System.Windows.Forms.Clipboard::SetDataObject': 'T1115',
        'System.Windows.Forms.Clipboard::GetDataObject': 'T1115',
        'System.Net.NetworkInformation.NetworkInterface::GetAllNetworkInterfaces': 'T1016',
        'System.Net.NetworkInformation.NetworkInterface::GetIPProperties': 'T1016',
        'System.Security.Cryptography.RSACryptoServiceProvider::Encrypt': 'T1560',
        'System.Net.WebClient::UploadData': 'T1041',
        'System.Net.WebClient::UploadString': 'T1041',
        'System.Net.HttpListener::Start': 'T1090',
        'System.Net.HttpListener::GetContext': 'T1090',
        'System.Management.ManagementObjectSearcher::Get': 'T1047',
        'System.Management.ManagementClass::GetInstances': 'T1047',
        # Base64 encode/decode, split by direction: ToBase64String
        # encodes outbound data (T1132, Data Encoding), FromBase64String
        # decodes inbound/stored data (T1140, Deobfuscate/Decode Files
        # or Information).
        'System.Convert::ToBase64String': 'T1132',
        'System.Convert::FromBase64String': 'T1140',
    }

    # Technique names for justification
    TECHNIQUE_NAMES = {
        'T1057': 'Process Discovery',
        'T1082': 'System Information Discovery',
        'T1083': 'File and Directory Discovery',
        'T1113': 'Screen Capture',
        'T1115': 'Clipboard Data',
        'T1056.001': 'Keylogging',
        'T1555': 'Credentials from Password Stores',
        'T1059': 'Command and Scripting Interpreter',
        'T1547.001': 'Registry Run Keys / Startup Folder',
        'T1134': 'Privilege Escalation',
        'T1622': 'Debugger Evasion',
        'T1497': 'Virtualization/Sandbox Evasion',
        'T1055': 'Process Injection',
        'T1489': 'Service Stop',
        'T1135': 'Network Share Discovery',
        'T1070': 'Indicator Removal on Host',
        'T1486': 'Data Encrypted for Impact',
        'T1490': 'Inhibit System Recovery',
        'T1071': 'Application Layer Protocol',
        'T1105': 'Ingress Tool Transfer',
        'T1016': 'System Network Configuration Discovery',
        # T1022 "Data Encrypted" was revoked in ATT&CK v19, folded into
        # T1560's definition (compression AND encryption prior to
        # exfiltration). Migrated 2026-08 (v14 -> v19).
        'T1560': 'Archive Collected Data',
        'T1047': 'Windows Management Instrumentation',
        'T1090': 'Proxy',
        'T1041': 'Exfiltration Over C2 Channel',
        'T1048': 'Exfiltration Over Alternative Protocol',
        'T1132': 'Data Encoding',
        'T1560.001': 'Archive via Utility',
        'T1074': 'Data Staged',
        'T1036.005': 'Match Legitimate Resource Name or Location',  # ATT&CK v19 name (v14: "Match Legitimate Name or Location")
        'T1543.003': 'Windows Service',
        'T1053.005': 'Scheduled Task',
        'T1548.002': 'Bypass User Account Control',
        'T1112': 'Modify Registry',
        'T1123': 'Audio Capture',
        'T1119': 'Automated Collection',
        'T1555': 'Credentials from Password Stores',
        'T1140': 'Deobfuscate/Decode Files or Information',
        # T1562 "Impair Defenses" was retired in ATT&CK v19; its
        # "Disable or Modify Tools" sub-technique was promoted to become
        # standalone parent technique T1685. Migrated 2026-08 (v14 -> v19).
        'T1685': 'Disable or Modify Tools',
        # Persistence / Defense Evasion coverage extension -- see
        # string_attck_mapper.py's STRING_MAPPING for the evidence tables.
        'T1546.010': 'Event Triggered Execution: AppInit DLLs',
        'T1547.004': 'Boot or Logon Autostart Execution: Winlogon Helper DLL',
        'T1547.005': 'Boot or Logon Autostart Execution: Security Support Provider',
        'T1547.002': 'Boot or Logon Autostart Execution: Authentication Package',
        'T1546.012': 'Event Triggered Execution: Image File Execution Options Injection',
        'T1546.003': 'Event Triggered Execution: Windows Management Instrumentation Event Subscription',
        'T1197': 'BITS Jobs',
        # Moved out of the Indicator Removal (T1070) family in ATT&CK
        # v19, now a sub-technique of the new T1685 parent instead.
        # Migrated 2026-08 (v14 -> v19).
        'T1685.005': 'Disable or Modify Tools: Clear Windows Event Logs',
        'T1218.010': 'System Binary Proxy Execution: Regsvr32',
        'T1218.005': 'System Binary Proxy Execution: Mshta',
        'T1055.012': 'Process Injection: Process Hollowing',
        # Credential Access / Collection coverage extension.
        'T1003.001': 'OS Credential Dumping: LSASS Memory',
        'T1003.002': 'OS Credential Dumping: Security Account Manager',
        'T1003.004': 'OS Credential Dumping: LSA Secrets',
        'T1552.002': 'Unsecured Credentials: Credentials in Registry',
        'T1552.004': 'Unsecured Credentials: Private Keys',
        'T1555.004': 'Credentials from Password Stores: Windows Credential Manager',
        'T1556.002': 'Modify Authentication Process: Password Filter DLL',
        'T1040': 'Network Sniffing',
        'T1125': 'Video Capture',
        'T1114.001': 'Email Collection: Local Email Collection',
        'T1039': 'Data from Network Shared Drive',
        # Execution / Command and Control coverage extension.
        'T1059.001': 'Command and Scripting Interpreter: PowerShell',
        'T1559.002': 'Inter-Process Communication: Dynamic Data Exchange',
        'T1127.001': 'Trusted Developer Utilities Proxy Execution: MSBuild',
        'T1569.002': 'System Services: Service Execution',
        'T1102.002': 'Web Service: Bidirectional Communication',
        'T1572': 'Protocol Tunneling',
        'T1090.002': 'Proxy: External Proxy',
        # Discovery coverage extension.
        'T1033': 'System Owner/User Discovery',
        'T1120': 'Peripheral Device Discovery',
        'T1614.001': 'System Location Discovery: System Language Discovery',
        'T1049': 'System Network Connections Discovery',
        'T1087.001': 'Account Discovery: Local Account',
        'T1018': 'Remote System Discovery',
        'T1010': 'Application Window Discovery',
        'T1518.001': 'Software Discovery: Security Software Discovery',
        # Impact coverage extension.
        'T1529': 'System Shutdown/Reboot',
        'T1531': 'Account Access Removal',
        'T1561.001': 'Disk Wipe: Disk Content Wipe',
        'T1496': 'Resource Hijacking',
        # Privilege Escalation / Exfiltration coverage extension.
        'T1134.001': 'Access Token Manipulation: Token Impersonation/Theft',
        'T1134.002': 'Access Token Manipulation: Create Process with Token',
        'T1134.003': 'Access Token Manipulation: Make and Impersonate Token',
        'T1546.008': 'Event Triggered Execution: Accessibility Features',
        'T1546.009': 'Event Triggered Execution: AppCert DLLs',
        'T1547.014': 'Boot or Logon Autostart Execution: Active Setup',
        'T1098': 'Account Manipulation',
        'T1567.001': 'Exfiltration Over Web Service: Exfiltration to Code Repository',
        'T1567.002': 'Exfiltration Over Web Service: Exfiltration to Cloud Storage',
        'T1567.003': 'Exfiltration Over Web Service: Exfiltration to Text Storage Sites',
        'T1567.004': 'Exfiltration Over Web Service: Exfiltration Over Webhook',
        'T1048.003': 'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol',
    }

    # Chrome Web Store extension IDs are permanent and publicly
    # verifiable. Kept intentionally short, confirmed entries only --
    # a wrong ID here would create a false T1555 finding.
    KNOWN_WALLET_EXTENSION_IDS = {
        'nkbihfbeogaeaoehlefnkodbefgpgknn': 'MetaMask',
    }

    # T1055's imports aren't equally diagnostic: OpenProcess is
    # ubiquitous, and QueueUserAPC operates on a thread handle rather
    # than the process handle OpenProcess supplies, so that pair alone
    # isn't a coherent injection primitive. These 4 each take a foreign
    # process handle directly (VirtualAllocEx/WriteProcessMemory) or are
    # only meaningful as part of an injection chain
    # (CreateRemoteThread/NtCreateThread); any one of them plus a second
    # corroborating import is a coherent signal. The read-primitive trio
    # below is the alternate qualifying combination.
    _T1055_STRONG_IMPORTS = {'WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread', 'NtCreateThread'}
    _T1055_READ_TRIO = {'OpenProcess', 'VirtualQueryEx', 'ReadProcessMemory'}

    # TerminateProcess alone is too generic to map to any one technique
    # (an AV process, a locked-file holder, its own child process are
    # all plausible targets). Corroborated by both a process-listing API
    # and OpenProcess, it's a coherent enumerate-then-kill primitive,
    # specific enough for Disable or Modify Tools (T1685; was T1562.001
    # under the retired T1562 parent -- migrated 2026-08, v14 -> v19).
    _T1685_KILL_COMBO = {'WTSEnumerateProcessesW', 'OpenProcess', 'TerminateProcess'}

    # Process Hollowing (T1055.012): create a process suspended,
    # unmap/hollow its memory, write the replacement payload in, then
    # resume it. All 5 steps together have no legitimate non-hollowing
    # purpose. Either native unmap API name is accepted (Nt*/Zw* are the
    # same call). Sophisticated hollowing resolves NtUnmapViewOfSection
    # dynamically via GetProcAddress to stay off the import table -- this
    # only catches the unsophisticated case.
    _T1055_HOLLOW_COMBO = {'CreateProcessW', 'WriteProcessMemory', 'SetThreadContext', 'ResumeThread'}
    _T1055_HOLLOW_UNMAP = {'NtUnmapViewOfSection', 'ZwUnmapViewOfSection'}

    # CreateFileW/A is IMPORT_MAPPING's "low confidence (generic)" entry
    # for T1070 -- opening a file is universal, so it doesn't corroborate
    # deletion intent. Excluded from corroboration in both directions:
    # it doesn't promote other T1070 evidence, and other evidence
    # doesn't promote it.
    _T1070_GENERIC_IMPORTS = {'CreateFileW', 'CreateFileA'}

    # Application Window Discovery (T1010): GetWindowTextW alone just
    # reads a program's own window title. Combined with EnumWindows
    # (every top-level window on the desktop), it's active recon of
    # what's running on the system.
    _T1010_WINDOW_COMBO = {'EnumWindows', 'GetWindowTextW'}

    # Token Impersonation/Theft (T1134.001) and Make and Impersonate
    # Token (T1134.003): ImpersonateLoggedOnUser alone is too generic
    # (legitimate service/IIS-style code uses it too). Paired with
    # DuplicateToken(Ex) or LogonUserW, it becomes the specific technique.
    _T1134_IMPERSONATE = 'ImpersonateLoggedOnUser'
    _T1134_DUPLICATE_TOKEN = {'DuplicateToken', 'DuplicateTokenEx'}
    _T1134_LOGON_USER = {'LogonUserW', 'LogonUserA'}

    def __init__(self):
        """Initialize ATT&CK mapper."""
        self.mappings = []

    def map_strings(self, strings: List[str]) -> List[ATTACKMapping]:
        """Map strings to ATT&CK techniques.

        Args:
            strings: Extracted strings from the sample.

        Returns:
            One ATTACKMapping per matched pattern, plus derived Data
            Staged / Exfiltration Over Webhook mappings where the same
            evidence supports both. Confidence is promoted to 'high'
            when 2+ distinct patterns corroborate the same technique.
        """
        from .string_attck_mapper import StringATTACKMapper
        string_mapper = StringATTACKMapper()
        string_results = string_mapper.map_strings(strings)

        pattern_count_by_technique: Dict[str, int] = {}
        for item in string_results:
            technique = item['technique']
            # CreateFile is STRING_MAPPING's own generic entry for
            # T1070, excluded from corroboration for the same reason as
            # _T1070_GENERIC_IMPORTS above.
            if technique == 'T1070' and item.get('pattern') == 'CreateFile':
                continue
            pattern_count_by_technique[technique] = pattern_count_by_technique.get(technique, 0) + 1

        mappings = []
        for item in string_results:
            technique = item['technique']
            evidence = item.get('pattern', item.get('string', ''))
            corroborating = pattern_count_by_technique.get(technique, 0)
            confidence = 'high' if corroborating >= 2 else item.get('confidence', 'medium')

            mappings.append(ATTACKMapping(
                technique=technique,
                name=self._get_technique_name(technique),
                source='string_pattern',
                evidence=evidence,
                confidence=confidence,
                justification=self._generate_justification(
                    technique=technique,
                    source='string_pattern',
                    evidence=evidence,
                    confidence=confidence,
                    count=corroborating
                )
            ))

        # An archive-utility engine (T1560.001) bundling collected data
        # is, by the same evidence, staging that data (T1074) -- how vs.
        # what of one action. Requires the same 2+ corroborating-pattern
        # threshold as the promotion above.
        archive_patterns = [i for i in string_results if i['technique'] == 'T1560.001']
        if len(archive_patterns) >= 2:
            evidence = ', '.join(p.get('pattern', p.get('string', '')) for p in archive_patterns)
            mappings.append(ATTACKMapping(
                technique='T1074',
                name=self._get_technique_name('T1074'),
                source='string_pattern',
                evidence=evidence,
                confidence='medium',
                justification=(
                    f"The malware strings {evidence} indicate an archive-building engine bundling "
                    f"data prior to transfer. The same evidence that supports Archive via Utility "
                    f"(T1560.001) also supports Data Staged (T1074) -- collecting data into an "
                    f"archive format is a form of staging it before exfiltration."
                )
            ))

        # A Discord webhook is push-only, so the same evidence that
        # shows a webhook URL is present supports both C2 command
        # delivery (T1102.002) and Exfiltration Over Webhook (T1567.004).
        webhook_patterns = [i for i in string_results if i['technique'] == 'T1102.002' and 'webhooks' in i.get('pattern', '')]
        if webhook_patterns:
            evidence = ', '.join(p.get('pattern', p.get('string', '')) for p in webhook_patterns)
            mappings.append(ATTACKMapping(
                technique='T1567.004',
                name=self._get_technique_name('T1567.004'),
                source='string_pattern',
                evidence=evidence,
                confidence='medium',
                justification=(
                    f"The malware string {evidence} was found in the binary. A webhook is a "
                    f"push-only endpoint; the same evidence that supports Web Service/Bidirectional "
                    f"Communication (T1102.002) also supports Exfiltration Over Webhook (T1567.004) "
                    f"-- MITRE's own page names Discord webhooks specifically as this technique's "
                    f"example."
                )
            ))

        return mappings

    def map_imports(self, imports: List) -> List[ATTACKMapping]:
        """Map imports to ATT&CK techniques.

        Aggregates all imports per technique so that combination-aware
        confidence (multiple corroborating APIs, not any one import
        alone) can be computed rather than taken from a single import
        in isolation.

        Args:
            imports: Parsed import-table entries.

        Returns:
            One ATTACKMapping per technique, plus derived mappings for
            recognized multi-import combinations (kill-process,
            process-hollowing, window-discovery, token-impersonation).
        """
        by_technique: Dict[str, List[str]] = {}
        for imp in imports:
            function = imp.function  # attribute, not dict key
            technique = self.IMPORT_MAPPING.get(function)
            if technique:
                by_technique.setdefault(technique, [])
                if function not in by_technique[technique]:
                    by_technique[technique].append(function)

        mappings = []
        for technique, functions in by_technique.items():
            func_set = set(functions)
            if technique == 'T1055':
                qualifying_combo = (
                    (func_set & self._T1055_STRONG_IMPORTS and len(functions) >= 2)
                    or self._T1055_READ_TRIO.issubset(func_set)
                )
                if qualifying_combo:
                    confidence = 'high'
                elif func_set & self._T1055_STRONG_IMPORTS:
                    # One of the 4 injection primitives alone still
                    # counts as real signal, just not 'high'.
                    confidence = 'medium'
                else:
                    # The remaining T1055-tagged imports (OpenProcess,
                    # VirtualQueryEx, ReadProcessMemory, QueueUserAPC)
                    # have legitimate non-injection uses and aren't
                    # corroboration outside the two recognized
                    # combinations above.
                    continue
            elif technique == 'T1070':
                corroborating = func_set - self._T1070_GENERIC_IMPORTS
                if len(corroborating) >= 2:
                    confidence = 'high'
                elif corroborating:
                    confidence = self._determine_import_confidence(next(iter(corroborating)))
                else:
                    # Only the generic CreateFileW/A present.
                    confidence = 'low'
            elif len(functions) >= 2:
                confidence = 'high'
            else:
                confidence = self._determine_import_confidence(functions[0])
            evidence = ', '.join(functions)

            mappings.append(ATTACKMapping(
                technique=technique,
                name=self._get_technique_name(technique),
                source='import',
                evidence=evidence,
                confidence=confidence,
                justification=self._generate_justification(
                    technique=technique,
                    source='import',
                    evidence=evidence,
                    confidence=confidence,
                    count=len(functions)
                )
            ))

        all_function_names = {imp.function for imp in imports}
        if self._T1685_KILL_COMBO.issubset(all_function_names):
            evidence = ', '.join(sorted(self._T1685_KILL_COMBO))
            mappings.append(ATTACKMapping(
                technique='T1685',
                name=self._get_technique_name('T1685'),
                source='import',
                evidence=evidence,
                confidence='medium',
                justification=(
                    f"The API functions {evidence} are all imported by the binary. This is a "
                    f"coherent enumerate-then-kill primitive: deliberately searching the process "
                    f"list (WTSEnumerateProcessesW) rather than acting on a handle already held, "
                    f"then opening and terminating a match. Consistent with Disable or Modify "
                    f"Tools (T1685) even without a decrypted target name to "
                    f"confirm which process is targeted -- medium rather than high confidence for "
                    f"that reason."
                )
            ))

        if self._T1055_HOLLOW_COMBO.issubset(all_function_names) and (self._T1055_HOLLOW_UNMAP & all_function_names):
            unmap_api = next(iter(self._T1055_HOLLOW_UNMAP & all_function_names))
            hollow_evidence = ', '.join(sorted(self._T1055_HOLLOW_COMBO | {unmap_api}))
            mappings.append(ATTACKMapping(
                technique='T1055.012',
                name=self._get_technique_name('T1055.012'),
                source='import',
                evidence=hollow_evidence,
                confidence='high',
                justification=(
                    f"The API functions {hollow_evidence} are all imported by the binary. This is "
                    f"the textbook process hollowing sequence MITRE's own T1055.012 page describes: "
                    f"create a process suspended, unmap its memory ({unmap_api}), write the "
                    f"replacement payload in, set its thread context, then resume it. All 5 steps "
                    f"together have no legitimate non-hollowing purpose."
                )
            ))

        if self._T1010_WINDOW_COMBO.issubset(all_function_names):
            window_evidence = ', '.join(sorted(self._T1010_WINDOW_COMBO))
            mappings.append(ATTACKMapping(
                technique='T1010',
                name=self._get_technique_name('T1010'),
                source='import',
                evidence=window_evidence,
                confidence='medium',
                justification=(
                    f"The API functions {window_evidence} are both imported by the binary. "
                    f"EnumWindows enumerates every top-level window on the desktop, not just the "
                    f"program's own; combined with reading each one's title (GetWindowTextW), this "
                    f"is active discovery of what's running on the system -- MITRE's own T1010 page "
                    f"cites identifying security tooling by window title as a concrete example."
                )
            ))

        if self._T1134_IMPERSONATE in all_function_names:
            duplicate_api = self._T1134_DUPLICATE_TOKEN & all_function_names
            logon_api = self._T1134_LOGON_USER & all_function_names
            if duplicate_api:
                api = next(iter(duplicate_api))
                evidence = f"{api}, {self._T1134_IMPERSONATE}"
                mappings.append(ATTACKMapping(
                    technique='T1134.001',
                    name=self._get_technique_name('T1134.001'),
                    source='import',
                    evidence=evidence,
                    confidence='high',
                    justification=(
                        f"The API functions {evidence} are both imported by the binary. Duplicating "
                        f"an existing token then impersonating it is MITRE's own T1134.001 example "
                        f"exactly."
                    )
                ))
            if logon_api:
                api = next(iter(logon_api))
                evidence = f"{api}, {self._T1134_IMPERSONATE}"
                mappings.append(ATTACKMapping(
                    technique='T1134.003',
                    name=self._get_technique_name('T1134.003'),
                    source='import',
                    evidence=evidence,
                    confidence='high',
                    justification=(
                        f"The API functions {evidence} are both imported by the binary. Creating a "
                        f"new logon session via {api} then impersonating it is MITRE's own T1134.003 "
                        f"example exactly."
                    )
                ))

        return mappings

    def map_bcl_calls(self, bcl_calls: List[str]) -> List[ATTACKMapping]:
        """Map fully-qualified .NET BCL API calls to ATT&CK techniques.

        Args:
            bcl_calls: Resolved call/callvirt/newobj targets from method bodies.

        Returns:
            One ATTACKMapping per technique; confidence is 'high' when
            2+ distinct calls corroborate it, else 'medium'.
        """
        by_technique: Dict[str, List[str]] = {}
        for call in bcl_calls:
            technique = self.DOTNET_API_MAPPING.get(call)
            if technique:
                by_technique.setdefault(technique, [])
                if call not in by_technique[technique]:
                    by_technique[technique].append(call)

        mappings = []
        for technique, calls in by_technique.items():
            confidence = 'high' if len(calls) >= 2 else 'medium'
            evidence = ', '.join(calls)

            mappings.append(ATTACKMapping(
                technique=technique,
                name=self._get_technique_name(technique),
                source='dotnet_api',
                evidence=evidence,
                confidence=confidence,
                justification=self._generate_justification(
                    technique=technique,
                    source='dotnet_api',
                    evidence=evidence,
                    confidence=confidence,
                    count=len(calls)
                )
            ))

        return mappings

    def map_yara(self, yara_data: Dict[str, Any]) -> List[ATTACKMapping]:
        """Map YARA rule matches to ATT&CK techniques.

        Args:
            yara_data: YaraParser.scan() output, read for its attck_mapping list.

        Returns:
            One high-confidence ATTACKMapping per YARA rule's own technique mapping.
        """
        mappings = []

        for item in yara_data.get('attck_mapping', []):
            mappings.append(ATTACKMapping(
                technique=item.get('technique', ''),
                name=item.get('name', ''),
                source='yara',
                evidence=item.get('rule', ''),
                confidence='high',
                justification=self._generate_justification(
                    technique=item.get('technique', ''),
                    source='yara',
                    evidence=item.get('rule', ''),
                    confidence='high'
                )
            ))

        return mappings

    def map_entropy(self, entropy_findings: List) -> List[ATTACKMapping]:
        """Map entropy findings to ATT&CK techniques.

        Args:
            entropy_findings: EntropyFinding objects to check for a high-confidence, high-entropy match.

        Returns:
            At most one T1486 mapping (only the first qualifying finding is used).
        """
        mappings = []

        for finding in entropy_findings:
            if finding.confidence == 'high' and finding.entropy > 7.5:
                mappings.append(ATTACKMapping(
                    technique='T1486',  # Data Encrypted for Impact
                    name='Data Encrypted for Impact',
                    source='entropy',
                    evidence=f"{finding.name} (entropy: {finding.entropy:.2f})",
                    confidence='medium',
                    justification=f"High entropy section '{finding.name}' (entropy: {finding.entropy:.2f}) suggests encrypted or packed data. This is consistent with Data Encrypted for Impact (T1486) behavior."
                ))
                break  # Only need one entropy mapping

        return mappings

    def map_config(self, config: Dict[str, Any]) -> List[ATTACKMapping]:
        """Map configuration artifacts (URLs, IPs, registry paths, mutexes, wallet paths, XOR-recovered IOCs) to ATT&CK techniques.

        Args:
            config: ConfigExtractor.extract() output.

        Returns:
            One ATTACKMapping per matched configuration category.
        """
        mappings = []

        # .onion URLs → T1071 (Application Layer Protocol)
        if config.get('urls'):
            onion_urls = [u for u in config['urls'] if '.onion' in u]
            if onion_urls:
                mappings.append(ATTACKMapping(
                    technique='T1071',
                    name='Application Layer Protocol',
                    source='config',
                    evidence=f"{len(onion_urls)} .onion URLs found",
                    confidence='high',
                    justification=f"Found {len(onion_urls)} .onion URLs in the binary. Onion URLs are characteristic of Tor-based command and control (T1071), indicating the malware can communicate via the Tor network."
                ))

        # C2 IPs → T1071
        if config.get('ips'):
            c2_ips = config['ips']
            if c2_ips:
                mappings.append(ATTACKMapping(
                    technique='T1071',
                    name='Application Layer Protocol',
                    source='config',
                    evidence=f"{len(c2_ips)} C2 IPs found",
                    confidence='medium',
                    justification=f"Found {len(c2_ips)} IP addresses in the configuration. These are likely command and control (C2) servers used for communication (T1071)."
                ))

        # Registry paths → T1112
        if config.get('registry_paths'):
            reg_paths = config['registry_paths']
            if reg_paths:
                mappings.append(ATTACKMapping(
                    technique='T1112',
                    name='Modify Registry',
                    source='config',
                    evidence=f"{len(reg_paths)} registry paths found",
                    confidence='medium',
                    justification=f"Found {len(reg_paths)} registry paths in the configuration. Registry modifications are used for persistence, configuration storage, and defense evasion (T1112)."
                ))

        # Mutexes → T1497 (anti-sandbox) or persistence
        if config.get('mutexes'):
            mutexes = config['mutexes']
            if mutexes:
                mappings.append(ATTACKMapping(
                    technique='T1497',
                    name='Virtualization/Sandbox Evasion',
                    source='config',
                    evidence=f"{len(mutexes)} mutexes found",
                    confidence='medium',
                    justification=f"Found {len(mutexes)} mutex names in the configuration. Mutexes are often used to check for a running instance (single-instance enforcement) and for sandbox detection (T1497)."
                ))

        # Wallet browser-extension IDs are fixed, public, and
        # verifiable -- a reference in an extracted file path is
        # high-confidence T1555 evidence. Kept short and confirmed-only;
        # a wrong ID would be worse than no rule at all.
        if config.get('file_paths'):
            wallet_hits = [
                (path, name)
                for path in config['file_paths']
                for ext_id, name in self.KNOWN_WALLET_EXTENSION_IDS.items()
                if ext_id in path
            ]
            if wallet_hits:
                names = ', '.join(sorted({name for _, name in wallet_hits}))
                mappings.append(ATTACKMapping(
                    technique='T1555',
                    name='Credentials from Password Stores',
                    source='config',
                    evidence=f"Browser extension path(s) referencing: {names}",
                    confidence='high',
                    justification=(
                        f"A file path referencing the {names} browser extension's fixed store ID "
                        f"was found in the binary. Checking for or targeting a specific cryptocurrency "
                        f"wallet extension's installation path is characteristic of Credentials from "
                        f"Password Stores (T1555) -- these extension IDs are assigned once by the "
                        f"browser's extension store and have no legitimate reason to appear hardcoded "
                        f"in unrelated software."
                    )
                ))

        # An IP/domain only recoverable by brute-forcing every possible
        # single-byte XOR key is itself evidence the malware reverses
        # the same obfuscation at runtime to use the value (T1140).
        if config.get('xor_recovered_iocs'):
            hits = config['xor_recovered_iocs']
            evidence = ', '.join(f"{h['ip']} (XOR key {h['xor_key']})" for h in hits)
            mappings.append(ATTACKMapping(
                technique='T1140',
                name='Deobfuscate/Decode Files or Information',
                source='config',
                evidence=evidence,
                confidence='high',
                justification=(
                    f"Recovered {evidence} by brute-forcing every possible single-byte XOR key "
                    f"against the binary and requiring a clean null-padded boundary around the "
                    f"match (not just a coincidental decode). A network address stored obfuscated "
                    f"like this is unusable to the malware until it reverses the same encoding at "
                    f"runtime -- direct evidence of Deobfuscate/Decode Files or Information (T1140)."
                )
            ))

        return mappings

    def map_all(self, strings: List[str], imports: List[Dict[str, str]],
                yara_data: Dict[str, Any], entropy_findings: List,
                config: Dict[str, Any], bcl_calls: Optional[List[str]] = None) -> List[ATTACKMapping]:
        """Run all mapping methods and combine results.

        Args:
            strings: Extracted strings from the sample.
            imports: Parsed import-table entries.
            yara_data: YaraParser.scan() output.
            entropy_findings: EntropyFinding objects.
            config: ConfigExtractor.extract() output.
            bcl_calls: Resolved .NET BCL API calls, if any.

        Returns:
            All mappings from every source, deduplicated by (technique, evidence).
        """
        all_mappings = []
        all_mappings.extend(self.map_strings(strings))
        all_mappings.extend(self.map_imports(imports))
        all_mappings.extend(self.map_bcl_calls(bcl_calls or []))
        all_mappings.extend(self.map_yara(yara_data))
        all_mappings.extend(self.map_entropy(entropy_findings))
        all_mappings.extend(self.map_config(config))

        # Deduplicate by (technique, evidence) combination
        seen = set()
        unique_mappings = []
        for mapping in all_mappings:
            key = f"{mapping.technique}_{mapping.evidence[:20]}"
            if key not in seen:
                unique_mappings.append(mapping)
                seen.add(key)

        return unique_mappings

    def _determine_import_confidence(self, function: str) -> str:
        """Determine confidence level for an import.

        Args:
            function: Imported function name.

        Returns:
            'low' for known-generic functions, 'high' for known-specific
            malware functions, 'medium' otherwise.
        """
        # Generic functions that are used by many legitimate apps
        generic = ['WriteFile', 'CreateFile', 'ReadFile', 'Sleep', 'GetSystemInfo']
        if function in generic:
            return 'low'

        # Highly specific malware functions
        specific = ['WTSEnumerateProcessesW', 'AdjustTokenPrivileges', 'RtlCaptureContext']
        if function in specific:
            return 'high'

        return 'medium'

    def _get_technique_name(self, technique_id: str) -> str:
        """Get the full name of an ATT&CK technique.

        Args:
            technique_id: MITRE technique ID, e.g. 'T1055'.

        Returns:
            The technique's name, or 'Unknown (<id>)' if not in TECHNIQUE_NAMES.
        """
        return self.TECHNIQUE_NAMES.get(technique_id, f'Unknown ({technique_id})')

    def _generate_justification(self, technique: str, source: str,
                                evidence: str, confidence: str,
                                count: int = 1) -> str:
        """Generate a human-readable justification for an ATT&CK mapping.

        Args:
            technique: MITRE technique ID.
            source: Evidence source ('string_pattern', 'import', 'dotnet_api', 'yara', 'entropy', 'config').
            evidence: The specific evidence string (a pattern, API name, rule name, etc.).
            confidence: Confidence tier assigned to this mapping.
            count: Number of corroborating findings for this technique from this source.

        Returns:
            A one-paragraph justification tailored to the evidence source.
        """
        technique_name = self._get_technique_name(technique)

        if source == 'string_pattern':
            if count >= 2:
                return f"The malware string '{evidence}' was found in the binary, alongside {count - 1} other string(s) also characteristic of {technique_name}. Multiple corroborating strings, not this one in isolation, is what makes this a strong signal."
            return f"The malware string '{evidence}' was found in the binary. This string is characteristic of {technique_name} behavior. The presence of this specific string alone (no other {technique_name}-related string corroborates it) indicates the malware has capabilities associated with this technique, but with less certainty than a corroborated combination would."

        elif source == 'import':
            if count >= 2 and confidence == 'high':
                return f"The API functions {evidence} are all imported by the binary. This combination is characteristic of {technique_name} — multiple corroborating APIs together, not one import in isolation, is what makes this a strong signal."
            if count >= 2:
                return f"The API functions {evidence} are imported by the binary. Each is individually associated with {technique_name}, but this specific combination doesn't form one of the corroborating patterns known to indicate {technique_name} with high confidence — treat this as suggestive rather than conclusive."
            return f"The API function '{evidence}' is imported by the binary. This API is commonly used to perform {technique_name}. Importing this function alone (no other {technique_name}-related import corroborates it) indicates the malware has the capability to execute this technique, but with less certainty than a corroborated combination would."

        elif source == 'dotnet_api':
            if count >= 2:
                return f"The managed .NET API calls {evidence} were resolved from the assembly's method bodies (call/callvirt/newobj targets, not just type/method names). Multiple corroborating BCL API calls, not one in isolation, is what makes this a strong signal for {technique_name}."
            return f"The managed .NET API call '{evidence}' was resolved from the assembly's method bodies. This BCL API is specific enough to {technique_name} that its presence alone indicates the capability, but with less certainty than a corroborated combination would."

        elif source == 'yara':
            return f"YARA rule '{evidence}' matched the sample. This rule was specifically designed to detect {technique_name} patterns, confirming the presence of this capability."

        elif source == 'entropy':
            return f"Entropy analysis detected {evidence}. High entropy sections often indicate {technique_name} through packed or encrypted data."

        elif source == 'config':
            return f"Configuration artifact '{evidence}' was extracted. This artifact is associated with {technique_name} in known malware campaigns."

        else:
            return f"Evidence '{evidence}' supports the attribution of {technique_name} to this sample."
