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
        'GetUserNameW': 'T1082',
        'GetUserNameA': 'T1082',

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
        # mciSendString(A/W) is the classic simple-audio-recording API
        # ("open new type waveaudio ... record" MCI command strings) --
        # essentially no common non-multimedia legitimate use, same
        # single-import-sufficient precedent as WH_KEYBOARD_LL for
        # keylogging. Found auditing WhiteSnake's missing T1123: its
        # report documents exactly this (class `dt`, command "open new
        # type waveaudio alias recorder"), and the API was only just made
        # visible by fixing dotnet_parser.py's P/Invoke extraction.
        'mciSendStringA': 'T1123',
        'mciSendStringW': 'T1123',

        # Credential Access
        'CredEnumerateW': 'T1555',
        'CredEnumerateA': 'T1555',
        'CredReadW': 'T1555',
        'CredReadA': 'T1555',

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

        # Defense Evasion
        'IsDebuggerPresent': 'T1622',
        'CheckRemoteDebuggerPresent': 'T1622',
        'GetTickCount': 'T1497',
        'QueryPerformanceCounter': 'T1497',
        'QueryPerformanceFrequency': 'T1497',
        'Sleep': 'T1497',
        'NtDelayExecution': 'T1497',
        # Was mapped to T1082 (System Information Discovery) -- wrong
        # verb. GetSystemInfo returns CPU architecture/core count/page
        # size, not host-identifying recon data the way GetComputerNameW/
        # GetUserNameW are; its dominant real-world use is checking
        # dwNumberOfProcessors for anti-VM purposes (VMs commonly report
        # fewer cores). Found auditing a real false positive on Akira,
        # where this import's only use context is CPU-feature/anti-VM
        # checking already correctly captured under T1497 -- the manual
        # report has zero mention of hostname/system-info harvesting.
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
        # Rm*/TerminateProcess -> T1489 "Service Stop" removed: same fix as
        # string_attck_mapper.py's STRING_MAPPING (duplicated bug, two
        # independent mapping tables had the identical wrong entries).
        # Restart Manager APIs are about file-lock handling, not stopping a
        # Windows service; TerminateProcess is too generic to safely
        # auto-map to any single technique from import presence alone. See
        # string_attck_mapper.py's comment at the same fix for the full
        # reasoning.

        # Discovery (Network)
        # WNetGetConnectionW/A removed from here: it resolves the remote
        # UNC path for an ALREADY-KNOWN local device/drive letter -- not
        # an enumeration API, so its presence isn't evidence the malware
        # discovers shares. NetShareEnum (below, Network Share section)
        # is the real T1135 API. Found auditing a real false positive on
        # Akira: its manual report shows share *targets* come from an
        # operator-supplied --share_file argument, not discovery.

        # Network
        'WSAStartup': 'S0105',
        'WSACleanup': 'S0105',
        'socket': 'S0105',
        'connect': 'S0105',
        'send': 'S0105',
        'recv': 'S0105',

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
    # _extract_bcl_calls() (scans method bodies for call/callvirt/newobj
    # targets, since import-table-based mapping has nothing to work with
    # for .NET samples -- a .NET executable's native import table is
    # typically just the CLR bootstrap stub, confirmed on WhiteSnake: one
    # entry, mscoree.dll _CorExeMain, regardless of what the managed code
    # actually does). Each entry chosen for being specific enough that a
    # single occurrence is real signal, not incidental to virtually all
    # software (deliberately excludes System.IO.File/System.Convert/
    # System.DateTime-style BCL calls used by any .NET program for
    # mundane reasons) -- same selectivity bar as IMPORT_MAPPING's own
    # entries. Registry/WMI reads (GetValue, OpenSubKey, GetSubKeyNames)
    # are deliberately excluded too: too common in legitimate .NET
    # software to be diagnostic alone, unlike the write/enumerate-instance
    # actions kept here.
    DOTNET_API_MAPPING = {
        'Microsoft.Win32.RegistryKey::SetValue': 'T1112',
        'Microsoft.Win32.RegistryKey::CreateSubKey': 'T1112',
        'Microsoft.Win32.RegistryKey::DeleteSubKeyTree': 'T1112',
        'System.Windows.Forms.Clipboard::GetText': 'T1115',
        'System.Windows.Forms.Clipboard::SetDataObject': 'T1115',
        'System.Windows.Forms.Clipboard::GetDataObject': 'T1115',
        'System.Net.NetworkInformation.NetworkInterface::GetAllNetworkInterfaces': 'T1016',
        'System.Net.NetworkInformation.NetworkInterface::GetIPProperties': 'T1016',
        'System.Security.Cryptography.RSACryptoServiceProvider::Encrypt': 'T1022',
        'System.Net.WebClient::UploadData': 'T1041',
        'System.Net.WebClient::UploadString': 'T1041',
        'System.Net.HttpListener::Start': 'T1090',
        'System.Net.HttpListener::GetContext': 'T1090',
        'System.Management.ManagementObjectSearcher::Get': 'T1047',
        'System.Management.ManagementClass::GetInstances': 'T1047',
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
        'S0105': 'Network Communication',
        'T1070': 'Indicator Removal on Host',
        'T1486': 'Data Encrypted for Impact',
        'T1490': 'Inhibit System Recovery',
        'T1071': 'Application Layer Protocol',
        'T1105': 'Ingress Tool Transfer',
        'T1016': 'System Network Configuration Discovery',
        'T1022': 'Data Encrypted',
        'T1047': 'Windows Management Instrumentation',
        'T1090': 'Proxy',
        'T1041': 'Exfiltration Over C2 Channel',
        'T1048': 'Exfiltration Over Alternative Protocol',
        'T1132': 'Data Encoding',
        'T1560.001': 'Archive via Utility',
        'T1074': 'Data Staged',
        'T1036.005': 'Masquerading as Legitimate Software',
        'T1543.003': 'Windows Service',
        'T1053.005': 'Scheduled Task',
        'T1548.002': 'Bypass User Account Control',
        'T1112': 'Modify Registry',
        'T1123': 'Audio Capture',
        'T1119': 'Automated Collection',
        'T1555': 'Credentials from Password Stores',
        'T1140': 'Deobfuscate/Decode Files or Information',
    }

    # Chrome Web Store assigns each extension a permanent, unique ID at
    # publish time -- these are public, stable, and verifiable directly
    # against the store (chrome.google.com/webstore/detail/<name>/<id>).
    # Kept intentionally short: only extensions confirmed here, not a
    # broad scrape, since a wrong ID would create a false T1555 finding.
    KNOWN_WALLET_EXTENSION_IDS = {
        'nkbihfbeogaeaoehlefnkodbefgpgknn': 'MetaMask',
    }

    # T1055's imports aren't equally diagnostic. OpenProcess is ubiquitous
    # (termination, enumeration, memory reads, injection — dozens of
    # legitimate reasons) and QueueUserAPC operates on a THREAD handle, not
    # the process handle OpenProcess supplies, so "OpenProcess +
    # QueueUserAPC" doesn't actually compose into one coherent injection
    # primitive despite both appearing in the same import table. Found
    # auditing a real regression this pairing caused: promoted to high
    # confidence in Akira, a sample whose manual RE report found no process
    # injection at all. These 4 each take a *foreign* process handle by
    # their own signature (VirtualAllocEx/WriteProcessMemory) or are only
    # meaningful as part of an injection chain (CreateRemoteThread/
    # NtCreateThread) — any one of them plus a second corroborating import
    # is a coherent signal. The read-primitive trio below is the alternate
    # qualifying combination, matching WhiteSnake's validated genuine
    # finding (reading another process's memory, all 3 co-present).
    _T1055_STRONG_IMPORTS = {'WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread', 'NtCreateThread'}
    _T1055_READ_TRIO = {'OpenProcess', 'VirtualQueryEx', 'ReadProcessMemory'}

    def __init__(self):
        """Initialize ATT&CK mapper."""
        self.mappings = []

    def map_strings(self, strings: List[str]) -> List[ATTACKMapping]:
        """Map strings to ATT&CK techniques.

        Each matched pattern keeps its own evidence entry (unlike
        map_imports, which now aggregates into one entry per technique) —
        string patterns are typically specific enough on their own
        (a ChaCha20 constant, a decryption key) that per-evidence detail is
        worth preserving. But confidence per-pattern was still scored in
        isolation, same root problem as map_imports before its fix: found
        auditing WhiteSnake's T1055, whose static evidence was 3 distinct
        patterns (OpenProcess, VirtualQueryEx, ReadProcessMemory) each
        individually scored 'medium' with no awareness that all 3
        corroborate each other. Patterns matching techniques with 2+
        distinct corroborating patterns present get promoted to 'high'.
        """
        from .string_attck_mapper import StringATTACKMapper
        string_mapper = StringATTACKMapper()
        string_results = string_mapper.map_strings(strings)

        pattern_count_by_technique: Dict[str, int] = {}
        for item in string_results:
            technique = item['technique']
            pattern_count_by_technique[technique] = pattern_count_by_technique.get(technique, 0) + 1

        mappings = []
        for item in string_results:
            technique = item['technique']
            evidence = item.get('pattern', item.get('string', ''))
            corroborating = pattern_count_by_technique[technique]
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

        # An archive-utility engine (T1560.001) built to bundle collected
        # data before it moves is, by the same evidence, staging that data
        # (T1074) -- the two techniques describe different facets (how vs.
        # what) of one action, not two independent claims from one weak
        # signal (unlike the CAPE signature overreaches fixed elsewhere in
        # this pipeline). Found auditing WhiteSnake's T1074: real, strong
        # ground-truth support (a custom ZIP engine building XML reports
        # before exfil) but no detection source anywhere -- a genuine
        # capability gap, not a mis-mapping. Requires the same 2+
        # corroborating pattern threshold as the confidence promotion
        # above, on the same evidence.
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

        return mappings

    def map_imports(self, imports: List) -> List[ATTACKMapping]:
        """Map imports to ATT&CK techniques.

        Confidence is combination-aware, not single-import-triggered: this
        directly implements the README's own stated 3-tier methodology
        ("VirtualAllocEx + WriteProcessMemory + CreateRemoteThread -> T1055"
        as the worked HIGH-confidence example — multiple corroborating
        artifacts, not any one import alone). Previously this method took
        confidence from a single hardcoded list per import AND discarded
        all but the FIRST matching import per technique via a `seen` set —
        so even when e.g. OpenProcess, VirtualQueryEx, and ReadProcessMemory
        were ALL present together, only one of them was ever recorded and
        the co-occurrence itself, the actual corroborating signal, was
        silently thrown away before confidence was even computed. Found
        auditing a real false positive (Akira's T1055, sourced from a lone
        OpenProcess) and a real missed finding (WhiteSnake's genuine T1055,
        where three imports co-occurring was the strongest static evidence
        available and the old code never surfaced it as such).
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
                    # One of the 4 specific injection primitives, alone
                    # or alongside non-corroborating imports -- these 4
                    # have essentially no legitimate non-injection use,
                    # so still real signal even uncorroborated, just not
                    # 'high'.
                    confidence = 'medium'
                else:
                    # Every other T1055-tagged import (OpenProcess,
                    # VirtualQueryEx, ReadProcessMemory, QueueUserAPC) has
                    # dozens of legitimate non-injection uses and isn't
                    # specific enough to report on its own OR in a
                    # combination that isn't one of the two recognized
                    # coherent patterns above -- merely having 2+ of them
                    # present isn't corroboration. Found auditing a real
                    # false positive on Akira: OpenProcess+QueueUserAPC
                    # got reported at 'medium' purely because 2+
                    # T1055-tagged imports were present, despite
                    # QueueUserAPC operating on a THREAD handle
                    # OpenProcess never supplies -- not a coherent
                    # injection primitive. Akira's manual report maps
                    # this exact code (WTSEnumerateProcessesW + OpenProcess
                    # + WaitForSingleObject + CloseHandle, a plain
                    # enumerate-and-terminate loop) to T1057/T1562, never
                    # T1055.
                    continue
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

        return mappings

    def map_bcl_calls(self, bcl_calls: List[str]) -> List[ATTACKMapping]:
        """Map fully-qualified .NET BCL API calls to ATT&CK techniques.

        Same combination-aware confidence rule as map_imports: a
        technique corroborated by 2+ distinct BCL calls is high
        confidence, a single call gets 'medium' (each DOTNET_API_MAPPING
        entry was already picked for being specific enough that one
        occurrence is real signal, not the generic-vs-specific split
        map_imports' _determine_import_confidence makes for native
        imports -- there's no equivalent "generic .NET call" in this
        table to begin with, since those were excluded when building it).
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
        """Map YARA rule matches to ATT&CK techniques."""
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
        """Map entropy findings to ATT&CK techniques."""
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
        """Map configuration artifacts to ATT&CK techniques."""
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

        # Telegram bot token → T1071
        if config.get('patterns'):
            for pattern in config['patterns']:
                if isinstance(pattern, dict):
                    pattern_str = str(pattern)
                    if 'telegram' in pattern_str.lower() or 'bot' in pattern_str.lower():
                        mappings.append(ATTACKMapping(
                            technique='T1071',
                            name='Application Layer Protocol',
                            source='config',
                            evidence='Telegram bot token found',
                            confidence='high',
                            justification="A Telegram bot token was found in the configuration. This indicates the malware uses Telegram's API as a command and control channel (T1071)."
                        ))
                        break

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

        # Cryptocurrency wallet browser extension IDs -> T1555 (Credentials
        # from Password Stores). MITRE names browser-extension wallet
        # targeting explicitly under T1555; a reference to one of these
        # fixed, public extension IDs in an extracted file path is a
        # reliable, low-noise signal (these IDs are assigned once by the
        # extension store and never legitimately appear in an unrelated
        # binary's file paths). Found auditing RoningLoader's diamondage.exe:
        # config_extractor already captured the file path referencing
        # MetaMask's extension ID, but nothing mapped it to a technique.
        # Deliberately a short, high-confidence-only list, not a scrape of
        # every wallet extension that exists -- wrong IDs here would be
        # worse than no rule at all.
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
        # single-byte XOR key is, by construction, evidence the malware
        # itself reverses that same obfuscation at runtime to use the
        # value it needs -- a direct, first-party observation of
        # Deobfuscate/Decode Files or Information (T1140), not a fragile
        # string-pattern guess.
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
        """Run all mapping methods and combine results."""
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
        """Determine confidence level for an import."""
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
        """Get the full name of an ATT&CK technique."""
        return self.TECHNIQUE_NAMES.get(technique_id, f'Unknown ({technique_id})')

    def _generate_justification(self, technique: str, source: str,
                                evidence: str, confidence: str,
                                count: int = 1) -> str:
        """Generate human-readable justification for an ATT&CK mapping."""
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
