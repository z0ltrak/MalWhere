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
        'GetSystemInfo': 'T1082',
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
        'WNetGetConnectionW': 'T1135',
        'WNetGetConnectionA': 'T1135',

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
                elif len(functions) >= 2:
                    confidence = 'medium'
                else:
                    confidence = self._determine_import_confidence(functions[0])
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

        return mappings

    def map_all(self, strings: List[str], imports: List[Dict[str, str]],
                yara_data: Dict[str, Any], entropy_findings: List,
                config: Dict[str, Any]) -> List[ATTACKMapping]:
        """Run all mapping methods and combine results."""
        all_mappings = []
        all_mappings.extend(self.map_strings(strings))
        all_mappings.extend(self.map_imports(imports))
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

        elif source == 'yara':
            return f"YARA rule '{evidence}' matched the sample. This rule was specifically designed to detect {technique_name} patterns, confirming the presence of this capability."

        elif source == 'entropy':
            return f"Entropy analysis detected {evidence}. High entropy sections often indicate {technique_name} through packed or encrypted data."

        elif source == 'config':
            return f"Configuration artifact '{evidence}' was extracted. This artifact is associated with {technique_name} in known malware campaigns."

        else:
            return f"Evidence '{evidence}' supports the attribution of {technique_name} to this sample."
