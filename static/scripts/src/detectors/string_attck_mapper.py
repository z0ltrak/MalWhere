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

        # MEDIUM Confidence — Suspicious API calls
        'WTSEnumerateProcessesW': {'technique': 'T1057', 'confidence': 'medium'},
        'WTSFreeMemory': {'technique': 'T1057', 'confidence': 'medium'},
        'WNetGetConnectionW': {'technique': 'T1135', 'confidence': 'medium'},
        'RmStartSession': {'technique': 'T1489', 'confidence': 'medium'},
        'RmShutdown': {'technique': 'T1489', 'confidence': 'medium'},
        'RmEndSession': {'technique': 'T1489', 'confidence': 'medium'},
        'RmRegisterResources': {'technique': 'T1489', 'confidence': 'medium'},
        'RmGetList': {'technique': 'T1489', 'confidence': 'medium'},
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
        'OpenProcess': {'technique': 'T1055', 'confidence': 'medium'},
        'AdjustTokenPrivileges': {'technique': 'T1134', 'confidence': 'medium'},
        'LookupPrivilegeValue': {'technique': 'T1134', 'confidence': 'medium'},
        'OpenProcessToken': {'technique': 'T1134', 'confidence': 'medium'},
        'GetTickCount': {'technique': 'T1497', 'confidence': 'medium'},
        'QueryPerformanceCounter': {'technique': 'T1497', 'confidence': 'medium'},
        'TerminateProcess': {'technique': 'T1489', 'confidence': 'medium'},
        'DeleteFile': {'technique': 'T1070', 'confidence': 'medium'},

        # LOW Confidence — Too generic (only map with other evidence)
        'WriteFile': {'technique': 'T1486', 'confidence': 'low'},
        'CreateFile': {'technique': 'T1070', 'confidence': 'low'},
        'Sleep': {'technique': 'T1497', 'confidence': 'low'},
        'GetSystemInfo': {'technique': 'T1082', 'confidence': 'low'},
        'FindFirstFile': {'technique': 'T1083', 'confidence': 'low'},
        'FindNextFile': {'technique': 'T1083', 'confidence': 'low'},
        'IsDebuggerPresent': {'technique': 'T1622', 'confidence': 'low'},
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
