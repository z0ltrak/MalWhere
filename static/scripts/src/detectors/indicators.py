"""Suspicious indicator detection module"""

from typing import List, Dict, Any, Set
from ..models.report import ImportInfo, SectionInfo


class IndicatorDetector:
    """Detect suspicious indicators in PE files."""

    # Suspicious function signatures with ATT&CK mapping
    SUSPICIOUS_IMPORTS = {
        # Process manipulation
        'CreateRemoteThread': 'Process injection (T1055)',
        'VirtualAllocEx': 'Process injection (T1055)',
        'WriteProcessMemory': 'Process injection (T1055)',
        'OpenProcess': 'Process access (T1055)',
        'TerminateProcess': 'Process termination (T1489)',
        'CreateProcess': 'Process creation (T1059)',
        'NtCreateProcess': 'Process creation (T1059)',
        'NtCreateThread': 'Thread creation (T1055)',

        # File system
        'CreateFile': 'File creation (T1070)',
        'DeleteFile': 'File deletion (T1070)',
        'MoveFile': 'File movement (T1070)',
        'CopyFile': 'File copy (T1070)',
        'WriteFile': 'File writing (T1486)',

        # Registry
        'RegCreateKey': 'Registry modification (T1112)',
        'RegOpenKey': 'Registry access (T1112)',
        'RegSetValue': 'Registry modification (T1112)',
        'RegDeleteKey': 'Registry deletion (T1112)',

        # Network
        'socket': 'Network socket (S0105)',
        'connect': 'Network connection (S0105)',
        'send': 'Network sending (S0105)',
        'recv': 'Network receiving (S0105)',
        'WSASocket': 'Network socket (S0105)',
        'WSAStartup': 'Network initialization (S0105)',
        'InternetOpen': 'Internet access (S0105)',
        'URLDownloadToFile': 'File download (T1105)',

        # Cryptography
        'CryptAcquireContext': 'Cryptography (T1486)',
        'CryptDecrypt': 'Cryptography (T1486)',
        'CryptEncrypt': 'Cryptography (T1486)',
        'CryptHashData': 'Cryptography (T1486)',
        'CryptDeriveKey': 'Cryptography (T1486)',
        'BCryptEncrypt': 'Cryptography (T1486)',
        'BCryptGenerateSymmetricKey': 'Cryptography (T1486)',

        # Anti-debugging
        'IsDebuggerPresent': 'Anti-debugging (T1622)',
        'CheckRemoteDebuggerPresent': 'Anti-debugging (T1622)',
        'NtQueryInformationProcess': 'Anti-debugging (T1622)',
        'GetTickCount': 'Anti-debugging/timing (T1497)',
        'QueryPerformanceCounter': 'Anti-debugging/timing (T1497)',

        # Privilege escalation
        'AdjustTokenPrivileges': 'Privilege escalation (T1134)',
        'LookupPrivilegeValue': 'Privilege escalation (T1134)',

        # Service manipulation
        'OpenSCManager': 'Service manipulation (T1569)',
        'CreateService': 'Service creation (T1569)',
        'StartService': 'Service start (T1569)',
        'NtLoadDriver': 'Driver loading - BYOVD (T1068)',
        'ZwLoadDriver': 'Driver loading - BYOVD (T1068)',

        # VSS/Ransomware specific
        'VssSnapshot': 'VSS manipulation (T1490)',
    }

    # Ransomware-specific indicators
    RANSOMWARE_INDICATORS = {
        'vssadmin': 'VSS deletion (T1490)',
        'wbadmin': 'Backup deletion (T1490)',
        'bcdedit': 'Boot config modification (T1490)',
        'wmic': 'WMI usage (T1047)',
        'shadowcopy': 'VSS manipulation (T1490)',
    }

    ANTI_DEBUG_IMPORTS = {
        'IsDebuggerPresent': 'Classic debugger check (T1622)',
        'CheckRemoteDebuggerPresent': 'Remote debugger check (T1622)',
        'NtQueryInformationProcess': 'Process debug port check (T1622)',
        'OutputDebugString': 'Debugger output detection (T1622)',
        'GetTickCount': 'Timing-based detection (T1497)',
        'QueryPerformanceCounter': 'Timing-based detection (T1497)',
        'NtSetInformationThread': 'Thread hiding (T1622)',
        'SetUnhandledExceptionFilter': 'Exception-based detection (T1622)'
    }

    ANTI_VM_IMPORTS = {
        'GetSystemMetrics': 'VM detection through screen resolution (T1497)',
        'NtQuerySystemInformation': 'System information enumeration (T1082)',
        'GetSystemInfo': 'System information enumeration (T1082)'
    }

    def __init__(self):
        self.indicators = {
            'suspicious_imports': [],
            'suspicious_strings': [],
            'high_entropy_sections': [],
            'anti_debug': [],
            'anti_vm': [],
            'ransomware_indicators': []
        }

    def check_imports(self, imports: List[ImportInfo]) -> List[str]:
        """Check imports for suspicious functions with ATT&CK mapping."""
        found = set()
        for imp in imports:
            if imp.function in self.SUSPICIOUS_IMPORTS:
                found.add(f"{imp.function} ({self.SUSPICIOUS_IMPORTS[imp.function]})")
        return sorted(list(found))

    def check_anti_debug(self, imports: List[ImportInfo]) -> List[Dict[str, str]]:
        """Check for anti-debugging techniques."""
        found = []
        for imp in imports:
            if imp.function in self.ANTI_DEBUG_IMPORTS:
                found.append({
                    'technique': self.ANTI_DEBUG_IMPORTS[imp.function],
                    'function': imp.function,
                    'confidence': 'high'
                })
        return found

    def check_anti_vm(self, imports: List[ImportInfo]) -> List[Dict[str, str]]:
        """Check for anti-VM techniques."""
        found = []
        for imp in imports:
            if imp.function in self.ANTI_VM_IMPORTS:
                found.append({
                    'technique': self.ANTI_VM_IMPORTS[imp.function],
                    'function': imp.function,
                    'confidence': 'medium'
                })
        return found

    def check_sections(self, sections: List[SectionInfo]) -> List[Dict[str, Any]]:
        """Check sections for high entropy (packing/encryption)."""
        high_entropy = []
        wx_sections = []

        for section in sections:
            # High entropy sections (packed/encrypted)
            if section.entropy > 7.5:
                high_entropy.append({
                    'name': section.name,
                    'entropy': section.entropy,
                    'note': 'Likely packed or encrypted'
                })

            # W+X sections (Write + Execute) - injection indicator
            if section.is_executable and section.is_writable:
                wx_sections.append({
                    'name': section.name,
                    'note': 'Writable + Executable section (potential injection indicator)'
                })

        # Add W+X findings to the result
        if wx_sections:
            high_entropy.extend(wx_sections)

        return high_entropy

    def check_ransomware_indicators(self, strings: List[str]) -> List[Dict[str, str]]:
        """Check for ransomware-specific indicators in strings."""
        found = []
        for s in strings:
            s_lower = s.lower()
            for indicator, description in self.RANSOMWARE_INDICATORS.items():
                if indicator in s_lower:
                    found.append({
                        'string': s[:50] + '...' if len(s) > 50 else s,
                        'indicator': indicator,
                        'description': description,
                        'confidence': 'high'
                    })
                    break
        return found[:50]

    def analyze(self, imports: List[ImportInfo], sections: List[SectionInfo],
                strings: List[str] = None) -> Dict[str, Any]:
        """Run all indicator checks."""
        result = {
            'suspicious_imports': self.check_imports(imports),
            'high_entropy_sections': self.check_sections(sections),
            'anti_debug': self.check_anti_debug(imports),
            'anti_vm': self.check_anti_vm(imports),
            'ransomware_indicators': []
        }

        if strings:
            result['ransomware_indicators'] = self.check_ransomware_indicators(strings)

        return result
