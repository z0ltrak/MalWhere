"""Suspicious indicator detection module"""
from typing import List, Dict, Any, Set
from ..models.report import ImportInfo, SectionInfo


class IndicatorDetector:
    """Detect suspicious indicators in PE files"""

    # Suspicious function signatures
    SUSPICIOUS_IMPORTS = {
        # Process manipulation
        'CreateRemoteThread': 'Process injection',
        'VirtualAllocEx': 'Process injection',
        'WriteProcessMemory': 'Process injection',
        'OpenProcess': 'Process access',
        'TerminateProcess': 'Process termination',
        'CreateProcess': 'Process creation',
        'NtCreateProcess': 'Process creation',
        'NtCreateThread': 'Thread creation',

        # File system
        'CreateFile': 'File creation',
        'DeleteFile': 'File deletion',
        'MoveFile': 'File movement',
        'CopyFile': 'File copy',
        'WriteFile': 'File writing',

        # Registry
        'RegCreateKey': 'Registry modification',
        'RegOpenKey': 'Registry access',
        'RegSetValue': 'Registry modification',
        'RegDeleteKey': 'Registry deletion',

        # Network
        'socket': 'Network socket',
        'connect': 'Network connection',
        'send': 'Network sending',
        'recv': 'Network receiving',
        'WSASocket': 'Network socket',
        'WSAStartup': 'Network initialization',
        'InternetOpen': 'Internet access',
        'URLDownloadToFile': 'File download',

        # Cryptography
        'CryptAcquireContext': 'Cryptography',
        'CryptDecrypt': 'Cryptography',
        'CryptEncrypt': 'Cryptography',
        'CryptHashData': 'Cryptography',
        'CryptDeriveKey': 'Cryptography',

        # Anti-debugging
        'IsDebuggerPresent': 'Anti-debugging',
        'CheckRemoteDebuggerPresent': 'Anti-debugging',
        'NtQueryInformationProcess': 'Anti-debugging',
        'GetTickCount': 'Anti-debugging/timing',

        # Privilege escalation
        'AdjustTokenPrivileges': 'Privilege escalation',
        'LookupPrivilegeValue': 'Privilege escalation',

        # Service manipulation
        'OpenSCManager': 'Service manipulation',
        'CreateService': 'Service creation',
        'StartService': 'Service start'
    }

    # Anti-debugging functions
    ANTI_DEBUG_IMPORTS = {
        'IsDebuggerPresent': 'Classic debugger check',
        'CheckRemoteDebuggerPresent': 'Remote debugger check',
        'NtQueryInformationProcess': 'Process debug port check',
        'OutputDebugString': 'Debugger output detection',
        'GetTickCount': 'Timing-based detection',
        'QueryPerformanceCounter': 'Timing-based detection',
        'NtSetInformationThread': 'Thread hiding',
        'SetUnhandledExceptionFilter': 'Exception-based detection'
    }

    # Anti-VM functions
    ANTI_VM_IMPORTS = {
        'GetSystemMetrics': 'VM detection through screen resolution',
        'NtQuerySystemInformation': 'System information enumeration',
        'GetSystemInfo': 'System information enumeration'
    }

    def __init__(self):
        self.indicators = {
            'suspicious_imports': [],
            'suspicious_strings': [],
            'high_entropy_sections': [],
            'anti_debug': [],
            'anti_vm': []
        }


    """Check imports for suspicious functions"""
    def check_imports(self, imports: List[ImportInfo]) -> List[str]:
        found = set()
        for imp in imports:
            if imp.function in self.SUSPICIOUS_IMPORTS:
                found.add(f"{imp.function} ({self.SUSPICIOUS_IMPORTS[imp.function]})")
        return sorted(list(found))


    """Check for anti-debugging techniques"""
    def check_anti_debug(self, imports: List[ImportInfo]) -> List[Dict[str, str]]:
        found = []
        for imp in imports:
            if imp.function in self.ANTI_DEBUG_IMPORTS:
                found.append({
                    'technique': self.ANTI_DEBUG_IMPORTS[imp.function],
                    'function': imp.function,
                    'confidence': 'high'
                })
        return found


    """Check for anti-VM techniques"""
    def check_anti_vm(self, imports: List[ImportInfo]) -> List[Dict[str, str]]:
        found = []
        for imp in imports:
            if imp.function in self.ANTI_VM_IMPORTS:
                found.append({
                    'technique': self.ANTI_VM_IMPORTS[imp.function],
                    'function': imp.function,
                    'confidence': 'medium'
                })
        return found


    """Check sections for high entropy (packing/encryption)"""
    def check_sections(self, sections: List[SectionInfo]) -> List[Dict[str, Any]]:
        high_entropy = []
        for section in sections:
            if section.entropy > 7.5:
                high_entropy.append({
                    'name': section.name,
                    'entropy': section.entropy,
                    'note': 'Likely packed or encrypted'
                })
        return high_entropy


    """Run all indicator checks"""
    def analyze(self, imports: List[ImportInfo], sections: List[SectionInfo]) -> Dict[str, Any]:
        return {
            'suspicious_imports': self.check_imports(imports),
            'high_entropy_sections': self.check_sections(sections),
            'anti_debug': self.check_anti_debug(imports),
            'anti_vm': self.check_anti_vm(imports)
        }
