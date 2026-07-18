"""YARA rule parser for static analysis."""

import yara
import os
import json
from typing import Dict, List, Any
from pathlib import Path


class YaraParser:
    """Parse PE files using YARA rules."""

    # Built-in rules for common packers and behaviors
    DEFAULT_RULES = '''
    rule UPX_packed {
        meta:
            description = "Detects UPX packed executables"
        strings:
            $upx1 = "UPX0"
            $upx2 = "UPX1"
            $upx3 = "UPX!"
            $upx4 = "UPX"
        condition:
            any of them
    }

    rule Themida_packed {
        meta:
            description = "Detects Themida packed executables"
        strings:
            $themida = "Themida"
            $themida2 = "TMD"
        condition:
            any of them
    }

    rule VMProtect_packed {
        meta:
            description = "Detects VMProtect packed executables"
        strings:
            $vmprotect = "VMProtect"
            $vmp = "VMP"
        condition:
            any of them
    }

    rule MPRESS_packed {
        meta:
            description = "Detects MPRESS packed executables"
        strings:
            $mpress = "MPRESS"
            $mpress2 = ".mpress"
        condition:
            any of them
    }

    rule ASPack_packed {
        meta:
            description = "Detects ASPack packed executables"
        strings:
            $aspack = ".aspack"
            $aspack2 = "ASPack"
        condition:
            any of them
    }

    rule PECompact_packed {
        meta:
            description = "Detects PECompact packed executables"
        strings:
            $pecompact = ".pecompact"
            $pecompact2 = "PECompact"
        condition:
            any of them
    }

    rule AutoRun_persistence {
        meta:
            description = "Detects autorun persistence mechanism"
        strings:
            $run = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
            $runonce = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce"
        condition:
            any of them
    }

    rule AntiDebug_IsDebuggerPresent {
        meta:
            description = "Detects IsDebuggerPresent API usage"
        strings:
            $api = "IsDebuggerPresent"
        condition:
            $api
    }

    rule AntiDebug_CheckRemoteDebuggerPresent {
        meta:
            description = "Detects CheckRemoteDebuggerPresent API usage"
        strings:
            $api = "CheckRemoteDebuggerPresent"
        condition:
            $api
    }

    rule AntiDebug_NtQueryInformationProcess {
        meta:
            description = "Detects NtQueryInformationProcess API usage"
        strings:
            $api = "NtQueryInformationProcess"
        condition:
            $api
    }

    rule C2_Detection {
        meta:
            description = "Detects potential C2 communication patterns"
        strings:
            $url = /https?:\/\/[^\s]+/
            $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        condition:
            any of them
    }
    '''

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.errors: List[str] = []
        self.rules = None
        self._compile_rules()

    def _compile_rules(self):
        """Compile the default YARA rules."""
        try:
            self.rules = yara.compile(source=self.DEFAULT_RULES)
        except Exception as e:
            self.errors.append(f"Failed to compile YARA rules: {e}")
            self.rules = None

    def scan(self) -> Dict[str, Any]:
        """Scan the file with YARA rules."""
        result = {
            'matches': [],
            'matched_rules': [],
            'packer_detected': False,
            'packers': []
        }

        if self.rules is None:
            self.errors.append("YARA rules not compiled")
            return result

        try:
            matches = self.rules.match(str(self.file_path))

            for match in matches:
                rule_name = match.rule
                result['matches'].append({
                    'rule': rule_name,
                    'meta': match.meta,
                    'strings': [str(s) for s in match.strings]
                })
                result['matched_rules'].append(rule_name)

                # Check for packer detection
                if 'packed' in rule_name.lower():
                    result['packer_detected'] = True
                    result['packers'].append({
                        'name': rule_name.replace('_packed', '').replace('_', ' '),
                        'confidence': 'high',
                        'source': 'YARA'
                    })

                # Map to ATT&CK techniques
                if 'persistence' in rule_name.lower():
                    result['attck_mapping'] = result.get('attck_mapping', [])
                    result['attck_mapping'].append({
                        'technique': 'T1547',
                        'name': 'Boot/Logon Autostart Execution',
                        'rule': rule_name
                    })
                elif 'AntiDebug' in rule_name:
                    result['attck_mapping'] = result.get('attck_mapping', [])
                    result['attck_mapping'].append({
                        'technique': 'T1622',
                        'name': 'Debugger Evasion',
                        'rule': rule_name
                    })

        except Exception as e:
            self.errors.append(f"YARA scan error: {e}")

        return result

    def get_errors(self) -> List[str]:
        """Get scanning errors."""
        return self.errors
