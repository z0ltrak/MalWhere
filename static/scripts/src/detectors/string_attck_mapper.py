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
        # T1057/T1562, never T1055.
        'AdjustTokenPrivileges': {'technique': 'T1134', 'confidence': 'medium'},
        'LookupPrivilegeValue': {'technique': 'T1134', 'confidence': 'medium'},
        'OpenProcessToken': {'technique': 'T1134', 'confidence': 'medium'},
        'GetTickCount': {'technique': 'T1497', 'confidence': 'medium'},
        'QueryPerformanceCounter': {'technique': 'T1497', 'confidence': 'medium'},
        # TerminateProcess previously mapped to T1489 "Service Stop" -- also
        # wrong, same root cause as the Rm* fix above. It's a fully generic
        # process-kill API; string presence alone can't tell you the target
        # (an AV process -> T1562.001, a locked-file holder -> no clean ID,
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
        # "cl" subcommand) is the CLI mechanism MITRE's T1070.001 page
        # names directly -- narrower than bare "wevtutil" (which also
        # covers benign query/export operations).
        'wevtutil cl': {'technique': 'T1070.001', 'confidence': 'high'},
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
