# RoningLoader — Comprehensive Static Analysis Report

**TFM 2025-2026 — Universidad Complutense de Madrid**

**SHA-256 (sample.exe):** `b0521ad45fd21cdae26afdc74307870c5859421e049bbff2a545852b0ccf0fe6`

**Analysis Date:** August 2026

**Analyst:** z0ltrak

---

## Executive Summary

This report presents a comprehensive manual static analysis of the RoningLoader malware suite. The analysis covers the complete infection chain from initial NSIS installer through DLL side-loading, encrypted payload decryption (RC4), kernel driver installation, userland rootkit capabilities, C2 communication protocol, keylogging, clipboard theft, and defense evasion targeting Chinese security products. All findings have been validated through manual reverse engineering using Ghidra.

---

## 1. Sample Information

| Attribute | Value |
|-----------|-------|
| **Filename** | `sample.exe` (NSIS installer) |
| **SHA-256** | `b0521ad45fd21cdae26afdc74307870c5859421e049bbff2a545852b0ccf0fe6` |
| **Family** | RoningLoader |
| **Type** | Multi-stage loader + RAT + Rootkit |
| **Compiler** | Rust (loader), C/C++ (payload), MSVC 2010/2019 |
| **Source** | MalWhere samples |

---

## 2. Infection Chain Overview

```
sample.exe (NSIS installer)
    │
    ├── 66VOAk0O.exe              ← Signed DirectX installer (legitimate, side-load victim)
    ├── D3D11InstallHelper.dll     ← Malicious Rust DLL (side-loaded)
    ├── 9ZUPMq.3w                  ← RC4-encrypted payload (2.8 MB)
    └── uninstall.exe              ← Decoy
           │
           ▼
    66VOAk0O.exe loads D3D11InstallHelper.dll via DLL side-loading
           │
           ▼
    CheckDirect3D11Status()        ← Misleading function name!
      ├── Read 9ZUPMq.3w from disk
      ├── RC4 decrypt with key "dkwk239c0v023kx"
      ├── Reflective PE loader → payload_at_4841.bin
      └── Execute decrypted payload
           │
           ▼
    payload_at_4841.bin (Rust RAT dropper)
      ├── Drop diamondage.dll      (258 KB) — Userland rootkit DLL
      ├── Drop diamondage.exe      (293 KB) — C2 client + keylogger
      ├── Drop goldendays.dll      (54 KB) — AV killer module
      ├── Drop vmservice.sys       (51 KB) — Kernel rootkit driver
      ├── Drop minifilter_driver.sys (50 KB) — File-hiding MiniFilter
      ├── Install persistence service
      ├── Disable Driver Signature Enforcement (DSE)
      └── Launch C2 client
```

---

## 3. Stage 1: Loader Analysis

### `66VOAk0O.exe` — Signed DirectX Installer

| Function | Purpose |
|----------|---------|
| `d3d11_installer_main` | Main orchestrator — loads DLL, calls decryption |
| `parse_command_line_args` | Parse `/quiet`, `/passive`, `/y`, `/wu`, `/langid` |
| `load_resource_string` | Load UI strings from resource section |
| `show_dialog_box` | Display fake "DirectX Update" dialog |
| `memset_zero` | Optimized memset |
| `format_string_va` | String formatting |
| `exit_wrapper` | CRT exit handler |

### `D3D11InstallHelper.dll` — Malicious Rust DLL

**Language:** Rust

**Exports:**

| Export | Purpose |
|--------|---------|
| `CheckDirect3D11Status` | **RC4 decryptor + reflective PE loader** (misleading name!) |
| `CheckDirect3D11StatusIS` | Registry version check (decoy) |
| `DoD3D11InstallUsingMSI` | Orchestrates payload thread execution |
| `DoUpdateForDirect3D11` | Registry timestamp update (decoy) |
| `DoUpdateForDirect3D11IS` | Wrapper for DoUpdateForDirect3D11 |
| `FinishD3D11InstallUsingMSI` | Wait for payload thread completion |
| `SetD3D11InstallMSIProperties` | Registry path setup (decoy) |

### RC4 Decryption Key

**Algorithm:** RC4 (15-byte effective key from 60-byte .rdata constant)

**Key Source:** `DAT_180028440`, `DAT_180028450`, `DAT_180028460`, RAX, immediate

**Effective Key:** `dkwk239c0v023kx` (15 bytes)

**Key Bytes:**
```
64 6B 77 6B 32 33 39 63 30 76 30 32 33 6B 78
```

**Encrypted File:** `9ZUPMq.3w` (2,858,217 bytes) → Decrypts to PE32+ executable with 4,841-byte header

---

## 4. Stage 2: RAT Dropper Analysis

### `payload_at_4841.bin` — Rust RAT Dropper

**Language:** Rust (confirmed by RNG seed pattern `0x2b992ddfa232`)

**Entry Point:** `main_malware`

### Complete Function Table

| Function | Purpose |
|----------|---------|
| `check_mutex` | Single-instance via `Global\DHGGlobalMutexDriver` |
| `read_registry_config` | Read from `HKCU\SOFTWARE\<PC>\` |
| `write_registry_config` | Write to `HKCU\SOFTWARE\<PC>\` |
| `parse_date` | Parse kill switch date "2026-01-25" |
| `timestamp_to_tm` | Time conversion for kill switch |
| `internet_time_sync` | HTTP Date from `http://www.baidu.com/` |
| `check_360_process` | Check if Qihoo 360 (`360tray.exe`) is running |
| `configure_firewall` | Disable/enable Windows Firewall via COM |
| `bypass_defender` | Inject shellcode into VSS service |
| `kill_av_processes` | Terminate 15 AV processes (360, Tencent, Kingsoft, Defender) |
| `inject_into_process` | IO Completion Port injection into svchost.exe |
| `extract_zip` | Extract ZIP archives |
| `install_zip_contents` | Install ZIP contents to disk |
| `install_vm_service` | Install kernel driver `vmservice.sys` |
| `install_minifilter_driver` | Install MiniFilter driver |
| `start_vmservice` | Start rootkit driver |
| `start_minifilter` | Start file-hiding driver |
| `execute_payload_loop` | Create symlink, launch fake MsMpEng.exe |
| `disable_dse` | Disable Driver Signature Enforcement via Code Integrity policy |

### Embedded Payloads

| Data Address | Size | Output File | Purpose |
|-------------|------|-------------|---------|
| `DAT_1400EB560` | 258,048 bytes | `diamondage.dll` | Userland rootkit DLL |
| `DAT_14012A970` | 293,818 bytes | `diamondage.exe` | C2 client + keylogger |
| `DAT_140152770` | 54,262 bytes | `goldendays.dll` | AV killer (zlib compressed) |
| `DAT_140198390` | 507,113 bytes | `svchost_shellcode.bin` | Raw x64 shellcode |
| `DAT_140214480` | 293,818 bytes | `payload_0x214480.bin` | Additional payload |
| `DAT_14025C040` | 3,052 bytes | `code_integrity.cip` | Code Integrity policy |
| `DAT_14025CC40` | 50,752 bytes | `minifilter_driver.sys` | MiniFilter driver |
| `DAT_140269280` | 51,264 bytes | `vmservice.sys` | Kernel rootkit driver |
| `DAT_140277720` | 227,392 bytes | `vss_shellcode.bin` | PE32+ VSS injection payload |

### Kill Switch

**Date:** `2026-01-25`

**Mechanism:** Fetches current time from Baidu HTTP `Date:` header, compares with hardcoded date. Bypasses local clock manipulation.

### Defense Evasion

| Technique | Implementation |
|-----------|---------------|
| **Firewall Bypass** | COM interface to disable Windows Firewall |
| **Defender Bypass** | Inject into VSS service (vssvc.exe) |
| **UAC Bypass** | `ShellExecuteW("runas")` to re-launch as admin |
| **AV Termination** | Kill 15 processes: 360 (×8), Tencent (×3), Kingsoft (×3), Defender |

---

## 5. Stage 3A: Userland Rootkit — `diamondage.dll`

**Language:** Rust

**Type:** PE32+ DLL (GUI) x86-64, 6 sections, 259,072 bytes

### Architecture

```
diamondage.dll (Userland Rootkit + Watchdog)
│
├── DLL_PROCESS_ATTACH:
│   ├── set_hidden_process_name("diamondage.exe")
│   ├── set_payload_path("C:\ProgramData\DiamondAge\diamondage.exe")
│   ├── init_hidden_connection_table()
│   └── dll_init()
│       ├── Hook NtQuerySystemInformation → hide diamondage.exe
│       └── Hook GetExtendedTcpTable → hide TCP connections
│
├── If DLL named "explorer.exe":
│   └── payload_launcher_thread()
│       └── ShellExecuteExW("C:\...\diamondage.exe") in infinite loop
│
└── Periodic (every 5 seconds):
    └── scan_and_hide_connections()
        └── Find diamondage.exe PIDs → add to hidden hash table
```

### API Hooks Installed

| API Hooked | DLL | Callback | Purpose |
|------------|-----|----------|---------|
| `NtQuerySystemInformation` | ntdll.dll | `hook_nt_query_system_information` | Hide `diamondage.exe` from process lists |
| `GetExtendedTcpTable` | iphlpapi.dll | `hook_get_extended_tcp_table` | Hide TCP connections by PID |

### Hooking Engine Functions

| Function | Purpose |
|----------|---------|
| `install_api_hook` | Install inline hook on API function |
| `toggle_api_hook` | Write/remove JMP patch in API function |
| `control_api_hooks` | Activate/deactivate all hooks |
| `adjust_hooks_in_threads` | Suspend threads, redirect RIP inside hooked functions |

---

## 6. Stage 3B: C2 Client + Keylogger — `diamondage.exe`

**Language:** C/C++ (MSVC 2010)

**Type:** PE32+ executable (GUI) x86-64, 6 sections, 293,818 bytes

### C2 Architecture

```
main_logic()
│
├── check_mutex("Global\DHGGlobalMutexDriver")
├── read_registry_config("Enable") — kill switch
├── XOR decrypt DAT_1400257a0 (0x61) → C2 address
├── background_thread() → DirectInput keylogger + clipboard stealer
├── start_clipboard_monitor() → Hidden window clipboard listener
├── read_registry_config("CopyC") → Base64 + XOR 0x05 → C2 commands
│
└── c2_command_handler()
    ├── connect_to_server() → TCP socket with keep-alive
    ├── collect_system_info() → 12+ system data fields
    └── receiver_thread()
        └── dispatch_c2_command() → 20+ commands
```

### C2 Server

| Attribute | Value |
|-----------|-------|
| **IP Address** | `202.95.11.173` (XOR-encrypted with 0x61 at `DAT_1400257a0`) |
| **Port** | `5552` |
| **Hosting** | RACKIP CONSULTANCY PTE. LTD., Singapore/Hong Kong |
| **ASN** | AS152194 CTG Server Limited |
| **Abuse Contact** | `abuse@ctgserver.net` |

### C2 Communication Protocol

**Transport:** TCP socket with keep-alive (180s idle, 5s interval)

**Packet Format:**
```
┌──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ Padding Size     │ Total Size       │ Random Padding   │ DATA             │
│ (4 bytes)        │ (4 bytes)        │ (N bytes)        │ (variable)       │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

**Anti-DPI:** Random padding size (`rand() % 0x1FF`, default 123 bytes) with random bytes.

### C2 Configuration Channel

**Registry Path:** `HKCU\SOFTWARE\<COMPUTERNAME>\CopyC`

**Encoding:** Base64 → XOR decrypt with key `0x05`

**Command Blob Structure (140 bytes after decode):**

| Offset | Size | Content |
|--------|------|---------|
| `+0x00` | 8 bytes | Header |
| `+0x08` | ~128 bytes | Format string for C2 commands |
| `+0x88` | 4 bytes | Task counter |

### Complete C2 Command Table

| Command | Function | Capability |
|---------|----------|------------|
| **0x00** | `FUN_140015ed8` | Set counter/flag |
| **0x01** | — | **DISABLE** (write `Enable=False`) |
| **0x02** | — | **EXIT** |
| **0x03** | — | Write `Remark` to registry |
| **0x04** | — | Write `ZU` to registry |
| **0x05** | `FUN_140015e58` | Setup/config |
| **0x06** | — | Update config string (39 bytes) |
| **0x07** | `FUN_140015ff8` | **Download & Execute** on desktop |
| **0x09** | `ShellExecuteA` | Execute file (VISIBLE) |
| **0x0A** | `ShellExecuteA` | Execute file (HIDDEN) |
| **0x23** | `dispatch_file_transfer` | **Reflective PE Loader** — load DLL/EXE from memory |
| **0x25** | `dispatch_file_transfer` | **Reflective PE Loader** — load DLL/EXE from memory |
| **0x70** | `handle_status_query` | **Steal clipboard** → send to C2 |
| **0x71** | — | **SET clipboard** (crypto wallet hijack!) |
| **0x7D** | — | **`cmd /c <command>`** (remote shell) |
| **0x7E** | `FUN_1400165c8` | Unknown handler |
| **0x80** | — | **Update CopyC** config (Base64+XOR) |
| **0xEC** | `dispatch_file_transfer` | **Reflective PE Loader** |
| **0xF1** | `FUN_1400169f8` | Unknown handler |
| **0xF3** | `FUN_140015b18` | Unknown handler |
| **0xF8** | `dispatch_file_transfer` | **Reflective PE Loader** |

### Reflective PE Loader

| Function | Purpose |
|----------|---------|
| `dispatch_file_transfer` | Launch file transfer worker thread |
| `file_transfer_worker` | Deserialize command, call `run()` method |
| `load_pe_from_memory` | **Reflective PE loader** — validate MZ/PE, allocate executable memory, fix relocations, resolve imports, call DllMain |
| `resolve_imports` | Resolve DLL imports |
| `fix_relocations` | Fix base relocations |
| `call_entry_point` | Call DllMain |
| `copy_sections` | Copy PE sections |

### Keylogger & Surveillance

| Function | Purpose |
|----------|---------|
| `background_thread` | Keylogger + clipboard stealer main loop |
| `check_keylogger_enabled` | Read `HKCU\offlinekey\open` toggle |
| `init_keylogger` | DirectInput keyboard hook setup |
| `main_keylogger_loop` | Capture keystrokes + clipboard, send to C2 |
| `c2_keystrokes_sender` | Append to `%APPDATA%\microsoft.dotnet.common.log` |

**Clipboard Hijack (Command 0x71):** C2 can **push arbitrary text** into victim's clipboard — classic crypto wallet address replacement attack.

**MetaMask Targeting:** Checks for Chrome extension `nkbihfbeogaaeaoehlefnkodbefgpgknn`.

### Idle Detection

`get_idle_status()` returns `0xD6` (idle) if user inactive > 5 minutes, `0x2A` (active) otherwise. C2 uses this to schedule noisy operations.

---

## 7. Stage 4A: Kernel Rootkit — `vmservice.sys`

**Language:** C/C++

**Type:** PE32+ executable (native) x86-64, 6 sections, 51,264 bytes

**Origin:** Repurposed Zemana AntiMalware driver (`Z:\Zemana\Projects\AntiMalware\bin\zam64.pdb`)

### DriverEntry

| Function | Purpose |
|----------|---------|
| `init_security_cookie` | Initialize GS cookie |
| `DriverEntry` | Set IRP handler, create device, start functionality |

### Kernel-Level DLL Injection

`LoadImageNotifyRoutine` intercepts every image load and injects `diamondage.dll` into target processes:

| Target Process | Injected DLL |
|----------------|-------------|
| `explorer.exe` | `C:\ProgramData\DiamondAge\diamondage.dll` |
| `taskmgr.exe` | `C:\ProgramData\DiamondAge\diamondage.dll` |
| `perfmon.exe` | `C:\ProgramData\DiamondAge\diamondage.dll` |

**Mechanism:** Uses `PsSetLoadImageNotifyRoutine` callback → `PsLookupProcessByProcessId` → find `LdrLoadDll` in ntdll → inject via kernel APC.

**Architecture Detection:** Checks `PsGetProcessWow64Process` to handle 32-bit vs 64-bit processes.

---

## 8. Stage 4B: File-Hiding MiniFilter — `minifilter_driver.sys`

**Language:** C/C++

**Type:** PE32+ executable (native) x86-64, 6 sections, 50,752 bytes

**Origin:** Repurposed Zemana AntiMalware MiniFilter driver

### DriverEntry

| Function | Purpose |
|----------|---------|
| `init_security_cookie` | Initialize GS cookie |
| `DriverEntry` | Register MiniFilter, create comm port, start filtering |

### Communication

**Device Path:** `\\.\MiniFilterControl`

**SymLink:** `\DosDevices\MiniFilterControl`

### IOCTL Commands

| IOCTL | Code | Operation |
|-------|------|-----------|
| `ADD_PATH` | `0x222000` | Add file path to hide/protect (max 20 files) |
| `REMOVE_PATH` | `0x222004` | Remove path (or clear all with PID=0xFFFFFFFF) |
| `QUERY_PATH` | `0x222008` | Check if path is protected |
| `UNKNOWN` | `0x22200C` | Unknown operation |
| `UNKNOWN` | `0x222010` | Unknown operation |

---

## 9. Stage 4C: AV Killer — `goldendays.dll`

**Language:** C/C++ (MSVC 2019)

**Type:** PE32+ executable (DLL) (GUI) x86-64, 6 sections, 105,984 bytes (decompressed from zlib)

**Encoding:** Zlib compressed in raw form

### Exported Functions

| Export | Purpose |
|--------|---------|
| `Wow64LogInitialize` | **Decoy** — returns 0 |
| `Wow64LogMessageArgList` | **Decoy** — returns 0 |
| `Wow64LogSystemService` | **Decoy** — returns 0 |
| `Wow64LogTerminate` | **Decoy** — returns 0 |

### AV Kill List (13 Processes)

| # | Process | Product |
|---|---------|---------|
| 1 | `ZhuDongFangYu.exe` | **Qihoo 360** Active Defense (主动防御) |
| 2 | `360Tray.exe` | **Qihoo 360** tray (capitalized) |
| 3 | `360tray.exe` | **Qihoo 360** tray (lowercase) |
| 4 | `360Safe.exe` | **Qihoo 360** Safe (main AV) |
| 5 | `HipsMain.exe` | **Qihoo 360** HIPS |
| 6 | `HipsDaemon.exe` | **Qihoo 360** HIPS daemon |
| 7 | `HipsTray.exe` | **Qihoo 360** HIPS tray |
| 8 | `QMToolWidget.exe` | **Tencent** PC Manager |
| 9 | `QQPCRTP.exe` | **Tencent** PC Manager (RTP) |
| 10 | `QQPCTray.exe` | **Tencent** PC Manager (tray) |
| 11 | `kxecenter.exe` | **Kingsoft** Antivirus |
| 12 | `kxetray.exe` | **Kingsoft** Antivirus (tray) |
| 13 | `kxemain.exe` | **Kingsoft** Antivirus (main) |

**Mechanism:** On `DLL_PROCESS_ATTACH`, iterates all running processes via `CreateToolhelp32Snapshot`, matches names with `stricmp`, terminates with `TerminateProcess`.

---

## 10. Stage 5: Deployment Scripts

### `config_1.bat` — Disable UAC

```batch
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
```

### `config_2.bat` — Block 360 Security via Firewall

- Reads `C:\ProgramData\lnk\123.txt` (contains path to `360tray.exe`)
- Blocks `360tray.exe` inbound/outbound via `netsh advfirewall`
- Derives `360Safe.exe` path, blocks it too
- Enables Windows Firewall silently
- Disables firewall notifications (hides from user)

**Chinese text encoding:** GB2312/GBK

---

## 11. Additional Embedded Files

| File | Type | Size | Purpose |
|------|------|------|---------|
| `code_integrity.cip` | Data | 3,052 bytes | Code Integrity policy to disable DSE |
| `config_0x197f90.bin` | Zlib compressed | 1,021 bytes | Contains `config_1.bat` + `config_2.bat` |
| `svchost_shellcode.bin` | Raw x64 shellcode | 508,137 bytes | Injected into svchost.exe via IOCP |
| `vss_shellcode.bin` | PE32+ native x64 | 227,392 bytes | Injected into VSS service |
| `payload_0x214480.bin` | Data | 293,818 bytes | Additional payload (possibly encrypted) |

---

## 12. Indicators of Compromise (IOCs)

### Network

| Type | Value |
|------|-------|
| **C2 IP** | `202.95.11.173` |
| **C2 Port** | `5552` |
| **C2 Hosting** | RACKIP CONSULTANCY PTE. LTD., Singapore/Hong Kong |
| **C2 ASN** | AS152194 CTG Server Limited |
| **Time Sync** | `http://www.baidu.com/` |
| **Abuse Contact** | `abuse@ctgserver.net` |

### File System

| Type | Value |
|------|-------|
| **Working Directory** | `C:\ProgramData\DiamondAge\` |
| **Secondary Directory** | `C:\ProgramData\Roning\` |
| **LNK Directory** | `C:\ProgramData\lnk\` |
| **Download Directory** | `C:\Users\Public\Downloads\` |
| **Log File** | `%APPDATA%\microsoft.dotnet.common.log` |
| **Keylogger Toggle** | `HKCU\offlinekey\open` |
| **C2 Config** | `HKCU\SOFTWARE\<COMPUTERNAME>\CopyC` |
| **Kill Switch** | `HKCU\SOFTWARE\<COMPUTERNAME>\Enable` |
| **Clipboard Toggle** | `HKCU\SOFTWARE\<COMPUTERNAME>\clipboard` |
| **Encrypted Payload** | `9ZUPMq.3w` (2,858,217 bytes) |
| **Fake Extension** | `.hjktxt` (actually ZIP files) |

### Mutexes

| Type | Value |
|------|-------|
| **Main Guard** | `Global\DHGGlobalMutexDriver` |
| **Keylogger Guard** | `SystemLogger` |

### Services

| Type | Value |
|------|-------|
| **Persistence** | `MicrosoftSoftware2ShadowCop4yProvider` |
| **Kernel Driver** | `vmservice` |
| **MiniFilter** | `MiniFilterDrv` |

### Devices

| Type | Value |
|------|-------|
| **Rootkit Control** | `\\.\ZemanaAntiMalware` |
| **MiniFilter Control** | `\\.\MiniFilterControl` |

### Browser

| Type | Value |
|------|-------|
| **Targeted Extension** | `nkbihfbeogaaeaoehlefnkodbefgpgknn` (MetaMask) |

### Certificate

| Type | Value |
|------|-------|
| **Organization** | Yongji Zaihui E-commerce Co., Ltd. |
| **Location** | Yongji, Shanxi, China |
| **CA** | Certum Code Signing 2021 CA |

---

## 13. ATT&CK Techniques

| Technique | ID | Implementation |
|-----------|-----|----------------|
| Data Encrypted for Impact | T1486 | RC4-encrypted payload delivery |
| DLL Side-Loading | T1574.002 | `D3D11InstallHelper.dll` side-loaded by signed EXE |
| Reflective Code Loading | T1620 | PE loaded from memory without touching disk |
| Process Injection | T1055 | IO Completion Port injection into svchost.exe |
| Boot or Logon Autostart Execution | T1547 | Windows service persistence |
| Kernel Modules and Extensions | T1547.006 | `vmservice.sys` kernel driver |
| File and Directory Discovery | T1083 | Directory enumeration |
| Process Discovery | T1057 | Process enumeration via snapshot |
| System Information Discovery | T1082 | OS, CPU, hardware ID collection |
| System Owner/User Discovery | T1033 | Checks own process token for Administrator/UAC elevation status |
| Input Capture | T1056 | DirectInput keylogger |
| Clipboard Data | T1115 | Clipboard monitoring and hijacking |
| Impair Defenses | T1562 | Terminate AV processes, disable firewall |
| Debugger Evasion | T1622 | Anti-debugging in driver |
| Modify Registry | T1112 | C2 configuration via registry |
| Command and Scripting Interpreter | T1059 | `cmd /c`, `PowerShell`, batch scripts |
| Indicator Removal | T1070 | Event log clearing via PowerShell |
| Inhibit System Recovery | T1490 | VSS deletion |
| Web Protocols | T1071.001 | HTTP to Baidu for time sync |
| Non-Standard Port | T1571 | C2 on port 5552 |
| Data Encoding | T1132 | Base64 + XOR for C2 commands |
| Deobfuscate/Decode Files or Information | T1140 | RC4, zlib, Base64, XOR |
| Code Signing Policy Modification | T1553.006 | Code Integrity policy to disable DSE |
| Credentials from Password Stores | T1555 | MetaMask extension targeting |

---

## 14. Attribution Assessment

| Attribute | Assessment |
|-----------|------------|
| **Target** | Chinese-speaking users (Qihoo 360, Tencent, Kingsoft AV targeting) |
| **Language** | Rust (loader + RAT dropper + rootkit DLL), C/C++ (C2 client + drivers) |
| **Origin** | Chinese — GB2312/GBK encoded batch scripts |
| **Certificate** | Yongji Zaihui E-commerce Co., Ltd., Shanxi, China |
| **Sophistication** | VERY HIGH — kernel drivers, MiniFilter, DSE bypass, IOCP injection |
| **C2 Infrastructure** | Singapore/Hong Kong hosting |

---

## 15. Decryption Keys

| Algorithm | Key | Usage |
|-----------|-----|-------|
| **RC4** | `dkwk239c0v023kx` (15 bytes) | Decrypt `9ZUPMq.3w` payload |
| **XOR 0x61** | `0x61` | Decrypt C2 address in `diamondage.exe` |
| **XOR 0x05** | `0x05` | Decrypt C2 CopyC commands |
| **XOR 0x5A** | `0x5A` | Decrypt `kernel32.dll` / `EnumTimeFormatsA` strings in loader |
| **Zlib** | Standard deflate | Decompress `goldendays.dll` and `config_0x197f90.bin` |

---

## 16. Summary of Key Findings

1. **Multi-stage architecture** — NSIS installer → DLL side-loading → RC4 decryption → reflective loading → kernel drivers
2. **Dual-language** — Rust for loader/stealth, C/C++ for C2 client and kernel drivers
3. **Chinese targeting** — Specifically kills Qihoo 360, Tencent PC Manager, and Kingsoft AV
4. **Kernel-level persistence** — Repurposed Zemana AntiMalware drivers for rootkit + file hiding
5. **Crypto wallet theft** — MetaMask extension checking + clipboard hijacking for address replacement
6. **Reflective PE loading** — C2 can deploy ANY payload without touching disk
7. **Sophisticated evasion** — DSE bypass, VSS injection, IO Completion Port injection, API hooking
8. **Kill switch** — 2026-01-25 via Baidu HTTP Date header
9. **Registry-based C2** — Commands delivered via `HKCU\SOFTWARE\<PC>\CopyC` as Base64+XOR blobs
10. **Comprehensive surveillance** — Keylogger, clipboard stealer, system recon, idle detection

---

## Appendix A: Complete Function Name Mapping

### D3D11InstallHelper.dll

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `CheckDirect3D11Status` | `decrypt_and_load_payload` | RC4 decrypt .3w + reflective load PE |
| `DoD3D11InstallUsingMSI` | `execute_payload` | Create thread to run decrypted payload |
| `CheckDirect3D11StatusIS` | `check_registry_version` | Read DirectX registry version |
| `DoUpdateForDirect3D11` | `update_registry_timestamp` | Write LastUpdate registry value |
| `FUN_180025da0` | `memcpy` | AVX-optimized memory copy |
| `FUN_180004745` | `file_reader` | CreateFileA + ReadFile → encrypted data |
| `FUN_1800058fa` | `free` | HeapFree wrapper |
| `FUN_1800157d0` | `env_var` | Read environment variable |
| `FUN_1800061a0` | `string_new` | Create heap-allocated string |
| `FUN_180014250` | `path_parse` | Windows path parser |

### payload_at_4841.bin (RAT Dropper)

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_14000b780` | `main_malware` | Main RAT execution |
| `FUN_14000ce20` | `log_message` | Write formatted message to log |
| `FUN_14000ea90` | `log_error_code` | Log numeric error code |
| `FUN_140015ab0` | `internet_time_sync` | HTTP Date from Baidu |
| `FUN_1400026b0` | `check_360_process` | Check if 360tray.exe running |
| `FUN_1400080a0` | `configure_firewall` | Enable/disable Windows Firewall |
| `FUN_140008f80` | `bypass_defender` | Inject into VSS service |
| `FUN_1400074d0` | `kill_av_processes` | Terminate 15 AV processes |
| `FUN_140009340` | `inject_into_process` | IOCP injection into svchost |
| `FUN_1400040b0` | `extract_zip` | Extract ZIP archives |
| `FUN_140005e30` | `install_vm_service` | Install kernel driver service |
| `FUN_140005a10` | `install_minifilter_driver` | Install MiniFilter driver |
| `FUN_140008470` | `disable_dse` | Disable Driver Signature Enforcement |

### diamondage.dll

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_180002b10` | `dll_init` | Hook NtQuerySystemInformation + GetExtendedTcpTable |
| `FUN_180002890` | `hook_nt_query_system_information` | Hide diamondage.exe from process lists |
| `LAB_1800026b0` | `hook_get_extended_tcp_table` | Hide TCP connections by PID |
| `FUN_180002e80` | `payload_launcher_thread` | Watchdog: launch + restart diamondage.exe |
| `FUN_180002420` | `scan_and_hide_connections` | Periodic scan for diamondage.exe PIDs |
| `FUN_1800052fc` | `install_api_hook` | Install inline API hook |
| `FUN_1800050d0` | `toggle_api_hook` | Write/remove JMP patch |
| `FUN_180001000` | `set_hidden_process_name` | Set hidden name to "diamondage.exe" |
| `FUN_180001030` | `set_payload_path` | Build ShellExecuteExW target path |

### diamondage.exe

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_1400149f4` | `main_logic` | Main C2 client logic |
| `FUN_140013d04` | `background_thread` | Keylogger + clipboard stealer |
| `FUN_140013314` | `check_mutex` | Single-instance mutex check |
| `FUN_140015248` | `read_registry_config` | Read from HKCU\SOFTWARE\<PC>\ |
| `FUN_140013a94` | `base64_decode` | Decode Base64 C2 commands |
| `FUN_1400189b4` | `start_clipboard_monitor` | Hidden window clipboard listener |
| `FUN_140014794` | `c2_command_handler` | Main C2 socket client |
| `FUN_1400180c4` | `connect_to_server` | TCP connect with keep-alive |
| `FUN_140014474` | `collect_system_info` | System reconnaissance |
| `FUN_140017c74` | `send_packet` | Send C2 packet with random padding |
| `FUN_140016b48` | `dispatch_c2_command` | C2 command dispatcher (20+ commands) |
| `FUN_1400158d4` | `load_pe_from_memory` | Reflective PE loader |
| `FUN_1400173ac` | `main_keylogger_loop` | DirectInput keylogger loop |
| `FUN_140016f2c` | `c2_keystrokes_sender` | Append to log file |

### vmservice.sys

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_140001b9c` | `DriverEntry` | Initialize kernel driver |
| `FUN_140001c00` | `IrpHandler` | IOCTL dispatch |
| `FUN_140001000` | `LoadImageNotifyRoutine` | Inject diamondage.dll into processes |
| `FUN_140001248` | `InjectDll` | Kernel-level DLL injection |

### minifilter_driver.sys

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_140001818` | `DriverEntry` | Register MiniFilter, start filtering |
| `FUN_140001444` | `SetupCommunicationPort` | Create \\.\MiniFilterControl device |
| `FUN_140001550` | `MiniFilterIrpHandler` | IOCTL dispatch for file hiding |
| `FUN_140001380` | `CommThread` | Heartbeat/monitor thread |

### goldendays.dll

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_1800010d0` | `register_kill_targets` | Register 13 process names to kill |
| `FUN_180001000` | `kill_process_by_name` | Find process by name, TerminateProcess |

---

## Appendix B: Decryption Scripts

### RC4 Decryptor for 9ZUPMq.3w

```python
def rc4_decrypt(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        result[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(result)

key = bytes([0x64, 0x6B, 0x77, 0x6B, 0x32, 0x33, 0x39, 0x63,
             0x30, 0x76, 0x30, 0x32, 0x33, 0x6B, 0x78])
# "dkwk239c0v023kx"

with open("9ZUPMq.3w", "rb") as f:
    encrypted = f.read()

decrypted = rc4_decrypt(encrypted, key)
with open("payload_decrypted.bin", "wb") as f:
    f.write(decrypted)
```

### Zlib Decompressor for goldendays.dll

```python
import zlib

with open("goldendays.dll", "rb") as f:
    data = f.read()

# Find zlib magic at offset 0x28
decompressed = zlib.decompress(data[0x28:])
with open("goldendays_clean.dll", "wb") as f:
    f.write(decompressed)
```

---

## Appendix C: Validation Summary

| Finding | Status |
|---------|--------|
| NSIS installer extraction | ✅ Verified |
| DLL side-loading | ✅ Verified |
| RC4 decryption key | ✅ Verified — `dkwk239c0v023kx` |
| Payload decryption | ✅ Verified — PE32+ with 4841-byte header |
| C2 address extraction | ✅ Verified — `202.95.11.173:5552` |
| C2 command protocol | ✅ Verified — 20+ commands mapped |
| Reflective PE loader | ✅ Verified — MZ/PE validation, reloc fix, import resolve |
| DirectInput keylogger | ✅ Verified |
| Clipboard hijacking | ✅ Verified — Command 0x71 |
| AV process kill list | ✅ Verified — 13 processes (360, Tencent, Kingsoft) |
| Kernel driver injection | ✅ Verified — explorer/taskmgr/perfmon |
| MiniFilter IOCTLs | ✅ Verified — 5 commands mapped |
| Zlib decompression | ✅ Verified — goldendays.dll + config scripts |
| Batch scripts | ✅ Verified — UAC disable + 360 firewall block |
| Certificate attribution | ✅ Verified — Yongji Zaihui E-commerce, Shanxi, China |
| Kill switch date | ✅ Verified — 2026-01-25 |
