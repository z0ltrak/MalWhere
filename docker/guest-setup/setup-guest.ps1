<#
.SYNOPSIS
    One-shot setup for the win10x64 CAPE guest VM (docker/README.md's
    "Creating the Guest VM" section, steps 6-10).

.DESCRIPTION
    Run this from an elevated PowerShell prompt, INSIDE the guest VM, once
    you've reached the desktop with the network attached (README step 5) and
    logged in as the mandatory local account below. It automates:
      - Step 6a: download Python 3.12 and the CAPE agent (needs real
        internet -- done first, deliberately, before DNS switches to the
        sandbox network's fake-answer-only resolver in 6b)
      - Step 6b: static IP + DNS on the sandbox network
      - Step 7: auto-login registry keys
      - Step 8: disable Windows Update, Defender, and the firewall
      - Step 9: fully disable UAC (not just the "Never notify" slider)
      - Step 10: install Python, wire up the CAPE agent, and start it at
        every logon via a Startup-folder shortcut

    It does NOT do Windows Setup itself (README steps 1-5) or the final
    snapshot (README step 11, run on the HOST after this script finishes).

    Exists to remove the class of bug this project has repeatedly hit on
    fresh machines: a hand-typed reg/netsh command with a wrong value (wrong
    adapter, wrong username, a typo in an IP) that only surfaces much later
    as "CAPE can't reach the agent" or "the VM didn't come back up logged
    in" -- see docker/README.md's "Automating this" note for context.

.NOTES
    MANDATORY local account: username "sandbox", password "sandbox".
    Hardcoded below (not read from the account you're running as) so the
    auto-login registry keys are guaranteed to match the account you
    actually created in Windows Setup. If you created the account with a
    different name/password, this script will still "succeed" but auto-login
    will silently log into a nonexistent identity -- redo Setup with these
    exact credentials instead of editing this script, or every other machine
    running this repo's setup diverges from what's documented and tested.
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1's default SecurityProtocol on a fresh, unpatched
# Windows 10 install doesn't include TLS 1.2 -- python.org (and
# raw.githubusercontent.com) refuse the handshake, and Invoke-WebRequest
# below fails with "The underlying connection was closed: An unexpected
# error occurred on a send." Force it before either download runs.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$SandboxUser     = 'sandbox'
$SandboxPassword = 'sandbox'
$StaticIP        = '192.168.122.100'
$PrefixLength    = 24
$Gateway         = '192.168.122.1'
$DnsServer       = '192.168.122.1'
$PythonVersion   = '3.12.7'
$PythonUrl       = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
$AgentUrl        = 'https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/agent/agent.py'
$AgentPath       = 'C:\agent.py'
$Pywin32PyTag    = 'cp312-cp312-win_amd64.whl'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Warn2($msg) { Write-Host "    WARNING: $msg" -ForegroundColor Yellow }

# --- Step 6a: download Python + the CAPE agent while real DNS still works --
# Has to happen before the switch to the sandbox's static IP/DNS below: once
# DNS points at $DnsServer (inetsim, by design a fake-answer-only blackhole
# with real DNS forwarding deliberately disabled -- see docker/README.md's
# "guest VM resolves real domains" Known Issue), python.org and
# raw.githubusercontent.com stop resolving to anything real. Force a public
# resolver on the current (DHCP) config just long enough to grab both files.
Write-Step "Fetching Python $PythonVersion and the CAPE agent (needs real internet, done before the sandbox network lockdown below)"
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
if (-not $adapter) { throw "No active network adapter found -- attach the NIC (README step 5) before running this script." }
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses 8.8.8.8

$pyInstaller = Join-Path $env:TEMP 'python-installer.exe'
Invoke-WebRequest -Uri $PythonUrl -OutFile $pyInstaller
Invoke-WebRequest -Uri $AgentUrl -OutFile $AgentPath

# pywin32: NOT bundled with the python.org installer, but analyzer.py imports
# win32api/win32con/etc. for essentially all of its Windows monitoring and
# injection code. Without it, analyzer.py crashes on import on every single
# task -- confirmed the hard way: this produced zero behavioral data (empty
# logs/CAPE/shots folders, no error anywhere CAPE surfaces) for every family
# tested, indistinguishable from the agent just hanging. Resolve the current
# wheel URL from PyPI's JSON API rather than hardcoding a version-specific
# download link that goes stale; fetch it now, in the same real-internet
# window as Python itself, since the sandbox network can't reach PyPI later.
Write-Step "Fetching pywin32 (analyzer.py needs it for all Windows API access -- see docker/README.md's Known Issues)"
$pywin32Info = Invoke-RestMethod -Uri 'https://pypi.org/pypi/pywin32/json'
$pywin32Wheel = $pywin32Info.urls | Where-Object { $_.filename -like "*-$Pywin32PyTag" } | Select-Object -First 1
if (-not $pywin32Wheel) { throw "Could not find a pywin32 wheel matching *-$Pywin32PyTag on PyPI -- check $PythonVersion still maps to that ABI tag." }
$pywin32WheelPath = Join-Path $env:TEMP $pywin32Wheel.filename
Invoke-WebRequest -Uri $pywin32Wheel.url -OutFile $pywin32WheelPath

# --- Step 6b: static IP + DNS -----------------------------------------------
Write-Step "Setting static IP $StaticIP/$PrefixLength, gateway $Gateway, DNS $DnsServer"
Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -ne '0.0.0.0' } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $StaticIP `
    -PrefixLength $PrefixLength -DefaultGateway $Gateway | Out-Null
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DnsServer

# --- Step 7: auto-login ------------------------------------------------------
Write-Step "Configuring auto-login as '$SandboxUser'"
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $winlogon -Name AutoAdminLogon -Value '1' -Type String
Set-ItemProperty $winlogon -Name DefaultUserName -Value $SandboxUser -Type String
Set-ItemProperty $winlogon -Name DefaultPassword -Value $SandboxPassword -Type String

# --- Step 8: disable Windows Update, Defender, firewall --------------------
Write-Step "Disabling the firewall (all profiles)"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Write-Step "Disabling Windows Update"
# Same "stop the service and hope" gap as Defender below, and it has the
# same failure mode: Set-Service -StartupType Disabled doesn't stop Update
# Orchestrator (UsoSvc) from restarting wuauserv on-demand regardless of its
# configured start type. Add the policy registry key too, and verify.
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Set-Service wuauserv -StartupType Disabled
Stop-Service UsoSvc -Force -ErrorAction SilentlyContinue
Set-Service UsoSvc -StartupType Disabled -ErrorAction SilentlyContinue
$wuPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $wuPolicyPath -Force | Out-Null
Set-ItemProperty -Path $wuPolicyPath -Name NoAutoUpdate -Value 1 -Type DWord

$wuSvc = Get-Service wuauserv -ErrorAction SilentlyContinue
if ($wuSvc -and $wuSvc.Status -ne 'Stopped') {
    Write-Warn2 "wuauserv is still '$($wuSvc.Status)' -- Windows Update may still be reachable. This mattered in practice: a guest that can quietly patch itself no longer matches whatever behavior a sample showed on the day the clean-baseline snapshot was taken, and dynamic-analysis results stop being reproducible over the guest's lifetime."
}

Write-Step "Disabling Defender real-time/cloud protection and sample submission"
# Set-MpPreference alone is NOT enough -- confirmed the hard way: a guest
# built with only this had RealTimeProtectionEnabled/BehaviorMonitorEnabled
# still True days later, with Tamper Protection OFF the whole time (so that
# wasn't even the cause -- the preference-based disable just doesn't
# reliably stick by itself). Defender's behavior monitor silently ate every
# single dynamic-analysis run: CAPE's monitor injection never produced any
# logs/dropped-files/screenshots, with no error anywhere, for weeks, because
# nothing crashes -- Defender just quietly neutralizes it. Belt-and-braces
# fix: Set-MpPreference AND the policy registry keys (a stronger, more
# durable disable than preferences alone), THEN VERIFY both the reported
# status and the actual WinDefend service state -- don't just trust that
# the commands didn't error.
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true `
    -DisableBehaviorMonitoring $true -MAPSReporting 0 -SubmitSamplesConsent 2 `
    -ErrorAction SilentlyContinue

$defenderPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$rtpPolicyPath = "$defenderPolicyPath\Real-Time Protection"
New-Item -Path $defenderPolicyPath -Force | Out-Null
Set-ItemProperty -Path $defenderPolicyPath -Name DisableAntiSpyware -Value 1 -Type DWord
New-Item -Path $rtpPolicyPath -Force | Out-Null
foreach ($name in 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection', 'DisableScanOnRealtimeEnable') {
    Set-ItemProperty -Path $rtpPolicyPath -Name $name -Value 1 -Type DWord
}

$tamperStatus = $null
try { $tamperStatus = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected } catch {}
if ($tamperStatus) {
    throw "Tamper Protection is ON -- Defender will silently re-enable itself and none of the above will take effect. Turn it off manually: Windows Security -> Virus & threat protection -> Manage settings -> Tamper Protection, then re-run this script."
}

Write-Step "Verifying Defender is actually off (not just that the commands didn't error)"
Start-Sleep -Seconds 2
$svc = Get-Service WinDefend -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    throw "WinDefend service is still '$($svc.Status)' after attempting to disable it. Reboot and re-run this script -- if it's still running after that, Defender is being re-enabled by something outside this script's control (Group Policy, an MDM/Intune enrollment, a scheduled platform update) and needs to be tracked down by hand before taking the clean-baseline snapshot, or every dynamic analysis run on this VM will silently produce empty results with no error."
}
Write-Host "    WinDefend service: Stopped -- confirmed off." -ForegroundColor Green

# --- Step 9: fully disable UAC ----------------------------------------------
Write-Step "Disabling UAC (EnableLUA=0 -- needs a reboot to take effect)"
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name EnableLUA -Value 0 -Type DWord

# --- Step 10: Python + CAPE agent -------------------------------------------
# Both files were already fetched in Step 6a, before the network went into
# its final sandboxed (no-real-DNS) state -- this just installs/wires up
# what's already on disk, no network needed here.
Write-Step "Installing Python $PythonVersion"
Start-Process $pyInstaller -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait

$pythonwPath = "C:\Program Files\Python$($PythonVersion -replace '\.\d+$','' -replace '\.','')\pythonw.exe"
if (-not (Test-Path $pythonwPath)) {
    $found = Get-ChildItem 'C:\Program Files\Python*','C:\Users\*\AppData\Local\Programs\Python\Python*' `
        -Filter pythonw.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $pythonwPath = $found.FullName }
    else { throw "pythonw.exe not found after install -- check $pyInstaller ran correctly." }
}
Write-Host "    Using pythonw.exe at: $pythonwPath"
$pythonExePath = Join-Path (Split-Path $pythonwPath) 'python.exe'

Write-Step "Installing pywin32 (offline -- fetched in Step 6a, before the sandbox network locked out real internet)"
& $pythonExePath -m pip install --no-index $pywin32WheelPath
if ($LASTEXITCODE -ne 0) { throw "pip install of the pywin32 wheel failed (exit $LASTEXITCODE) -- see output above." }

Write-Step "Verifying pywin32 actually imports (not just that pip reported success)"
$verifyOut = & $pythonExePath -c "import win32api; print(win32api.GetVersion())" 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "win32api failed to import after installing pywin32: $verifyOut -- analyzer.py will silently crash on every task without this. Confirmed hitting exactly this: it produces empty logs/CAPE/shots folders with no error anywhere CAPE surfaces, indistinguishable from the agent just hanging."
}
Write-Host "    win32api imports OK (GetVersion: $verifyOut)." -ForegroundColor Green

Write-Step "Creating a Startup-folder shortcut so the agent runs at every logon"
$startupDir = [Environment]::GetFolderPath('Startup')
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $startupDir 'CAPE Agent.lnk'))
$shortcut.TargetPath = $pythonwPath
$shortcut.Arguments = "`"$AgentPath`""
$shortcut.Save()

Write-Step "Starting the agent now, so you can verify it without rebooting first"
Start-Process $pythonwPath -ArgumentList "`"$AgentPath`""

Write-Host ""
Write-Host "Done. Next steps:" -ForegroundColor Green
Write-Host "  1. Reboot (required for the UAC change to take effect)."
Write-Host "  2. From the HOST, verify the agent: curl -s http://${StaticIP}:8000/ | python3 -m json.tool"
Write-Host "     Expect: is_user_admin: true (confirms UAC is actually off, not just the slider)."
Write-Host "  3. Reset and verify the agent's OWN internal status is clean, from the HOST -- this is"
Write-Host "     the step that's easy to skip and silently ruins the snapshot: the agent is a"
Write-Host "     long-running process that's ALSO part of the live snapshot's frozen memory, and if"
Write-Host "     anything (a stray test, a health-check, poking at it while debugging something"
Write-Host "     else) ever called its /execute or /execpy endpoints before you snapshot, its"
Write-Host "     internal status gets stuck at 'running' -- baked into the snapshot forever. CAPE's"
Write-Host "     analyzer.py then hangs completely silently on every single future task using this"
Write-Host "     snapshot: zero logs, zero dropped files, zero screenshots, no error anywhere,"
Write-Host "     because it never gets past its own startup. Confirmed hitting exactly this."
Write-Host "     curl -s -X POST http://${StaticIP}:8000/status -d 'status=init'"
Write-Host "     curl -s http://${StaticIP}:8000/status"
Write-Host "     Expect the second command to show `"status`": `"init`" -- if it shows anything else,"
Write-Host "     do NOT snapshot yet; something is still using the agent."
Write-Host "  4. Take the clean-baseline snapshot (README step 11), from the host, VM still running:"
Write-Host "     virsh snapshot-create-as win10x64 clean_baseline --atomic"
