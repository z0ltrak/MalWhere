<#
.SYNOPSIS
    One-shot setup for the win10x64 CAPE guest VM (docker/README.md's
    "Creating the Guest VM" section, steps 6-10).

.DESCRIPTION
    Run this from an elevated PowerShell prompt, INSIDE the guest VM, once
    you've reached the desktop with the network attached (README step 5) and
    logged in as the mandatory local account below. It automates:
      - Step 6: static IP + DNS on the sandbox network
      - Step 7: auto-login registry keys
      - Step 8: disable Windows Update, Defender, and the firewall
      - Step 9: fully disable UAC (not just the "Never notify" slider)
      - Step 10: install Python 3.12, drop the CAPE agent, and start it at
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

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Warn2($msg) { Write-Host "    WARNING: $msg" -ForegroundColor Yellow }

# --- Step 6: static IP + DNS ------------------------------------------------
Write-Step "Setting static IP $StaticIP/$PrefixLength, gateway $Gateway, DNS $DnsServer"
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
if (-not $adapter) { throw "No active network adapter found -- attach the NIC (README step 5) before running this script." }

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
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Set-Service wuauserv -StartupType Disabled

Write-Step "Disabling Defender real-time/cloud protection and sample submission"
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true `
    -DisableBehaviorMonitoring $true -MAPSReporting 0 -SubmitSamplesConsent 2 `
    -ErrorAction SilentlyContinue
$tamperStatus = $null
try { $tamperStatus = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected } catch {}
if ($tamperStatus) {
    Write-Warn2 "Tamper Protection is ON -- Defender will silently re-enable itself and none of the above took effect. Turn it off manually: Windows Security -> Virus & threat protection -> Manage settings -> Tamper Protection, then re-run this script."
}

# --- Step 9: fully disable UAC ----------------------------------------------
Write-Step "Disabling UAC (EnableLUA=0 -- needs a reboot to take effect)"
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name EnableLUA -Value 0 -Type DWord

# --- Step 10: Python + CAPE agent -------------------------------------------
Write-Step "Downloading and installing Python $PythonVersion"
$pyInstaller = Join-Path $env:TEMP 'python-installer.exe'
Invoke-WebRequest -Uri $PythonUrl -OutFile $pyInstaller
Start-Process $pyInstaller -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait

$pythonwPath = "C:\Program Files\Python$($PythonVersion -replace '\.\d+$','' -replace '\.','')\pythonw.exe"
if (-not (Test-Path $pythonwPath)) {
    $found = Get-ChildItem 'C:\Program Files\Python*','C:\Users\*\AppData\Local\Programs\Python\Python*' `
        -Filter pythonw.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $pythonwPath = $found.FullName }
    else { throw "pythonw.exe not found after install -- check $pyInstaller ran correctly." }
}
Write-Host "    Using pythonw.exe at: $pythonwPath"

Write-Step "Downloading the CAPE agent to $AgentPath"
Invoke-WebRequest -Uri $AgentUrl -OutFile $AgentPath

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
Write-Host "  3. Take the clean-baseline snapshot (README step 11), from the host, VM still running:"
Write-Host "     virsh snapshot-create-as win10x64 clean_baseline --atomic"
