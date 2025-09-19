# securewin
What is SecureWin?
SecureWin is a PowerShell script designed to significantly improve the security posture of Windows 10 and 11 systems by automating a comprehensive set of hardening measures. It inspects autostart programs, installs all system updates, disables outdated and risky services, configures an aggressive firewall policy, disables remote access features, strengthens Windows Defender protections, and performs system health verifications.

This script aims to reduce the attack surface available to malware, spyware (including stealthy threats like FinFisher and Pegasus), hackers, and unauthorized users. It is ideal for users seeking strong baseline protections while understanding the impact on system accessibility and network behavior.

What Does SecureWin Do?
SecureWin runs the following actions to harden Windows security:

Startup and Autostart Inspection
Lists programs in user and system Startup folders.

Queries registry keys tracking programs auto-run at system or user login.

Queries scheduled tasks for automated jobs.

Windows Update and Patch Management
Runs Windows Update scan and installs all available updates.

Automatically reboots after update installation.

Network and SMB Hardening
Disables SMBv1 protocol, an outdated and insecure file-sharing protocol.

Enables required security signatures for SMB connections.

Disables insecure guest access to SMB shares.

Firewall Configuration
Enables firewall profiles (Domain, Private, Public).

Blocks all inbound and outbound network traffic by default.

Adds explicit firewall rules to allow trusted apps (e.g., web browsers Brave and Edge), Windows Update, DNS (Cloudflare 1.1.1.1), HTTP, HTTPS, DHCP.

Blocks suspicious outbound port 8080 traffic.

Remote Access and Scripting Controls
Disables Remote Desktop protocol (inbound and outbound).

Stops and disables Windows Remote Management service.

Disables PowerShell Remoting.

Disables Windows Script Host to prevent script-based attacks.

Windows Defender Security Enhancements
Enables Attack Surface Reduction rules and Controlled Folder Access.

Ensures PowerShell execution policy requires signed scripts.

Runs offline malware scan via Windows Defender.

System Integrity Verification
Runs System File Checker (sfc /scannow) to repair system files.

Uses DISM to check and restore Windows image health.

How to Use
Open PowerShell as Administrator.

Download the securewin.ps1 script from this repository.

Unblock the script by right-clicking it, selecting Properties, and clicking 'Unblock'.

Run the script:

powershell
.\securewin.ps1
The script will execute multiple commands and may reboot your system automatically after installing updates.

After running, your network and remote access will be restricted according to the firewall and service rules.

Review firewall configuration and service changes if you rely on Remote Desktop, specific network ports, or remote management tools.

Important Notes
This script is built for systems running Windows 10 or later with administrative privileges.

It enforces a strict security posture by blocking nearly all inbound and outbound traffic except for essential services and trusted apps.

Disables services and features that could be used for remote control or lateral movement inside networks.

Not recommended to run without understanding the impacts, especially where remote or network-dependent workflows are critical.

Regularly check for Windows updates manually if automatic updates can't be completed.

Regular running of this script or similar hardening is recommended to maintain security baseline.

Full Commands Executed by securewin.ps1
powershell
dir /a "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
dir /a "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
schtasks /query /fo LIST /v
dir /a "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
dir /a "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
UsoClient StartScan
Install-Module PSWindowsUpdate
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll -AutoReboot
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
New-NetFirewallRule -DisplayName "Block suspicious outbound port 8080" -Direction Outbound -LocalPort 8080 -Protocol TCP -Action Block
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -PropertyType DWord -Value 0 -Force
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -AllowInboundRules False
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
Get-NetFirewallRule -Action Block -Enabled True
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -AllowInboundRules False
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Disable-NetFirewallRule
New-NetFirewallRule -DisplayName "Allow Windows Update" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow
New-NetFirewallRule -DisplayName "Allow Outbound HTTP" -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow
New-NetFirewallRule -DisplayName "Allow Outbound HTTPS" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow
New-NetFirewallRule -DisplayName "Allow Inbound Response" -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow
New-NetFirewallRule -DisplayName "Allow Brave Browser" -Direction Outbound -Program "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe" -Action Allow
New-NetFirewallRule -DisplayName "Allow Microsoft Edge" -Direction Outbound -Program "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -Action Allow
New-NetFirewallRule -DisplayName "Allow DNS through Cloudflare 1.1.1.1" -Direction Outbound -Protocol UDP -RemoteAddress "1.1.1.1" -RemotePort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -AllowInboundRules False -DefaultOutboundAction Block
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
Get-NetFirewallProfile | Select-Object Name, DefaultOutboundAction
New-NetFirewallRule -DisplayName "Allow Cloudflare WARP Service" -Direction Outbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe" -Action Allow
New-NetFirewallRule -DisplayName "Allow Cloudflare WARP Client" -Direction Outbound -Program "C:\Program Files\Cloudflare\Cloudflare WARP\Cloudflare WARP.exe" -Action Allow
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
Disable-PSRemoting -Force
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -DisableScriptScanning $false
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block
New-NetFirewallRule -DisplayName "Allow Brave Browser" -Direction Outbound -Program "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe" -Action Allow
New-NetFirewallRule -DisplayName "Allow Cloudflare DNS" -Direction Outbound -Protocol UDP -RemoteAddress 1.1.1.1 -RemotePort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow DHCP" -Direction Outbound -Protocol UDP -RemotePort 67,68 -Action Allow
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow Brave HTTPS" -Direction Outbound -Program "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe" -Protocol TCP -RemotePort 443 -Action Allow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Force
Stop-Service -Name TermService -Force
Set-Service -Name TermService -StartupType Disabled
New-NetFirewallRule -DisplayName "Block RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block
New-NetFirewallRule -DisplayName "Block RDP Inbound UDP" -Direction Inbound -Protocol UDP -LocalPort 3389 -Action Block
New-NetFirewallRule -DisplayName "Block RDP Outbound" -Direction Outbound -Protocol TCP -RemotePort 3389 -Action Block
New-NetFirewallRule -DisplayName "Block RDP Outbound UDP" -Direction Outbound -Protocol UDP -RemotePort 3389 -Action Block
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
Stop-Service WinRM -Force
Set-Service WinRM -StartupType Disabled
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Force
sfc /scannow
DISM /Online /Cleanup-Image /CheckHealth
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /RestoreHealth
Start-MpWDOScan
Disclaimer
This script changes critical system and network settings and should only be run after thoroughly reviewing and understanding its effects. It may impact remote access and network services. Use in controlled environments or personal systems with caution.
