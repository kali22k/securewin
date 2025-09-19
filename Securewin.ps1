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


# Allow outbound HTTP and HTTPS traffic for all apps (Ports 80 and 443)
New-NetFirewallRule -DisplayName "Allow Outbound HTTP" -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow
New-NetFirewallRule -DisplayName "Allow Outbound HTTPS" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow

# Optional: Allow inbound response traffic
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

# Allow Brave HTTPS (outbound TCP 443)
New-NetFirewallRule -DisplayName "Allow Brave HTTPS" -Direction Outbound -Program "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe" -Protocol TCP -RemotePort 443 -Action Allow


Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Force


Stop-Service -Name TermService -Force
Set-Service -Name TermService -StartupType Disabled

# Block inbound RDP traffic
New-NetFirewallRule -DisplayName "Block RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block
New-NetFirewallRule -DisplayName "Block RDP Inbound UDP" -Direction Inbound -Protocol UDP -LocalPort 3389 -Action Block

# Block outbound RDP traffic
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