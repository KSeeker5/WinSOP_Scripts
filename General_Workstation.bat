@echo off
color 0A
if not exist "C:\Fileshare\" mkdir "C:\Fileshare"
ipconfig /all | findstr IPv4
ipconfig /all | findstr IPv4 > C:\IP-MAC.txt
ipconfig /all | findstr Physical
ipconfig /all | findstr Physical >> C:\IP-MAC.txt
echo.
echo.
echo.
echo Input 1 - if you are on Windows XP/2003
echo Input 2 - if you are on Windows Vista/7/2008/2008R2/2012
echo Input 3 - if you need both sets of security patches
echo Input 4 - if you don't need security patches
set /p Patch=""
if %Patch%==1 (
echo "Opening Download Pages -MS08-067, MS11-080, & MS14-070-"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067'); $IE.visible=$true"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-080'); $IE.visible=$true"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-070'); $IE.visible=$true"
) else if %Patch%==2 (
echo "Opening Download Pages -MS09-050, MS16-032, & MS17-010-"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-050'); $IE.visible=$true"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032'); $IE.visible=$true"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010'); $IE.visible=$true"
) else if %Patch%==3 (
echo "Opening Download Pages -MS08-067, MS11-080, MS14-070, MS09-050, & MS16-032-"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067'); $IE.visible=$true"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-080'); $IE.visible=$true"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-070'); $IE.visible=$true"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-050'); $IE.visible=$true"
powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032'); $IE.visible=$true"
) else (echo "No patches installed")
echo.
echo.
echo.
pause
color 0B
echo Downloading Chrome
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B9D1B64B7-DF02-0224-9135-13DEB803C07A%7D%26lang%3Den%26browser%3D4%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Ddefaultbrowser/chrome/install/ChromeStandaloneSetup64.exe','C:\Fileshare\ChromeInstaller.exe')"
echo Downloading SysInternals Suite
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.sysinternals.com/files/SysinternalsSuite.zip','C:\Fileshare\SysinternalsSuite.zip')"
echo Downloading CCleaner
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://download.ccleaner.com/ccsetup539.exe','C:\Fileshare\CCleanerSetup.exe')"
echo Downloading MalwareBytes
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://downloads.malwarebytes.com/file/mb3/','C:\Fileshare\MalwareBytesInstaller.exe')"
echo Downloading GlassWire
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.glasswire.com/GlassWireSetup.exe','C:\Fileshare\GlassWireSetup.exe')"
echo Downloading Kiwi Syslog Agent
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://downloads.solarwinds.com/solarwinds/Release/Kiwi/Syslog/Kiwi-Syslog-Server-9.6.3-Freeware.zip','C:\Fileshare\KiwiSyslogServer.zip')"
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://downloads.solarwinds.com/solarwinds/Release/Kiwi/LogForwarder/SolarWinds-LogForwarder-v1.1.19.zip','C:\Fileshare\KiwiSyslogForwarder.zip')
echo Downloading Wireshark
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://1.na.dl.wireshark.org/win64/Wireshark-win64-2.4.4.exe','C:\Fileshare\Wireshark.exe')"
echo Downloading Security Essentials
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/ENUS/amd64/MSEInstall.exe','C:\Fileshare\MSEInstall.exe')"
echo Downloading Splunk
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.splunk.com/products/splunk/releases/6.4.2/windows/splunk-6.4.2-00f5bb3fa822-x64-release.msi','C:\Fileshare\SplunkInstall.msi')"
echo Downloading NMAP
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://nmap.org/dist/nmap-7.60-setup.exe','C:\Fileshare\NMAP-Setup.exe')"
echo Downloading Security Task manager
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://www.neuber.com/download/SecurityTaskManager_Setup.exe','C:\Fileshare\SecurityTaskManager_Setup.exe')"
::echo Downloading Nessus
::  powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://www.tenable.com/downloads/nessus'); $IE.visible=$true"
::powershell -command "(new-object System.Net.WebClient).DownloadFile('https://tenable-downloads-production.s3.amazonaws.com/uploads/download/file/7561/Nessus-7.0.2-x64.msi','C:\Fileshare\Nessus_Install.msi')"
echo.
echo.
echo.
color 0D
echo Changing Administrator Password
net user Administrator P@ssw0rd
echo Adding "Admin" Account
net user Admin r3dT3@m1sB4d /ADD
echo Disabling New Admin Account
net user Admin /active:no
echo.
echo.
echo.
color 0E
echo Disabling File Sharing
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No
echo Disabling Administrative Shares
REG ADD HKEY_LOCAL_MACHINESYSTEMCurrentControlSetservicesLanmanServerParameters /f /v AutoShareWks /t REG_SZ /d 0
echo Configuring audit policy
echo Process Tracking: Success
auditpol /set /category:"Detailed Tracking" /Success:enable /failure:disable
echo Account Management: Success & Failure
auditpol /set /category:"Account Management" /Success:enable /failure:enable
echo Logon Events: Success & Failure
auditpol /set /category:"Logon/Logoff" /Success:enable /failure:enable
echo Account Logon Events: Success & Failure
auditpol /set /category:"Account Logon" /Success:enable /failure:enable
echo.
echo.
echo.
color 0A
echo Displaying Completed Audit Policy
auditpol /get /category:*
auditpol /get /category:* > C:\AuditPolicy.txt
echo.
echo.
echo.
color 0B
echo Installing Chrome
C:\Fileshare\ChromeInstaller.exe /silent /install
echo Installing SysInternals Suite
if not exist "C:\Fileshare\Sysinternals_Suite\" mkdir "C:\Fileshare\Sysinternals_Suite"
powershell -command "(new-object -com shell.application).namespace('C:\Fileshare\Sysinternals_Suite').CopyHere((new-object -com shell.application).namespace('C:\Fileshare\SysinternalsSuite.zip').Items(),16)"
echo Installing CCleaner
C:\Fileshare\CCleanerSetup.exe /silent /install
echo Installing MalwareBytes
C:\Fileshare\MalwareBytesInstaller.exe /silent /install
echo Installing GlassWire
C:\Fileshare\GlassWireSetup.exe /silent /install
echo Installing Kiwi Syslog
if not exist "C:\Fileshare\Kiwi_Syslog\" mkdir "C:\Fileshare\Kiwi_Syslog"
powershell -command "(new-object -com shell.application).namespace('C:\Fileshare\Kiwi_Syslog').CopyHere((new-object -com shell.application).namespace('C:\Fileshare\KiwiSyslogServer.zip').Items(),16)"
powershell -command "(new-object -com shell.application).namespace('C:\Fileshare\Kiwi_Syslog').CopyHere((new-object -com shell.application).namespace('C:\Fileshare\KiwiSyslogForwarder.zip').Items(),16)"
echo Installing Wireshark
C:\Fileshare\Wireshark.exe /silent /install
echo Installing Security Essentials
C:\Fileshare\MSEInstall.exe
::echo Installing Splunk*
::C:\Fileshare\SplunkInstall.msi /passive
echo Installing NMAP
C:\Fileshare\NMAP-Setup.exe /silent /install
echo Installing Security Task Manager
C:\Fileshare\SecurityTaskManager_Setup.exe /silent /install
::echo Installing Nessus
::C:\Fileshare\Nessus_Install.msi /passive
echo.
echo.
echo.
color 0D
echo Displaying Scheduled Tasks
schtasks /Query
schtasks /Query > C:\ScheduledTasks.txt
echo.
echo.
echo.
echo Changing Color For Visibility
color 0A
echo Creating File Sharing Scripts
::Block File Sharing Script
::echo @echo off > C:\Block_File_Sharing.bat
::echo netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No >> C:\Block_File_Sharing.bat
::echo exit >> C:\Block_File_Sharing.bat
::Enable File Sharing Script
::echo @echo off > C:\Enable_File_Sharing.bat
::echo netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes >> C:\Enable_File_Sharing.bat
::echo exit >> C:\Enable_File_Sharing.bat
::Share File Script
echo @echo off > C:\Share_File.bat
echo netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes >> C:\Share_File.bat
echo net share Fileshare$=C:\Fileshare /grant:everyone,read >> C:\Share_File.bat
echo exit >> C:\Share_File.bat
::Stop Sharing File Script
echo @echo off > C:\Stop_Sharing_File.bat
echo net share Fileshare$ /delete >> C:\Stop_Sharing_File.bat
echo netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No >> C:\Stop_Sharing_File.bat
echo exit >> C:\Stop_Sharing_File.bat
::Block All Incoming Ports Script
echo @echo off > C:\Block_All_Ports.bat
echo netsh advfirewall set currentprofile firewallpolicy blockinbound,allowoutbound >> C:\Block_All_Ports.bat
echo exit >> C:\Block_All_Ports.bat
::Enable ICMP Script
echo @echo off > C:\Enable_ICMP.bat
echo netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow >> C:\Enable_ICMP.bat
echo netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol=icmpv6:8,any dir=in action=allow >> C:\Enable_ICMP.bat
echo exit >> C:\Enable_ICMP.bat
::Disable ICMP Script
::echo @echo off > C:\Disable_ICMP.bat
::echo netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=block >> C:\Disable_ICMP.bat
::echo netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol=icmpv6:8,any dir=in action=block >> C:\Disable_ICMP.bat
::echo exit >> C:\Disable_ICMP.bat
echo Opening Task Manager To Inspect Processes & Services
start taskmgr
echo Blocking All Inbound Ports
start cmd /k "C:\Block_All_Ports.bat"
echo Enabling ICMP
start cmd /k "C:\Enable_ICMP.bat"
echo.
echo.
echo.
echo ****************************************
echo Security Got! Your System is Now Secure!
echo ****************************************
pause
