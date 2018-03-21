@echo off
color 0A

:: Create directory for downloaded files, Windows patches, program installers, and additional scripts

if not exist "C:\DownloadedFiles\" mkdir "C:\DownloadedFiles"
if not exist "C:\DownloadedFiles\Windows_Patches" mkdir "C:\DownloadedFiles\Windows_Patches"
if not exist "C:\DownloadedFiles\ProgramInstallers" mkdir "C:\DownloadedFiles\ProgramInstallers"
if not exist "C:\DownloadedFiles\Additional_Scripts" mkdir "C:\DownloadedFiles\Additional_Scripts"

:: Find and record the current IP address and MAC address

ipconfig /all | findstr IPv4
ipconfig /all | findstr IPv4 > C:\IP-MAC.txt
ipconfig /all | findstr Physical
ipconfig /all | findstr Physical >> C:\IP-MAC.txt
echo.
echo.
echo.

:: Download Security Patches for Windows 2008R2, 2012, and 8.1

:: SYNTAX:
:: powershell -command "(new-object System.Net.WebClient).DownloadFile('link','C:\DownloadedFiles\Windows_Patches\MSPatchName.extension')"
:: -----2008R2 First-----
echo Downloading patches for 2008 R2 (MS16-032 ^& MS17-010)
:: MS16-032
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/F/2/D/F2D919E1-2E08-4ACF-AEDB-575AD146750E/Windows6.1-KB3139914-x64.msu','C:\DownloadedFiles\Windows_Patches\MS16-032_2008R2.msu')"
:: ----------TINYURL: https://tinyurl.com/ms16-032-08r2
:: MS17-010
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu','C:\DownloadedFiles\Windows_Patches\MS17-010_2008R2.msu')"
:: ----------TINYURL: https://tinyurl.com/ms17-010-08r2
:: -----2012 Next-----
echo Downloading patches for 2012 (MS16-032 ^& MS17-010)
:: MS16-032
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/0/C/9/0C99ACB1-DCE3-4B5F-BBFC-D40D51889A49/Windows8-RT-KB3139914-x64.msu','C:\DownloadedFiles\Windows_Patches\MS16-032_2012.msu')"
:: ----------TINYURL: https://tinyurl.com/ms16-032-2012
:: MS17-010
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8-rt-kb4012214-x64_b14951d29cb4fd880948f5204d54721e64c9942b.msu','C:\DownloadedFiles\Windows_Patches\MS17-010_2012.msu')"
:: ----------TINYURL: https://tinyurl.com/ms17-010-2012
:: -----8.1 Last-----
echo Downloading patches for Windows 8.1 (MS16-032 ^& MS17-010)
:: MS16-032
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/B/D/3/BD3A7357-E60C-498C-BC60-A07C18E9E8F8/Windows8.1-KB3139914-x64.msu','C:\DownloadedFiles\Windows_Patches\MS16-032_8.1.msu')"
:: ----------TINYURL: https://tinyurl.com/ms16-032-8-1
:: MS17-010
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu','C:\DownloadedFiles\Windows_Patches\MS17-010_8.1.msu')"
:: ----------TINYURL: https://tinyurl.com/ms17-010-8-1
echo.
echo.
echo.

:: Downloading Necessary Programs

color 0B
echo Downloading Chrome
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B9D1B64B7-DF02-0224-9135-13DEB803C07A%7D%26lang%3Den%26browser%3D4%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Ddefaultbrowser/chrome/install/ChromeStandaloneSetup64.exe','C:\DownloadedFiles\ProgramInstallers\ChromeInstaller.exe')"
:: ----------TINYURL: https://tinyurl.com/ycwuvgl9
echo Downloading SysInternals Suite
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.sysinternals.com/files/SysinternalsSuite.zip','C:\DownloadedFiles\ProgramInstallers\SysinternalsSuite.zip')"
:: ----------TINYURL: https://tinyurl.com/qawmvp4
echo Downloading CCleaner
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://download.ccleaner.com/ccsetup539.exe','C:\DownloadedFiles\ProgramInstallers\CCleanerSetup.exe')"
:: ----------TINYURL: https://tinyurl.com/y7zkvxay
echo Downloading MalwareBytes
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://downloads.malwarebytes.com/file/mb3/','C:\DownloadedFiles\ProgramInstallers\MalwareBytesInstaller.exe')"
:: ----------TINYURL: https://tinyurl.com/gl84yd8
echo Downloading GlassWire
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.glasswire.com/GlassWireSetup.exe','C:\DownloadedFiles\ProgramInstallers\GlassWireSetup.exe')"
:: ----------TINYURL: https://tinyurl.com/y9z2czk8
echo Downloading Kiwi Syslog Agent
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://downloads.solarwinds.com/solarwinds/Release/Kiwi/Syslog/Kiwi-Syslog-Server-9.6.3-Freeware.zip','C:\DownloadedFiles\ProgramInstallers\KiwiSyslogServer.zip')"
:: ----------TINYURL: https://tinyurl.com/y8fawso2
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://downloads.solarwinds.com/solarwinds/Release/Kiwi/LogForwarder/SolarWinds-LogForwarder-v1.1.19.zip','C:\DownloadedFiles\ProgramInstallers\KiwiSyslogForwarder.zip')
:: ----------TINYURL: https://tinyurl.com/yazkgkle
echo Downloading Wireshark
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://1.na.dl.wireshark.org/win64/Wireshark-win64-2.4.4.exe','C:\DownloadedFiles\ProgramInstallers\Wireshark.exe')"
:: ----------TINYURL: https://tinyurl.com/y9v8h72d
echo Downloading Security Essentials
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/ENUS/amd64/MSEInstall.exe','C:\DownloadedFiles\ProgramInstallers\MSEInstall.exe')"
:: ----------TINYURL: https://tinyurl.com/y76r5jbc
echo Downloading Splunk
:: powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.splunk.com/products/splunk/releases/6.4.2/windows/splunk-6.4.2-00f5bb3fa822-x64-release.msi','C:\DownloadedFiles\ProgramInstallers\SplunkInstall.msi')"
:: ----------TINYURL: https://tinyurl.com/yd5n5qey (6.4.2)
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.splunk.com/products/splunk/releases/7.0.2/windows/splunk-7.0.2-03bbabbd5c0f-x64-release.msi','C:\DownloadedFiles\ProgramInstallers\SplunkInstall.msi')"
:: ----------TINYURL: https://tinyurl.com/yd3zyo2q (7.0.2)
echo Downloading NMAP
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://nmap.org/dist/nmap-7.60-setup.exe','C:\DownloadedFiles\ProgramInstallers\NMAP-Setup.exe')"
:: ----------TINYURL: https://tinyurl.com/ycvoek4u
echo Downloading Security Task manager
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://www.neuber.com/download/SecurityTaskManager_Setup.exe','C:\DownloadedFiles\ProgramInstallers\SecurityTaskManager_Setup.exe')"
:: ----------TINYURL: https://tinyurl.com/yco9fv4o
::echo Downloading Nessus
::   powershell -command "$IE=(new-object -com internetexplorer.application); $IE.navigate2('https://www.tenable.com/downloads/nessus'); $IE.visible=$true"
::powershell -command "(new-object System.Net.WebClient).DownloadFile('https://tenable-downloads-production.s3.amazonaws.com/uploads/download/file/7561/Nessus-7.0.2-x64.msi','C:\DownloadedFiles\ProgramInstallers\Nessus_Install.msi')"
:: ----------TINYURL: https://tinyurl.com/yaxc4wsy
echo Downloading Visual Studio C++ 2008 SP1 Redistributable Package
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/2/d/6/2d61c766-107b-409d-8fba-c39e61ca08e8/vcredist_x64.exe','C:\DownloadedFiles\ProgramInstallers\vcredist_x64.exe')"
:: ----------TINYURL: https://tinyurl.com/yay28mdv
echo.
echo.
echo.

:: Changing Admin Password and creating 'dummy' Admin account (and disabling it)

color 0D
echo Changing Administrator Password
net user Administrator PressingButton$2
echo Adding "Admin" Account
net user Admin D03sntM@tt3rWh@tTh1s1sB3caus3The@cc0unt1sD3d /ADD
echo Disabling New Admin Account
net user Admin /active:no
echo.
echo.
echo.

:: Deactivate Guest account, if it is active

net user Guest | findstr Active | findstr Yes
if %errorlevel%==0 echo Guest account is active, deactivating
if %errorlevel%==1 echo Guest account is not active
net user Guest /active:NO

:: Change all account passwords to #1 in password list
net users > C:\UserList.txt
(
  for /F %%h in (UserList.txt) do (
    echo %%h | findstr NEXS
    if %errorlevel%==1 net user %%h PressingButton$2 >> C:\UserList.txt 
  )
)

:: Creating Password Policy
net accounts /FORCELOGOFF:30 /MINPWLEN:8 /MAXPWAGE:30 /MINPWAGE:10 /UNIQUEPW:3
echo Password policy:
echo Force log off after 30 minutes > C:\Password_Policy.txt
echo Minimum password length of 8 characters > C:\Password_Policy.txt
echo Maximum password age of 30 > C:\Password_Policy.txt
echo Minimum password age of 10 > C:\Password_Policy.txt
echo Unique password threshold set to 3 (default is 5) > C:\Password_Policy.txt

:: Disabling File Sharing & Administrative Shares

color 0E
echo Disabling File Sharing
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No
echo Disabling Administrative Shares
REG ADD HKEY_LOCAL_MACHINESYSTEMCurrentControlSetservicesLanmanServerParameters /f /v AutoShareWks /t REG_SZ /d 0

:: Configuring Audit Policy (& Displaying finished result)

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

:: Checking Scheduled Tasks

color 0D
echo Displaying Scheduled Tasks
schtasks /Query
schtasks /Query > C:\ScheduledTasks.txt
echo.
echo.
echo.

:: Exporting Current Firewall rules before changes are made

if not exist "C:\DownloadedFiles\FirewallRules\" mkdir "C:\DownloadedFiles\FirewallRules"
netsh advfirewall export "C:\DownloadedFiles\FirewallRules\ORIGINAL_RULES.wfw"
:: Export a backup copy of the firewall rules (just in case)
if not exist "C:\Backups\Firewall_Rules\" mkdir "C:\Backups\Firewall_Rules"
netsh advfirewall export "C:\Backups\Firewall_Rules\ORIGINAL_RULES.wfw"

:: Disabling All Firewall Rules Not Explicitly Stated

echo Disabling all non-explicit firewall rules
netsh advfirewall set domain firewallpolicy blockinbound,blockoutbound
netsh advfirewall set private firewallpolicy blockinbound,blockoutbound
netsh advfirewall set public firewallpolicy blockinbound,blockoutbound

:: Deleting all explicitly stated firewall rules

echo Deleting all explicit firewall rules
powershell -command "Remove-NetFirewallRule -All"

:: Create ICMP and DNS inbound rules

echo Creating ICMP ^& DNS inbound rules
netsh advfirewall firewall add rule name="A" service=any protocol=ICMPv4:8,any dir=in action=allow
netsh advfirewall firewall add rule name="Allow DNS.exe to DNS the things" program="%SystemRoot%\System32\dns.exe" dir=in action=allow protocol=UDP localport=53

:: Create Active Directory Domain rules

echo Creating Active Directory Domain rules
netsh advfirewall firewall add rule name="Active Directory Domain Controller - LDAP (TCP-In)" program="%SystemRoot%\System32\lsass.exe" dir=in action=allow protocol=TCP localport=389
netsh advfirewall firewall add rule name="Active Directory Domain Controller - LDAP (UDP-In)" program="%SystemRoot%\System32\lsass.exe" dir=in action=allow protocol=UDP localport=389
netsh advfirewall firewall add rule name="Active Directory Domain Controller - Secure LDAP (TCP-In)" program="%SystemRoot%\System32\lsass.exe" dir=in action=allow protocol=TCP localport=636

:: Create DNS outbound rules

echo Creating DNS outbound rules
netsh advfirewall firewall add rule name="Allow DNS" program="%SystemRoot%\System32\dns.exe" dir=out action=allow protocol=UDP remoteport=53

:: Create NTP inbound rules

netsh advfirewall firewall add rule name="Allow NTP to do the timey-wimey" program="%SystemRoot%\System32\w32tm.exe" service=any dir=in action=allow protocol=UDP localport=123

:: Create NTP outbound rules

netsh advfirewall firewall add rule name="Allow NTP" program="%SystemRoot%\System32\w32tm.exe" service=any dir=out action=allow protocol=UDP localport=123

:: ------------------------Rules go here

:: ----------Display Scheduled Tasks Script
echo @echo off > C:\DownloadedFiles\Additional_Scripts\Display_Scheduled_Tasks.bat
echo color 0D >> C:\DownloadedFiles\Additional_Scripts\Display_Scheduled_Tasks.bat
echo echo Displaying Scheduled Tasks >> C:\DownloadedFiles\Additional_Scripts\Display_Scheduled_Tasks.bat
echo schtasks /Query >> C:\DownloadedFiles\Additional_Scripts\Display_Scheduled_Tasks.bat
echo schtasks /Query ^> C:\ScheduledTasks.txt >> C:\DownloadedFiles\Additional_Scripts\Display_Scheduled_Tasks.bat

:: ----------Install Programs Script
echo @echo off > C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo color 0B >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing Chrome >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo C:\DownloadedFiles\ProgramInstallers\ChromeInstaller.exe /silent /install >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing SysInternals Suite >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo if not exist "C:\DownloadedFiles\ProgramInstallers\Sysinternals_Suite\" mkdir "C:\DownloadedFiles\ProgramInstallers\Sysinternals_Suite" >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo powershell -command "(new-object -com shell.application).namespace('C:\DownloadedFiles\ProgramInstallers\Sysinternals_Suite').CopyHere((new-object -com shell.application).namespace('C:\DownloadedFiles\ProgramInstallers\SysinternalsSuite.zip').Items(),16)" >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing CCleaner >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo C:\DownloadedFiles\ProgramInstallers\CCleanerSetup.exe /silent /install >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing MalwareBytes >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo C:\DownloadedFiles\ProgramInstallers\MalwareBytesInstaller.exe /silent /install >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing GlassWire >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo C:\DownloadedFiles\ProgramInstallers\GlassWireSetup.exe /silent /install >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing Kiwi Syslog >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo if not exist "C:\DownloadedFiles\ProgramInstallers\Kiwi_Syslog\" mkdir "C:\DownloadedFiles\ProgramInstallers\Kiwi_Syslog" >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo powershell -command "(new-object -com shell.application).namespace('C:\DownloadedFiles\ProgramInstallers\Kiwi_Syslog').CopyHere((new-object -com shell.application).namespace('C:\DownloadedFiles\ProgramInstallers\KiwiSyslogServer.zip').Items(),16)" >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo powershell -command "(new-object -com shell.application).namespace('C:\DownloadedFiles\ProgramInstallers\Kiwi_Syslog').CopyHere((new-object -com shell.application).namespace('C:\DownloadedFiles\ProgramInstallers\KiwiSyslogForwarder.zip').Items(),16)" >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing Wireshark >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo C:\DownloadedFiles\ProgramInstallers\Wireshark.exe /silent /install >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing Security Essentials >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo C:\DownloadedFiles\ProgramInstallers\MSEInstall.exe >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo ::echo Installing Splunk >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo ::C:\DownloadedFiles\ProgramInstallers\SplunkInstall.msi /passive >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing NMAP >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo C:\DownloadedFiles\ProgramInstallers\NMAP-Setup.exe /silent /install >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo echo Installing Security Task Manager >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo C:\DownloadedFiles\ProgramInstallers\SecurityTaskManager_Setup.exe /silent /install >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo ::echo Installing Nessus >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat
echo ::C:\DownloadedFiles\ProgramInstallers\Nessus_Install.msi /passive >> C:\DownloadedFiles\Additional_Scripts\Install_Programs.bat

:: Start task manager to inspect processes and services

echo Opening Task Manager to inspect Processes ^& Services
start taskmgr
echo.
echo.
echo.

:: Ending Text (Just for fun)

echo ****************************************
echo Security Got! Your System is Now Secure!
echo ****************************************
echo.
pause
::End