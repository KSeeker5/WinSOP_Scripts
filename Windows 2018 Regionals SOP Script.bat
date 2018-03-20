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
echo Downloading patches for 2008 R2 (MS16-032 & MS17-010)
:: MS16-032
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/F/2/D/F2D919E1-2E08-4ACF-AEDB-575AD146750E/Windows6.1-KB3139914-x64.msu','C:\DownloadedFiles\Windows_Patches\MS16-032_2008R2.msu')"
:: ----------TINYURL: https://tinyurl.com/ms16-032-08r2
:: MS17-010
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu','C:\DownloadedFiles\Windows_Patches\MS17-010_2008R2.msu')"
:: ----------TINYURL: https://tinyurl.com/ms17-010-08r2
:: -----2012 Next-----
echo Downloading patches for 2012 (MS16-032 & MS17-010)
:: MS16-032
powershell -command "(new-object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/0/C/9/0C99ACB1-DCE3-4B5F-BBFC-D40D51889A49/Windows8-RT-KB3139914-x64.msu','C:\DownloadedFiles\Windows_Patches\MS16-032_2012.msu')"
:: ----------TINYURL: https://tinyurl.com/ms16-032-2012
:: MS17-010
powershell -command "(new-object System.Net.WebClient).DownloadFile('http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8-rt-kb4012214-x64_b14951d29cb4fd880948f5204d54721e64c9942b.msu','C:\DownloadedFiles\Windows_Patches\MS17-010_2012.msu')"
:: ----------TINYURL: https://tinyurl.com/ms17-010-2012
:: -----8.1 Last-----
echo Downloading patches for Windows 8.1 (MS16-032 & MS17-010)
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
echo.
echo.
echo.

:: Changing Admin Password and creating 'dummy' Admin account (and disabling it)

color 0D
echo Changing Administrator Password
net user Administrator PressingButton$2
echo Adding "Admin" Account
net user Admin M1k3H@y$4ev3r /ADD
echo Disabling New Admin Account
net user Admin /active:no
echo.
echo.
echo.

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

:: Disabling All Firewall Rules

netsh advfirewall set currentprofile firewallpolicy blockinbound,blockoutbound

::Enable ICMP

netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow
netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol=icmpv6:8,any dir=in action=allow