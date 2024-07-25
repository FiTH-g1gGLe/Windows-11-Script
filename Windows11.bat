@echo off
setlocal
:: Check for admin privileges
:: The "goto" command allows us to jump to different parts of the script

:: Check if the script is running as an administrator
openfiles >nul 2>&1
if '%errorlevel%' == '0' goto :admin
echo This script requires administrative privileges.
echo.
echo Attempting to restart with administrative privileges...
echo.

:: Restart the script as administrator
:: The "%~f0" represents the full path of the batch file
:: "start" command is used to start a new process with different privileges
:: "cmd /c" is used to execute the batch file in a new command window
:: "runas" command is used to run the script with elevated permissions
:: The "/C" option tells cmd to execute the command and then terminate
powershell -Command "Start-Process cmd -ArgumentList '/c %~f0' -Verb RunAs"
exit /b

:admin
:: Code to execute when running as admin goes here
echo Script is running with administrative privileges.
echo.
pause












rem ==================================================================================
rem Script to Modify SvcHostSplitThresholdInKB Settings
rem ==================================================================================
rem This part of the script modifies the SvcHostSplitThresholdInKB registry key
rem based on the amount of physical RAM in the system.
rem ==================================================================================

:: Retrieve the total physical memory in kilobytes using WMIC
echo Retrieving total physical memory...
for /f "tokens=2 delims==" %%a in ('wmic os get totalvisiblememorysize /value') do (
    set "ramKB=%%a"
)

:: Convert kilobytes to gigabytes
set /a "ramGB=%ramKB% / 1048576"
set "ramGB=%ramGB%"

:: Calculate the remaining MB for more precise output
set /a "ramMB=(%ramKB% %% 1048576) / 1024"

:: Check the RAM range and set the registry value accordingly
if %ramGB% geq 3 if %ramGB% lss 5 (
    echo Setting SvcHostSplitThresholdInKB for 4GB RAM...
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 4194304 /f >nul 2>&1
) else if %ramGB% geq 7 if %ramGB% lss 9 (
    echo Setting SvcHostSplitThresholdInKB for 8GB RAM...
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 8388608 /f >nul 2>&1
) else if %ramGB% geq 15 if %ramGB% lss 17 (
    echo Setting SvcHostSplitThresholdInKB for 16GB RAM...
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 16777216 /f >nul 2>&1
) else if %ramGB% geq 31 if %ramGB% lss 33 (
    echo Setting SvcHostSplitThresholdInKB for 32GB RAM...
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 33554432 /f >nul 2>&1
) else if %ramGB% geq 63 if %ramGB% lss 65 (
    echo Setting SvcHostSplitThresholdInKB for 64GB RAM...
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 67108864 /f >nul 2>&1
) else (
    echo No matching RAM range found for setting registry value.
)

echo SvcHostSplitThresholdInKB settings have been applied.

rem =========================================
rem Script to Configure System Boot Settings
rem =========================================
rem This script modifies various boot configuration settings
rem using the `bcdedit` command to impact system performance,
rem stability, and functionality.
rem =========================================

:: Disabling Dynamic Tick and High Precision Event Timer (HPET)
echo Disabling Dynamic Tick...
bcdedit /deletevalue useplatformclock >nul 2>&1
echo Disabling HPET...
bcdedit /deletevalue disabledynamictick >nul 2>&1

:: Setting platform tick and TSC sync policy
echo Configuring system timer settings...
bcdedit /set useplatformtick yes >nul 2>&1
bcdedit /set tscsyncpolicy legacy >nul 2>&1

:: Boot settings
echo Configuring boot settings...
echo Disabling Quiet Boot...
bcdedit /set quietboot yes >nul 2>&1
echo Disabling Modern Boot UI...
bcdedit /set bootux disabled >nul 2>&1
echo Setting Boot Menu to Legacy...
bcdedit /set bootmenupolicy legacy >nul 2>&1
echo Disabling Boot Log...
bcdedit /set bootlog no >nul 2>&1

:: Virtualization and Hypervisor settings
echo Configuring virtualization settings...
echo Enabling x2APIC...
bcdedit /set x2apicpolicy Enable >nul 2>&1
echo Disabling Hypervisor...
bcdedit /set hypervisorlaunchtype off >nul 2>&1
echo Disabling Isolated Context...
bcdedit /set isolatedcontext no >nul 2>&1
echo Disabling VSM and VM settings...
bcdedit /set vsmlaunchtype Off >nul 2>&1
bcdedit /set vm No >nul 2>&1

:: Debugging and memory settings
echo Configuring debugging and memory settings...
echo Disabling Debug Mode...
bcdedit /set debug No >nul 2>&1
echo Disabling Integrity Services...
bcdedit /set integrityservices disable >nul 2>&1
echo Disabling Emergency Management Services (EMS)...
bcdedit /set ems No >nul 2>&1
echo Disabling Physical Address Extension (PAE)...
bcdedit /set pae ForceDisable >nul 2>&1

:: Custom global settings
echo Applying custom global settings...
bcdedit /set {globalsettings} custom:16000067 true >nul 2>&1
bcdedit /set {globalsettings} custom:16000069 true >nul 2>&1
bcdedit /set {globalsettings} custom:16000068 true >nul 2>&1

:: Advanced memory settings
echo Configuring advanced memory settings...
echo Setting Linear Address Space Opt-Out...
bcdedit /set linearaddress57 OptOut >nul 2>&1
echo Increasing User Address Space...
bcdedit /set increaseuserva 268435328 >nul 2>&1
echo Configuring First Megabyte Policy...
bcdedit /set firstmegabytepolicy UseAll >nul 2>&1
echo Setting Avoid Low Memory...
bcdedit /set avoidlowmemory 0x8000000 >nul 2>&1
echo Disabling Low Memory Usage...
bcdedit /set nolowmem Yes >nul 2>&1
echo Configuring Memory Settings Access...
bcdedit /set allowedinmemorysettings 0x0 >nul 2>&1

:: Miscellaneous settings
echo Configuring miscellaneous settings...
echo Setting Default Configuration Access Policy...
bcdedit /set configaccesspolicy Default >nul 2>&1
echo Disabling Use Physical Destination...
bcdedit /set usephysicaldestination No >nul 2>&1
echo Disabling Firmware PCI Settings...
bcdedit /set usefirmwarepcisettings No >nul 2>&1
echo Disabling ELAM Drivers...
bcdedit /set disableelamdrivers Yes >nul 2>&1

echo Boot settings have been configured.
pause

rem =========================================
rem Script to Optimize System Settings for Gaming
rem =========================================
rem This script applies various registry settings to optimize
rem system performance for gaming.
rem =========================================

:: Disable Hibernate
echo Disabling Hibernate...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f >nul 2>&1

:: Set Graphics Hardware Scheduling Mode
echo Configuring Graphics Hardware Scheduling Mode...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f >nul 2>&1

:: Disable Power Throttling
echo Disabling Power Throttling...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f >nul 2>&1

:: Configure Game DVR Settings
echo Configuring Game DVR settings...
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_DSEBehavior /t REG_DWORD /d 2 /f >nul 2>&1

:: Set Intel Processor Power Management Service Start Type
echo Configuring Intel Processor Power Management Service...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IntelPPM" /v Start /t REG_DWORD /d 3 /f >nul 2>&1

:: Set AMD Processor Power Management Service Start Type
echo Configuring AMD Processor Power Management Service...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdPPM" /v Start /t REG_DWORD /d 3 /f >nul 2>&1

:: Disable Write Combining
echo Disabling Write Combining...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >nul 2>&1

:: Disable CUDA Context Preemption
echo Disabling CUDA Context Preemption...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f >nul 2>&1

:: Disable Preemption on S3/S4
echo Disabling Preemption on S3/S4...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisablePreemptionOnS3S4" /t REG_DWORD /d "1" /f >nul 2>&1

:: Disable Last Access Update
echo Disabling Last Access Update...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DisableLastAccessUpdate" /t REG_DWORD /d "1" /f >nul 2>&1

:: Set SystemResponsiveness to 1
echo Adjusting SystemResponsiveness setting...
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 1 /f >nul 2>&1

:: Setting GPU Priority for games
echo Setting GPU Priority to High (8)...
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
if %ERRORLEVEL% NEQ 0 (
    echo Failed to set GPU Priority.
) else (
    echo GPU Priority has been set successfully.
)

:: Setting CPU Priority for games
echo Setting CPU Priority to High (6)...
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f
if %ERRORLEVEL% NEQ 0 (
    echo Failed to set CPU Priority.
) else (
    echo CPU Priority has been set successfully.
)

:: Setting Scheduling Category for games
echo Setting Scheduling Category to High...
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
if %ERRORLEVEL% NEQ 0 (
    echo Failed to set Scheduling Category.
) else (
    echo Scheduling Category has been set to High.
)

:: Setting SFIO Priority for games
echo Setting SFIO Priority to High...
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
if %ERRORLEVEL% NEQ 0 (
    echo Failed to set SFIO Priority.
) else (
    echo SFIO Priority has been set to High.
)

rem =========================================
rem Script to Optimize Steam Settings
rem =========================================
rem This script modifies Steam settings to improve performance.
rem =========================================

:: Modify Steam registry settings
echo Configuring Steam settings...
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Valve\Steam" /v "SmoothScrollWebViews" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Valve\Steam" /v "DWriteEnable" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Valve\Steam" /v "StartupMode" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Valve\Steam" /v "H264HWAccel" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Valve\Steam" /v "DPIScaling" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Valve\Steam" /v "GPUAccelWebViews" /t REG_DWORD /d 0 /f >nul 2>&1

:: Remove Steam from startup
echo Removing Steam from startup...
REG DELETE "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Steam" /f >nul 2>&1

echo Steam settings and startup behavior have been modified..



pause
cls





rem =========================================
rem script is designed for extensive cleanup of temporary files, browser caches, application data, and system logs.
rem =========================================
echo -----------------------------------------------
echo Starting system cleanup process...
echo -----------------------------------------------

REM Set variables for directories
set "TEMP1=%USERPROFILE%\AppData\Local\Temp"
set "TEMP2=%windir%\Temp"
set "DISCORD_CACHE=%APPDATA%\discord\Cache"
set "DISCORD_CODE_CACHE=%APPDATA%\discord\Code Cache"
set "DISCORD_GPU_CACHE=%APPDATA%\discord\GPUCache"
set "LOGFILES=%USERPROFILE%\Logs"
set "PREFETCH=%windir%\Prefetch"
set "FIREFOX_PROFILES=C:\Users\%USERNAME%\AppData\Roaming\Mozilla\Firefox\Profiles"
set "OPERA_LOCAL=%USERPROFILE%\AppData\Local\Opera\Opera"
set "OPERA_ROAMING=%USERPROFILE%\AppData\Roaming\Opera\Opera"
set "SAFARI_LOCAL=%USERPROFILE%\AppData\Local\Applec~1\Safari"
set "SAFARI_ROAMING=%USERPROFILE%\AppData\Roaming\Applec~1\Safari"
set "FLASH_COOKIES=%USERPROFILE%\AppData\Roaming\Macromedia\Flashp~1"
set "IE_BASE=%USERPROFILE%\AppData\Local\Microsoft\Windows"
set "IE_HISTORY=%IE_BASE\History"
set "IE_IETEMP=%IE_BASE\Tempor~1"
set "IE_COOKIES=%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies"
set "CHROME_DIR=%USERPROFILE%\AppData\Local\Google\Chrome\User Data"

echo Variables set for cleanup tasks.

REM Delete temporary files from user and system directories
echo Deleting temporary files from user temp directory (%TEMP1%)...
del /q /f "%TEMP1%\*.*" > nul 2>&1
echo Done.

echo Deleting temporary files from system temp directory (%TEMP2%)...
del /q /f "%TEMP2%\*.*" > nul 2>&1
echo Done.

REM Clear browser cache (example for Google Chrome)
echo Clearing Google Chrome cache...
del /q /f "%CHROME_DIR%\Default\Cache\*.*" > nul 2>&1
echo Done.

REM Delete Discord directories
echo Deleting Discord cache directory...
rd /s /q "%DISCORD_CACHE%" > nul 2>&1
echo Done.

echo Deleting Discord Code Cache directory...
rd /s /q "%DISCORD_CODE_CACHE%" > nul 2>&1
echo Done.

echo Deleting Discord GPU Cache directory...
rd /s /q "%DISCORD_GPU_CACHE%" > nul 2>&1
echo Done.

REM Delete log files
echo Deleting log files from user logs directory (%LOGFILES%)...
del /q /f "%LOGFILES%\*.log" > nul 2>&1
echo Done.

REM Delete files from Prefetch directory
echo Deleting files from Prefetch directory (%PREFETCH%)...
del /q /f "%PREFETCH%\*.*" > nul 2>&1
echo Done.

REM Clean Firefox profiles
echo Cleaning Firefox profiles...
for /d %%x in ("%FIREFOX_PROFILES%\*") do (
    del /q /s /f "%%x\*sqlite" > nul 2>&1
)
echo Done.

REM Clean Opera directories
echo Cleaning Opera local data directory...
rd /s /q "%OPERA_LOCAL%" > nul 2>&1
echo Done.

echo Cleaning Opera roaming data directory...
rd /s /q "%OPERA_ROAMING%" > nul 2>&1
echo Done.

REM Clean Safari directories
echo Cleaning Safari local data directory...
rd /s /q "%SAFARI_LOCAL%" > nul 2>&1
echo Done.

echo Cleaning Safari roaming data directory...
rd /s /q "%SAFARI_ROAMING%" > nul 2>&1
echo Done.

REM Clean Flash cookies
echo Cleaning Flash cookies directory...
rd /s /q "%FLASH_COOKIES%" > nul 2>&1
echo Done.

REM Clean Internet Explorer data
echo Cleaning Internet Explorer history...
rd /s /q "%IE_HISTORY%" > nul 2>&1
echo Done.

echo Cleaning Internet Explorer temporary files...
rd /s /q "%IE_IETEMP%" > nul 2>&1
echo Done.

echo Cleaning Internet Explorer cookies...
rd /s /q "%IE_COOKIES%" > nul 2>&1
echo Done.

REM Additional clean-up tasks
echo -----------------------------------------------
echo Additional clean-up tasks...

REM Back up Windows Update downloads before deleting
echo Backing up Windows Update downloads directory...
robocopy "%SYSTEMROOT%\SoftwareDistribution\Download" "%SYSTEMROOT%\DownloadBackup" /E /MIR > nul 2>&1
echo Done.

REM Delete Windows Update downloads
echo Deleting Windows Update downloads directory...
rd /s /q "%SYSTEMROOT%\SoftwareDistribution\Download" > nul 2>&1
echo Done.

REM Clean system temp files
echo Cleaning system temp files...
del /q /s /f "%USERPROFILE%\AppData\Local\Temp\*" > nul 2>&1
del /q /s /f "%WINDIR%\Temp\*" > nul 2>&1
echo Done.

REM Clean Explorer thumbnail cache
echo Cleaning Explorer thumbnail cache...
del /q /s /f "%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.db" > nul 2>&1
echo Done.

REM Clean various system log files
echo Cleaning CBS logs...
del /q /s /f "%WINDIR%\Logs\CBS\*" > nul 2>&1
echo Done.

echo Cleaning system32 log files...
del /q /s /f "%WINDIR%\System32\LogFiles\*" > nul 2>&1
echo Done.

echo Cleaning WDI log files...
del /q /s /f "%WINDIR%\System32\WDI\LogFiles\*" > nul 2>&1
echo Done.

echo Cleaning Panther log files...
del /q /s /f "%WINDIR%\Panther\*" > nul 2>&1
echo Done.

echo Cleaning Debug log files...
del /q /s /f "%WINDIR%\Debug\*" > nul 2>&1
echo Done.

echo Cleaning Wbem log files...
del /q /s /f "%WINDIR%\System32\Wbem\Logs\*" > nul 2>&1
echo Done.

echo Cleaning winevt log files...
del /q /s /f "%WINDIR%\System32\winevt\Logs\*" > nul 2>&1
echo Done.

echo Cleaning ServiceProfiles temp files...
del /q /s /f "%WINDIR%\ServiceProfiles\NetworkService\AppData\Local\Temp\*" > nul 2>&1
del /q /s /f "%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Temp\*" > nul 2>&1
echo Done.

echo -----------------------------------------------
echo System cleanup process completed.
echo -----------------------------------------------

pause
cls


rem =========================================
rem script is designed for Windows 11 Services
rem =========================================
echo ---------------------------------------------------
echo Starting Windows Services Optimization process...
echo ---------------------------------------------------


REM List of services to disable
set "disableServicesList=AJRouter AppVClient AssignedAccessManagerSvc autotimesvc Backupper Service BDESVC BTAGService bthserv cbdhsvc CDPSvc CDPUserSvc CscService DeviceAssociationService DevicesFlowUserSvc DevicesFlowUserSvc_5f1ad DevQueryBroker diagnosticshub.standardcollector.service diagsvc DiagTrack DialogBlockingService DispBrokerDesktopSvc DisplayEnhancementService dLauncherLoopback dmwappushservice DsmSvc DsSvc DusmSvc edgeupdate edgeupdatem EFS Fax fdPHost FDResPub FontCache icssvc IKEEXT iphlpsvc LanmanWorkstation lfsvc lmhosts MessagingService_5f1ad MicrosoftEdgeElevationService MixedRealityOpenXRSvc MsKeyboardFilter NetTcpPortSharing NlaSvc NPSMSvc OneSyncSvc OneSyncSvc_5f1ad PcaSvc PhoneSvc PimIndexMaintenanceSvc_5f1ad PrintNotify RasMan RemoteAccess RemoteRegistry RetailDemo RmSvc SEMgrSvc SensorDataService SensorService SensrSvc SessionEnv SharedAccess ShellHWDetection shpamsvc Spooler SSDPSRV ssh-agent SstpSvc stisvc SysMain TabletInputService TapiSrv TermService TokenBroker TrkWks tzautoupdate UevAgentService uhssvc UnistoreSvc UserDataSvc W32Time WalletService WbioSrvc Wcmsvc WebClient Wecsvc wercplsupport WerSvc WinHttpAutoProxySvc WinRM wlidsvc WMPNetworkSvc WpcMonSvc WPDBusEnum WSService WaaSMedicSvc WalletService WarpJITSvc WbioSrvc WcsPlugInService WdNisSvc WdiServiceHost WdiSystemHost WebClient Wecsvc WerSvc WiaRpc WinHttpAutoProxySvc WinRM WpcMonSvc WpnService WwanSvc XblAuthManager XblGameSave XboxGipSvc XboxNetApiSvc autotimesvc bthserv camsvc cbdhsvc_* cloudidsvc dcsvc defragsvc diagnosticshub.standardcollector.service diagsvc dmwappushservice dot3svc edgeupdate edgeupdatem embeddedmode fdPHost fhsvc hidserv icssvc lfsvc lltdsvc lmhosts msiserver netprofm p2pimsvc p2psvc perceptionsimulation pla seclogon smphost spectrum svsvc swprv upnphost vds vm3dservice vmicguestinterface vmicheartbeat vmickvpexchange vmicrdv vmicshutdown vmictimesync vmicvmsession vmicvss vmvss wbengine wcncsvc webthreatdefsvc wercplsupport wisvc wlidsvc wlpasvc wmiApSrv workfolderssvc wuauserv wudfsvc"

REM List of services to set to "manual"
set "setManualServicesList=ALG AppIDSvc AppMgmt AppReadiness AppXSvc Appinfo AxInstSV BDESVC BTAGService BcastDVRUserService_* BluetoothUserService_* BrokerInfrastructure CDPSvc COMSysApp CaptureService_* CertPropSvc ClipSVC ConsentUxUserSvc_* CredentialEnrollmentManagerUserSvc_* CscService DcpSvc DevQueryBroker DeviceAssociationBrokerSvc_* DeviceAssociationService DeviceInstall DevicePickerUserSvc_* DevicesFlowUserSvc_* DisplayEnhancementService DmEnrollmentSvc DsSvc DsmSvc EFS EapHost EntAppSvc FDResPub Fax FrameServer FrameServerMonitor GraphicsPerfSvc HomeGroupListener HomeGroupProvider HvHost IEEtwCollectorService IKEEXT InstallService InventorySvc IpxlatCfgSvc KtmRm LicenseManager LxpSvc MSDTC MSiSCSI McpManagementService MessagingService_* MicrosoftEdgeElevationService MixedRealityOpenXRSvc MpsSvc MsKeyboardFilter NPSMSvc_* NaturalAuthentication NcaSvc NcbService NcdAutoSetup NetSetupSvc Netman NgcCtnrSvc NgcSvc NlaSvc P9RdrService_* PNRPAutoReg PNRPsvc PcaSvc PeerDistSvc PenService_* PerfHost PhoneSvc PimIndexMaintenanceSvc_* PlugPlay PolicyAgent PrintNotify PrintWorkflowUserSvc_* PushToInstall QWAVE RasAuto RasMan RetailDemo RmSvc RpcLocator SCPolicySvc SCardSvr SDRSVC SEMgrSvc SNMPTRAP SSDPSRV ScDeviceEnum SecurityHealthService Sense SensorDataService SensorService SensrSvc SessionEnv SharedAccess SharedRealitySvc SmsRouter SstpSvc StateRepository StiSvc StorSvc TabletInputService TapiSrv TextInputManagementService TieringEngineService TimeBroker TimeBrokerSvc TokenBroker TroubleshootingSvc TrustedInstaller UI0Detect UdkUserSvc_* UmRdpService UnistoreSvc_* UserDataSvc_* UsoSvc VSS VacSvc W32Time WEPHOSTSVC WFDSConMgrSvc WMPNetworkSvc WManSvc WPDBusEnum WSService WaaSMedicSvc WalletService WarpJITSvc WbioSrvc WcsPlugInService WdNisSvc WdiServiceHost WdiSystemHost WebClient Wecsvc WerSvc WiaRpc WinHttpAutoProxySvc WinRM WpcMonSvc WpnService WwanSvc XblAuthManager XblGameSave XboxGipSvc XboxNetApiSvc autotimesvc bthserv camsvc cbdhsvc_* cloudidsvc dcsvc defragsvc diagnosticshub.standardcollector.service diagsvc dmwappushservice dot3svc edgeupdate edgeupdatem embeddedmode fdPHost fhsvc hidserv icssvc lfsvc lltdsvc lmhosts msiserver netprofm p2pimsvc p2psvc perceptionsimulation pla seclogon smphost spectrum svsvc swprv upnphost vds vm3dservice vmicguestinterface vmicheartbeat vmickvpexchange vmicrdv vmicshutdown vmictimesync vmicvmsession vmicvss vmvss wbengine wcncsvc webthreatdefsvc wercplsupport wisvc wlidsvc wlpasvc wmiApSrv workfolderssvc wuauserv wudfsvc"

REM List of services to set to "Automatic"
set "servicesList=AudioEndpointBuilder AudioSrv BFE BrokerInfrastructure BthAvctpSvc BthHFSrv CDPUserSvc_* CoreMessagingRegistrar CryptSvc DPS DcomLaunch Dhcp DispBrokerDesktopSvc Dnscache DusmSvc EventLog EventSystem FontCache KeyIso LSM LanmanServer LanmanWorkstation MpsSvc Netlogon OneSyncSvc_* Power ProfSvc RpcEptMapper RpcSs SENS SamSs Schedule SgrmBroker ShellHWDetection Spooler SysMain SystemEventsBroker TermService Themes TrkWks UserManager VGAuthService VMTools VaultSvc Wcmsvc WinDefend Winmgmt WlanSvc WpnUserService_* gpsvc iphlpsvc mpssvc nsi tiledatamodelsvc webthreatdefusersvc_*"

REM List of services to set to "Automatic (Delayed Start)"
set "delayedStartList=BITS DoSvc MapsBroker WSearch sppsvc wscsvc"

REM Loop through each service and set it to "disabled"
for %%i in (%disableServicesList%) do (
    echo Disabling service: %%i
    sc config "%%i" start= disabled
)

echo.
echo All specified services have been disabled.
echo.

REM Loop through each service and set it to "manual"
for %%i in (%setManualServicesList%) do (
    echo Setting service %%i to manual
    sc config "%%i" start= demand
)

echo.
echo All specified services have been set to manual.
echo.

REM Loop through each service and set it to "Automatic"
for %%i in (%servicesList%) do (
    echo Setting service %%i to Automatic
    sc config "%%i" start= auto
)

echo.
echo All specified services have been set to Automatic.
echo.



REM Loop through each service and set it to "Automatic (Delayed Start)"
for %%i in (%delayedStartList%) do (
    echo Setting service %%i to Automatic (Delayed Start)
    sc config "%%i" start= delayed-auto
)

echo.
echo ------------------------------------------------------
echo All Windows Services have been Optimized..
echo ------------------------------------------------------

pause


REM AJRouter: AllJoyn Router Service
REM AppVClient: Microsoft App-V Client
REM AssignedAccessManagerSvc: Assigned Access Manager Service
REM autotimesvc: Auto Time Zone Updater
REM Backupper Service: Backupper Service
REM BDESVC: BitLocker Drive Encryption Service
REM BTAGService: Bluetooth Audio Gateway Service
REM BthAvctpSvc: Bluetooth AVCTP Service
REM bthserv: Bluetooth Support Service
REM cbdhsvc: Connected Devices Platform Service
REM CDPSvc: Connected Devices Platform Service
REM CDPUserSvc: Connected Devices Platform User Service
REM CscService: Offline Files
REM DeviceAssociationService: Device Association Service
REM DevicesFlowUserSvc: Devices Flow User Service
REM DevicesFlowUserSvc_5f1ad: Devices Flow User Service (5f1ad)
REM DevQueryBroker: Device Query Broker
REM diagnosticshub.standardcollector.service: Diagnostic Execution Service
REM diagsvc: Diagnostic Policy Service
REM DiagTrack: Connected User Experiences and Telemetry
REM DialogBlockingService: Dialog Blocking Service
REM DispBrokerDesktopSvc: Display Broker Desktop Service
REM DisplayEnhancementService: Display Enhancement Service
REM dLauncherLoopback: Microsoft Launcher Loopback Service
REM dmwappushservice: Device Management Wireless Application Protocol (WAP) Push message Routing Service
REM DsmSvc: Data Sharing Service
REM DsSvc: Data Sharing Service
REM DusmSvc: Data Usage Service
REM edgeupdate: Microsoft Edge Update Service
REM edgeupdatem: Microsoft Edge Update Service (manual)
REM EFS: Encrypting File System (EFS)
REM Fax: Fax Service
REM fdPHost: Function Discovery Provider Host
REM FDResPub: Function Discovery Resource Publication
REM FontCache: Windows Font Cache Service
REM icssvc: Windows Mobile Hotspot Service
REM IKEEXT: IKE and AuthIP IPsec Keying Modules
REM iphlpsvc: IP Helper
REM LanmanWorkstation: Workstation
REM lfsvc: Geolocation Service
REM lmhosts: TCP/IP NetBIOS Helper
REM MessagingService_5f1ad: Messaging Service (5f1ad)
REM MicrosoftEdgeElevationService: Microsoft Edge Elevation Service
REM MixedRealityOpenXRSvc: Windows Mixed Reality OpenXR Service
REM MsKeyboardFilter: Microsoft Keyboard Filter Service
REM NetTcpPortSharing: Net.Tcp Port Sharing Service
REM NlaSvc: Network Location Awareness
REM NPSMSvc: Network Projector
REM OneSyncSvc: Sync Host
REM OneSyncSvc_5f1ad: OneSync Service (5f1ad)
REM PcaSvc: Program Compatibility Assistant Service
REM PhoneSvc: Phone Service
REM PimIndexMaintenanceSvc_5f1ad: People Bar Service (5f1ad)
REM PrintNotify: PrintNotify
REM RasMan: Remote Access Connection Manager
REM RemoteAccess: Remote Access Auto Connection Manager
REM RemoteRegistry: Remote Registry
REM RetailDemo: Retail Demo Service
REM RmSvc: Radio Management Service
REM SEMgrSvc: SENS
REM SensorDataService: Sensor Data Service
REM SensorService: Sensor Service
REM SensrSvc: Adaptive Brightness
REM SessionEnv: Remote Desktop Configuration
REM SharedAccess: Internet Connection Sharing
REM ShellHWDetection: Shell Hardware Detection
REM shpamsvc: Smart Card
REM Spooler: Print Spooler
REM SSDPSRV: SSDP Discovery
REM ssh-agent: OpenSSH SSH Agent
REM SstpSvc: Secure Socket Tunneling Protocol Service
REM stisvc: Windows Image Acquisition (WIA)
REM SysMain: Superfetch
REM TabletInputService: Tablet PC Input Service
REM TapiSrv: Telephony
REM TermService: Terminal Services
REM TokenBroker: Windows Push Notification System Service
REM TrkWks: Distributed Link Tracking Client
REM tzautoupdate: Time Broker
REM UevAgentService: User Experience Virtualization Agent
REM uhssvc: User Data Storage
REM UnistoreSvc: Unistore Service
REM UserDataSvc: User Data Access
REM W32Time: Windows Time
REM WalletService: WalletService
REM WbioSrvc: Windows Biometric Service
REM Wcmsvc: Windows Connection Manager
REM WebClient: WebClient
REM Wecsvc: Windows Event Collector
REM wercplsupport: Windows Error Reporting Service (Support)
REM WerSvc: Windows Error Reporting Service
REM WinHttpAutoProxySvc: WinHTTP Web Proxy Auto-Discovery Service
REM WinRM: Windows Remote Management (WS-Management)
REM wlidsvc: Microsoft Account Sign-in Assistant
REM WMPNetworkSvc: Windows Media Player Network Sharing Service
REM WpcMonSvc: Portable Device Enumerator Service
REM WPDBusEnum: Portable Device Enumerator Service
REM WpnUserService_5f1ad: Windows Push Notifications User Service (5f1ad)
REM XblAuthManager: Xbox Live Auth Manager
REM XblGameSave: Xbox Live Game Save
REM XboxNetApiSvc: Xbox Live Networking Service
REM ALG: Application Layer Gateway Service
REM AppIDSvc: Application Identity
REM AppMgmt: Application Management
REM AppReadiness: App Readiness
REM AppXSvc: AppX Deployment Service (AppXSVC)
REM Appinfo: Application Information
REM AxInstSV: ActiveX Installer (AxInstSV)
REM BDESVC: BitLocker Drive Encryption Service
REM BTAGService: Bluetooth Audio Gateway Service
REM BcastDVRUserService_*: Broadcast DVR server user service
REM BluetoothUserService_*: Bluetooth user service
REM BrokerInfrastructure: Background Tasks Infrastructure Service
REM CDPSvc: Connected Devices Platform Service
REM COMSysApp: COM+ System Application
REM CaptureService_*: CaptureService
REM CertPropSvc: Certificate Propagation
REM ClipSVC: Client License Service (ClipSVC)
REM ConsentUxUserSvc_*: Consent UX
REM CredentialEnrollmentManagerUserSvc_*: Credential Enrollment Manager for User Experience
REM CscService: Offline Files
REM DcpSvc: Data Collection and Publishing Service
REM DevQueryBroker: Device Query Broker
REM DeviceAssociationBrokerSvc_*: Device Association Broker Service
REM DeviceAssociationService: Device Association Service
REM DeviceInstall: Device Install Service
REM DevicePickerUserSvc_*: Device Picker user service
REM DevicesFlowUserSvc_*: Devices Flow User Service
REM DisplayEnhancementService: Display Enhancement Service
REM DmEnrollmentSvc: Device Management Enrollment Service
REM DsSvc: Data Sharing Service
REM DsmSvc: Device Setup Manager
REM EFS: Encrypting File System (EFS)
REM EapHost: Extensible Authentication Protocol
REM EntAppSvc: Enterprise App Management Service
REM FDResPub: Function Discovery Resource Publication
REM Fax: Fax Service
REM FrameServer: Frame Server
REM FrameServerMonitor: Frame Server Monitor
REM GraphicsPerfSvc: GraphicsPerfSvc
REM HomeGroupListener: HomeGroup Listener
REM HomeGroupProvider: HomeGroup Provider
REM HvHost: Hyper-V Host Compute Service
REM IEEtwCollectorService: ETW Collector Service for Desktop Sharing
REM IKEEXT: IKE and AuthIP IPsec Keying Modules
REM InstallService: Windows Installer
REM InventorySvc: Inventory Service
REM IpxlatCfgSvc: IP Translation Configuration Service
REM KtmRm: KtmRm
REM LicenseManager: License Manager
REM LxpSvc: Microsoft UPnP Device Host
REM MSDTC: Distributed Transaction Coordinator
REM MSiSCSI: Microsoft iSCSI Initiator Service
REM McpManagementService: Media Center Extender Service
REM MessagingService_*: Messaging Service
REM MicrosoftEdgeElevationService: Microsoft Edge Elevation Service
REM MixedRealityOpenXRSvc: Windows Mixed Reality OpenXR Service
REM MpsSvc: Windows Firewall
REM MsKeyboardFilter: Microsoft Keyboard Filter
REM NPSMSvc_*: Net.Pipe Listener Adapter
REM NaturalAuthentication: Natural Authentication
REM NcaSvc: Network Connectivity Assistant
REM NcbService: Network Connection Broker
REM NcdAutoSetup: Network Connected Devices Auto-Setup
REM NetSetupSvc: Network Setup Service
REM Netman: Network Connection Manager
REM NgcCtnrSvc: Microsoft Passport Container
REM NgcSvc: Microsoft Passport
REM NlaSvc: Network Location Awareness
REM P9RdrService_*: Payment and Risk
REM PNRPAutoReg: PNRP Machine Name Publication Service
REM PNRPsvc: PNRP (Peer Name Resolution Protocol)
REM PcaSvc: Program Compatibility Assistant Service
REM PeerDistSvc: BranchCache
REM PenService_*: Pen Service
REM PerfHost: Performance Counter DLL Host
REM PhoneSvc: Phone Service
REM PimIndexMaintenanceSvc_*: Contact Data
REM PlugPlay: Plug and Play
REM PolicyAgent: IPsec Policy Agent
REM PrintNotify: Printer Extensions and Notifications
REM PrintWorkflowUserSvc_*: PrintWorkflow
REM PushToInstall: Windows PushToInstall Service
REM QWAVE: Quality Windows Audio Video Experience
REM RasAuto: Remote Access Auto Connection Manager
REM RasMan: Remote Access Connection Manager
REM RetailDemo: Retail Demo Service
REM RmSvc: Radio Management Service
REM RpcLocator: Remote Procedure Call (RPC) Locator
REM SCPolicySvc: Smart Card
REM SCardSvr: Smart Card Removal Policy
REM SDRSVC: Storage Data Access Service
REM SEMgrSvc: System Event Notification Service
REM SNMPTRAP: SNMP Trap
REM SSDPSRV: SSDP Discovery
REM ScDeviceEnum: Smart Card Device Enumeration Service
REM SecurityHealthService: Windows Security Health Service
REM Sense: Sense
REM SensorDataService: Sensor Data Service
REM SensorService: Sensor Service
REM SensrSvc: Adaptive Brightness
REM SessionEnv: Remote Desktop Configuration
REM SharedAccess: Internet Connection Sharing
REM SharedRealitySvc: Windows Mixed Reality OpenXR Service
REM SmsRouter: SMS Router Service
REM SstpSvc: Secure Socket Tunneling Protocol Service
REM StateRepository: State Repository Service
REM StiSvc: Windows Image Acquisition (WIA)
REM StorSvc: Storage Service
REM TabletInputService: Tablet PC Input Service
REM TextInputManagementService: Text Input User Service_*
REM TieringEngineService: Storage Tiers Management
REM TimeBroker: Time Broker
REM TimeBrokerSvc: Time Broker
REM TokenBroker: Token Broker
REM TroubleshootingSvc: Troubleshooting Service
REM TrustedInstaller: Windows Modules Installer
REM UI0Detect: Interactive Services Detection
REM UdkUserSvc_*: Microsoft UEFI Certificate Authority User Service
REM UmRdpService: Remote Desktop Services UserMode Port Redirector
REM UnistoreSvc_*: User Data Storage
REM UserDataSvc_*: User Data Storage
REM UsoSvc: Update Orchestrator Service
REM VSS: Volume Shadow Copy
REM VacSvc: Microsoft Visual Analytics Service
REM W32Time: Windows Time
REM WEPHOSTSVC: Windows Encryption Provider Host Service
REM WFDSConMgrSvc: Wi-Fi Direct Services Connection Manager Service
REM WMPNetworkSvc: Windows Media Player Network Sharing Service
REM WManSvc: Windows Management Service
REM WPDBusEnum: Portable Device Enumerator Service
REM WSService: Windows Store Service (WSService)
REM WaaSMedicSvc: Windows Update Medic Service
REM WalletService: WalletService
REM WarpJITSvc: Windows Remediation Service
REM WbioSrvc: Windows Biometric Service
REM WcsPlugInService: Windows Color System
REM WdNisSvc: Windows Defender Antivirus Network Inspection Service
REM WdiServiceHost: Diagnostic Policy Service
REM WdiSystemHost: Diagnostic Service Host
REM WebClient: WebClient
REM Wecsvc: Windows Event Collector
REM WerSvc: Windows Error Reporting Service
REM WiaRpc: Still Image Acquisition Events
REM WinHttpAutoProxySvc: WinHTTP Web Proxy Auto-Discovery Service
REM WinRM: Windows Remote Management (WS-Management)
REM WpcMonSvc: Portable Device Enumerator Service
REM WpnService: Windows Push Notifications Service
REM WwanSvc: WWAN AutoConfig
REM XblAuthManager: Xbox Live Auth Manager
REM XblGameSave: Xbox Live Game Save
REM XboxGipSvc: Xbox Live Networking Service
REM autotimesvc: Auto Time Zone Updater
REM bthserv: Bluetooth Support Service
REM camsvc: Capability Access Manager Service
REM cbdhsvc_*: Connected Devices Platform Service
REM cloudidsvc: Microsoft Account Sign-in Assistant
REM dcsvc: DataCollectionService
REM defragsvc: Optimize Drives
REM diagnosticshub.standardcollector.service: Diagnostic Execution Service
REM diagsvc: Diagnostic Policy Service
REM dmwappushservice: Device Management Wireless Application Protocol (WAP) Push message Routing Service
REM dot3svc: Wired AutoConfig
REM edgeupdate: Microsoft Edge Update Service
REM edgeupdatem: Microsoft Edge Update Service (manual)
REM embeddedmode: Embedded Mode
REM fdPHost: Function Discovery Provider Host
REM fhsvc: File History Service
REM hidserv: Human Interface Device Service
REM icssvc: Windows Mobile Hotspot Service
REM lfsvc: Geolocation Service
REM lltdsvc: Link-Layer Topology Discovery Mapper
REM lmhosts: TCP/IP NetBIOS Helper
REM msiserver: Windows Installer
REM netprofm: Network List Service
REM p2pimsvc: Peer Name Resolution Protocol
REM p2psvc: Peer Networking Grouping
REM perceptionsimulation: Windows Perception Simulation Service
REM pla: Performance Logs & Alerts
REM seclogon: Secondary Logon
REM smphost: Storage Management
REM spectrum: Spectrum
REM svsvc: Spot Verifier
REM swprv: Microsoft Software Shadow Copy Provider
REM upnphost: UPnP Device Host
REM vds: Virtual Disk
REM vm3dservice: Vm3dService
REM vmicguestinterface: Hyper-V Data Exchange Service Guest Interface
REM vmicheartbeat: Hyper-V Heartbeat Service
REM vmickvpexchange: Hyper-V Data Exchange Service
REM vmicrdv: Hyper-V Remote Desktop Virtualization Service
REM vmicshutdown: Hyper-V Guest Shutdown Service
REM vmictimesync: Hyper-V Time Synchronization Service
REM vmicvmsession: Hyper-V Guest Service Interface
REM vmicvss: Hyper-V Volume Shadow Copy Requestor
REM vmvss: Hyper-V Volume Shadow Copy Service
REM wbengine: Block Level Backup Engine Service
REM wcncsvc: Windows Connect Now - Config Registrar
REM webthreatdefsvc: Web Device Management
REM wercplsupport: Windows Error Reporting Service (Support)
REM wisvc: Windows Insider Service
REM wlidsvc: Microsoft Account Sign-in Assistant
REM wlpasvc: Local Profile Assistant Service
REM wmiApSrv: WMI Performance Adapter
REM workfolderssvc: Work Folders
REM wuauserv: Windows Update
REM AudioEndpointBuilder: Manages audio devices
REM AudioSrv: Windows Audio Service
REM BFE: Base Filtering Engine
REM BrokerInfrastructure: Background Tasks Infrastructure Service
REM BthAvctpSvc: Bluetooth AVCTP Service
REM BthHFSrv: Bluetooth Handsfree Service
REM CDPUserSvc_*: Connected Devices Platform User Service
REM CoreMessagingRegistrar: CoreMessaging Registrar
REM CryptSvc: Cryptographic Services
REM DPS: Diagnostic Policy Service
REM DcomLaunch: DCOM Server Process Launcher
REM Dhcp: DHCP Client
REM DispBrokerDesktopSvc: Display Broker Desktop Service
REM Dnscache: DNS Client
REM DusmSvc: Data Usage
REM EventLog: Windows Event Log
REM EventSystem: COM+ Event System
REM FontCache: Windows Font Cache Service
REM KeyIso: CNG Key Isolation
REM LSM: Local Session Manager
REM LanmanServer: Server
REM LanmanWorkstation: Workstation
REM MpsSvc: Windows Firewall
REM Netlogon: Netlogon
REM OneSyncSvc_*: Sync Host
REM Power: Power Service
REM ProfSvc: User Profile Service
REM RpcEptMapper: RPC Endpoint Mapper
REM RpcSs: Remote Procedure Call (RPC)
REM SENS: System Event Notification Service
REM SamSs: Security Accounts Manager
REM Schedule: Task Scheduler
REM SgrmBroker: System Guard Runtime Monitor Broker
REM ShellHWDetection: Shell Hardware Detection
REM Spooler: Print Spooler
REM SysMain: Superfetch
REM SystemEventsBroker: System Events Broker
REM TermService: Remote Desktop Services
REM Themes: Themes
REM TrkWks: Distributed Link Tracking Client
REM UserManager: User Manager
REM VGAuthService: Credential Manager
REM VMTools: VMware Tools Service
REM VaultSvc: Credential Vault
REM Wcmsvc: Windows Connection Manager
REM WinDefend: Windows Defender Antivirus Service
REM Winmgmt: Windows Management Instrumentation
REM WlanSvc: WLAN AutoConfig
REM WpnUserService_*: Windows Push Notifications User Service
REM gpsvc: Group Policy Client
REM iphlpsvc: IP Helper
REM mpssvc: Windows Firewall
REM nsi: Network Store Interface Service
REM tiledatamodelsvc: Tile Data model server
REM webthreatdefusersvc_*: Microsoft Defender SmartScreen User Service
REM BITS: Background Intelligent Transfer Service
REM DoSvc: Delivery Optimization
REM MapsBroker: Downloaded Maps Manager
REM WSearch: Windows Search
REM sppsvc: Software Protection
REM wscsvc: Security Center




rem =========================================
rem Script to Optimize Network Settings
rem =========================================
echo -----------------------------------------------
echo Starting Network Optimization...
echo -----------------------------------------------

cd %temp%
set Pwsh=^>nul powershell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command
setlocal EnableDelayedExpansion

rem Run as Trusted Installer via MinSudo
dism>nul || (where MinSudo >nul 2>&1 || (
curl -L "https://github.com/M2Team/NanaRun/releases/download/1.0.18.0/NanaRun_1.0_Preview2_1.0.18.0.zip" -o "NanaRun.zip" -s || ^
echo Failed to download MinSudo, run this script as an administrator. && pause && exit
%Pwsh% "Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::ExtractToDirectory('NanaRun.zip', '.\NanaRun');"
move /y .\NanaRun\x64\MinSudo.exe MinSudo.exe >nul
del /f NanaRun.zip
rmdir /s /q NanaRun
) & MinSudo -NoL -TI -P "%~f0" && exit)
cls

rem Reset TCP/IP Stack
netsh winhttp reset proxy >nul
netsh winsock reset >nul
netsh int ip reset >nul
echo Reset TCP/IP Stack

rem Disable IPsec Task Offload and TCP Chimney Offload
%Pwsh% Disable-NetAdapterIPsecOffload -Name *
Netsh int tcp set global chimney=disabled >nul
call :NICSetting "IPsecOffloadV1IPv4" "0"
call :NICSetting "IPsecOffloadV2" "0"
call :NICSetting "IPsecOffloadV2IPv4" "0"
echo Disable IPsec Task Offload and TCP Chimney Offload

rem Enable UDP and TCP Checksums
%Pwsh% Enable-NetAdapterChecksumOffload -Name *
call :NICSetting "TCPUDPChecksumOffloadIPv4" "3"
call :NICSetting "TCPUDPChecksumOffloadIPv6" "3"
call :NICSetting "UDPChecksumOffloadIPv4" "3"
call :NICSetting "UDPChecksumOffloadIPv6" "3"
call :NICSetting "TCPChecksumOffloadIPv4" "3"
call :NICSetting "TCPChecksumOffloadIPv6" "3"
call :NICSetting "IPChecksumOffloadIPv4" "3"
echo Enable UDP and TCP Checksums

rem Enable Large Send Offload (LSO)
%Pwsh% Enable-NetAdapterLso -Name *
call :NICSetting "LsoV1IPv4" "1"
call :NICSetting "LsoV2IPv4" "1"
call :NICSetting "LsoV2IPv6" "1"
echo Enable Large Send Offload (LSO)

rem Disable Flow Control
call :NICSetting "*FlowControl" "1"
echo Disable Flow Control

rem Increase IRPStackSize
Reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v IRPStackSize /t REG_DWORD /d 32 /f >nul
echo Increase IRPStackSize

rem Improving Live Migration
Reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v RequireSecuritySignature /t REG_DWORD /d 0 /f >nul
echo Improving Live Migration

rem Disable Interrupt Moderation
call :NICSetting "*InterruptModeration" "0"
echo Disable Interrupt Moderation

rem Low Latency Interrupt Moderation Profile
call :NICSetting "TxIntModerationProfile" "0"
call :NICSetting "RxIntModerationProfile" "0"
echo Low Latency Interrupt Moderation Profile

rem Receive Completion Method: Polling
call :NICSetting "RecvCompletionMethod" "0"
echo Receive Completion Method: Polling

rem Disable Buffer List Tracking
Reg add HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters /v TrackNblOwner /t REG_DWORD /d 0 /f >nul
echo Disable Buffer List Tracking

rem Enable Fast Send Datagram
Reg add HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters /v FastSendDatagramThreshold /t REG_DWORD /d 409600 /f >nul
echo Enable Fast Send Datagram

rem Set the maximum number of concurrent connections (per server endpoint) allowed when making requests using an HttpClient object.
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f >nul
rem Maximum number of HTTP 1.0 connections to a Web server
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f >nul
echo Increase Concurrent Connections Limit

rem Lower TCP connection timeout
netsh int tcp set global initialRto=2000 >nul
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces TcpInitialRTT 2000
echo Lower Initial RTO

rem Disable RTT resiliency for non SACK clients
Netsh int tcp set global nonsackrttresiliency=disabled >nul
echo Disable RTT resiliency for non SACK clients

rem Lower Max SYN Retransmissions
netsh int tcp set global maxsynretransmissions=2 >nul
echo Lower Max SYN Retransmissions

rem Enable Large System Cache
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v Size /t REG_DWORD /d 3 /f >nul
echo Enable Large System Cache

rem Enable Auto-Tuning
Netsh winsock set autotuning on >nul
Netsh int tcp set global autotuninglevel=normal >nul
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v TcpAutotuning /t REG_DWORD /d 1 /f >nul
echo Enable Auto-Tuning

rem Disable Receive Segment Coalescing State (RSC)
%Pwsh% Disable-NetAdapterRsc -Name *
netsh int tcp set global rsc=disabled >nul
echo Disable Receive Segment Coalescing State (RSC)

rem Disable DMA Coalescing
call :NICSetting "DMACoalescing" "0"
echo Disable DMA Coalescing

rem Disable Packet Coalescing
%Pwsh% Set-NetOffloadGlobalSetting -PacketCoalescingFilter disabled
echo Disable Packet Coalescing

rem Enable Direct Cache Access (DCA)
Netsh int tcp set global dca=enabled >nul
echo Enable Direct Cache Access (DCA)

rem Disable Connected Standby
Reg add HKLM\System\CurrentControlSet\Control\Power /v EnforceDisconnectedStandby /t REG_DWORD /d 0 /f >nul
powercfg /setacvalueindex scheme_current sub_none connectivityinstandby 0
powercfg /s scheme_current
echo Disable Connected Standby

rem Enable Weak Host Model
for /f "tokens=1" %%a in ('netsh interface ip show interface ^| findstr /I "connected"') do (
netsh int ipv4 set int %%a weakhostreceive=enabled weakhostsend=enabled
netsh int ipv6 set int %%a weakhostreceive=enabled weakhostsend=enabled
) >nul
echo Enable Weak Host Model

rem Set Congestion Provider To BBR2/NewReno
netsh int tcp set global ecncapability=enabled >nul
wmic os get Caption | find "11" >nul && (
for /f "tokens=7" %%a in ('netsh int tcp show supplemental ^| findstr /I "template"') do netsh int tcp set supplemental %%a CongestionProvider=bbr2 >nul
echo Set Congestion Provider To BBR2
) || (
for /f "tokens=7" %%a in ('netsh int tcp show supplemental ^| findstr /I "template"') do netsh int tcp set supplemental %%a CongestionProvider=newreno >nul
echo Set Congestion Provider To NewReno
)

rem Increase the TCP Initial Congestion Window
for /f "tokens=7" %%a in ('netsh int tcp show supplemental ^| findstr /I "template"') do Netsh int tcp set supplemental %%a icw=10 >nul
echo Increase the TCP Initial Congestion Window

rem Disable Network Power Savings
%Pwsh% Disable-NetAdapterPowerManagement -Name *
echo Disable Network Power Savings

rem Disable Delivery Optimization (peer-to-peer functionality)
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
sc config DoSvc start=disabled >nul
sc stop "DoSvc" >nul
echo Disable Delivery Optimization

rem Disable Network Throttling
Reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched /v NonBestEffortLimit /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f >nul
echo Disable Network Throttling

rem Reduce Time To Live
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters DefaultTTL 64
echo Reduce Time To Live

rem Disable Window Scaling Heuristics
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters EnableWsd 0
netsh int tcp set heuristics disabled >nul
echo Disable Window Scaling Heuristics

rem Increase Network Priority
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider LocalPriority 4
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider HostsPriority 5
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider DnsPriority 6
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider NetBtPriority 7
echo Increase Network Priority

rem Decrease length of TIME_WAIT state
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters TcpTimedWaitDelay 30
echo Decrease length of TIME_WAIT state

rem Enable TCP Selective Acks
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters SackOpts 1
echo Enable TCP Selective Acks

rem Enable Path MTU
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters EnablePMTUDiscovery 1
echo Enable Path MTU

rem Remove TCP Connection Limit
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters EnableConnectionRateLimiting 0
echo Remove TCP Connection Limit

rem Set Dynamic Port Range to Maximum
netsh int ip set dynamicport tcp start=1025 num=64511 >nul
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters MaxUserPort 65534
echo Set Dynamic Port Range to Maximum

rem Enable NetDMA
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters EnableTCPA 1
echo Enable NetDMA

rem Disable TCP 1323 Timestamps
Netsh int tcp set global timestamps=disabled >nul
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters Tcp1323Opts 1
echo Disable TCP 1323 Timestamps

rem Disable Nagle's Algorithm
Reg add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s ^| findstr /i /l "ServiceName"') do (
	call :TCPIP "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" TCPNoDelay 1
	call :TCPIP "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" TcpAckFrequency 1
) >nul 2>&1
echo Disable Nagle's Algorithm

rem Enable Network Task Offloading
Netsh int ip set global taskoffload=enabled >nul 2>&1
call :TCPIP "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" DisableTaskOffload 0
Reg add HKLM\System\CurrentControlSet\Services\Ipsec /v EnabledOffload /t REG_DWORD /d 1 /f >nul
echo Enable Network Task Offloading

rem Disable NetBIOS
Reg add HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces /v NetbiosOptions /t REG_DWORD /d 1 /f >nul
sc stop netbt >nul
sc config netbt start=disabled >nul
sc stop lmhosts >nul
sc config lmhosts start=disabled >nul
rem If NetBIOS manages to become enabled, protect against NBT-NS poisoning attacks
Reg add HKLM\System\CurrentControlSet\Services\NetBT\Parameters /v NodeType /t REG_DWORD /d 2 /f >nul
echo Disable NetBIOS

rem Disable LLMNR
Reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f >nul
echo Disable LLMNR

rem Enable DNS over HTTPS
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f >nul
echo Enable DNS over HTTPS

rem Disable Memory Pressure Protection (MPP)
Netsh int tcp set security mpp=disabled >nul
Netsh int tcp set security profiles=disabled >nul
call :TCPIP HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters EnableMPP 0
echo Disable Memory Pressure Protection (MPP)

rem Disable Network Adapter Power Saving
mkdir "%SYSTEMDRIVE%\Backup" 2>nul
for /f "tokens=3*" %%a in ('Reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /k /v /f "Description" /s /e ^| findstr /ri "REG_SZ"') do ^
for /f %%g in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /s /f "%%b" /d ^| findstr /C:"HKEY"') do (
if not exist "%SYSTEMDRIVE%\Backup\(Default) %%b.reg" Reg export "%%g" "%SYSTEMDRIVE%\Backup\(Default) %%b.reg" /y
::Disable Wake Features
Reg add "%%g" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
Reg add "%%g" /v "WakeOnLink" /t REG_SZ /d "0" /f
Reg add "%%g" /v "S5WakeOnLan" /t REG_SZ /d "0" /f
Reg add "%%g" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f
Reg add "%%g" /v "*ModernStandbyWoLMagicPacket	" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f
::Energy Efficient Ethernet
Reg add "%%g" /v "*EEE" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EeePhyEnable" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AdvancedEEE" /t REG_SZ /d "0" /f
::Ultra Low Power Mode
Reg add "%%g" /v "ULPMode" /t REG_SZ /d "0" /f
::Wi-Fi capability that saves power consumption
Reg add "%%g" /v "uAPSDSupport" /t REG_SZ /d "0" /f
::Disable Power Saving Features
Reg add "%%g" /v "*NicAutoPowerSaver" /t REG_SZ /d "0" /f
Reg add "%%g" /v "SelectiveSuspend" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnablePME" /t REG_SZ /d "0" /f
Reg add "%%g" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PowerSavingMode" /t REG_SZ /d "0" /f
Reg add "%%g" /v "SavePowerNowEnabled" /t REG_SZ /d "0" /f
Reg add "%%g" /v "GigaLite" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
Reg add "%%g" /v "bLowPowerEnable" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PowerSaveMode" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PowerDownPll" /t REG_SZ /d "0" /f
Reg add "%%g" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
Reg add "%%g" /v "MIMOPowerSaveMode" /t REG_SZ /d "3" /f
Reg add "%%g" /v "AlternateSemaphoreDelay" /t REG_SZ /d "0" /f
Reg add "%%g" /v "SipsEnabled" /t REG_SZ /d "0" /f
::Enable Throughput Booster
Reg add "%%g" /v "ThroughputBoosterEnabled" /t REG_SZ /d "1" /f
::Access Point Compatibility Mode: 'High Performance'
Reg add "%%g" /v "ApCompatMode" /t REG_SZ /d "0" /f
rem Disable network adapter power management
Reg add "%%g" /v "PnPCapabilities" /t REG_DWORD /d "24" /f
::Enable Offloads
Reg add "%%g" /v "*PMARPOffload" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*PMNSOffload" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*PMWiFiRekeyOffload" /t REG_SZ /d "1" /f
) >nul 2>&1
echo Disable Network Adapter Power Saving

rem Configure Network Adapter Device Parameters
for /f %%a in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| find "PCI\VEN_"') do (

rem Set Network Adapter Interrupt Priority to Undefined
Reg delete "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
echo Set Network Adapter Interrupt Priority to Undefined

rem Set Network Adapter Policy to IrqPolicySpreadMessagesAcrossAllProcessors
Reg add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "5" /f >nul
echo Set Network Adapter Policy to IrqPolicySpreadMessagesAcrossAllProcessors

rem Enable Network Adapter MSI Mode
Reg add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul
echo Enable Network Adapter MSI Mode

)

rem Optimize RSS
call :NICSetting "TxIntModeration" "2"
netsh int tcp set global rss=enabled >nul
set /a MaxRssProc=%NUMBER_OF_PROCESSORS%-2
for /f "tokens=3*" %%a in ('Reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /k /v /f "Description" /s /e ^| findstr /ri "REG_SZ"') do ^
for /f %%g in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /s /f "%%b" /d ^| findstr /C:"HKEY"') do (
rem Add RSS Support
Reg add "%%g\Ndi\Params\*RSS" /v "ParamDesc" /t REG_SZ /d "Receive Side Scaling" /f
Reg add "%%g\Ndi\Params\*RSS" /v "default" /t REG_SZ /d "1" /f
Reg add "%%g\Ndi\Params\*RSS" /v "type" /t REG_SZ /d "enum" /f
Reg add "%%g\Ndi\Params\*RSS\Enum" /v "0" /t REG_SZ /d "Disabled" /f
Reg add "%%g\Ndi\Params\*RSS\Enum" /v "1" /t REG_SZ /d "Enabled" /f

rem Unlock RSS Queues
Reg add "%%g\Ndi\Params\*NumRssQueues" /v "ParamDesc" /t REG_SZ /d "Maximum Number of RSS Queues" /f
Reg add "%%g\Ndi\Params\*NumRssQueues" /v "default" /t REG_SZ /d "4" /f
Reg add "%%g\Ndi\Params\*NumRssQueues" /v "type" /t REG_SZ /d "enum" /f
Reg add "%%g\Ndi\Params\*NumRssQueues\Enum" /v "1" /t REG_SZ /d "1 Queue" /f
Reg add "%%g\Ndi\Params\*NumRssQueues\Enum" /v "2" /t REG_SZ /d "2 Queues" /f
Reg add "%%g\Ndi\Params\*NumRssQueues\Enum" /v "3" /t REG_SZ /d "3 Queues" /f
Reg add "%%g\Ndi\Params\*NumRssQueues\Enum" /v "4" /t REG_SZ /d "4 Queues" /f

rem Enable RSS
Reg add "%%g" /v "*RSS" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*NumRssQueues" /t REG_SZ /d "4" /f
Reg add "%%g" /v "*RSSProfile" /t REG_SZ /d "4" /f
Reg add "%%g" /v "*NumaNodeId" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*RssBaseProcGroup" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*RssMaxProcGroup" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*RssBaseProcNumber" /t REG_SZ /d "0" /f

rem Increase RSS Processors
Reg add "%%g" /v "*RssMaxProcNumber" /t REG_SZ /d "%MaxRssProc%" /f
Reg add "%%g" /v "*MaxRssProcessors" /t REG_SZ /d "%MaxRssProc%" /f

rem Use RssV2
Reg add "%%g" /v "RssV2" /t REG_SZ /d "1" /f
Reg add "%%g" /v "ValidateRssV2" /t REG_SZ /d "1" /f
) >nul
echo Enable RSS

rem Restart Explorer
rem taskkill /f /im explorer.exe >nul && start explorer.exe

rem Release/Renew IP address
ipconfig /release >nul
ipconfig /renew >nul
echo Renew IP address

rem Flush DNS Cache
ipconfig /flushdns >nul
echo Flush DNS Cache

rem Restart Network Adapter
choice /c yn /m "Operations complete, would you like to restart your network adapter?"
if %errorlevel% equ 1 %Pwsh% Restart-NetAdapter *
pause & exit

:NICSetting
for /f "tokens=3*" %%a in ('Reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /k /v /f "Description" /s /e ^| findstr /ri "REG_SZ"') do ^
for /f %%g in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /s /f "%%b" /d ^| findstr /C:"HKEY"') do (
	Reg add "%%g" /v "%1" /t REG_SZ /d "%2" /f
) >nul 2>&1
goto:eof

:NICSettingPwsh
for /f "skip=3 tokens=4*" %%a in ('netsh interface show interface') do (
%Pwsh% Set-NetAdapterAdvancedProperty -Name "%%a" -RegistryKeyword "%1" -RegistryValue "%2"
) >nul
goto:eof

:TCPIP
set regpath=%~1
Reg add "%regpath%" /v "%~2" /t REG_DWORD /d "%~3" /f >nul
Reg add "%regpath:Tcpip=Tcpip6%" /v "%~2" /t REG_DWORD /d "%~3" /f >nul
goto:eof


::https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.QualityofService::QosTimerResolution
Reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >>%log% 2>>%error%
Reg add "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNicBuffers" /t REG_DWORD /d "1" /f >>%log% 2>>%error%
echo Qos TimerResolution

echo -----------------------------------------------
echo Network Settings Optimized...
echo -----------------------------------------------


pause