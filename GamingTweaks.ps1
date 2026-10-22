<#
    GamingTweaks.ps1  -  one menu, every change backed up, one-click revert
    ---------------------------------------------------------------------
    Built from the useful parts of WinUtil, Atlas, ReviOS and FR33THY's Ultimate,
    leaving out the tweaks that break Windows (UAC fully off, WebView removal,
    write-cache flushing off, DEP/firewall off, wiping startup tasks, etc).

    Keeps working: Microsoft Store, Xbox / Gaming Services, Photos, Calculator,
                   Notepad, Terminal, Snipping Tool, Edge WebView, anti-cheat services.

    Every registry value, service, task, power plan, NIC setting and DNS server the
    script touches is recorded in C:\GamingTweaks\backup.json BEFORE it is changed.
    Menu option [R] puts all of it back.

    Source: https://github.com/FiTH-g1gGLe/Windows-11-Script

    Run:  double-click Run-GamingTweaks.cmd
     or:  powershell -ExecutionPolicy Bypass -File .\GamingTweaks.ps1
#>

#region ---------- bootstrap ----------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$Version = '1.1.0'
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$Host.UI.RawUI.WindowTitle = "GamingTweaks v$Version"

$Root       = Join-Path $env:SystemDrive 'GamingTweaks'
$BackupFile = Join-Path $Root 'backup.json'
New-Item -ItemType Directory -Path $Root -Force | Out-Null
try { Start-Transcript -Path (Join-Path $Root ("log-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))) -ErrorAction Stop | Out-Null } catch {}
#endregion

#region ---------- output helpers ----------
function Write-Title($t) { Write-Host ""; Write-Host "=== $t ===" -ForegroundColor Cyan }
function Write-Ok($t)    { Write-Host "  [+] $t" -ForegroundColor Green }
function Write-Skip($t)  { Write-Host "  [-] $t" -ForegroundColor DarkGray }
function Write-Warn2($t) { Write-Host "  [!] $t" -ForegroundColor Yellow }
function Confirm-Yes($q) {
    $a = Read-Host "  $q [y/N]"
    return ($a -match '^(y|yes)$')
}
#endregion

#region ---------- system detection ----------
$cv        = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$Build     = [int]$cv.CurrentBuild
$WinName   = if ($Build -ge 22000) { 'Windows 11' } else { 'Windows 10' }
$WinVer    = $cv.DisplayVersion
$Chassis   = @((Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue).ChassisTypes)
$HasBatt   = [bool](Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
$IsLaptop  = $HasBatt -or [bool]($Chassis | Where-Object { $_ -in 8,9,10,11,12,14,18,21,30,31,32 })
$GpuNames  = @((Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue).Name)
$HasNvidia = [bool]($GpuNames -match 'NVIDIA')
$HasAmdGpu = [bool]($GpuNames -match 'AMD|Radeon')
$CpuName   = ((Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1).Name).Trim()
$RamGB     = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
$IsX3D     = $CpuName -match 'X3D'
# Two-chiplet X3D (7900X3D, 7950X3D, 9900X3D, 9950X3D): AMD's driver needs core parking + Game Bar to keep games on the V-Cache chiplet
$IsDualX3D = $CpuName -match '(79|99)\d0X3D'
$AntiCheat = @()
if (Get-Service -Name vgc, vgk -ErrorAction SilentlyContinue)            { $AntiCheat += 'Riot Vanguard' }
if (Get-Service -Name 'FACEIT*' -ErrorAction SilentlyContinue)          { $AntiCheat += 'FACEIT' }
if (Get-Service -Name 'EasyAntiCheat*' -ErrorAction SilentlyContinue)   { $AntiCheat += 'Easy Anti-Cheat' }
if (Get-Service -Name 'BEService*' -ErrorAction SilentlyContinue)       { $AntiCheat += 'BattlEye' }
#endregion

#region ---------- backup engine ----------
$script:Backup = @{ Registry = @{}; Tasks = @{}; Flags = @{}; NetAdv = @{}; Dns = @{} }

function ConvertTo-HT($obj) {
    $h = @{}
    if ($null -ne $obj) { foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    return $h
}

function Import-Backup {
    if (Test-Path $BackupFile) {
        try {
            $j = Get-Content $BackupFile -Raw | ConvertFrom-Json
            foreach ($k in 'Registry', 'Tasks', 'Flags', 'NetAdv', 'Dns') { $script:Backup[$k] = ConvertTo-HT $j.$k }
        } catch { Write-Warn2 "Could not read $BackupFile - starting a new backup" }
    }
}

function Save-Backup {
    $script:Backup | ConvertTo-Json -Depth 8 | Set-Content -Path $BackupFile -Encoding UTF8
}

function Get-RegPsPath([string]$Path) {
    $p = $Path -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU\\', 'HKEY_CURRENT_USER\' -replace '^HKU\\', 'HKEY_USERS\'
    return "Registry::$p"
}

function Get-RegValue([string]$Path, [string]$Name) {
    $p = Get-RegPsPath $Path
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    return (Get-Item -LiteralPath $p).GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
}

# Records the original value (once), then writes the new one.
function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    $p  = Get-RegPsPath $Path
    $id = "$Path|$Name"
    if (-not $script:Backup.Registry.ContainsKey($id)) {
        $entry = [ordered]@{ Path = $Path; Name = $Name; Existed = $false; Kind = $null; Value = $null }
        if (Test-Path -LiteralPath $p) {
            $key = Get-Item -LiteralPath $p
            if ($key.GetValueNames() -contains $Name) {
                $entry.Existed = $true
                $entry.Kind    = $key.GetValueKind($Name).ToString()
                $entry.Value   = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            }
        }
        $script:Backup.Registry[$id] = $entry
    }
    try {
        if (-not (Test-Path -LiteralPath $p)) { New-Item -Path $p -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $p -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Warn2 "Could not set $Path\$Name ($($_.Exception.Message))"
    }
}

# Service start type via registry so it is backed up like everything else. 2=Auto 3=Manual 4=Disabled
# Windows defaults, used as the "original" if a service is already at the target value
# (e.g. a previous run was closed before it could save its backup)
$SvcDefaults = @{ DiagTrack = 2; dmwappushservice = 3; 'diagnosticshub.standardcollector.service' = 3; WerSvc = 3; Ndu = 2 }
# Per-user services (e.g. NPSMSvc) have a template plus one copy per user (NPSMSvc_1a2b3) - set them all
function Set-SvcAll([string]$Name, [int]$Start) {
    $root = 'HKLM\SYSTEM\CurrentControlSet\Services'
    $hit = $false
    foreach ($k in (Get-ChildItem -LiteralPath (Get-RegPsPath $root) -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -eq $Name -or $_.PSChildName -like "$($Name)_*" })) {
        Set-Svc $k.PSChildName $Start; $hit = $true
    }
    return $hit
}

function Set-Svc([string]$Name, [int]$Start) {
    $k = "HKLM\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path -LiteralPath (Get-RegPsPath $k))) { Write-Skip "service $Name not present"; return }
    $id = "$k|Start"
    if (-not $script:Backup.Registry.ContainsKey($id) -and $SvcDefaults.ContainsKey($Name) -and (Get-RegValue $k 'Start') -eq $Start) {
        $script:Backup.Registry[$id] = [ordered]@{ Path = $k; Name = 'Start'; Existed = $true; Kind = 'DWord'; Value = $SvcDefaults[$Name] }
    }
    Set-Reg $k 'Start' $Start
    Save-Backup
    # Ask it to stop without waiting. Drivers like Ndu can't stop while Windows is running -
    # they are simply not loaded after the next reboot.
    if ($Start -eq 4) { & sc.exe stop $Name *> $null }
}

function Disable-Task([string]$Full) {
    $tp = (Split-Path $Full -Parent).TrimEnd('\') + '\'
    $tn = Split-Path $Full -Leaf
    $t  = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue
    if (-not $t) { return }
    if ($t.State -ne 'Disabled') {
        try {
            Disable-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop | Out-Null
            $script:Backup.Tasks[$Full] = 1
        } catch { Write-Skip "task $tn is protected, left alone" }
    }
}

function Set-Flag([string]$Name, $Value) {
    if (-not $script:Backup.Flags.ContainsKey($Name)) { $script:Backup.Flags[$Name] = $Value }
}
#endregion

#region ---------- 0. restore point ----------
function New-RestorePoint {
    Save-Baseline
    Write-Title 'Restore point'
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
        Set-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' 'SystemRestorePointCreationFrequency' 0
        Checkpoint-Computer -Description 'Before GamingTweaks' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Ok 'Restore point created'
    } catch { Write-Warn2 "Restore point failed: $($_.Exception.Message)" }
    Save-Backup
}
#endregion

#region ---------- 1. power ----------
function Get-Guid([string]$Text) {
    return [regex]::Match($Text, '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}').Value
}

function Invoke-Power {
    Write-Title 'Power plan'
    Set-Flag 'PowerScheme' (Get-Guid ((powercfg /getactivescheme) -join ' '))

    $g = $script:Backup.Flags['OurScheme']
    if (-not $g -or -not ((powercfg /list) -join ' ').Contains($g)) {
        $bases = if ($IsDualX3D) { @('381b4222-f694-41f0-9685-ff5bb260df2e') }   # AMD recommends Balanced for dual-CCD X3D
                 else { @('e9a42b02-d5df-448d-aa00-03f14749eb61', '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c', '381b4222-f694-41f0-9685-ff5bb260df2e') }
        foreach ($base in $bases) {
            $g = Get-Guid ((powercfg -duplicatescheme $base 2>$null) -join ' ')
            if ($g -and $g -ne $base) { break } else { $g = $null }
        }
        if (-not $g) { Write-Warn2 'Could not create a power plan'; return }
        $script:Backup.Flags['OurScheme'] = $g
        powercfg -changename $g 'GamingTweaks' 'Max performance plan from GamingTweaks' | Out-Null
    }

    # AC on every PC; DC (battery) only on desktops so laptops still save battery unplugged
    function pc($sub, $set, $val) {
        powercfg /setacvalueindex $g $sub $set $val 2>$null | Out-Null
        if (-not $IsLaptop) { powercfg /setdcvalueindex $g $sub $set $val 2>$null | Out-Null }
    }
    pc 'SUB_PCIEXPRESS' 'ASPM' 0                                                               # PCIe link power saving off
    pc '2a737441-1930-4402-8d77-b2bebba308a3' '48e6b7a6-50f5-4782-a5d4-53bb8f07e226' 0         # USB selective suspend off
    pc 'SUB_DISK' 'DISKIDLE' 0                                                                 # never spin down disks
    pc 'SUB_PROCESSOR' 'PERFBOOSTMODE' 2                                                       # turbo boost: aggressive
    pc 'SUB_PROCESSOR' 'PERFEPP' 0                                                             # energy/perf preference: max performance
    if ($IsDualX3D) {
        Write-Skip "$CpuName : core parking + min CPU state left at default so games stay on the V-Cache chiplet"
    } else {
        pc 'SUB_PROCESSOR' 'CPMINCORES' 100                                                    # unpark all cores
        if (-not $IsLaptop) { pc 'SUB_PROCESSOR' 'PROCTHROTTLEMIN' 100 }                       # min CPU state 100%
    }
    if (-not $IsLaptop) {
        pc 'SUB_SLEEP' 'STANDBYIDLE' 0                                                         # never auto-sleep
        pc 'SUB_SLEEP' 'HYBRIDSLEEP' 0
    }
    powercfg /setactive $g | Out-Null
    Write-Ok "Active plan: GamingTweaks ($g) - turbo boost aggressive, EPP max performance"

    if (-not $IsLaptop) {
        Set-Flag 'HibernateWasOn' (Test-Path "$env:SystemDrive\hiberfil.sys")
        powercfg /hibernate off 2>$null | Out-Null
        Write-Ok 'Hibernate + Fast Startup off (frees disk space, cleaner boots)'
        Set-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling' 'PowerThrottlingOff' 1
        Write-Ok 'Power throttling off'
    } else {
        Write-Skip 'Laptop: hibernate and power throttling left alone, battery settings untouched'
    }
    Save-Backup
}
#endregion

#region ---------- 2. gaming & input ----------
function Invoke-Gaming {
    Write-Title 'Gaming & input'
    # Game Mode on
    Set-Reg 'HKCU\Software\Microsoft\GameBar' 'AutoGameModeEnabled' 1
    Set-Reg 'HKCU\Software\Microsoft\GameBar' 'AllowAutoGameMode' 1
    Write-Ok 'Game Mode on'

    # Background recording / Game DVR off (Xbox app + Store still work)
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' 0
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'HistoricalCaptureEnabled' 0
    if ($IsDualX3D) {
        Write-Ok 'Background recording off'
        Write-Skip 'Game Bar left on: the AMD X3D driver uses it to recognise games'
    } else {
        Set-Reg 'HKCU\System\GameConfigStore' 'GameDVR_Enabled' 0
        Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR' 0
        Set-Reg 'HKCU\Software\Microsoft\GameBar' 'UseNexusForGameBarEnabled' 0
        Write-Ok 'Game DVR / background capture off'
    }

    # CPU scheduling: foreground boost + MMCSS game profile
    Set-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation' 38
    $mm = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
    Set-Reg $mm 'SystemResponsiveness' 10
    Set-Reg "$mm\Tasks\Games" 'GPU Priority' 8
    Set-Reg "$mm\Tasks\Games" 'Priority' 6
    Set-Reg "$mm\Tasks\Games" 'Scheduling Category' 'High' 'String'
    Set-Reg "$mm\Tasks\Games" 'SFIO Priority' 'High' 'String'
    Write-Ok 'Foreground priority + MMCSS games profile'

    # Raw mouse input (no "enhance pointer precision")
    Set-Reg 'HKCU\Control Panel\Mouse' 'MouseSpeed' '0' 'String'
    Set-Reg 'HKCU\Control Panel\Mouse' 'MouseThreshold1' '0' 'String'
    Set-Reg 'HKCU\Control Panel\Mouse' 'MouseThreshold2' '0' 'String'
    Write-Ok 'Mouse acceleration off'

    # No sticky/filter/toggle keys popups mid-game
    Set-Reg 'HKCU\Control Panel\Accessibility\StickyKeys' 'Flags' '506' 'String'
    Set-Reg 'HKCU\Control Panel\Accessibility\Keyboard Response' 'Flags' '122' 'String'
    Set-Reg 'HKCU\Control Panel\Accessibility\ToggleKeys' 'Flags' '58' 'String'
    Write-Ok 'Sticky / Filter / Toggle keys shortcuts off'

    # Startup apps launch straight away instead of after Windows' built-in delay
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' 'Startupdelayinmsec' 0
    Write-Ok 'Startup app delay removed'

    # Realtek onboard audio: no power-saving sleep (fixes the first sound being cut off / delayed)
    $audioClass = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}'
    $rtk = 0
    foreach ($k in (Get-ChildItem -LiteralPath (Get-RegPsPath $audioClass) -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' })) {
        $id = "$($k.GetValue('MatchingDeviceId'))"
        if ($id -match 'VEN_10EC') {
            $ps = "$audioClass\$($k.PSChildName)\PowerSettings"
            Set-Reg $ps 'ConservationIdleTime' ([byte[]](0xFF, 0xFF, 0xFF, 0xFF)) 'Binary'
            Set-Reg $ps 'PerformanceIdleTime'  ([byte[]](0xFF, 0xFF, 0xFF, 0xFF)) 'Binary'
            Set-Reg $ps 'IdlePowerState'       ([byte[]](0x00, 0x00, 0x00, 0x00)) 'Binary'
            $rtk++
        }
    }
    if ($rtk) { Write-Ok 'Realtek audio power saving off' } else { Write-Skip 'No Realtek onboard audio found' }

    # Snappier desktop
    Set-Reg 'HKCU\Control Panel\Desktop' 'MenuShowDelay' '0' 'String'
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'EnableTransparency' 0
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarAnimations' 0
    Write-Ok 'Transparency + taskbar animations off, menus instant'

    # Memory compression off only when there is plenty of RAM
    if ($RamGB -ge 16) {
        try {
            Set-Flag 'MemCompressionWasOn' ([bool](Get-MMAgent).MemoryCompression)
            Disable-MMAgent -MemoryCompression -ErrorAction Stop
            Write-Ok "Memory compression off (${RamGB} GB RAM)"
        } catch { Write-Skip 'Memory compression unchanged' }
    } else { Write-Skip "Memory compression kept (${RamGB} GB RAM is under 16 GB)" }
    Save-Backup
}
#endregion

#region ---------- 3. GPU ----------
function Invoke-Gpu {
    Write-Title 'GPU'
    # Hardware-accelerated GPU scheduling (needed for DLSS Frame Generation)
    Set-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode' 2
    Write-Ok 'Hardware-accelerated GPU scheduling on'

    # Windowed / borderless games use flip model (lower latency, VRR in borderless)
    $k   = 'HKCU\Software\Microsoft\DirectX\UserGpuPreferences'
    $cur = Get-RegValue $k 'DirectXUserGlobalSettings'
    $parts = @()
    if ($cur) { $parts = @($cur -split ';' | Where-Object { $_ -and $_ -notmatch '^SwapEffectUpgradeEnable=' }) }
    $parts += 'SwapEffectUpgradeEnable=1'
    Set-Reg $k 'DirectXUserGlobalSettings' (($parts -join ';') + ';') 'String'
    Write-Ok 'Optimizations for windowed games on'

    # MSI interrupt mode for the graphics card(s)
    foreach ($d in (Get-PnpDevice -Class Display -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'PCI\*' })) {
        Set-Reg "HKLM\SYSTEM\CurrentControlSet\Enum\$($d.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" 'MSISupported' 1
        Write-Ok "MSI mode: $($d.FriendlyName)"
    }

    # NVIDIA telemetry
    if ($HasNvidia) {
        foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'NvTmRep*' -or $_.TaskName -like 'NvTmMon*' -or $_.TaskName -like 'NvProfileUpdater*' })) {
            Disable-Task ($t.TaskPath + $t.TaskName)
        }
        Write-Ok 'NVIDIA telemetry tasks off'
    }
    Save-Backup
}
#endregion

#region ---------- 4. background, privacy, ads ----------
function Invoke-Background {
    Write-Title 'Background apps, telemetry, ads, AI'
    # Telemetry services (Store / Xbox / updates unaffected)
    Set-Svc 'DiagTrack' 4
    Set-Svc 'dmwappushservice' 4
    Set-Svc 'diagnosticshub.standardcollector.service' 4
    Set-Svc 'WerSvc' 4
    Set-Svc 'Ndu' 4    # network data usage monitor - known memory leak, only feeds Task Manager's app history
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' 1
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
    Set-Reg 'HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
    foreach ($t in '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
                   '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
                   '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
                   '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
                   '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
                   '\Microsoft\Windows\Feedback\Siuf\DmClient',
                   '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload',
                   '\Microsoft\Windows\Windows Error Reporting\QueueReporting',
                   # extra telemetry tasks (from privacy.sexy)
                   '\Microsoft\Windows\Application Experience\MareBackup',
                   '\Microsoft\Windows\Application Experience\PcaPatchDbTask',
                   '\Microsoft\Windows\Application Experience\SdbinstMergeDbTask',
                   '\Microsoft\Windows\Application Experience\AitAgent',
                   '\Microsoft\Windows\Device Information\Device',
                   '\Microsoft\Windows\Device Information\Device User',
                   '\Microsoft\Windows\Autochk\Proxy',
                   '\Microsoft\Office\OfficeTelemetryAgentLogOn2016',
                   '\Microsoft\Office\OfficeTelemetryAgentFallBack2016') { Disable-Task $t }
    Write-Ok 'Telemetry + error reporting off'

    # Activity history, advertising ID, tailored experiences
    $sys = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
    Set-Reg $sys 'EnableActivityFeed' 0
    Set-Reg $sys 'PublishUserActivities' 0
    Set-Reg $sys 'UploadUserActivities' 0
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 0
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 0
    Write-Ok 'Activity history, ad ID, tailored experiences off'

    # Ads, suggestions, auto-installed apps
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1
    $cdm = 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    foreach ($v in 'ContentDeliveryAllowed', 'OemPreInstalledAppsEnabled', 'PreInstalledAppsEnabled', 'SilentInstalledAppsEnabled',
                   'SoftLandingEnabled', 'SystemPaneSuggestionsEnabled', 'SubscribedContent-310093Enabled', 'SubscribedContent-338388Enabled',
                   'SubscribedContent-338389Enabled', 'SubscribedContent-338393Enabled', 'SubscribedContent-353694Enabled',
                   'SubscribedContent-353696Enabled', 'SubscribedContent-353698Enabled') { Set-Reg $cdm $v 0 }
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Start_IrisRecommendations' 0
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowSyncProviderNotifications' 0
    Write-Ok 'Start menu ads, tips, suggested apps off'

    # Web / Bing results in Start search
    Set-Reg 'HKCU\Software\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search' 'BingSearchEnabled' 0
    Write-Ok 'Bing web results in Start search off'

    # Copilot, Recall, Widgets
    Set-Reg 'HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'AllowRecallEnablement' 0
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 0
    Write-Ok 'Copilot, Recall, Widgets off'

    # Background apps (UWP apps not running when closed)
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' 'GlobalUserDisabled' 1
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search' 'BackgroundAppGlobalToggle' 0
    Write-Ok 'Background apps off'

    # Edge staying resident in the background (Edge itself is kept: WebView needs it)
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'StartupBoostEnabled' 0
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'BackgroundModeEnabled' 0
    Write-Ok 'Edge startup boost + background mode off'

    # Delivery Optimization: no uploading updates to other PCs (Store downloads still work)
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode' 0
    Write-Ok 'Delivery Optimization peer-to-peer off'

    # More privacy (from privacy.sexy) - none of these affect Store, Xbox or sign-in
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync' 'DisableSettingSync' 2
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync' 'DisableSettingSyncUserOverride' 1
    Set-Reg 'HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' 'HasAccepted' 0
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 1
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 1
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' 'PreventHandwritingErrorReports' 1
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC' 'PreventHandwritingDataSharing' 1
    Set-Reg 'HKCU\Software\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod' 0
    Set-Reg 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System' 'AllowExperimentation' 0
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoUseStoreOpenWith' 1
    Write-Ok 'Settings sync, online speech, typing/ink collection, feedback prompts, feature experiments off'

    if (Confirm-Yes 'Apply Edge ad/telemetry blocking policies? (Edge will then say "managed by your organisation")') {
        $e = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'
        foreach ($v in 'EdgeShoppingAssistantEnabled', 'PersonalizationReportingEnabled', 'DiagnosticData', 'HubsSidebarEnabled',
                       'ShowRecommendationsEnabled', 'SpotlightExperiencesAndRecommendationsEnabled', 'ShowMicrosoftRewards',
                       'EdgeCollectionsEnabled', 'UserFeedbackAllowed', 'NewTabPageContentEnabled', 'PromotionalTabsEnabled',
                       'EdgeFollowEnabled', 'WebWidgetAllowed') { Set-Reg $e $v 0 }
        Set-Reg $e 'NewTabPageHideDefaultTopSites' 1
        Write-Ok 'Edge: shopping, rewards, Copilot sidebar, sponsored tiles, news feed, telemetry off'
    } else { Write-Skip 'Edge left as is' }
    Save-Backup
}
#endregion

#region ---------- 5. Windows Update off ----------
function Invoke-UpdatesOff {
    Write-Title 'Windows Update (Store keeps working)'
    $wu = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    Set-Reg "$wu\AU" 'NoAutoUpdate' 1
    Set-Reg $wu 'ExcludeWUDriversInQualityUpdate' 1
    Set-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' 'SearchOrderConfig' 0
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' 'PreventDeviceMetadataFromNetwork' 1
    # Stay on the current Windows version (no surprise 24H2 -> 25H2 upgrades)
    if ($WinVer) {
        Set-Reg $wu 'TargetReleaseVersion' 1
        Set-Reg $wu 'ProductVersion' $WinName 'String'
        Set-Reg $wu 'TargetReleaseVersionInfo' $WinVer 'String'
    }
    # Pause everything for 10 years
    $ux    = 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    $start = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $end   = (Get-Date).AddYears(10).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Set-Reg $ux 'FlightSettingsMaxPauseDays' 3650
    foreach ($n in 'PauseFeatureUpdatesStartTime', 'PauseQualityUpdatesStartTime', 'PauseUpdatesStartTime') { Set-Reg $ux $n $start 'String' }
    foreach ($n in 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime', 'PauseUpdatesExpiryTime') { Set-Reg $ux $n $end 'String' }
    Write-Ok 'Automatic updates off, paused 10 years, driver updates blocked, version locked'
    Write-Skip 'Windows Update service left running on purpose: the Microsoft Store needs it'
    Save-Backup
}
#endregion

#region ---------- 6. network ----------
$GameExes = 'r5apex', 'r5apex_dx12', 'cs2', 'VALORANT-Win64-Shipping', 'FortniteClient-Win64-Shipping', 'cod',
            'Marvel-Win64-Shipping', 'RainbowSix', 'RainbowSix_BE', 'OverwatchClient', 'Overwatch', 'TslGame', 'RocketLeague'
function Invoke-Network {
    Write-Title 'Network'
    # No multimedia network throttling
    Set-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' 'NetworkThrottlingIndex' 0xffffffff
    Write-Ok 'Network throttling off'

    # Nagle off on interfaces that have an IP (helps games that use TCP)
    $ifRoot = 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    foreach ($i in (Get-ChildItem -LiteralPath (Get-RegPsPath $ifRoot) -ErrorAction SilentlyContinue)) {
        $ip  = ($i.GetValue('DhcpIPAddress'), $i.GetValue('IPAddress')) | Where-Object { $_ -and "$_" -ne '0.0.0.0' }
        if ($ip) {
            Set-Reg "$ifRoot\$($i.PSChildName)" 'TcpAckFrequency' 1
            Set-Reg "$ifRoot\$($i.PSChildName)" 'TCPNoDelay' 1
            Set-Reg "$ifRoot\$($i.PSChildName)" 'TcpDelAckTicks' 0
        }
    }
    Write-Ok 'Nagle algorithm off'

    # TCP stack on sensible defaults (fixes anything an old tweak tool broke)
    netsh int tcp set global autotuninglevel=normal | Out-Null
    netsh int tcp set global rss=enabled | Out-Null
    Write-Ok 'TCP auto-tuning normal, RSS on'

    # Adapter power saving / Energy Efficient Ethernet off
    # (+ packet / DMA coalescing off, from UnLovedCookie's Network script "latency" mode)
    $kw = '*EEE', 'AdvancedEEE', 'EEELinkAdvertisement', 'EnableGreenEthernet', 'GigaLite', 'PowerSavingMode', 'ULPMode',
          'EnableSavePowerNow', 'ReduceSpeedOnPowerDown', '*PacketCoalescing', 'DMACoalescing'
    $lowPing = Confirm-Yes 'Lowest-ping mode? Turns off NIC interrupt moderation (slightly more CPU use, lower latency)'
    if ($lowPing) { $kw += '*InterruptModeration' }
    $pmDone = @()
    foreach ($a in (Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {
        foreach ($p in (Get-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -ErrorAction SilentlyContinue | Where-Object { $_.RegistryKeyword -in $kw })) {
            $cur = "$($p.RegistryValue)"
            if ($cur -ne '0') {
                $id = "$($a.Name)|$($p.RegistryKeyword)"
                if (-not $script:Backup.NetAdv.ContainsKey($id)) { $script:Backup.NetAdv[$id] = $cur }
                Set-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword $p.RegistryKeyword -RegistryValue 0 -NoRestart -ErrorAction SilentlyContinue
            }
        }
        try { Disable-NetAdapterPowerManagement -Name $a.Name -NoRestart -ErrorAction Stop; $pmDone += $a.Name } catch {}
        Write-Ok "Power saving + coalescing off$(if ($lowPing) { ', interrupt moderation off' }): $($a.Name)"
    }

    # MSI interrupt mode for wired/wireless network cards
    foreach ($d in (Get-PnpDevice -Class Net -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'PCI\*' })) {
        Set-Reg "HKLM\SYSTEM\CurrentControlSet\Enum\$($d.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" 'MSISupported' 1
    }
    Write-Ok 'Network card MSI mode on'

    # Don't cache failed DNS lookups (a game server that was briefly down resolves again straight away)
    Set-Reg 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'MaxNegativeCacheTtl' 0
    Write-Ok 'DNS negative cache off'

    # Mark game traffic as high priority (DSCP 46). Only helps if your router honours DSCP / has QoS - harmless otherwise.
    Set-Reg 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' '1' 'String'
    foreach ($app in $GameExes) {
        Remove-NetQosPolicy -Name "GT-$app" -Confirm:$false -ErrorAction SilentlyContinue
        New-NetQosPolicy -Name "GT-$app" -AppPathNameMatchCondition "$app.exe" -DscpAction 46 -NetworkProfile All -ErrorAction SilentlyContinue | Out-Null
    }
    $script:Backup.Flags['QoS'] = $true
    Write-Ok "Game traffic priority (DSCP 46) for: $($GameExes -join ', ')"
    if ($pmDone) {
        $prev = @($script:Backup.Flags['NetPM'])
        $script:Backup.Flags['NetPM'] = @(($prev + $pmDone) | Where-Object { $_ } | Select-Object -Unique)
    }
    ipconfig /flushdns | Out-Null
    Write-Ok 'DNS cache flushed'
    Write-Skip 'Adapter changes fully apply after a reboot'
    Save-Backup
}

function Invoke-Dns {
    Write-Title 'DNS servers'
    Write-Host '  1. Cloudflare  1.1.1.1 / 1.0.0.1   (usually fastest)'
    Write-Host '  2. Google      8.8.8.8 / 8.8.4.4'
    Write-Host '  3. Quad9       9.9.9.9 / 149.112.112.112 (blocks malware domains)'
    Write-Host '  4. Back to automatic (router / ISP)'
    $c = Read-Host '  Choose'
    $servers = switch ($c) { '1' { '1.1.1.1', '1.0.0.1' } '2' { '8.8.8.8', '8.8.4.4' } '3' { '9.9.9.9', '149.112.112.112' } '4' { 'reset' } default { $null } }
    if (-not $servers) { return }
    foreach ($a in (Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')) {
        $guid = $a.InterfaceGuid
        if (-not $script:Backup.Dns.ContainsKey($guid)) {
            $script:Backup.Dns[$guid] = "$(Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" 'NameServer')"
        }
        if ($servers -eq 'reset') { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses }
        else { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers }
        Write-Ok "$($a.Name): $($servers -join ', ')"
    }
    ipconfig /flushdns | Out-Null
    Save-Backup
}
#endregion

#region ---------- 7. timer resolution ----------
$TimerExe  = Join-Path $Root 'TimerResolution.exe'
$TimerTask = 'GamingTweaks Timer Resolution'
function Invoke-TimerRes {
    Write-Title 'Timer resolution'
    $code = @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
public static class TimerRes {
    [DllImport("ntdll.dll")] static extern int NtSetTimerResolution(uint desired, [MarshalAs(UnmanagedType.U1)] bool set, out uint current);
    public static void Main(string[] args) {
        uint res = 5000; uint cur;
        if (args.Length > 0) { uint.TryParse(args[0], out res); }
        NtSetTimerResolution(res, true, out cur);
        Thread.Sleep(Timeout.Infinite);
    }
}
'@
    try {
        Get-Process TimerResolution -ErrorAction SilentlyContinue | Stop-Process -Force
        if (-not (Test-Path $TimerExe)) { Add-Type -TypeDefinition $code -OutputAssembly $TimerExe -OutputType WindowsApplication -ErrorAction Stop }
        Write-Host '  1. 0.5 ms  (most common)'
        Write-Host '  2. 1.0 ms  (on some PCs gives steadier frame times - use [T] to compare)'
        $res = if ("$(Read-Host '  Choose [1]')".Trim() -eq '2') { 10000 } else { 5000 }
        Unregister-ScheduledTask -TaskName $TimerTask -Confirm:$false -ErrorAction SilentlyContinue
        $action    = New-ScheduledTaskAction -Execute $TimerExe -Argument "$res"
        $trigger   = New-ScheduledTaskTrigger -AtStartup
        $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TimerTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
        if ($Build -ge 22000) { Set-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'GlobalTimerResolutionRequests' 1 }
        Start-ScheduledTask -TaskName $TimerTask
        $script:Backup.Flags['TimerRes'] = $true
        Write-Ok "Timer resolution $($res / 10000) ms set at every boot (smoother frame pacing)"
        if ($Build -lt 22000) { Write-Skip 'Windows 10: only partly effective (no global timer option before Windows 11)' }
    } catch { Write-Warn2 "Timer resolution failed: $($_.Exception.Message)" }
    Save-Backup
}
#endregion

#region ---------- 8. cleanup ----------
function Clear-Folder([string]$Path, [string]$Keep = '') {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
        Where-Object { -not ($Keep -and $Keep.StartsWith($_.FullName, [StringComparison]::OrdinalIgnoreCase)) } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-Cleanup {
    Write-Title 'Cleanup'
    Write-Host '  Never touched: browser data/passwords, Prefetch (keeps app launches fast), restore points,'
    Write-Host '  event logs, crash minidumps (needed to diagnose BSODs), the Windows\Installer patch cache.'
    $freeBefore = (Get-PSDrive -Name $env:SystemDrive.TrimEnd(':')).Free
    $keep = if ($PSCommandPath) { Split-Path $PSCommandPath -Parent } else { '' }

    # Temp folders
    Clear-Folder $env:TEMP $keep
    Clear-Folder "$env:WINDIR\Temp" $keep
    Write-Ok 'Temp files'

    # Old Windows Update downloads (stop the service briefly, never wait forever)
    & sc.exe stop wuauserv *> $null
    for ($i = 0; $i -lt 15 -and (Get-Service wuauserv -ErrorAction SilentlyContinue).Status -ne 'Stopped'; $i++) { Start-Sleep -Seconds 1 }
    Clear-Folder "$env:WINDIR\SoftwareDistribution\Download"
    Start-Service wuauserv -ErrorAction SilentlyContinue
    Write-Ok 'Old Windows Update downloads'

    # Delivery Optimization cache, app crash dumps, error report archives
    try { Delete-DeliveryOptimizationCache -Force -ErrorAction Stop } catch {}
    Clear-Folder "$env:LOCALAPPDATA\CrashDumps"
    Clear-Folder "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
    Clear-Folder "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
    Clear-Folder "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive"
    Write-Ok 'Delivery Optimization cache, app crash dumps, error reports'

    # Discord caches (often several GB; Discord rebuilds them) - idea from your old Windows11.bat
    if (Get-Process -Name 'Discord*' -ErrorAction SilentlyContinue) {
        Write-Skip 'Discord is running - close it (tray icon > Quit) to clear its cache next time'
    } else {
        foreach ($app in 'discord', 'discordptb', 'discordcanary') {
            foreach ($c in 'Cache', 'Code Cache', 'GPUCache') { Clear-Folder "$env:APPDATA\$app\$c" }
        }
        Write-Ok 'Discord cache'
    }

    # Shader caches: only worth clearing after a GPU driver update (games re-compile = brief stutter)
    if (Confirm-Yes 'Clear GPU shader caches? Only do this right after a graphics driver update') {
        foreach ($d in "$env:LOCALAPPDATA\Microsoft\DirectX Shader Cache",
                       "$env:LOCALAPPDATA\NVIDIA\DXCache", "$env:LOCALAPPDATA\NVIDIA\GLCache",
                       "$env:USERPROFILE\AppData\LocalLow\NVIDIA\PerDriverVersion\DXCache",
                       "$env:LOCALAPPDATA\AMD\DxCache", "$env:LOCALAPPDATA\AMD\DxcCache", "$env:LOCALAPPDATA\AMD\GLCache",
                       "$env:LOCALAPPDATA\Intel\ShaderCache") { Clear-Folder $d }
        Write-Ok 'Shader caches cleared - first game launch / first match may stutter while they rebuild'
    } else { Write-Skip 'Shader caches kept' }

    if (Confirm-Yes 'Empty the Recycle Bin?') {
        try { Clear-RecycleBin -Force -ErrorAction Stop } catch {}
        Write-Ok 'Recycle Bin emptied'
    }

    # Component store: removes superseded Windows files (safe; the slow one - a few minutes)
    if (Confirm-Yes 'Clean up the Windows component store (WinSxS)? Safe, frees GBs, takes a few minutes') {
        Write-Host '  Running DISM /StartComponentCleanup ...'
        Start-Process -FilePath dism.exe -ArgumentList '/Online', '/Cleanup-Image', '/StartComponentCleanup' -Wait -NoNewWindow
        Write-Ok 'Component store cleaned'
    } else { Write-Skip 'Component store left' }

    $freed = ((Get-PSDrive -Name $env:SystemDrive.TrimEnd(':')).Free - $freeBefore) / 1GB
    Write-Ok ("Freed about {0:N2} GB on {1}" -f [math]::Max(0, $freed), $env:SystemDrive)
    if (Test-Path "$env:SystemDrive\Windows.old") {
        Write-Skip 'Windows.old found: remove it via Settings > System > Storage > Temporary files > "Previous Windows installation(s)"'
    }
}
#endregion

#region ---------- extras (opt-in) ----------
$BloatApps = @(
    'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.BingSearch', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
    'Microsoft.MicrosoftOfficeHub', 'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.People', 'Microsoft.PowerAutomateDesktop',
    'Microsoft.Todos', 'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps', 'Microsoft.ZuneVideo', 'Microsoft.549981C3F5F10',
    'Microsoft.Windows.DevHome', 'Microsoft.OutlookForWindows', 'Microsoft.Copilot', 'Microsoft.Windows.Ai.Copilot.Provider',
    'Microsoft.MicrosoftJournal', 'Microsoft.StartExperiencesApp', 'Clipchamp.Clipchamp', 'MicrosoftTeams', 'MSTeams',
    'Microsoft.YourPhone', 'MicrosoftCorporationII.MicrosoftFamily'
)
function Invoke-Bloat {
    Write-Title 'Remove bloat apps'
    Write-Host '  Removes: News, Weather, Bing, Get Help, Tips, Office hub, Solitaire, People, Power Automate, To Do,'
    Write-Host '           Feedback Hub, Maps, Films & TV, Cortana, Dev Home, new Outlook, Copilot, Journal, Clipchamp,'
    Write-Host '           Teams, Phone Link, Family.'
    Write-Host '  Keeps:   Store, Xbox, Gaming Services, Photos, Calculator, Notepad, Paint, Terminal, Snipping Tool, Camera.'
    Write-Warn2 'Not covered by Revert - reinstall any of these from the Microsoft Store if you miss them.'
    if (-not (Confirm-Yes 'Remove them?')) { return }
    $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    foreach ($n in $BloatApps) {
        $pk = Get-AppxPackage -AllUsers -Name $n -ErrorAction SilentlyContinue
        if ($pk) { $pk | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue; Write-Ok $n }
        $prov | Where-Object DisplayName -eq $n | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
    }
}

function Invoke-Vbs {
    Write-Title 'Core Isolation / VBS off'
    Write-Host '  Often +5-10% FPS in CPU-heavy games. Turns off Memory Integrity.'
    if ($AntiCheat -contains 'FACEIT' -or $AntiCheat -contains 'Riot Vanguard') {
        Write-Warn2 "$($AntiCheat -join ', ') detected: if a game then refuses to start, run Revert or turn Memory Integrity back on."
    }
    Set-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 0
    Set-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 0
    if ($null -ne (Get-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity')) {
        Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 0
    }
    Write-Ok 'VBS + Memory Integrity off (reboot, then check msinfo32: "Virtualization-based security: Not enabled")'
    Save-Backup
}

function Invoke-Uac {
    Write-Title 'UAC prompts off'
    # Keeps EnableLUA=1 so Store / UWP apps still work. Only the Yes/No prompt goes away.
    Set-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 0
    Set-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' 0
    Write-Ok 'UAC set to "Never notify" (Store and Xbox apps keep working)'
    Save-Backup
}

function Invoke-Defender {
    Write-Title 'Microsoft Defender off'
    $s = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($s -and $s.IsTamperProtected) {
        Write-Warn2 'Tamper Protection is on, so Windows will block this.'
        Write-Host  '  Windows Security is opening: Virus & threat protection > Manage settings > Tamper Protection = Off'
        Write-Host  '  Then run this option again.'
        Start-Process 'windowsdefender://threatsettings'
        return
    }
    # turn real-time off first so Defender does not block the policy writes below
    try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop } catch {}
    $d = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
    Set-Reg $d 'DisableAntiSpyware' 1
    Set-Reg "$d\Real-Time Protection" 'DisableRealtimeMonitoring' 1
    Set-Reg "$d\Real-Time Protection" 'DisableBehaviorMonitoring' 1
    Set-Reg "$d\Real-Time Protection" 'DisableIOAVProtection' 1
    Set-Reg "$d\Real-Time Protection" 'DisableOnAccessProtection' 1
    Set-Reg "$d\Real-Time Protection" 'DisableScanOnRealtimeEnable' 1
    Set-Reg "$d\Spynet" 'SpynetReporting' 0
    Set-Reg "$d\Spynet" 'SubmitSamplesConsent' 2
    Set-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 0
    Set-Reg 'HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' 0
    foreach ($t in '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan',
                   '\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance',
                   '\Microsoft\Windows\Windows Defender\Windows Defender Cleanup',
                   '\Microsoft\Windows\Windows Defender\Windows Defender Verification') { Disable-Task $t }
    Write-Ok 'Defender real-time / cloud / scheduled scans + SmartScreen off'
    Write-Warn2 'Only download games, mods and tools from sources you trust.'
    Save-Backup
}

function Invoke-Spectre {
    Write-Title 'Spectre / Meltdown mitigations off'
    Write-Host "  CPU: $CpuName"
    Write-Host '  Helps older CPUs (Intel up to ~10th gen, Ryzen 1000/2000). On newer CPUs it can be SLOWER.'
    if (-not (Confirm-Yes 'Apply?')) { return }
    $mm = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    Set-Reg $mm 'FeatureSettingsOverride' 3
    Set-Reg $mm 'FeatureSettingsOverrideMask' 3
    Write-Ok 'Mitigations off after reboot - benchmark before/after and revert if no gain'
    Save-Backup
}
#endregion

#region ---------- services ----------
function Invoke-Services {
    Write-Title 'Services'
    Write-Host '  Most Windows services already sit at Manual and use no CPU until something needs them, so this'
    Write-Host '  means fewer background wake-ups and a little RAM back - not a big FPS jump.'
    Write-Host '  Kept on purpose: Windows Update + Store, Xbox Live / Game Save / controllers, audio, networking,'
    Write-Host '  UPnP (game NAT type), SysMain, Microsoft account sign-in.'
    $svcRoot = 'HKLM\SYSTEM\CurrentControlSet\Services'
    function Off($list) {
        $done = @()
        foreach ($e in $list.GetEnumerator()) {
            if (Test-Path -LiteralPath (Get-RegPsPath "$svcRoot\$($e.Key)")) { Set-Svc $e.Key 4; $done += $e.Value }
        }
        $done = @($done | Where-Object { $_ })
        if ($done) { Write-Ok ("Disabled: " + ($done -join ', ')) }
    }

    Off ([ordered]@{
        MapsBroker = 'Downloaded Maps Manager'; RetailDemo = 'Retail Demo'; wisvc = 'Windows Insider'
        WpcMonSvc = 'Parental Controls'; Fax = 'Fax'; RemoteRegistry = 'Remote Registry'
        TrkWks = 'Distributed Link Tracking'; PcaSvc = 'Program Compatibility Assistant'
        SEMgrSvc = 'Payments and NFC'; WalletService = 'Wallet'; AJRouter = 'AllJoyn Router'
        diagsvc = 'Diagnostic Execution'; wercplsupport = 'Problem Reports'; InventorySvc = 'Inventory and Compatibility Appraisal'
        whesvc = 'Health and Optimized Experiences'; TroubleshootingSvc = 'Recommended Troubleshooting'
        SCardSvr = 'Smart Card'; ScDeviceEnum = 'Smart Card Device Enumeration'; SCPolicySvc = 'Smart Card Removal Policy'
        WMPNetworkSvc = 'Media Player Network Sharing'; autotimesvc = 'Cellular Time'; PhoneSvc = 'Phone (calls via Phone Link)'
        vmickvpexchange = 'Hyper-V guest services'; vmicguestinterface = ''; vmicshutdown = ''; vmicheartbeat = ''
        vmicvss = ''; vmictimesync = ''; vmicrdv = ''; vmicvmsession = ''
        'Razer Game Scanner Service' = 'Razer Game Scanner'; LogiRegistryService = 'Logitech Gaming Registry'
        NvTelemetryContainer = 'NVIDIA Telemetry Container'
        # from GTweak's service groups
        Telemetry = 'Intel Telemetry'; Wecsvc = 'Windows Event Collector'; WebClient = 'WebDAV client'
        CertPropSvc = 'Certificate Propagation (smart card)'; AssignedAccessManagerSvc = 'Kiosk mode'
        AppMgmt = 'Group Policy app install'; workfolderssvc = 'Work Folders'
    })
    if (-not $IsLaptop) {
        Off ([ordered]@{
            SensorDataService = 'Sensor Data'; SensorService = 'Sensor'; SensrSvc = 'Sensor Monitoring'
            WwanSvc = 'Mobile broadband (SIM)'; wlpasvc = 'eSIM profile assistant'
        })
    }

    if (-not (Confirm-Yes 'Do you use a printer (or "Microsoft Print to PDF")?')) {
        Off ([ordered]@{ Spooler = 'Print Spooler'; PrintNotify = 'Printer Extensions' })
    } else { Write-Skip 'Printing kept' }

    if (-not (Confirm-Yes 'Do you use Bluetooth (headphones, controller, mouse, phone)?')) {
        Off ([ordered]@{ bthserv = 'Bluetooth Support'; BTAGService = 'Bluetooth Audio Gateway'; BthAvctpSvc = 'Bluetooth AVCTP' })
    } else { Write-Skip 'Bluetooth kept' }

    if (-not (Confirm-Yes 'Do you share folders with other PCs or use a NAS / network drive?')) {
        Off ([ordered]@{ LanmanServer = 'File and printer sharing (Server)'; lmhosts = 'NetBIOS helper'; FDResPub = 'Network discovery publishing' })
    } else { Write-Skip 'File sharing kept' }

    if (Confirm-Yes 'Turn off Windows Search indexing? (Start still finds apps + settings; searching files gets slower)') {
        Off ([ordered]@{ WSearch = 'Windows Search indexing' })
    } else { Write-Skip 'Search indexing kept' }

    Write-Host ''
    Write-Host '  AGGRESSIVE MODE: more always-running services set to start only when needed, plus more turned off.' -ForegroundColor Cyan
    Write-Host '  Still kept: Store downloads (BITS, Delivery Optimization), Xbox networking (IP Helper), sign-in,'
    Write-Host '  notifications, typing / search box, audio, display, networking.'
    if (Confirm-Yes 'Use aggressive mode?') {
        $manual = [ordered]@{
            CDPSvc = 'Connected Devices Platform'; DPS = 'Diagnostic Policy'; WdiServiceHost = 'Diagnostic Service Host'
            WdiSystemHost = 'Diagnostic System Host'; RasMan = 'Remote Access (VPN) Manager'; ShellHWDetection = 'AutoPlay'
            StorSvc = 'Storage Service'; UsoSvc = 'Update Orchestrator'; edgeupdate = 'Edge Update'; edgeupdatem = ''
        }
        $done = @()
        foreach ($e in $manual.GetEnumerator()) { if (Set-SvcAll $e.Key 3) { $done += $e.Value } }
        Write-Ok ('Start only when needed: ' + (@($done | Where-Object { $_ }) -join ', '))

        $off = [ordered]@{
            WSAIFabricSvc = 'Windows AI Fabric'; lfsvc = 'Geolocation'; webthreatdefsvc = 'Web Threat Defense'
            webthreatdefusersvc = ''; NPSMSvc = 'Now Playing media flyout'; OneSyncSvc = 'Mail/Calendar sync'
            MessagingService = 'Text messaging'; AarSvc = 'Voice assistant activation'; P9RdrService = 'WSL file access'
            PimIndexMaintenanceSvc = 'Contacts indexing'
        }
        if (-not $IsDualX3D) { $off['BcastDVRUserService'] = 'Game recording (DVR)' }
        $done = @()
        foreach ($e in $off.GetEnumerator()) { if (Set-SvcAll $e.Key 4) { $done += $e.Value } }
        Write-Ok ('Disabled: ' + (@($done | Where-Object { $_ }) -join ', '))

        if (-not (Confirm-Yes 'Do you sign in with a fingerprint reader or face camera (Windows Hello)? (a PIN is fine either way)')) {
            if (Set-SvcAll 'WbioSrvc' 4) { Write-Ok 'Disabled: Windows Biometric Service' }
        }
        if (Confirm-Yes 'Turn off SysMain? (SSD-only PCs: frees RAM, but games and apps may load slightly slower)') {
            if (Set-SvcAll 'SysMain' 4) { Write-Ok 'Disabled: SysMain' }
        } else { Write-Skip 'SysMain kept' }
    } else { Write-Skip 'Aggressive mode skipped' }

    Write-Host ''
    Write-Host "  Running services right now: $((Get-Service | Where-Object Status -eq 'Running').Count) (drops further after the reboot)"
    Write-Skip 'Changes take full effect after a reboot. Revert [R] restores every service.'
    Save-Backup
}
#endregion

#region ---------- games, MPO, timer test, NVIDIA ----------
function Invoke-Games {
    Write-Title 'Game priority'
    foreach ($app in $GameExes) {
        # 6 = Above Normal. (High can make Discord / game audio crackle.)
        Set-Reg "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$app.exe\PerfOptions" 'CpuPriorityClass' 6
    }
    Write-Ok "Above Normal CPU priority: $($GameExes -join ', ')"
    Set-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' 'IoLatencyCap' 0
    Write-Ok 'MMCSS IO latency cap off'
    Save-Backup
}

function Invoke-Mpo {
    Write-Title 'Multiplane Overlay (MPO) off'
    Write-Host '  Fixes flicker, black screens or stutter in borderless games / with video on a 2nd monitor on some setups.'
    Write-Host '  If you have none of those problems, leave MPO on.'
    if (-not (Confirm-Yes 'Turn MPO off?')) { return }
    Set-Reg 'HKLM\SOFTWARE\Microsoft\Windows\Dwm' 'OverlayTestMode' 5
    Write-Ok 'MPO off after reboot'
    Save-Backup
}

function Test-Timer {
    Write-Title 'Timer test (like MeasureSleep)'
    if (-not ('GTTimer' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
public static class GTTimer {
    [DllImport("ntdll.dll")] public static extern int NtQueryTimerResolution(out uint min, out uint max, out uint cur);
    public static string Run(int n) {
        uint a, b, c; NtQueryTimerResolution(out a, out b, out c);
        Stopwatch sw = new Stopwatch(); double sum = 0, worst = 0;
        for (int i = 0; i < n; i++) { sw.Restart(); Thread.Sleep(1); double ms = sw.Elapsed.TotalMilliseconds; sum += ms; if (ms > worst) worst = ms; }
        return String.Format("Timer resolution now: {0:0.000} ms | Sleep(1) average: {1:0.000} ms | worst: {2:0.000} ms", c / 10000.0, sum / n, worst);
    }
}
'@
    }
    Write-Host '  Measuring 300 sleeps...'
    Write-Host ('  ' + [GTTimer]::Run(300)) -ForegroundColor Green
    Write-Host '  Closer to 1.0 ms with a low "worst" is better. Try 0.5 ms vs 1.0 ms with option 8 and keep the steadier one.'
}

$DrsDir   = Join-Path $env:ProgramData 'NVIDIA Corporation\Drs'
$DrsBack  = Join-Path $Root 'NvidiaDrsBackup'
$NpiDir   = Join-Path $Root 'ProfileInspector'
function Invoke-NvidiaProfile {
    Write-Title 'NVIDIA driver profile (Profile Inspector import)'
    if (-not $HasNvidia) { Write-Skip 'No NVIDIA graphics card found'; return }
    Write-Host '  Global settings: Prefer maximum performance, Low Latency On, texture filtering High performance,'
    Write-Host '  negative LOD bias Clamp, shader cache Unlimited, CUDA force-P2 off, Threaded optimisation On, Ansel off.'
    Write-Host '  NOT touched: ray tracing, anisotropic filtering, anti-aliasing, Resizable BAR, G-Sync on/off.'
    $gsync = Confirm-Yes 'Do you use G-Sync / G-Sync Compatible (FreeSync monitor)?'

    if (-not (Test-Path $DrsBack) -and (Test-Path $DrsDir)) {
        New-Item -ItemType Directory -Path $DrsBack -Force | Out-Null
        Copy-Item "$DrsDir\*" $DrsBack -Force -ErrorAction SilentlyContinue
        $script:Backup.Flags['NvDrs'] = $true
        Save-Backup
        Write-Ok "Current NVIDIA profiles backed up to $DrsBack"
    }

    $exe = Get-ChildItem $NpiDir -Recurse -Filter 'nvidiaProfileInspector.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $exe) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $rel   = Invoke-RestMethod 'https://api.github.com/repos/Orbmu2k/nvidiaProfileInspector/releases/latest' -UseBasicParsing
            $asset = $rel.assets | Where-Object { $_.name -like '*.zip' } | Select-Object -First 1
            $zip   = Join-Path $Root 'npi.zip'
            Invoke-WebRequest $asset.browser_download_url -OutFile $zip -UseBasicParsing
            Expand-Archive $zip -DestinationPath $NpiDir -Force
            Remove-Item $zip -Force
            $exe = Get-ChildItem $NpiDir -Recurse -Filter 'nvidiaProfileInspector.exe' | Select-Object -First 1
            Write-Ok "Downloaded NVIDIA Profile Inspector $($rel.tag_name) (github.com/Orbmu2k)"
        } catch { Write-Warn2 "Could not download Profile Inspector: $($_.Exception.Message)"; return }
    }

    # Setting IDs from NVIDIA's NvApiDriverSettings (cross-checked against a working .nip)
    $set = [ordered]@{
        274197361  = 1            # Power management mode: Prefer maximum performance
        8102046    = 1            # Max pre-rendered frames: 1
        277041152  = 1            # Low Latency Mode: enabled
        390467     = 1            # Low Latency Mode (control panel state): On
        13510289   = 20           # Texture filtering quality: High performance
        1686376    = 1            # Texture filtering negative LOD bias: Clamp
        15151633   = 1            # Anisotropic sample optimisation: On
        11306135   = 4294967295   # Shader cache size: Unlimited
        1343646814 = 0            # CUDA force P2 state: Off
        549528094  = 1            # Threaded optimisation: On
        276158834  = 0            # Ansel: Off
        11041231   = $(if ($gsync) { 1199655232 } else { 138504007 })   # V-Sync: On (G-Sync recipe) / Force off
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<?xml version="1.0" encoding="utf-16"?>')
    [void]$sb.AppendLine('<ArrayOfProfile>')
    [void]$sb.AppendLine('  <Profile>')
    [void]$sb.AppendLine('    <ProfileName>Base Profile</ProfileName>')
    [void]$sb.AppendLine('    <Executeables />')
    [void]$sb.AppendLine('    <Settings>')
    foreach ($e in $set.GetEnumerator()) {
        [void]$sb.AppendLine('      <ProfileSetting>')
        [void]$sb.AppendLine('        <SettingNameInfo />')
        [void]$sb.AppendLine("        <SettingID>$($e.Key)</SettingID>")
        [void]$sb.AppendLine("        <SettingValue>$($e.Value)</SettingValue>")
        [void]$sb.AppendLine('        <ValueType>Dword</ValueType>')
        [void]$sb.AppendLine('      </ProfileSetting>')
    }
    [void]$sb.AppendLine('    </Settings>')
    [void]$sb.AppendLine('  </Profile>')
    [void]$sb.AppendLine('</ArrayOfProfile>')
    $nip = Join-Path $Root 'GamingTweaks.nip'
    Set-Content -Path $nip -Value $sb.ToString() -Encoding Unicode

    Start-Process -FilePath $exe.FullName -ArgumentList "-silentImport `"$nip`"" -Wait
    Write-Ok "Imported $nip"
    if ($gsync) {
        Write-Host '  G-Sync checklist: NVIDIA Control Panel > Set up G-SYNC > enable for full screen and windowed mode,'
        Write-Host '  V-Sync OFF in every game, turn on Reflex where available (it caps FPS just under your refresh rate).'
    } else {
        Write-Host '  Tip: cap FPS a bit below what your PC holds steadily (Reflex, in-game cap or RTSS) for smoother frame times.'
    }
}
#endregion

#region ---------- revert ----------
function Invoke-RevertAll {
    Write-Title 'Revert everything'
    if (-not (Test-Path $BackupFile)) { Write-Warn2 'No backup found - nothing to revert'; return }
    if (-not (Confirm-Yes 'Put every setting this script changed back the way it was?')) { return }

    foreach ($e in @($script:Backup.Registry.Values)) {
        $p = Get-RegPsPath $e.Path
        try {
            if ($e.Existed) {
                $v = $e.Value
                switch ($e.Kind) {
                    'Binary'      { $v = [byte[]]@($v) }
                    'MultiString' { $v = [string[]]@($v) }
                    'QWord'       { $v = [long]$v }
                    'DWord'       { $v = [int]$v }
                }
                if (-not (Test-Path -LiteralPath $p)) { New-Item -Path $p -Force | Out-Null }
                New-ItemProperty -LiteralPath $p -Name $e.Name -Value $v -PropertyType $e.Kind -Force -ErrorAction Stop | Out-Null
            } elseif (Test-Path -LiteralPath $p) {
                Remove-ItemProperty -LiteralPath $p -Name $e.Name -ErrorAction SilentlyContinue
            }
        } catch { Write-Warn2 "Could not restore $($e.Path)\$($e.Name)" }
    }
    Write-Ok "Registry + services restored ($($script:Backup.Registry.Count) values)"

    foreach ($t in @($script:Backup.Tasks.Keys)) {
        $tp = (Split-Path $t -Parent).TrimEnd('\') + '\'
        Enable-ScheduledTask -TaskPath $tp -TaskName (Split-Path $t -Leaf) -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Ok 'Scheduled tasks re-enabled'

    $f = $script:Backup.Flags
    if ($f['PowerScheme']) { powercfg /setactive $f['PowerScheme'] | Out-Null }
    if ($f['OurScheme'])   { powercfg -delete $f['OurScheme'] 2>$null | Out-Null }
    if ($f['HibernateWasOn'] -eq $true) { powercfg /hibernate on 2>$null | Out-Null }
    if ($f['MemCompressionWasOn'] -eq $true) { Enable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue }
    Write-Ok 'Power plan, hibernate, memory compression restored'

    if ($f['TimerRes']) {
        Unregister-ScheduledTask -TaskName $TimerTask -Confirm:$false -ErrorAction SilentlyContinue
        Get-Process TimerResolution -ErrorAction SilentlyContinue | Stop-Process -Force
        Remove-Item $TimerExe -Force -ErrorAction SilentlyContinue
        Write-Ok 'Timer resolution task removed'
    }

    foreach ($id in @($script:Backup.NetAdv.Keys)) {
        $n, $k = $id -split '\|', 2
        Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword $k -RegistryValue $script:Backup.NetAdv[$id] -NoRestart -ErrorAction SilentlyContinue
    }
    foreach ($n in @($f['NetPM'] | Where-Object { $_ })) { Enable-NetAdapterPowerManagement -Name $n -NoRestart -ErrorAction SilentlyContinue }
    foreach ($guid in @($script:Backup.Dns.Keys)) {
        $a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceGuid -eq $guid }
        if (-not $a) { continue }
        $orig = "$($script:Backup.Dns[$guid])"
        if ($orig.Trim()) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ($orig -split '[,\s]+' | Where-Object { $_ }) }
        else { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses }
    }
    if ($f['QoS']) { Get-NetQosPolicy -ErrorAction SilentlyContinue | Where-Object Name -like 'GT-*' | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue }
    Write-Ok 'Network adapters, DNS + QoS policies restored'

    try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}

    if ($f['NvDrs'] -and (Test-Path $DrsBack)) {
        Copy-Item "$DrsBack\*" $DrsDir -Force -ErrorAction SilentlyContinue
        Rename-Item $DrsBack ("NvidiaDrsBackup-reverted-{0:yyyyMMdd-HHmmss}" -f (Get-Date)) -ErrorAction SilentlyContinue
        Write-Ok 'NVIDIA profiles restored (if you updated the driver since, use Profile Inspector > Restore defaults instead)'
    }

    Move-Item $BackupFile (Join-Path $Root ("backup-reverted-{0:yyyyMMdd-HHmmss}.json" -f (Get-Date))) -Force
    $script:Backup = @{ Registry = @{}; Tasks = @{}; Flags = @{}; NetAdv = @{}; Dns = @{} }
    Write-Ok 'Done. Removed apps are not reinstalled automatically (get them from the Store).'
    Write-Warn2 'Reboot to finish.'
}
#endregion

#region ---------- info + all ----------
function Get-Snapshot {
    $os = Get-CimInstance Win32_OperatingSystem
    return [ordered]@{
        Date     = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Services = (Get-Service | Where-Object Status -eq 'Running').Count
        Procs    = (Get-Process).Count
        RamGB    = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 1)
    }
}
function Save-Baseline {
    if (-not $script:Backup.Flags.ContainsKey('Baseline')) {
        $script:Backup.Flags['Baseline'] = Get-Snapshot
        Save-Backup
    }
}
function Show-Info {
    Write-Title 'This PC'
    Write-Host "  Windows : $WinName $WinVer (build $Build)"
    Write-Host "  CPU     : $CpuName"
    Write-Host "  GPU     : $($GpuNames -join ' | ')"
    Write-Host "  RAM     : $RamGB GB"
    Write-Host "  Type    : $(if ($IsLaptop) { 'Laptop' } else { 'Desktop' })"
    Write-Host "  Anti-cheat services: $(if ($AntiCheat) { $AntiCheat -join ', ' } else { 'none found' })"
    if ($IsDualX3D) { Write-Host '  X3D     : dual-CCD - core parking and Game Bar kept on purpose' -ForegroundColor Yellow }
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if ($dg) { Write-Host "  VBS     : $(if ($dg.VirtualizationBasedSecurityStatus -eq 2) { 'running' } else { 'off' })" }
    Write-Host "  Power   : $(((powercfg /getactivescheme) -join ' ') -replace '^.*\(|\)\s*$', '')"
    Write-Host "  HAGS    : $(if ((Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode') -eq 2) { 'on' } else { 'off/default' })"
    Write-Host "  Backup  : $(if (Test-Path $BackupFile) { "$($script:Backup.Registry.Count) values saved in $BackupFile" } else { 'none yet' })"
    $b = $script:Backup.Flags['Baseline']
    $n = Get-Snapshot
    Write-Title 'Before / after'
    if ($b) {
        Write-Host ("  {0,-18}{1,10}{2,10}" -f '', 'Before', 'Now')
        Write-Host ("  {0,-18}{1,10}{2,10}" -f 'Running services', $b.Services, $n.Services)
        Write-Host ("  {0,-18}{1,10}{2,10}" -f 'Processes', $b.Procs, $n.Procs)
        Write-Host ("  {0,-18}{1,10}{2,10}" -f 'RAM in use (GB)', $b.RamGB, $n.RamGB)
        Write-Host "  'Before' was measured $($b.Date). Compare after a reboot, a minute after logging in."
    } else {
        Write-Host "  Running services: $($n.Services) | Processes: $($n.Procs) | RAM in use: $($n.RamGB) GB"
        Write-Host '  (A "before" snapshot is saved automatically the first time you apply anything.)'
    }
    Write-Title 'Startup apps (disable what you do not need: Task Manager > Startup apps)'
    Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  - $($_.Name)" }
}

function Invoke-All {
    New-RestorePoint
    Invoke-Power
    Invoke-Gaming
    Invoke-Gpu
    Invoke-Background
    Invoke-Services
    Invoke-UpdatesOff
    Invoke-Network
    Invoke-TimerRes
    Invoke-Games
    if ($HasNvidia) { Invoke-NvidiaProfile }
    Invoke-Bloat
    Write-Title 'Optional FPS-for-security trade-offs'
    Write-Host '  Core Isolation/VBS off (biggest FPS gain of the three), UAC prompts off, Defender off.'
    if (Confirm-Yes 'Apply all three?') { Invoke-Vbs; Invoke-Uac; Invoke-Defender }
    Invoke-Cleanup
    Save-Backup
    Write-Title 'Finished'
    Write-Host '  Next: set your GPU control panel (see README), disable startup apps you do not need, then reboot.'
    if (Confirm-Yes 'Reboot now?') { Restart-Computer -Force }
}
#endregion

#region ---------- menu ----------
Import-Backup
while ($true) {
    Clear-Host
    Write-Host ''
    Write-Host "  GamingTweaks v$Version" -ForegroundColor Cyan
    Write-Host "  $WinName $WinVer | $(if ($IsLaptop) { 'Laptop' } else { 'Desktop' }) | $($GpuNames -join ', ') | $RamGB GB" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  [1] APPLY EVERYTHING RECOMMENDED  (2-9, S, G, N + asks about the extras)' -ForegroundColor Green
    Write-Host ''
    Write-Host '  [2] Power plan            [6] Windows Update off (Store still works)'
    Write-Host '  [3] Gaming & input        [7] Network'
    Write-Host '  [4] GPU                   [8] Timer resolution'
    Write-Host '  [5] Background & privacy  [9] Cleanup'
    Write-Host ''
    Write-Host '  Extras'
    Write-Host '  [A] Remove bloat apps     [D] UAC prompts off'
    Write-Host '  [B] DNS servers           [E] Defender off'
    Write-Host '  [C] Core Isolation off    [F] Spectre/Meltdown off (older CPUs)'
    Write-Host '  [G] Game priority (Apex etc)  [N] NVIDIA profile import  [M] MPO off  [T] Timer test'
    Write-Host '  [S] Services'
    Write-Host ''
    Write-Host '  [P] Restore point   [I] PC info + startup apps   [R] REVERT EVERYTHING   [Q] Quit' -ForegroundColor Yellow
    Write-Host ''
    $c = "$(Read-Host '  Choose')".Trim().ToUpper()
    if ($c -notin '1','2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','N','M','T','S','P','I','R','Q') { continue }
    if ($c -notin 'I', 'T', 'Q', 'R', 'P') { Save-Baseline }
    switch ($c) {
        '1' { Invoke-All }
        '2' { Invoke-Power }
        '3' { Invoke-Gaming }
        '4' { Invoke-Gpu }
        '5' { Invoke-Background }
        '6' { Invoke-UpdatesOff }
        '7' { Invoke-Network }
        '8' { Invoke-TimerRes }
        '9' { Invoke-Cleanup }
        'A' { Invoke-Bloat }
        'B' { Invoke-Dns }
        'C' { Invoke-Vbs }
        'D' { Invoke-Uac }
        'E' { Invoke-Defender }
        'F' { Invoke-Spectre }
        'G' { Invoke-Games }
        'S' { Invoke-Services }
        'N' { Invoke-NvidiaProfile }
        'M' { Invoke-Mpo }
        'T' { Test-Timer }
        'P' { New-RestorePoint }
        'I' { Show-Info }
        'R' { Invoke-RevertAll }
        'Q' { try { Stop-Transcript | Out-Null } catch {}; exit }
    }
    Write-Host ''
    Read-Host '  Press Enter to go back to the menu' | Out-Null
}
#endregion
