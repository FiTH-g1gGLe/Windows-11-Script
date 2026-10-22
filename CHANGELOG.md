# Changelog

## v1.3.0
- **Startup apps manager** — new *Startup apps* tab in the window and option `U` in the text menu
  - Lists everything from the Run keys (user, all users, 32-bit) and both Startup folders
  - Untick / toggle to stop an app starting with Windows — written the same way Task Manager does it, so it shows as Disabled there too
  - **Delete** removes the entry completely; it is backed up first and **Revert everything** puts it back
- PC info now lists startup apps with their on / off state

## v1.2.1
- Graphics cards disabled in Device Manager (e.g. an unused integrated GPU) are no longer shown or tweaked

## v1.2.0
- **New window (GUI)** — opens by default from `Run-GamingTweaks.cmd`
  - Tabs: Tweaks, Your choices, Extras, Info + tools
  - Recommended options pre-ticked; every question becomes a tick box, so it runs start to finish without stopping
  - Live colour log, progress bar, Recommended / Untick all / Restore point / Revert everything buttons
  - Shows your hardware in the header; PC info, timer test and backup folder on the Info tab
- **Text menu kept**: `Run-GamingTweaks-Console.cmd` or `Run-GamingTweaks.cmd -Console`
- Both share the same backup, so Revert works from either
- If the window can't open, it falls back to the text menu automatically

## v1.1.0
- **Aggressive services mode** in `S`: ~25 more services set to start on demand or turned off,
  while keeping the Store, Xbox, sign-in, notifications and typing working
- Per-user services (e.g. `NPSMSvc_1a2b3`) are now handled along with their templates
- Optional: Windows Hello biometrics service and SysMain
- **Before / after report** in `I`: running services, processes and RAM, measured automatically
  the first time anything is applied

## v1.0.0 — GamingTweaks

A complete rewrite. The old `Windows11.bat` has been replaced by **GamingTweaks**, a PowerShell menu script.

### New
- Menu with 12 sections and 11 extras — run everything or pick one at a time
- Full backup of every change and one-key **Revert everything** (`R`)
- Restore point before any changes, plus a log of every run
- Hardware detection: laptop/desktop, AMD dual-CCD X3D, NVIDIA, RAM size, Realtek audio, Windows 10/11
- NVIDIA Profile Inspector import with a profile backup
- Services section that keeps the Microsoft Store, Xbox and sign-in working
- Safe cleanup that never touches browser data, Prefetch, restore points or event logs
- Timer resolution choice (0.5 / 1.0 ms) and a built-in timer test
- PC info screen to check that everything applied

### Removed from the old script (and why)
| Old behaviour | Problem |
|---|---|
| Deleted every `*.sqlite` in Firefox profiles, deleted Opera profiles | Wiped bookmarks, history and site data |
| ~30 `bcdedit` boot changes (PAE off, ELAM off, integrity services off, platform tick, etc.) | No undo; several are 32-bit-only or weaken boot security; some can worsen frame pacing |
| `DisableWriteCombining`, `DisableCudaContextPreemption` | Can cause GPU driver crashes |
| Network stack reset, BBR2, Large System Cache, MinSudo download | Breaks VPNs/static IPs; BBR2 is buggy on Windows; server-only setting |
| Services: 174 disabled, then 114 of them set back to Manual | Mostly cancelled itself out; also set Remote Desktop to Automatic |
| Backed up Windows Update downloads before deleting them | Freed no space |

The original is kept in `legacy/Windows11.bat` for reference.
