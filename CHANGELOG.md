# Changelog

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
