<div align="center">

# 🎮 GamingTweaks

**One menu. Every change backed up. One key to undo it all.**

A Windows 10/11 gaming optimisation script that adapts to your PC, keeps the Microsoft Store,
Xbox and anti-cheat working, and can put everything back exactly as it was.

`v1.3.0` · PowerShell · Windows 10 / 11 · Window or text menu

</div>

---

## ⚡ Quick start

1. Click the green **Code** button above, then **Download ZIP**, and extract it
2. Double-click **`Run-GamingTweaks.cmd`** and accept the admin prompt — the GamingTweaks window opens
3. Check the **Tweaks**, **Your choices** and **Extras** tabs (the recommended options are already ticked)
4. Click **Apply selected**, then reboot
5. Open **Info + tools → PC info** to see before / after

Changed your mind? Click **Revert everything**.

### Prefer the text menu?
Double-click **`Run-GamingTweaks-Console.cmd`** (or run `Run-GamingTweaks.cmd -Console`) and press **`1`**,
then **`I`** after rebooting, or **`R`** to revert. Both use the same backup, so you can apply in one
and revert in the other.

| Window | Text menu |
|---|---|
| Tick boxes for every section and question, set everything up front | Asks yes / no as it goes |
| Live colour log, progress bar, one click to apply | Same log in the console |
| Recommended / Untick all / Restore point / Revert buttons | Keys `1`-`9`, `S` `G` `N` `A`-`F` `M` `T` `P` `I` `R` |

> Backup and logs are kept in `C:\GamingTweaks`.

---

## 🛡️ The safety net

- A **System Restore point** is made first
- **Every** registry value, service, scheduled task, power plan, network adapter setting, DNS server
  and NVIDIA profile is saved to `C:\GamingTweaks\backup.json` **before** it is changed
- **`R`** restores all of it
- Every run is logged to `C:\GamingTweaks\log-<date>.txt`

*Not covered by `R`: removed bloat apps (reinstall them from the Store) and deleted junk files.*

---

## 🧠 It adapts to your PC

| Detected | What changes |
|---|---|
| **Laptop** | Battery settings untouched, hibernate left on |
| **Desktop** | Full performance power settings |
| **AMD 7900X3D / 7950X3D / 9900X3D / 9950X3D** | Balanced-based plan, core parking + Game Bar kept so games stay on the V-Cache chiplet |
| **NVIDIA GPU** | Telemetry off + driver profile import offered |
| **16 GB+ RAM** | Memory compression off |
| **Realtek audio** | Audio power saving off |
| **Windows 11** | Global timer resolution enabled |

---

## 📋 What it does

The window and the text menu run exactly the same sections (keys shown for the text menu):

| Key | Section | What it does |
|:-:|---|---|
| **1** | **Apply everything recommended** | Restore point → 2-9, S, G, N → asks about bloat apps and the optional trade-offs |
| **2** | Power plan | Own Ultimate-based plan, aggressive turbo boost, max-performance EPP, all cores unparked, no PCIe/USB/disk power saving |
| **3** | Gaming & input | Game Mode, no Game DVR, foreground CPU boost, MMCSS games profile, raw mouse input, no Sticky Keys pop-ups, no startup delay, Realtek audio fix |
| **4** | GPU | Hardware-accelerated GPU scheduling, windowed-game optimisations, MSI mode, NVIDIA telemetry off |
| **5** | Background & privacy | Telemetry + ~20 telemetry tasks, ads, Bing search, Copilot, Recall, Widgets, background apps, settings sync and tracking off; optional Edge ad blocking |
| **6** | Windows Update off | Paused 10 years, driver updates blocked, version locked — **the Store keeps working** |
| **7** | Network | Throttling and Nagle off, adapter power saving / EEE / coalescing off, NIC MSI mode, DSCP 46 game traffic priority, optional lowest-ping mode |
| **8** | Timer resolution | 0.5 ms or 1.0 ms at every boot |
| **9** | Cleanup | Temp, update + Delivery Optimization caches, crash dumps, Discord cache; asks about shader caches, Recycle Bin and WinSxS; shows space freed |
| **S** | Services | ~40 unused services off; asks about printing, Bluetooth, file sharing and search indexing; optional **aggressive mode** (~25 more set to on-demand or off) |
| **G** | Game priority | Above Normal CPU priority for Apex and 9 other games, MMCSS IO latency cap off |
| **N** | NVIDIA profile | Downloads NVIDIA Profile Inspector, backs up your profile, imports 12 tuned settings |

### Extras — never applied without asking

| Key | Option | Notes |
|:-:|---|---|
| **A** | Remove bloat apps | Keeps Store, Xbox, Gaming Services, Photos, Calculator, Notepad, Paint, Terminal, Snipping Tool, Camera |
| **B** | DNS servers | Cloudflare, Google, Quad9 or automatic |
| **C** | Core Isolation off | VBS / Memory Integrity off — often +5-10% FPS in CPU-heavy games |
| **D** | UAC prompts off | "Never notify" — Store apps keep working |
| **E** | Defender off | Needs Tamper Protection off first; the script opens the right page |
| **F** | Spectre / Meltdown off | Older CPUs only |
| **M** | MPO off | Only if you get flicker or stutter in borderless games |
| **T** | Timer test | Measures how accurately Windows wakes up |
| **P** | Restore point | Make one any time |
| **U** | Startup apps | Turn apps on/off at startup (same as Task Manager) or delete the entry — backed up, Revert restores it |
| **I** | PC info | Hardware, anti-cheat, VBS, power plan, HAGS, **before/after** services, processes and RAM, startup apps |
| **R** | **Revert everything** | Puts every recorded setting back |

<details>
<summary><b>🟢 NVIDIA profile settings (option N)</b></summary>

| Setting | Value |
|---|---|
| Power management mode | Prefer maximum performance |
| Low Latency Mode | On |
| Texture filtering quality | High performance |
| Negative LOD bias | Clamp |
| Shader cache size | Unlimited |
| CUDA force P2 state | Off |
| Threaded optimisation | On |
| Ansel | Off |
| V-Sync | On for G-Sync users, otherwise Off |

**Not touched:** ray tracing, anisotropic filtering, anti-aliasing, Resizable BAR, G-Sync itself.
Profile Inspector is downloaded from its [official GitHub](https://github.com/Orbmu2k/nvidiaProfileInspector).

</details>

<details>
<summary><b>🔧 Services kept on purpose (option S)</b></summary>

**Always kept:** Windows Update and the Microsoft Store, Store downloads (BITS, Delivery Optimization),
Xbox Live / Game Save / controllers / networking, Microsoft account sign-in, notifications, typing and
the search box, audio, display, networking and UPnP (keeps your NAT type open).

**Aggressive mode** (asks first) sets Connected Devices, Diagnostic Policy, Remote Access, AutoPlay,
Storage Service, Update Orchestrator and Edge Update to start only when needed, and turns off AI Fabric,
Geolocation, Web Threat Defense, Now Playing, Mail/Calendar sync, messaging, voice activation, WSL file
access, contacts indexing and game recording. It also asks about Windows Hello biometrics and SysMain.

**Typical result on a clean Windows 11 desktop:** ~110-130 running services before, ~85-95 after
aggressive mode, ~75-85 if you also say no to Bluetooth, printing, file sharing and search indexing.
Motherboard / RGB / vendor apps add their own services on top - uninstalling those is the next biggest win.
Check your own numbers with **`I`**.

</details>

---

## 🚫 Left out on purpose

These appear in other tweak tools. They break things, risk your data or hardware, or don't help:

| Tweak | Why not |
|---|---|
| UAC fully off | Breaks Store apps |
| Removing Edge / WebView | Breaks apps and game launchers |
| Disabling the Windows Update service | Breaks Store downloads |
| Page file off | Apex crashes with "out of memory" |
| Write-cache flushing off | File corruption on power loss |
| DEP / CFG / firewall off | No FPS gain |
| HPET / dynamic tick / platform tick | Mixed results, can worsen frame pacing |
| Real-time driver thread priorities | More likely to cause stutter |
| BBR2, Large System Cache, network resets | Buggy or server-only |
| GPU thermal throttling / power gating off | Hardware risk |
| Renaming / deleting Windows system files | Breaks Windows |
| Deleting every `.log` / `.bak` / `.tmp` on the drive | Deletes app and game files |
| Wiping browser data, logins or restore points | Data loss |

---

## 🏆 Do these by hand — the biggest real gains

- **BIOS:** XMP / EXPO on · Resizable BAR on · Ryzen: PBO with a negative Curve Optimizer
- **Drivers:** clean install with NVCleanstall
- **In game:** NVIDIA Reflex on · cap FPS a few frames under your refresh rate
- **G-Sync:** G-Sync on, V-Sync on in the control panel, V-Sync off in game
- **Windows:** highest refresh rate in *Settings → Display → Advanced display* · trim *Task Manager → Startup apps*

---

## ❓ Good to know

- **Windows Security may flag the script** because it contains the optional "Defender off" code. That part only runs if you choose it.
- **FACEIT / Vanguard game won't start after `C`?** Press `R`, or turn Memory Integrity back on in Windows Security.
- **Reverting NVIDIA profiles after a driver update?** Use Profile Inspector → *Restore defaults* instead.
- **Want proof it helped?** Record a short session in [CapFrameX](https://www.capframex.com/) before and after, and compare the 1% lows.

---

## 📁 Files

| File | |
|---|---|
| `Run-GamingTweaks.cmd` | Double-click this to start (opens the window) |
| `Run-GamingTweaks-Console.cmd` | Text-menu version |
| `GamingTweaks.ps1` | The script itself |
| `README.txt` | Offline copy of this guide |
| `legacy/Windows11.bat` | The original 2024 script, kept for reference — **not recommended**, see [CHANGELOG](CHANGELOG.md) |

<div align="center">

*Built from the best parts of WinUtil, Atlas, ReviOS, FR33THY's Ultimate, UnLovedCookie's Network,
GTweak, privacy.sexy, Sparkle and shoober420's scripts — reviewed line by line, risky parts removed.*

**Use at your own risk. Make a backup before tweaking any PC.**

</div>
