
   ==================================================================
                         G A M I N G T W E A K S   v1.1.0
         One menu. Every change backed up. One key to undo it all.
   ==================================================================

   Built from the best parts of WinUtil, Atlas, ReviOS, FR33THY's
   Ultimate, UnLovedCookie's Network, GTweak, privacy.sexy, Sparkle
   and shoober420's scripts - with everything that breaks Windows,
   the Microsoft Store, Xbox or anti-cheat left out.


   ------------------------------------------------------------------
    QUICK START
   ------------------------------------------------------------------

     1.  Extract the zip (keep all three files together)
     2.  Double-click  Run-GamingTweaks.cmd  and accept the admin prompt
     3.  Press  1  to apply everything recommended
     4.  Reboot
     5.  Press  I  to check everything applied

     Changed your mind?  Run it again and press  R .

     Backup + logs live in   C:\GamingTweaks


   ------------------------------------------------------------------
    THE SAFETY NET
   ------------------------------------------------------------------

     * A System Restore point is made first.
     * Every registry value, service, scheduled task, power plan,
       network adapter setting, DNS server and NVIDIA profile is
       recorded in C:\GamingTweaks\backup.json BEFORE it is changed.
     * [R] puts all of it back exactly as it was.
     * Every run is logged to C:\GamingTweaks\log-<date>.txt

     Not covered by [R]: removed bloat apps (reinstall from the Store)
     and deleted temp/junk files (they are gone - that's the point).


   ------------------------------------------------------------------
    IT ADAPTS TO YOUR PC
   ------------------------------------------------------------------

     Laptop .......... battery settings untouched, no hibernate change
     Desktop ......... full performance power settings
     AMD dual-CCD X3D  (7900X3D / 7950X3D / 9900X3D / 9950X3D)
                       Balanced-based plan, core parking + Game Bar kept
                       so games stay on the V-Cache chiplet
     NVIDIA GPU ...... telemetry off + driver profile import offered
     16 GB+ RAM ...... memory compression off
     Realtek audio ... audio power saving off
     Windows 11 ...... global timer resolution enabled


   ==================================================================
    THE MENU
   ==================================================================

   [1]  APPLY EVERYTHING RECOMMENDED
        Makes a restore point, runs 2-9, S, G and N in order, asks
        about removing bloat apps [A], then offers the optional
        FPS-for-security trade-offs [C] [D] [E] together.

   ------------------------------------------------------------------
   [2]  POWER PLAN
   ------------------------------------------------------------------
        * Own "GamingTweaks" plan built from Ultimate Performance
        * Turbo boost: Aggressive    * Energy preference: max performance
        * All CPU cores unparked     * Minimum CPU state 100%
        * No PCIe, USB or disk power saving
        * Never auto-sleep, hibernate + Fast Startup off (desktops)
        * Power throttling off (desktops)

   ------------------------------------------------------------------
   [3]  GAMING & INPUT
   ------------------------------------------------------------------
        * Game Mode on, background recording / Game DVR off
        * Foreground apps get more CPU time (Win32PrioritySeparation)
        * Multimedia scheduler "Games" profile: GPU priority 8, high
        * Mouse acceleration off (raw 1:1 aim)
        * Sticky / Filter / Toggle Keys pop-ups off
        * Startup apps launch with no delay
        * Realtek audio never sleeps (no cut-off first sound)
        * Transparency + taskbar animations off, menus instant
        * Memory compression off (16 GB+ RAM)

   ------------------------------------------------------------------
   [4]  GPU
   ------------------------------------------------------------------
        * Hardware-accelerated GPU scheduling on (needed for Frame Gen)
        * Optimisations for windowed / borderless games on
        * MSI interrupt mode for the graphics card
        * NVIDIA telemetry tasks off

   ------------------------------------------------------------------
   [5]  BACKGROUND & PRIVACY
   ------------------------------------------------------------------
        * Telemetry, error reporting + ~20 telemetry tasks off
        * Activity history, advertising ID, tailored experiences off
        * Start menu ads, tips and auto-installed apps off
        * Bing / web results in Start search off
        * Copilot, Recall and Widgets off
        * Background UWP apps off, Edge background mode off
        * Settings sync, online speech, typing/ink collection off
        * Feedback prompts + Microsoft feature experiments off
        * Network data usage monitor off (fixes a memory leak)
        * Optional: Edge ad / shopping / Copilot / telemetry blocking

   ------------------------------------------------------------------
   [6]  WINDOWS UPDATE OFF   (the Microsoft Store keeps working)
   ------------------------------------------------------------------
        * Automatic updates off, paused for 10 years
        * Driver updates blocked (no surprise GPU driver swaps)
        * Locked to your current Windows version (no 25H2 -> 26H2)
        * Peer-to-peer update sharing off
        Update by hand any time: Settings > Windows Update > Resume.

   ------------------------------------------------------------------
   [7]  NETWORK
   ------------------------------------------------------------------
        * Network throttling off, Nagle's algorithm off
        * TCP auto-tuning + RSS on sensible defaults
        * Adapter power saving, Energy Efficient Ethernet and
          packet / DMA coalescing off
        * Optional lowest-ping mode (interrupt moderation off)
        * Network card MSI mode on
        * Failed DNS lookups not cached
        * Game traffic marked high priority (DSCP 46) for Apex, CS2,
          Valorant, Fortnite, CoD, R6, Overwatch, PUBG, Rocket League
          and Marvel Rivals - helps if your router has QoS

   ------------------------------------------------------------------
   [8]  TIMER RESOLUTION
   ------------------------------------------------------------------
        * Choose 0.5 ms or 1.0 ms, applied at every boot
        * Use [T] to measure which gives steadier timing on your PC

   ------------------------------------------------------------------
   [9]  CLEANUP
   ------------------------------------------------------------------
        * Temp files, old Windows Update downloads
        * Delivery Optimization cache, app crash dumps, error reports
        * Discord cache (when Discord is closed)
        * Asks: GPU shader caches (only after a driver update!)
        * Asks: empty the Recycle Bin
        * Asks: WinSxS component store clean-up (frees GBs)
        * Shows how much space was freed
        Never touched: browser data + passwords, Prefetch, restore
        points, event logs, BSOD minidumps, Windows\Installer cache.

   ------------------------------------------------------------------
   [S]  SERVICES
   ------------------------------------------------------------------
        Turns off ~40 services a home gaming PC never uses: maps,
        Windows Insider, fax, smart card, wallet / NFC, remote
        registry, retail demo, kiosk mode, Hyper-V guest, Intel /
        Razer / Logitech / NVIDIA telemetry and more.
        Asks about: printing, Bluetooth, file sharing / NAS,
                    search indexing.
        Always kept: Windows Update + Store, Xbox Live / Game Save /
                     controllers, audio, networking, UPnP (NAT type),
                     SysMain, Microsoft account sign-in.
        Aggressive mode (asks first): ~25 more services set to start
        only when needed or turned off - Store downloads, Xbox
        networking, sign-in, notifications and typing still work.
        Typical clean Win11 desktop: ~110-130 running before,
        ~85-95 after, ~75-85 with no Bluetooth/printer/sharing/search.

   ------------------------------------------------------------------
   [G]  GAME PRIORITY
   ------------------------------------------------------------------
        * "Above Normal" CPU priority for Apex (r5apex + r5apex_dx12),
          CS2, Valorant, Fortnite, CoD, R6, Overwatch, PUBG,
          Rocket League and Marvel Rivals
        * Multimedia scheduler disk latency cap off

   ------------------------------------------------------------------
   [N]  NVIDIA PROFILE IMPORT
   ------------------------------------------------------------------
        Downloads NVIDIA Profile Inspector (official GitHub), backs up
        your current driver profiles, then sets globally:
          Power management ............ Prefer maximum performance
          Low Latency Mode ............ On
          Texture filtering quality ... High performance
          Negative LOD bias ........... Clamp
          Shader cache size ........... Unlimited
          CUDA force P2 state ......... Off
          Threaded optimisation ....... On
          Ansel ....................... Off
          V-Sync ...................... On for G-Sync / Off otherwise
        Not touched: ray tracing, anisotropic filtering, anti-aliasing,
        Resizable BAR, G-Sync itself.


   ==================================================================
    EXTRAS  (never applied without asking)
   ==================================================================

   [A]  Remove bloat apps
        News, Weather, Bing, Get Help, Tips, Office hub, Solitaire,
        People, Power Automate, To Do, Feedback Hub, Maps, Films & TV,
        Cortana, Dev Home, new Outlook, Copilot, Journal, Clipchamp,
        Teams, Phone Link, Family.
        Kept: Store, Xbox, Gaming Services, Photos, Calculator,
        Notepad, Paint, Terminal, Snipping Tool, Camera.

   [B]  DNS servers ...... Cloudflare, Google, Quad9 or automatic
   [C]  Core Isolation ... VBS / Memory Integrity off (often +5-10%
                           FPS in CPU-heavy games)
   [D]  UAC prompts off .. "Never notify" - Store apps still work
   [E]  Defender off ..... needs Tamper Protection off first; the
                           script opens the right page for you
   [F]  Spectre/Meltdown . mitigations off - older CPUs only
   [M]  MPO off .......... only if you get flicker or stutter in
                           borderless games / with a 2nd monitor
   [T]  Timer test ....... measures how accurately Windows wakes up
   [P]  Restore point .... make one any time
   [I]  PC info .......... hardware, anti-cheat, VBS, power plan,
                           HAGS, before/after services + RAM,
                           and your startup apps
   [R]  REVERT EVERYTHING


   ==================================================================
    LEFT OUT ON PURPOSE
   ==================================================================

     These are in other tools you may have seen. They break things,
     risk your data or hardware, or simply don't help:

     x  UAC fully off ................ breaks Store apps
     x  Removing Edge / WebView ...... breaks apps and launchers
     x  Disabling the Update service . breaks Store downloads
     x  Page file off ................ Apex crashes "out of memory"
     x  Write-cache flushing off ..... file corruption on power loss
     x  DEP / CFG / firewall off ..... no FPS gain
     x  HPET / dynamic tick / platform tick boot edits
     x  Real-time driver thread priorities
     x  BBR2, Large System Cache, network stack resets
     x  GPU thermal throttling / power gating off
     x  Renaming or deleting Windows system files
     x  Deleting every .log / .bak / .tmp across the drive
     x  Wiping browser data, saved logins or restore points
     x  IPv6 off, QoS "bandwidth" myths


   ==================================================================
    DO THESE BY HAND  (the biggest real gains)
   ==================================================================

     BIOS
       * XMP / EXPO on for your RAM
       * Resizable BAR on
       * Ryzen: PBO with a negative Curve Optimizer

     Drivers
       * Clean install with NVCleanstall (no telemetry / extras)

     In game
       * NVIDIA Reflex on (or AMD Anti-Lag)
       * Cap FPS a few frames under your refresh rate, or just under
         what your PC holds steady - smoother than uncapped
       * G-Sync users: G-Sync on, V-Sync on in the control panel,
         V-Sync off in game

     Windows
       * Settings > Display > Advanced display: highest refresh rate
       * Task Manager > Startup apps: disable what you don't need


   ==================================================================
    GOOD TO KNOW
   ==================================================================

     * Windows Security may flag the script because it contains the
       optional "Defender off" code. That part only runs if you pick it.
     * FACEIT / Vanguard games refusing to start after [C]?
       Press R, or turn Memory Integrity back on in Windows Security.
     * Reverting NVIDIA profiles after a driver update? Use Profile
       Inspector > "Restore defaults" instead.
     * Best way to see what helped: record a short Apex session in
       CapFrameX before and after, and compare the 1% lows.

   ==================================================================

   github.com/FiTH-g1gGLe/Windows-11-Script
