# 🛡 Log Sentinel

> **Know what your computer is really doing.**
> A one-click Windows security tool with live monitoring, plain-English findings, and one-click blocking. Free for personal use. No cloud. No telemetry. ~30 MB.

[Download for Windows](#-quick-start) · [See it in action](#-what-it-looks-like) · [Pricing](#-pricing) · [Feature list](#-features)

---

## What it does in one paragraph

Log Sentinel is a desktop app that pulls together everything Windows knows about itself — Event Log, processes, network connections, services, scheduled tasks, autoruns, USB history, installed software, hosts file, registry — runs 50+ detection rules across all of it, maps every finding to **MITRE ATT&CK**, and shows you the result as one easy-to-read **Health Score** with plain-English fixes.

Then it gets out of your way.

---

## Why this, not antivirus

| Antivirus | Log Sentinel |
|---|---|
| Catches known **signatures** | Watches actual **behavior** |
| Quietly fails when malware is new | Shows you every new process + connection in real time |
| One opaque "you're protected" sticker | A 0–100 Health Score with the WHY |
| You hope it caught the thing | You can see for yourself |
| Subscription forever | One-time purchase |

**Use both.** They don't overlap. Antivirus stops what's known; Log Sentinel surfaces what isn't.

---

## 🎬 What it looks like

```
┌─ HEALTH CHECK ───────────────────────────────────────────────────┐
│                                                                    │
│      ╭────────╮      YOUR PC HEALTH                                │
│      │   56   │      Multiple problems found. Take action soon.    │
│      │ Grade D│      ↓ 2 pts vs last scan  ·  7 new  ·  6 resolved │
│      ╰────────╯                                                    │
│                                                                    │
│   🛡 Security 10   👁 Privacy 16   ⚡ Performance 11   🔧 Stability │
│                                                                    │
│   📋 RECOMMENDED ACTIONS                                          │
│                                                                    │
│   ┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃   │
│   ┃ [HIGH]  [Privacy]  T1219                              ⚙   ┃   │
│   ┃ A remote-control program is running on your PC.            ┃   │
│   ┃                                                            ┃   │
│   ┃ WHY IT MATTERS              WHAT TO DO                     ┃   │
│   ┃ TeamViewer/AnyDesk let       1. Did you install this?      ┃   │
│   ┃ someone else control your    2. If no — uninstall it...    ┃   │
│   ┃ computer. Common scam ...    3. Change your passwords...   ┃   │
│   ┃                                                            ┃   │
│   ┃ [Open Task Manager]  [Defender Quick Scan]   ✓ Mark fixed  ┃   │
│   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛   │
└────────────────────────────────────────────────────────────────────┘
```

14 tabs, all populated automatically: Health Check · Trends · Timeline · Dashboard · Live Feed · Findings · Events · Network · Processes · Services · Persistence · Live Monitor · Firewall · System.

---

## ⚡ Quick start

### Trial and monthly keys

Log Sentinel starts with a 30-day trial. After that, the app requires a fresh 30-day licence key. To issue a customer key:

```bash
py -3 tools/make_license_key.py customer@example.com --days 30 --device MACHINE_ID
```

The customer enters their email and key in the activation window. Ask them to send the Machine ID shown on that screen so the key works only on that PC. This early offline system is useful for controlled sales and demos; for a public release, move key generation and activation to a private server.

### Easy: download the .exe

1. Download `LogSentinel.exe` (~30 MB, single file)
2. Right-click → **Run as administrator** (for full power)
3. The app opens maximized. Wait 30 seconds for the first scan to finish.
4. Read the Health Check tab. Click **✨ Quick Win** to auto-fix the safe stuff.

### Run from source (developers)

```bash
git clone https://github.com/yourname/log-sentinel.git
cd log-sentinel
python app.py
```

Requires Python 3.10+. **Zero pip dependencies** — pure standard library.

### Build the portable .exe yourself

```bash
BUILD.bat
```

Drops `dist\LogSentinel.exe`. See [BUILD.md](BUILD.md) for code-signing + installer instructions.

---

## ✨ Features

### The headline ones

- **🏥 Health Check** — One score (0–100), color-coded categories (Security / Privacy / Performance / Stability), plain-English findings with one-click fixes
- **⚡ Live Mode** — Real-time process + network monitoring with toast alerts the moment something Critical or High shows up
- **🚨 Panic Button** — One click cuts every network adapter on the machine. The killer ransomware-response feature. Reversible.
- **🔥 Firewall + Domain Blocker** — Block any IP, port, or website (Facebook, TikTok, your call) in two clicks. All reversible.
- **🍯 Honeypot Tripwires** — Drop fake `passwords.txt` / `wallet_backup.txt` files. The moment ransomware reads or modifies them, you know.
- **🔍 File Integrity Monitor** — Watch any file. We hash + compare on every scan. Flags any change.
- **⏱ Attack Timeline** — Every event and finding plotted on one time axis. Find the moment things went wrong.
- **📊 System Vitals** — Live CPU / RAM / Disk / Battery / Wi-Fi / Internet / Antivirus state, all updating in real time
- **🌐 GeoIP Connections** — See which countries your PC is talking to with country flags
- **🌳 Process Tree** — Parent → child relationships, suspicious processes flagged
- **🛠 Custom Detection Rules** — Write your own rules in JSON, with a built-in GUI editor
- **📈 Trends** — Every scan saved, health score charted over time
- **⏰ Scheduled Scans** — Run silently via Windows Task Scheduler
- **✉ Email Alerts** — SMTP-based, fires only on Critical/High findings
- **🔐 Password Strength Checker** — Offline, with crack-time estimate

### Detection coverage

| Category | What we catch |
|---|---|
| **Authentication** | Brute-force logons, off-hours access, account lockouts, privilege escalation |
| **Persistence** | New scheduled tasks, autoruns, services, especially from Temp folders |
| **Process** | Known attacker tools (mimikatz, rubeus, cobaltstrike), process impersonation, suspicious paths |
| **Network** | Suspicious listening ports (4444, 31337…), TOR connections, beaconing patterns |
| **PowerShell** | Encoded commands, download cradles, IEX abuse |
| **Defense evasion** | Audit log clearing, firewall changes, unsigned binaries |
| **Ransomware** | Honeypot file modification, audit log clearing, shadow copy deletion patterns |
| **Privacy** | Webcam/mic users, browser extensions, USB history |
| **Performance** | Startup bloat, RAM hogs, suspicious miners |
| **Stability** | Unexpected shutdowns, recently modified system files |

Every finding tagged with its **MITRE ATT&CK** technique ID — clickable, links to attack.mitre.org.

---

## 💰 Pricing

| Tier | Price | For |
|---|---|---|
| **Free** | $0 | Single machine, manual scans, full Health Check, IP/website blocker, watermarked reports |
| **Pro** | $79 one-time | Live mode, scheduled scans, email alerts, honeypots, FIM, custom rules, white-label reports |
| **Consultant** | $499/year | Run on unlimited machines you service, branded PDF reports, priority support |

No subscription trap. Pay once, own it. Updates for a year included.

[See full feature comparison →](outreach/index.html)

---

## 🔒 Privacy guarantees

- **Zero telemetry.** Open Wireshark while it's running and verify yourself.
- **Zero account required.** No signup, no email harvesting.
- **Zero data leaves your PC** unless YOU configure it (e.g., your own SMTP for alerts).
- **Source is open** so you can audit every claim above.

Your scan history lives at `~/.log_sentinel/`. Delete that folder and Log Sentinel forgets everything.

---

## 🛠 Architecture

Pure Python, single-machine, single-file when bundled. Zero pip dependencies.

```
log-sentinel/
├── app.py                  # Tkinter desktop GUI
├── main.py                 # CLI version + report generation
├── demo.py                 # Synthetic attack scenario
├── BUILD.bat               # PyInstaller portable .exe builder
├── LogSentinel.spec        # PyInstaller config
├── LAUNCH-as-admin.bat     # UAC-elevated launcher
├── src/
│   ├── collector.py        # Windows Event Log via wevtutil
│   ├── system_collector.py # Processes, network, services, autoruns, etc.
│   ├── analyzer.py         # 11 event-based detection rules
│   ├── system_analyzer.py  # 9 snapshot-based detection rules
│   ├── custom_rules.py     # User-defined rule engine
│   ├── live_monitor.py     # Real-time polling thread
│   ├── threat_intel.py     # Built-in IOC database
│   ├── mitre.py            # MITRE ATT&CK technique mapping
│   ├── plain_english.py    # Human-readable explanations
│   ├── health_score.py     # 0–100 score calculation
│   ├── remediation.py      # One-click fix actions
│   ├── firewall_manager.py # netsh wrapper for IP/port rules
│   ├── hosts_manager.py    # hosts file editor for website blocking
│   ├── fim.py              # File integrity monitor
│   ├── honeypots.py        # Tripwire file engine
│   ├── system_monitor.py   # Live CPU/RAM/disk/battery/Wi-Fi
│   ├── panic.py            # Device isolation
│   ├── geoip.py            # Offline IP→country lookup
│   ├── email_alerts.py     # SMTP alerts
│   ├── password_check.py   # Offline password strength
│   ├── scheduler.py        # Windows Task Scheduler integration
│   ├── scan_history.py     # Trend tracking
│   ├── preferences.py      # Persistent user state
│   ├── quick_win.py        # Batch safe-fix engine
│   ├── reporter.py         # HTML/JSON/PDF reports
│   ├── categorizer.py      # Event ID → category mapping
│   └── everyday_scanner.py # Startup, mic/cam, recent files, etc.
├── outreach/               # Landing page, email templates, demo script
├── reports/                # Generated reports
└── BUILD.md, USER_GUIDE.md
```

---

## 📜 Licence

Free for personal use. Commercial / multi-machine use requires a licence (see [Pricing](#-pricing) above).

Source available — that's not the same as MIT or GPL. Read it, audit it, learn from it. Don't repackage and resell.

---

## ❓ FAQ

- **"Is this a replacement for antivirus?"** No. Use both.
- **"Does it phone home?"** No. Verify with Wireshark.
- **"Will it overwhelm me?"** The Health Check tab is designed for total beginners.
- **"What if I block the wrong thing?"** Every change is reversible from the Active Rules tab.
- **"Without admin?"** Most features work. Security log + firewall + hosts file + panic button need admin.

[Full FAQ on the landing page →](outreach/index.html)

---

## 🤝 Get in touch

- 🐛 Bugs / feature requests: [GitHub Issues](https://github.com/yourname/log-sentinel/issues)
- 💬 General: hello@logsentinel.example
- 📦 Consultant licensing: licensing@logsentinel.example

---

*Built with care, sold without bullshit.*
