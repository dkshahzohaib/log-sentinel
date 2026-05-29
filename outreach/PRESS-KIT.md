# Press kit — Log Sentinel

For journalists, bloggers, podcast hosts, YouTube reviewers, and anyone writing about the product.

---

## One-liners (pick the angle)

- **For privacy / personal:** "Know what your computer is really doing, in plain English."
- **For SMB:** "The PC security check IT consultants charge $300 for, in 90 seconds, on your laptop."
- **For SOC / IR:** "Portable Windows triage with MITRE-mapped findings — no agent, no cloud."
- **For tech press:** "An open-source, offline-only, single-binary Windows security analyser written in pure Python stdlib."
- **For comparison:** "The 80% of Splunk that matters for a single PC, for the price of a coffee."

---

## Elevator pitch (30 seconds)

> "Log Sentinel is a one-click Windows security tool that does what your antivirus can't: it tells you exactly what's running on your PC and what's wrong, in plain English. It collects every Windows log, every running process, every network connection, every autorun and scheduled task, runs 50+ detection rules across all of it, maps each finding to MITRE ATT&CK, and shows you the result as a single Health Score. There's a Panic button that cuts your network in one click during ransomware. Ransomware tripwires you can drop in your folders. Domain blocking via the hosts file. All offline. All on one machine. No subscription. The source is on GitHub. We've packed enterprise-SOC-grade tooling into something a non-technical user can actually use."

---

## Key claims (each one verifiable)

| Claim | How to verify |
|---|---|
| "100% offline" | Run Wireshark while the app is running. Zero outbound packets unless YOU configure SMTP. |
| "No telemetry" | Source is open. grep for `requests`, `urllib`, `http.client` — not used except in user-configured features. |
| "Zero pip dependencies" | `cat requirements.txt` — empty/comments only. Pure standard library. |
| "Single .exe, no install" | Download `LogSentinel.exe`, double-click. ~30 MB. Runs anywhere. |
| "50+ detection rules" | `grep -c '@rule\|register' src/*.py`. Plus the user-extensible custom rule engine. |
| "MITRE ATT&CK mapped" | Every rule has a technique ID in `src/mitre.py`. Click any finding to open attack.mitre.org. |
| "Reversible" | Firewall rules are tagged `LogSentinel_*`. Hosts file entries marked `# LogSentinel\|...`. Snoozed findings stored in JSON. Delete-all buttons exist. |
| "Plain-English findings" | See `src/plain_english.py` — every rule has problem / why_matters / what_to_do fields. |

---

## Boilerplate "About" paragraph

> Log Sentinel is a desktop security tool for Windows that brings enterprise-grade monitoring and incident-response capabilities to a single PC. Built with zero third-party dependencies, the application runs completely offline, requires no account, and stores everything locally. It targets three audiences: privacy-conscious individuals, small business owners without dedicated IT, and incident-response consultants who need a portable triage tool. Available free for personal use, with one-time paid tiers for advanced features and consultant licensing.

---

## Standard FAQ for press / reviewers

**Q: How is this different from Wazuh / OSSEC / EDR products?**
A: Those need a server, an agent install, and a SOC analyst to operate. Log Sentinel runs on a single PC, double-clicked, with a UI a non-technical user can read. We're not trying to replace EDR for enterprises. We're filling the gap between "trust your antivirus" and "spend $50K on a SIEM."

**Q: How is this different from Sysinternals (Process Explorer, Autoruns)?**
A: Sysinternals are 11 separate tools that don't talk to each other. We bundle the same data sources (and more) into one GUI with detection rules running across all of them. We also map findings to MITRE, generate reports, and have remediation actions. Sysinternals shows; we explain and fix.

**Q: How is this different from Defender / built-in Windows Security?**
A: Defender does signature-based AV. We do behavioral monitoring, persistence detection, network analysis, FIM, honeypots, and more. We complement Defender, never replace it — our app even monitors whether Defender is running and warns you if it gets disabled.

**Q: Is the source open?**
A: Yes — readable, auditable. Free for personal use. Commercial use requires a licence.

**Q: Why Python and Tkinter, not Rust / Go / Electron?**
A: Three reasons: (1) Tkinter ships with Python, so we have zero runtime dependencies. The user just runs an .exe. (2) Python's stdlib is enough for everything we do — no external packages means no supply-chain risk. (3) Tkinter is "ugly" by reputation, but with care it can look good (you'll see), and starts in under a second. Electron would 10x our binary size for prettier checkboxes; not worth it for security tooling.

**Q: What about Mac and Linux?**
A: Roadmap. Right now Windows is where the malware is, where the buyers are, and where the WMI/Event-Log telemetry is rich. Mac/Linux ports are doable but won't be feature-equal — different threat models, different APIs. We'll get there.

**Q: How big is the team?**
A: One developer. That's a feature, not a bug — we move fast, every change is intentional, and there's no marketing department turning every release into a landing page.

---

## Screenshot inventory

All screenshots in `reports/` (PNG, 1536×793 native):

1. `live_monitor.png` — System Vitals tab with live CPU/RAM/Disk/Battery gauges, Wi-Fi/Internet/AV cards, Hardware/Disks panels — **best for "real-time monitoring" angle**
2. `health_v2_screenshot.png` — Hero shot of Health Check with score 56, big verdict, delta line, category cards — **best for first-impression / hero**
3. `popout_v3.png` — Recommended Actions in standalone window — **best for "plain-English findings" angle**
4. `firewall_tab.png` — Firewall tab with IP form, big block/allow buttons, admin status — **best for "block anything" angle**
5. `fw_websites.png` — Websites sub-tab with form + Facebook/TikTok/Reddit presets — **best for "domain blocker" angle**
6. `timeline_v2.png` — Attack Timeline with severity swim-lanes — **best for "forensic timeline" angle**
7. `process_tree.png` — Tree-view processes with parent → child nesting — **best for "Process Tree" angle**
8. `network_geoip.png` — Network tab with country flags + connections-by-country bar chart — **best for "GeoIP" angle**

Want a specific shot? Email and we'll generate it.

---

## Logo / branding

(To be created — placeholder for now)

- **Primary logo:** Shield with "LS" inside, teal (#4ecdc4) on dark
- **Wordmark:** "🛡 Log Sentinel" in Segoe UI Bold
- **Brand colors:** Dark BG #1a1a2e · Card #2d2d4a · Accent teal #4ecdc4 · Critical red #ff4757 · Warning orange #ff7f50

---

## Comparable products / market positioning

| Product | Audience | Price | Limitation we beat |
|---|---|---|---|
| **Splunk Enterprise** | SOC teams | $50K+/yr | Massive setup + ongoing cost |
| **Wazuh** | DevSecOps | "Free" but ops-heavy | Needs server + agents |
| **CrowdStrike Falcon** | Mid-market | $$$$ | Per-endpoint cloud licensing |
| **Malwarebytes** | Consumers | $40/yr | Sig-based, no behavioral monitoring |
| **Process Explorer (Sysinternals)** | Power users | Free | No detection logic, no UI for novices |
| **Autoruns (Sysinternals)** | Power users | Free | Single-purpose, dense UI |
| **CCleaner** | Consumers | "Free" | Bundled adware, no real security value |
| **GlassWire** | Prosumers | $39/yr | Network only, no event-log analysis |

We sit between Sysinternals (free, technical) and the enterprise tier ($$$$, complex). Closest competitor: **GlassWire**, but we cover much more than network.

---

## Quotes you can use

> "Antivirus tells you you're fine. Task Manager hides the interesting stuff. We show you the truth."

> "Built with care, sold without bullshit."

> "The first security tool that doesn't talk down to you."

> "We complement Defender, never replace it. We even watch Defender for you."

---

## Embargo / availability

No NDA needed. No embargo. Story can run anytime.

If you want hands-on access before publishing:
- Email **press@logsentinel.example**
- Mention publication / channel
- Include any specific scenarios you'd like to test (we'll pre-stage VMs)

We respond within 24 hours.

---

## Contact for media

- General: hello@logsentinel.example
- Press inquiries: press@logsentinel.example
- Founder / interviews: [your name + title]
- Twitter/X: @[handle]
- LinkedIn: [profile URL]
