# 90-second demo video script

A demo video sells more than any feature list. This is the script + shot list for a tight 90-second walkthrough.

## Goals

1. **First 5 seconds:** Show the score. Hook the viewer.
2. **First 30 seconds:** Convince them this is for them.
3. **30–80 seconds:** Show 3 features that nothing else does.
4. **Last 10 seconds:** Tell them what to do next.

## Tools

- **Screen recorder:** OBS Studio (free) or Loom (free tier is fine for ≤2 min videos)
- **Editor:** OpenShot or DaVinci Resolve (free)
- **Voice:** Record on your phone in a closet with a hoodie over your head — that's what podcasts do. You don't need a mic.
- **Cursor highlighter:** Use a free tool like ZoomIt for click-emphasis
- **Music:** Skip it. Music makes demos feel like ads. Voice + clicks is enough.

## Set up before recording

- Boot a clean Windows VM (no ad notifications)
- Set screen resolution to 1920×1080
- Hide your taskbar (auto-hide), close every other window
- Run Log Sentinel as admin so you don't need to alt-tab to a UAC prompt
- Pre-arrange:
  - Have a "weird" command ready: `curl https://example.com` in a terminal
  - Have notepad already running so the live feed has something to show
  - Have a fake "passwords.txt" honeypot pre-deployed in Documents

---

# THE SCRIPT

(timing in [brackets])

---

### [0:00–0:05] Hook

**Visual:** Black screen → fade in to the Log Sentinel Health Check tab with a big red 56 on the gauge.

**Voiceover (calm, conversational):**

> "This is what's actually running on your computer right now."

*(2-second pause while the viewer absorbs the dashboard)*

---

### [0:05–0:20] The problem in one sentence

**Visual:** Slowly zoom in on the gauge → cut to the recommended-actions cards scrolling.

**VO:**

> "Antivirus tells you you're fine. Task Manager hides the interesting stuff. Most people have no way to know if their PC is doing anything weird — until something obvious goes wrong, and by then it's too late."

---

### [0:20–0:35] What it does, in one breath

**Visual:** Quickly tab through Health Check → Live Feed → Network → Firewall → System monitor.

**VO:**

> "Log Sentinel is one Windows app that pulls together everything you'd need a SOC team for: live process and network monitoring, plain-English findings mapped to MITRE ATT&CK, threat intelligence, ransomware tripwires, and one-click blocking for any IP, port, or website."

---

### [0:35–0:50] First wow moment — Live Mode

**Visual:** Click ▶ Live Mode in the toolbar. Cut to a second window showing a terminal. Type `curl https://example.com` and hit enter.

Cut back to Live Feed tab — the connection appears instantly.

**VO:**

> "Click Live Mode and the app catches every new process and connection in real time. Watch — I run curl in another window..."
>
> *(brief pause, let the viewer see the new entry pop in with a toast)*
>
> "...and we caught it. Time, IP, owning process, MITRE technique, all without me touching the mouse."

---

### [0:50–1:05] Second wow moment — The Panic Button

**Visual:** Click the red 🚨 PANIC button in the toolbar. The panic dialog opens, listing adapters. Click "Isolate now".

**VO:**

> "When something serious happens, the Panic button cuts every network adapter in one click. This is the difference between losing one file and losing everything when ransomware starts spreading."

*(The dialog confirms 'isolated'. Reverse it before continuing.)*

> "And it's reversible — one click puts you back online."

*(Click Restore Network.)*

---

### [1:05–1:20] Third wow moment — Block any website

**Visual:** Switch to Firewall tab → Websites sub-tab. Click the Facebook preset → click 🚫 BLOCK THIS WEBSITE.

**VO:**

> "Need to block a website system-wide? Two clicks. Goes into the hosts file, works in every browser. Same for IPs, ports, anything. All reversible from the Active Rules tab."

---

### [1:20–1:30] Close

**Visual:** Cut back to the Health Check tab. Show the Quick Win button. Click it. Confirmation popup.

**VO:**

> "When you're ready, click Quick Win and we'll auto-fix everything safe to fix. The rest, we'll walk you through in plain English."
>
> *(2-second pause on the Quick Win confirmation message)*
>
> "Single .exe. No installer. No subscription. No telemetry. Download below."

**End card:** Logo + URL + "Download free for Windows" + duration: 3 seconds.

---

# Shot list

| Time | Shot | Action |
|---|---|---|
| 0:00 | Health tab, score 56 | Static, 2 sec |
| 0:05 | Slow zoom on gauge | 5 sec |
| 0:10 | Scroll down through action cards | 5 sec |
| 0:20 | Tab cycle: Live Feed → Network → Firewall → System monitor | 4 quick cuts, 3 sec each |
| 0:35 | Click Live Mode toolbar btn | Single click, 2 sec |
| 0:38 | Cut to terminal, type curl | 5 sec |
| 0:43 | Cut back to Live Feed, new entry visible | 4 sec |
| 0:47 | Toast notification slides in | 3 sec |
| 0:50 | Click red PANIC button | 1 sec |
| 0:52 | Panic dialog opens | 3 sec |
| 0:55 | Click Isolate now → confirmation popup | 4 sec |
| 1:00 | Show "Isolated" status, click restore | 5 sec |
| 1:05 | Switch to Firewall tab → Websites | 2 sec |
| 1:08 | Click Facebook preset | 1 sec |
| 1:10 | Click big red BLOCK | 2 sec |
| 1:13 | Confirmation popup | 3 sec |
| 1:18 | Cut to Active Rules tab showing the new entry | 2 sec |
| 1:20 | Back to Health tab | 2 sec |
| 1:22 | Click Quick Win | 2 sec |
| 1:25 | Confirmation popup | 3 sec |
| 1:30 | End card with URL | 3 sec |

---

# Voice tips

- Don't read the script word-for-word. Print it, glance, paraphrase. Sounds more human.
- Pause after every claim. Silence is fine. Don't fill it.
- Drop your inflection at the end of sentences. Up-talk sounds uncertain.
- Record one full take, listen back, re-record. Three takes max.
- Edit out every "uh", "um", and "so" — they're weight your video doesn't need.

# Common mistakes

- ❌ Don't show the Settings dialog or anything that requires explanation
- ❌ Don't show every tab — pick the 3 strongest
- ❌ Don't include a "thank you for watching" tail card
- ❌ Don't add intro animation longer than 2 seconds
- ❌ Don't use a stock voiceover artist — your voice is more credible

# Where to publish

1. **YouTube unlisted** — host it once, embed in the landing page hero
2. **Loom** — for cold emails (lets you see who watched)
3. **Twitter/X** — clip the strongest 30 seconds (the curl-detection moment)
4. **LinkedIn** — same clip, different copy
5. **Show HN post** — embed and link

# Iteration

After 100 views, check:
- **Drop-off point.** Where do people stop watching? Cut everything before it.
- **Replay point.** Where do people rewind? Make that the first thing in v2.

Best demo videos are revised 3–5 times. The one you ship in week 1 is not the one that converts in week 4.
