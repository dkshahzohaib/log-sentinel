# Log Sentinel — User Guide

A walkthrough for normal humans. No jargon. No prerequisites.

---

## What is this thing?

Log Sentinel is a Windows app that checks your computer for problems and tells you about them in plain English. It's like a yearly physical, but for your PC, that you can run any time you want.

When you open it, you'll see a big number (your **Health Score**) and a list of things that need attention. That's it. That's the whole product.

---

## Installing

Two ways:

### Easiest: download the .exe
1. Get `LogSentinel.exe` from [the website].
2. Save it anywhere — your Desktop, Downloads, a USB stick, doesn't matter.
3. Double-click to run.

### For full power: run as administrator
Some checks (like seeing your Windows security log, or blocking things in your firewall) need administrator access. To unlock them:
1. **Right-click** `LogSentinel.exe`
2. Pick **"Run as administrator"**
3. Click **Yes** on the Windows popup

You can run without admin and most things still work. The app will tell you which features need admin.

---

## The first time you open it

The window opens maximized. You'll see a row of tabs across the top — start with **Health Check** (it should already be selected).

Wait about 30 seconds. The bottom-left status bar will say "Collecting…" while it gathers info. When it says "✓ Collected …", the scan is done.

You'll see:

```
   ╭────────╮     YOUR PC HEALTH
   │   87   │     A few minor things to look at.
   │ Grade B│     ↑ 5 pts vs last scan  ·  3 new  ·  7 resolved
   ╰────────╯
```

The **score** is 0–100. The **grade** is A through F. The **delta line** tells you whether things got better or worse since last time.

---

## Understanding your score

| Score | Grade | What it means |
|---|---|---|
| 95–100 | A | Your computer looks healthy. |
| 80–94 | B | A few minor things to look at. |
| 60–79 | C | Some real concerns — please review. |
| 30–59 | D | Multiple problems. Take action soon. |
| 0–29 | F | ⚠ Serious threats detected. Act now. |

Don't panic if it's lower than you expected. Some things are surprisingly easy to fix, and our scoring is strict — Windows alone (with its built-in stuff) often scores in the C range.

---

## The Recommended Actions cards

Below the score, you'll see a list of cards. Each one is one thing the app found.

```
┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃
┃ [HIGH]  [Privacy]  T1219                                  ┃
┃ A remote-control program is running on your PC.            ┃
┃                                                            ┃
┃ WHY IT MATTERS              WHAT TO DO                     ┃
┃ TeamViewer/AnyDesk let       1. Did you install this?      ┃
┃ someone else control your    2. If no — uninstall it...    ┃
┃ computer. Common scam ...    3. Change your passwords...   ┃
┃                                                            ┃
┃ [Open Task Manager]  [Defender Quick Scan]   ✓ Mark fixed  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

Each card has:

- **Severity badge:** Critical / High / Medium / Low. Critical = drop everything. Low = only if you have time.
- **Category:** Security / Privacy / Performance / Stability.
- **MITRE ID:** A code like T1219 — click it to see what it means on the official site.
- **Headline:** One sentence about what's wrong.
- **Why it matters:** Why you should care.
- **What to do:** Step-by-step instructions.
- **Buttons:** One-click "Fix it" actions, plus snooze / mark fixed / ignore.

### What to click

- **Fix-it buttons** (left side): These do something. "Open Task Manager" opens Task Manager focused on the right thing. "Run Defender Quick Scan" kicks off Windows' built-in scan.
- **✓ Mark fixed:** Tell the app you handled this. It won't show up again unless it comes back.
- **💤 Snooze 7d:** Hide for 7 days. Useful for things you'll get to later.
- **✕ Ignore:** Never show this again. Use carefully.
- **ⓘ Details:** See the full event data behind the finding.

---

## The toolbar buttons (top of window)

| Button | What it does |
|---|---|
| 🔄 **Scan Now** | Run a fresh scan. Takes 30–60 seconds. |
| ▶ **Live Mode** | Start real-time monitoring. New processes and connections appear instantly. |
| ✨ **Quick Win** | Auto-fix everything safe to auto-fix. Asks you to confirm first. |
| 🚨 **PANIC** | The big red button. Cuts ALL network in one click. Only press in an emergency. |
| 🔐 **Password Check** | Type a password, see how strong it is. Offline. |
| 📄 **Export Report** | Save a polished HTML report you can share or save as PDF. |
| ⚙ **Settings** | Configure scheduled scans, email alerts, themes, custom rules, etc. |

---

## The 14 tabs

You don't have to use all of them. Most people live in the first 2–3.

| Tab | When you'd use it |
|---|---|
| 🏥 **Health Check** | Your home base. Score + recommended actions. |
| 📈 **Trends** | "How is my PC doing over time?" |
| ⏱ **Timeline** | "When did things start going wrong?" |
| **Dashboard** | Power-user overview with severity counts and category breakdowns. |
| ⚡ **Live Feed** | Real-time stream of new processes/connections (Live Mode must be ON). |
| **Findings** | Power-user list of every detection with filters. |
| **Events** | Raw Windows Event Log. For nerds. |
| 🌐 **Network** | Every connection right now. With country flags. |
| **Processes** | Every running program. Switch to "Tree" view to see what spawned what. |
| **Services** | Every Windows service. |
| **Persistence** | Things that auto-start when you boot — autoruns, scheduled tasks, USB history. |
| 📊 **Live Monitor** | Live CPU/RAM/Disk/Battery/Wi-Fi/AV gauges. |
| 🔥 **Firewall** | Block IPs, ports, and websites. Has 3 sub-tabs. |
| **System** | Installed software, DNS cache, recent files. |

---

## Common things people want to do

### "I just want to know if my PC is safe."
Open the app. Wait for the scan. Look at the score. If it's green (A or B), you're fine. If yellow or red, scroll the cards and follow the "What to do" steps.

### "How do I block Facebook?"
1. Click the **🔥 Firewall** tab → **Websites** sub-tab.
2. Click the **Facebook** preset button.
3. Click the big red **🚫 BLOCK THIS WEBSITE** button.
4. Confirm.

Done. Reverse it from the **Active Rules** sub-tab any time.

### "How do I block a specific IP address?"
1. **🔥 Firewall** tab → **IPs & Ports** sub-tab.
2. Type the IP in the form.
3. Pick direction (Outgoing is most common — stops your PC from talking to the IP).
4. Click **🚫 BLOCK THIS IP**.

### "I think I have ransomware. What do I do RIGHT NOW?"
1. Click the red **🚨 PANIC** button in the toolbar.
2. Click **Isolate now**.

That kills your network instantly. The malware can't spread or talk to its server. Now run a full antivirus scan and call for help. When it's clean, click the panic button again to restore your network.

### "I want to set ransomware traps."
1. ⚙ **Settings** → **Honeypot Files** → **Deploy / manage honeypots**.
2. Pick a folder (Documents is a good one).
3. Pick a template (passwords.txt or wallet_backup.txt are the most attractive to attackers).
4. Click **🪤 Deploy tripwire**.

Now if anything reads, modifies, or deletes that file, you'll get a Critical alert next scan.

### "I want to be told by email when something Critical happens."
1. ⚙ **Settings** → scroll to **Email Alerts** → **Configure email alerts**.
2. Pick a preset (Gmail, Outlook, etc.) or fill in your own SMTP details.
3. Use an **app password**, not your main password (Google/Microsoft require this).
4. Add your email to the "TO" field.
5. Tick **Enable email alerts**.
6. Click **✉ Send test email** to verify.

You'll get an email after every scan that finds Critical or High issues.

### "I want this to scan automatically every day."
1. ⚙ **Settings** → **Scheduled Scans** section.
2. Pick how often (24 hours = once a day is sensible).
3. Click **✓ Enable**.

It registers a Windows scheduled task. Disable any time from the same place.

### "How do I make a custom detection rule?"
1. ⚙ **Settings** → **Custom Detection Rules** → **Open rules editor**.
2. Click **➕ Add rule**.
3. Edit the JSON in the right-hand panel.
4. Click **💾 Save changes**.

The rule fires from your next scan onward. See the JSON of any existing rule for the full schema.

---

## Things people get worried about (you don't have to)

- **"It found 30 things — am I in danger?"** Probably not. Most are Low/Info severity. Look at Critical and High first. The rest can wait.
- **"It says my Health is D — is my PC infected?"** Not necessarily. A D often comes from things like "you have 15 startup programs" or "lots of external connections." Read the cards.
- **"The scan is slow."** First scan takes 30–60 seconds. Mostly that's reading the Windows Event Log. Subsequent scans are faster.
- **"It opened a Command Prompt with sfc /scannow!"** That's normal — you clicked a Fix button that runs Windows' built-in repair tool. Let it finish.

---

## Things that legitimately need attention

If you see ANY of these, treat them seriously:

- **Critical** — Audit log cleared
- **Critical** — Process impersonation (svchost.exe outside System32)
- **Critical** — Known attacker tool detected (mimikatz, etc.)
- **Critical** — Honeypot file modified or deleted
- **High** — Brute-force login attempts
- **High** — User added to Administrators group (if you didn't do it)
- **High** — Privilege escalation events

Each one's card tells you exactly what to do. Don't skip them.

---

## Where stuff is stored

All your settings, scan history, custom rules, snoozed findings live in:

```
C:\Users\<your-username>\.log_sentinel\
```

You can copy that folder to back up everything. Delete it to start fresh. Log Sentinel itself is just one .exe — there's no installer, no registry entries, nothing else.

---

## Getting help

- **Built-in:** Most things have tooltips. Hover over labels.
- **Re-run welcome tour:** ⚙ Settings → "Re-run welcome tour"
- **Email:** hello@logsentinel.example

---

## A short philosophy

We built this because most security tools either drown you in jargon or hide everything behind a "your PC is fine" sticker. Both are bad. The first scares you, the second lies.

Log Sentinel tries to be the third option: show you what's happening, in words you can understand, and give you a one-click way to fix it.

If you click around, get confused, or think something is wrong — it's our fault, not yours. Email us and we'll fix it.

— The Log Sentinel team
