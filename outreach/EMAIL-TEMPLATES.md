# Cold-email templates for Log Sentinel

Three audiences, three templates. Don't blast — personalize the first line.
60-second test: would *you* reply if you got this?

## Rules of the road

1. **First line must be personal.** Reference something they actually wrote, tweeted, or shipped. If you can't find it, don't send.
2. **One ask per email.** Either "try this for free" or "15 minutes of your time" — never both.
3. **No attachments on first contact.** Link to the landing page or a Loom video.
4. **Subject line under 50 characters.** Lowercase reads more human than Title Case.
5. **Send Tuesday–Thursday, 9–11am their time.** Friday afternoon is the inbox graveyard.
6. **Don't follow up more than twice.** After two ignored, they're not interested.

---

## Template 1 — IR / Forensics consultants

**Audience:** Incident response shops, DFIR consultants, MSSP analysts.
**Why it works:** Their pain is "I show up at a site, the user thinks they have malware, and I have 30 minutes to triage on a machine I've never seen." A portable .exe that produces a triage report in 90 seconds is exactly that toolkit.

### Subject line options
- a triage tool i wrote — would love your eyes on it
- portable IR triage exe — 90s scan with mitre mapping
- found this useful for client visits — wondering if you would

### Body

> Hi {first name},
>
> I saw your post about [SPECIFIC TWEET / BLOG / TALK]. Stuck with me because I had the same problem at a client last month — laptop "felt off" but Defender was clean and I didn't have time to set up a full toolkit on their box.
>
> I ended up writing a single-file triage tool for it: drop on a USB, double-click, get a 90-second scan with MITRE-mapped findings, plain-English remediation, and a PDF you can hand to the client. Reads Event Log, processes, network, services, scheduled tasks, autoruns, USB history, hosts file — all the usual triage corners.
>
> No agent, no cloud, no subscription. Just a portable .exe.
>
> Free for you forever in exchange for 15 minutes of feedback. Would the trade work?
>
> {Your name}
>
> [link to landing page]

### Variations
- If they wrote about Sysmon → mention you bundle a curated config
- If they wrote about ransomware → lead with the honeypot tripwire feature
- If they wrote about offline triage → lead with the portable .exe

---

## Template 2 — Small business owners with no IT team

**Audience:** Owners of 5–30-person businesses, solo professionals, freelancers, accountants.
**Why it works:** They've been burned by either ignoring security entirely or paying $200/mo for a tool they never look at. They want a clear answer: am I OK?

### Subject line options
- is your computer actually safe?
- the security check IT consultants charge $300 for
- found in 90 seconds: 7 things slowing your laptop

### Body

> Hi {first name},
>
> Quick question — when was the last time anyone checked whether your computer is doing anything weird in the background?
>
> Most antivirus catches obvious malware. But things like a hidden program running scheduled jobs at 3am, a website your browser keeps connecting to, or a fake "system" file in a Temp folder — those slip through.
>
> I built a tool that runs a 90-second check and tells you in plain English what's wrong (if anything) and exactly how to fix it. No subscription, no monthly fees, no IT team needed. Free to try.
>
> Most people I show it to find at least 3 things they didn't know about.
>
> Worth 90 seconds of your time?
>
> {Your name}
>
> [landing page]

### Variations
- For accountants/lawyers → emphasize "client data" angle
- For solo entrepreneurs → emphasize "your computer is your livelihood"
- For e-commerce shops → emphasize ransomware tripwire

---

## Template 3 — Prosumers / privacy-conscious individuals

**Audience:** Reddit r/privacy, r/cybersecurity, r/sysadmin lurkers; HN crowd; gamers worried about cheats; crypto holders worried about wallet theft.
**Why it works:** They already think about this stuff but are using fragmented tools (Sysinternals, Wireshark, Process Hacker). One unified GUI is what they want.

### Subject line options
- log sentinel — the tool i wish existed for my own pc
- portable pc auditor i built (no telemetry, no cloud)
- show hn-style: what's actually running on your windows pc?

### Body

> Hi {first name},
>
> Saw your comment on [SUB / THREAD]. We're chasing the same thing.
>
> I built a single-file Windows tool that pulls together what I usually need 5 different programs for: live process + network monitor (à la Process Hacker), event-log analyzer, autoruns scanner, hosts-file editor, firewall manager, file integrity monitor, and a MITRE-mapped detection engine — all in one GUI, all offline.
>
> No telemetry, no account, source is on GitHub if you want to verify. Free for personal use forever.
>
> If you've got 5 minutes, I'd love to know what's missing or what you'd change. The project is small enough that I can actually act on feedback.
>
> {Your name}
>
> [landing page]
> [github]

### Variations
- For crypto holders → lead with honeypot files for `wallet_backup.txt`
- For gamers → lead with "see what your anti-cheat is actually doing"
- For privacy folks → lead with "verify nothing leaves your PC"

---

## Follow-up #1 (5–7 days later, if no reply)

Keep it under 5 lines.

> Hi {first name},
>
> Quick bump on this. Totally fine if "no thanks" — I'd just love a one-line "not for me" so I can stop bothering you. (Promise this is my last email.)
>
> {Your name}

This is the most-replied-to email in the sequence. People hate guilt; they reply just to release you.

---

## What NOT to do

- ❌ Don't say "revolutionary" or "AI-powered" or "next-gen"
- ❌ Don't paste your full feature list
- ❌ Don't link to a 10-minute video
- ❌ Don't BCC 50 people
- ❌ Don't follow up more than twice
- ❌ Don't pretend you read their post when you didn't
- ❌ Don't include screenshots in the email body — they trip spam filters

---

## How to find these people

| Audience | Where they hang out |
|---|---|
| IR consultants | LinkedIn (search "incident response" + city), Twitter/X #DFIR, SANS forum, r/DFIR |
| SMB owners | LinkedIn (filter: company size 5–30), local chamber of commerce listings, Yelp small-biz directories, Google Maps reviews of local IT shops (their clients) |
| Prosumers | r/sysadmin, r/cybersecurity, r/selfhosted, HN (Show HN), Twitter/X #BlueTeam |
| MSPs | r/MSP, MSPGeek forum, Reddit r/sysadmin, ConnectWise/Datto user groups |

## Cadence guidance

- **Week 1:** Send 5/day, max. You're learning what works.
- **Week 2:** If reply rate > 5%, scale to 15/day.
- **Week 3+:** If you're getting demos booked, stop sending cold and start nurturing.

If reply rate is 0% after 50 emails, the message is wrong — not the audience. Re-write the subject line and first line. Don't add more volume.

## Track this

Spreadsheet columns:
- Date sent
- Recipient name + email + role
- Personalization hook used
- Subject line
- Replied? (yes / no / "no thanks" / booked demo)
- Source (LinkedIn / Twitter / Reddit / referral)

After 100 sends, you'll know:
- Best subject line (highest open rate)
- Best persona (highest reply rate)
- Best channel (highest call-booked rate)

Double down on what works. Kill what doesn't.
