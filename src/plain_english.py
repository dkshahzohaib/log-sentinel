"""
Maps every detection rule to plain-English text a non-technical user can act on.

Each rule gets:
  problem      — what happened (in plain words)
  why_matters  — why someone should care
  what_to_do   — concrete next step
  risk_level   — Critical / High / Medium / Low / Info (UI colour)
  category     — Security / Privacy / Performance / Stability (user-facing)
"""

from dataclasses import dataclass


@dataclass
class PlainEnglish:
    problem: str
    why_matters: str
    what_to_do: str
    user_category: str = "Security"      # Security / Privacy / Performance / Stability


# ──────────────────────────────────────────────
# Rule → friendly explanation
# ──────────────────────────────────────────────

EXPLANATIONS: dict[str, PlainEnglish] = {

    "brute_force_login": PlainEnglish(
        problem="Someone is trying lots of wrong passwords on your account.",
        why_matters=(
            "This is how attackers break into accounts — they guess passwords "
            "again and again until one works. If your password is short or "
            "common, they will eventually get in."
        ),
        what_to_do=(
            "1. Change your Windows password right now to something long "
            "(12+ characters, mix letters/numbers/symbols).\n"
            "2. Turn on Windows account lockout (lockout after 5 wrong tries).\n"
            "3. If this is a remote attempt (the IP shown is not yours), "
            "disconnect from the internet, then re-connect after fixing the password."
        ),
        user_category="Security",
    ),

    "brute_force_from_ip": PlainEnglish(
        problem="An IP address is hammering your machine with login attempts.",
        why_matters=(
            "An external IP trying many passwords usually means an automated "
            "scanner is targeting you. They WILL break in if your password is weak."
        ),
        what_to_do=(
            "1. Open Windows Defender Firewall and block this IP address.\n"
            "2. If your machine is exposed to the internet (RDP, SSH), turn "
            "those services OFF unless you really need them.\n"
            "3. Change your password to something strong."
        ),
        user_category="Security",
    ),

    "audit_log_cleared": PlainEnglish(
        problem="Your security log was just wiped clean.",
        why_matters=(
            "Windows keeps a record of every important security event — who "
            "logged in, what changed. Wiping it is what attackers do to hide "
            "their tracks. If you didn't do this on purpose, something is wrong."
        ),
        what_to_do=(
            "1. Disconnect from the internet immediately (unplug Wi-Fi/Ethernet).\n"
            "2. Run a full Windows Defender scan: Start → Windows Security → "
            "Virus & threat protection → Scan options → Full scan.\n"
            "3. Change ALL your important passwords from a different device.\n"
            "4. Consider a fresh Windows install if you handle sensitive data."
        ),
        user_category="Security",
    ),

    "privilege_escalation": PlainEnglish(
        problem="A program just gained powerful admin-level access.",
        why_matters=(
            "Programs with these privileges can read passwords from memory, "
            "install drivers, and control the whole system. Normal apps don't "
            "need them — usually only Windows itself does."
        ),
        what_to_do=(
            "1. Look at WHICH user got the privileges (shown in details). "
            "If it's not you or 'SYSTEM', that's bad.\n"
            "2. Run a full antivirus scan.\n"
            "3. If you didn't just install something, treat this as a possible compromise."
        ),
        user_category="Security",
    ),

    "new_user_created": PlainEnglish(
        problem="A new user account was just created on your computer.",
        why_matters=(
            "Attackers often create a hidden 'backdoor' account so they can get "
            "back in even after you change your main password."
        ),
        what_to_do=(
            "1. Open Settings → Accounts → Family & other users.\n"
            "2. If you don't recognise this account, delete it.\n"
            "3. Check what's in Computer Management → Local Users and Groups → Users.\n"
            "4. Change your main password."
        ),
        user_category="Security",
    ),

    "user_added_to_admin_group": PlainEnglish(
        problem="A user account was just given admin rights.",
        why_matters=(
            "Admin = full control. If a regular account suddenly becomes admin, "
            "either someone is escalating their access (bad) or you did this on "
            "purpose (fine). Verify which one."
        ),
        what_to_do=(
            "1. Did you add an admin yourself? If yes, ignore.\n"
            "2. If no — open Computer Management → Local Users and Groups → Groups → Administrators "
            "and remove the unknown member."
        ),
        user_category="Security",
    ),

    "new_service_installed": PlainEnglish(
        problem="A new background service was installed on your computer.",
        why_matters=(
            "Services run silently in the background — even when you're not "
            "logged in. Malware uses them to stay alive forever. Real software "
            "installs services too, so check the source."
        ),
        what_to_do=(
            "1. Look at the service path (shown in details). If it's in a Temp, "
            "Downloads, or AppData folder — that's almost certainly malware.\n"
            "2. Open services.msc, find the service, and stop it.\n"
            "3. Right-click → Properties → Disable.\n"
            "4. Run a full antivirus scan."
        ),
        user_category="Security",
    ),

    "suspicious_process": PlainEnglish(
        problem="A program is running with suspicious commands.",
        why_matters=(
            "Some Windows tools (PowerShell, certutil, mshta) are normal but "
            "are also abused by attackers because they can download and run "
            "code without leaving files on disk."
        ),
        what_to_do=(
            "1. Look at the command line shown — does it make sense to you?\n"
            "2. If you didn't start it, end the process via Task Manager.\n"
            "3. Run a full antivirus scan."
        ),
        user_category="Security",
    ),

    "suspicious_process_critical": PlainEnglish(
        problem="A known hacker tool is running on your computer.",
        why_matters=(
            "This program (mimikatz, procdump, etc.) is famous for stealing "
            "passwords from Windows memory. It has no legitimate reason to be "
            "running on a normal user's PC."
        ),
        what_to_do=(
            "1. UNPLUG your network cable / turn off Wi-Fi NOW.\n"
            "2. End the process via Task Manager.\n"
            "3. Change your Windows password from a different device.\n"
            "4. Change your email/banking passwords from a different device.\n"
            "5. Run a full antivirus scan; consider reinstalling Windows."
        ),
        user_category="Security",
    ),

    "powershell_encoded": PlainEnglish(
        problem="A program ran hidden, scrambled commands in PowerShell.",
        why_matters=(
            "PowerShell is a powerful Windows command tool. Attackers scramble "
            "their commands so antivirus can't read them. Legitimate software "
            "rarely does this."
        ),
        what_to_do=(
            "1. Run a full antivirus scan immediately.\n"
            "2. Check the Persistence tab for new autoruns or scheduled tasks.\n"
            "3. If you can identify the program that ran this, uninstall it."
        ),
        user_category="Security",
    ),

    "scheduled_task_created": PlainEnglish(
        problem="A new scheduled task was created.",
        why_matters=(
            "Scheduled tasks run automatically on a timer. Malware uses them to "
            "wake itself up periodically. Legitimate apps create them too "
            "(Windows Update, Chrome) so check the name."
        ),
        what_to_do=(
            "1. Open Task Scheduler (search Start menu).\n"
            "2. Find the task by name.\n"
            "3. If you don't recognise it, right-click → Disable, then Delete.\n"
            "4. If you're unsure, search the task name on Google first."
        ),
        user_category="Security",
    ),

    "account_locked_out": PlainEnglish(
        problem="An account got locked after too many wrong passwords.",
        why_matters=(
            "If it's YOUR account and you weren't typing — someone else was. "
            "If it's another account, someone is trying to break in."
        ),
        what_to_do=(
            "1. If it locked YOU out — reset your password (use a strong one).\n"
            "2. Check if anyone else uses this PC.\n"
            "3. If unexplained, treat as a brute-force attempt."
        ),
        user_category="Security",
    ),

    "firewall_rule_changed": PlainEnglish(
        problem="A Windows Firewall rule was just changed.",
        why_matters=(
            "The firewall blocks unwanted network traffic. Attackers add rules "
            "to let their tools out (or to let attackers in). If you didn't "
            "change a firewall setting, this is suspicious."
        ),
        what_to_do=(
            "1. Open Windows Defender Firewall → Advanced settings.\n"
            "2. Look at Inbound Rules and Outbound Rules.\n"
            "3. Disable any rule you don't recognise.\n"
            "4. Run an antivirus scan."
        ),
        user_category="Security",
    ),

    "off_hours_logon": PlainEnglish(
        problem="Someone logged into your account at an unusual hour.",
        why_matters=(
            "If you're asleep at 3am and your account logged in, someone else "
            "did. This is one of the strongest signs of a remote intruder."
        ),
        what_to_do=(
            "1. Was it you? (Late-night work, different timezone trip?) If yes, ignore.\n"
            "2. If not — change your password from another device.\n"
            "3. Turn off Remote Desktop if you don't use it.\n"
            "4. Check the Network tab for connections from unfamiliar IPs."
        ),
        user_category="Security",
    ),

    "system_crash": PlainEnglish(
        problem="Your computer shut down unexpectedly.",
        why_matters=(
            "Could be hardware (overheating, dying disk, bad RAM), software bug, "
            "or someone forced a power-off. Repeated crashes need attention."
        ),
        what_to_do=(
            "1. Check Reliability Monitor (search 'Reliability' in Start) for the cause.\n"
            "2. If it happens often: run 'sfc /scannow' from admin Command Prompt.\n"
            "3. Check temperature with HWMonitor (free)."
        ),
        user_category="Stability",
    ),

    "suspicious_listening_port": PlainEnglish(
        problem="A program is listening on a port commonly used by malware.",
        why_matters=(
            "Ports like 4444, 1337, 31337 are famous default ports for hacking "
            "tools (Metasploit, etc.). A normal app won't use these."
        ),
        what_to_do=(
            "1. Identify the program in the details (shown next to the port).\n"
            "2. End that process in Task Manager.\n"
            "3. Run a full antivirus scan.\n"
            "4. Check the Persistence tab to see if it set itself to auto-start."
        ),
        user_category="Security",
    ),

    "uncommon_listening_port": PlainEnglish(
        problem="A program is listening on an unusual network port.",
        why_matters=(
            "Most programs listen on standard ports (80, 443, etc.). Unusual "
            "ports MIGHT be a custom server you set up, or MIGHT be malware "
            "waiting for someone to connect to it."
        ),
        what_to_do=(
            "1. Check what program owns the port.\n"
            "2. If you don't recognise the program — investigate or uninstall.\n"
            "3. If it's Steam, Discord, Zoom, etc. — fine, you can ignore."
        ),
        user_category="Security",
    ),

    "external_connection": PlainEnglish(
        problem="Lots of programs are talking to external servers right now.",
        why_matters=(
            "Some is normal (browser, email, Windows Update). But unusual "
            "amounts can mean spyware, miners, or data-theft tools."
        ),
        what_to_do=(
            "1. Open the Network tab and look at the destination IPs.\n"
            "2. For any IP you don't recognise, look it up on virustotal.com or abuseipdb.com.\n"
            "3. End the owning processes if any look bad."
        ),
        user_category="Privacy",
    ),

    "suspicious_autorun": PlainEnglish(
        problem="A program is set to start automatically when you turn on your PC.",
        why_matters=(
            "Many programs add themselves to startup (Spotify, Skype). But "
            "malware does the same to come back every time you reboot. The "
            "command shown looks unusual."
        ),
        what_to_do=(
            "1. Open Task Manager → Startup tab.\n"
            "2. Find the program by name.\n"
            "3. Right-click → Disable.\n"
            "4. If you don't recognise it at all, uninstall it from Settings → Apps."
        ),
        user_category="Security",
    ),

    "process_in_temp": PlainEnglish(
        problem="A program is running from a temporary folder.",
        why_matters=(
            "Real software installs to Program Files. Programs running from "
            "Temp, AppData, or Downloads are the #1 sign of malware that "
            "got dropped via email or a sketchy download."
        ),
        what_to_do=(
            "1. End the process in Task Manager.\n"
            "2. Note its full path.\n"
            "3. Delete the file at that path.\n"
            "4. Run a full antivirus scan to find more pieces."
        ),
        user_category="Security",
    ),

    "process_name_spoof": PlainEnglish(
        problem="A program is pretending to be a Windows system file.",
        why_matters=(
            "Real Windows files like svchost.exe and lsass.exe ONLY live in "
            "C:\\Windows\\System32. A copy with the same name elsewhere is "
            "malware impersonating Windows to look harmless."
        ),
        what_to_do=(
            "1. THIS IS SERIOUS. Disconnect from the internet now.\n"
            "2. End the process in Task Manager.\n"
            "3. Note the file path, then delete that file.\n"
            "4. Run a full antivirus scan.\n"
            "5. Consider reinstalling Windows if this PC handles sensitive data."
        ),
        user_category="Security",
    ),

    "remote_access_tool": PlainEnglish(
        problem="A remote-control program is running on your PC.",
        why_matters=(
            "TeamViewer, AnyDesk, etc. let someone else control your computer. "
            "Useful when YOU install them on purpose. Common scam: someone "
            "phones pretending to be Microsoft and tricks you into installing one."
        ),
        what_to_do=(
            "1. Did YOU install this for IT support? If yes, ignore.\n"
            "2. If you don't remember installing it: uninstall via Settings → Apps.\n"
            "3. Change your passwords (the person on the other end may have seen them)."
        ),
        user_category="Privacy",
    ),

    "ioc_match_process": PlainEnglish(
        problem="A program known to be used by hackers is running.",
        why_matters=(
            "This program's name matches our list of known attacker tools "
            "(credential dumpers, lateral-movement tools, post-exploit frameworks). "
            "These have no legitimate use on a normal PC."
        ),
        what_to_do=(
            "1. UNPLUG from the internet.\n"
            "2. End the process.\n"
            "3. Change all your important passwords from a different device.\n"
            "4. Full antivirus scan, then consider reinstalling Windows."
        ),
        user_category="Security",
    ),

    "ioc_match_ip": PlainEnglish(
        problem="Your computer is connected to a known-bad IP address.",
        why_matters=(
            "The remote IP is on our threat-intel list (TOR exit, bulletproof "
            "host, etc.). Either you're using TOR/VPN intentionally, or "
            "something is calling home."
        ),
        what_to_do=(
            "1. Find the program making the connection (Network tab).\n"
            "2. End it.\n"
            "3. Block that IP in Windows Firewall.\n"
            "4. Run a full scan."
        ),
        user_category="Security",
    ),

    # ──────────────────────────────────────────
    # New "everyday user" rules (defined in everyday_scanner.py)
    # ──────────────────────────────────────────

    "slow_startup_program": PlainEnglish(
        problem="A program slows down your computer's boot.",
        why_matters=(
            "It runs every time Windows starts and stays in memory. Too many of "
            "these = slow boot, less RAM for what you actually want to use."
        ),
        what_to_do=(
            "Open Task Manager (Ctrl+Shift+Esc) → Startup tab → Disable any "
            "startup item you don't need. (Disabling doesn't uninstall — you "
            "can re-enable later.)"
        ),
        user_category="Performance",
    ),

    "high_memory_process": PlainEnglish(
        problem="A program is using a lot of RAM right now.",
        why_matters=(
            "If this isn't your browser or video editor, something is hogging "
            "memory and slowing your machine down."
        ),
        what_to_do=(
            "Decide if you need it open. If not, close it. If you don't "
            "recognise the program at all, end it from Task Manager and "
            "investigate where it came from."
        ),
        user_category="Performance",
    ),

    "webcam_or_mic_access": PlainEnglish(
        problem="A program may be using your webcam or microphone.",
        why_matters=(
            "Spyware (and shady apps) can record you without notice. Windows "
            "shows the small camera/mic icon in the system tray when something "
            "is using them — but that's easy to miss."
        ),
        what_to_do=(
            "Open Settings → Privacy & security → Camera (and Microphone). "
            "Review the list. Switch off access for any app that shouldn't have it."
        ),
        user_category="Privacy",
    ),

    "recently_modified_critical": PlainEnglish(
        problem="Important system files were modified recently.",
        why_matters=(
            "If you didn't update Windows or install software, something else "
            "is changing system files. Could be malware persisting, or an "
            "update gone wrong."
        ),
        what_to_do=(
            "1. Run 'sfc /scannow' from an admin Command Prompt.\n"
            "2. If issues: run 'DISM /Online /Cleanup-Image /RestoreHealth'.\n"
            "3. Run a full antivirus scan."
        ),
        user_category="Stability",
    ),

    "browser_extension_suspicious": PlainEnglish(
        problem="A browser extension you have looks suspicious.",
        why_matters=(
            "Browser extensions can read everything you do online: passwords, "
            "banking, emails. Many free ones are sold to ad/data companies."
        ),
        what_to_do=(
            "Open your browser → Extensions → review the list. Remove anything "
            "you don't actively use, or anything you don't remember installing."
        ),
        user_category="Privacy",
    ),
}


_DEFAULT = PlainEnglish(
    problem="Something unusual was detected.",
    why_matters="Investigate the details to understand what it means.",
    what_to_do="Look at the details panel for more information.",
    user_category="Security",
)


def explain(rule: str) -> PlainEnglish:
    return EXPLANATIONS.get(rule, _DEFAULT)


# ──────────────────────────────────────────────
# User-facing categories
# ──────────────────────────────────────────────

USER_CATEGORIES = ["Security", "Privacy", "Performance", "Stability"]

USER_CATEGORY_COLORS = {
    "Security":    "#ff4757",
    "Privacy":     "#a855f7",
    "Performance": "#3aa89f",
    "Stability":   "#ffd93d",
}

USER_CATEGORY_ICONS = {
    "Security":    "🛡",
    "Privacy":     "👁",
    "Performance": "⚡",
    "Stability":   "🔧",
}
