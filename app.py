#!/usr/bin/env python3
"""
Log Sentinel — Desktop GUI

A multi-tab Tkinter application that:
  - Collects Windows Event Logs + processes + network + services + tasks
    + autoruns + DNS + USB history + installed software
  - Categorises everything
  - Runs detection rules
  - Shows critical findings, lets you filter/search/export

Run:
    python app.py

For Security event log access, run as Administrator.
"""

from __future__ import annotations

import json
import ctypes
import platform
import subprocess


# ──────────────────────────────────────────────
# Windows HiDPI awareness — must be called BEFORE any Tk window is created.
# Without this, Tkinter renders at 96 DPI and Windows blurry-scales it on
# any 125% / 150% / 200% display, producing the "pixelated" look.
# ──────────────────────────────────────────────
def _enable_hidpi() -> None:
    if platform.system() != "Windows":
        return
    try:
        # PROCESS_PER_MONITOR_DPI_AWARE = 2 (Win 8.1+) — best quality
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except (AttributeError, OSError):
        pass
    try:
        # Fallback for older Windows
        ctypes.windll.user32.SetProcessDPIAware()
    except (AttributeError, OSError):
        pass


_enable_hidpi()
import queue
import socket
import sys
import threading
import tkinter as tk
import webbrowser
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, font, messagebox, ttk

sys.path.insert(0, str(Path(__file__).parent))

from src.collector import LogEvent, collect as collect_events
from src.analyzer import analyze, Finding, SEVERITY_ORDER
from src.categorizer import (
    CATEGORIES, CATEGORY_COLORS,
    category_for_event_id, category_for_rule,
)
from src.reporter import generate_html, generate_json, generate_pdf
from src.system_collector import (
    AutorunEntry, NetConnection, Process, ScheduledTask,
    Service, Software, SystemInfo, UsbDevice, RecentFile, DnsEntry,
    collect_autoruns, collect_dns_cache, collect_installed_software,
    collect_network, collect_processes, collect_recent_files,
    collect_scheduled_tasks, collect_services, collect_system_info,
    collect_usb_history,
)
from src.system_analyzer import analyze_system
from src.live_monitor import LiveMonitor, ActivityEvent
from src.mitre import technique_for_rule, technique_short
from src import threat_intel
from src.plain_english import (
    explain, USER_CATEGORIES, USER_CATEGORY_COLORS, USER_CATEGORY_ICONS,
)
from src.health_score import calculate as calc_health, top_actions
from src.remediation import actions_for_finding
from src.everyday_scanner import scan_everyday
from src import preferences, scan_history, quick_win
from src import firewall_manager
from src.firewall_manager import FirewallRule
from src import hosts_manager
from src import system_monitor as sysmon
from src import licensing
from src import panic
from src import password_check
from src import remediation
from src.version import version_label


# ──────────────────────────────────────────────
# Theme
# ──────────────────────────────────────────────

# ─── Splunk-inspired theme (black + Splunk orange) ────────────
# Splunk's signature look: pure black canvas, dark grey panels,
# vivid orange (#ed7700) for primary actions and accents.
DARK_THEME = {
    "bg":            "#000000",   # pure black canvas
    "bg_panel":      "#141414",   # sidebar / toolbar
    "bg_card":       "#1c1c1c",   # primary cards
    "bg_card_solid": "#222222",   # raised cards / inputs
    "bg_hover":      "#2a2a2a",
    "bg_active":     "#363636",
    "fg":            "#ffffff",
    "fg_dim":        "#b3b3b3",
    "fg_subtle":     "#808080",
    "accent":        "#ed7700",   # Splunk orange
    "accent_alt":    "#f7a609",   # secondary amber
    "border":        "#333333",
    "border_subtle": "#262626",
    "row_alt":       "#181818",
    "selected":      "#3d2a14",   # dark orange-tinted selection
}

# ─── Light theme (off-white) ──────────────────────────────────
LIGHT_THEME = {
    "bg":            "#fafafa",
    "bg_panel":      "#ffffff",
    "bg_card":       "#ffffff",
    "bg_card_solid": "#ffffff",
    "bg_hover":      "#f3f3f3",
    "bg_active":     "#e8e8e8",
    "fg":            "#1a1a1a",
    "fg_dim":        "#5a5a5a",
    "fg_subtle":     "#8a8a8a",
    "accent":        "#ed7700",
    "accent_alt":    "#b35b00",
    "border":        "#d4d4d4",
    "border_subtle": "#ebebeb",
    "row_alt":       "#f7f7f7",
    "selected":      "#ffe6c8",
}

# Theme dict — mutated in place by apply_theme() so existing references work
THEME = dict(DARK_THEME)


def apply_theme(name: str) -> None:
    """Switch the active theme. Mutates THEME in place so existing
    widgets that already captured THEME by reference still work
    (after they're rebuilt or when their bg= is updated)."""
    src = LIGHT_THEME if name == "light" else DARK_THEME
    THEME.clear()
    THEME.update(src)

SEVERITY_FG = {
    "Critical": "#ff4757",
    "High":     "#ff7f50",
    "Medium":   "#ffd93d",
    "Low":      "#6dd5ed",
    "Info":     "#888",
}
SENSITIVITY_LEVELS = ["Info", "Low", "Medium", "High", "Critical"]
SENSITIVITY_LABELS = {
    "Info": "Everything",
    "Low": "Low and above",
    "Medium": "Medium and above",
    "High": "High and Critical",
    "Critical": "Critical only",
}
SENSITIVITY_DESCRIPTIONS = {
    "Info": "Show every detail, including informational records.",
    "Low": "Show small warnings and anything more serious.",
    "Medium": "Hide minor noise. Show Medium, High, and Critical.",
    "High": "Focus on serious security risks only.",
    "Critical": "Emergency view. Show only Critical findings.",
}
EVENT_LABELS = {
    4624: "Successful login",
    4625: "Failed password/login",
    4634: "Account logged off",
    4647: "User initiated logoff",
    4648: "Explicit credential login",
    4672: "Admin privileges assigned",
    4720: "User account created",
    4723: "Password change attempted",
    4724: "Password reset attempted",
    4740: "Account locked out",
    4771: "Kerberos login failed",
    4776: "Credential check failed",
    4800: "Workstation locked",
    4801: "Workstation unlocked",
    1102: "Audit log cleared",
    6005: "Event log service started",
    6006: "Event log service stopped",
    6008: "Unexpected shutdown",
}
EVENT_TYPE_FILTERS = {
    "All": set(),
    "Failed passwords": {4625, 4771, 4776},
    "Successful logins": {4624},
    "Account changes": {4720, 4722, 4723, 4724, 4725, 4726, 4740},
    "Admin / privilege": {4672, 4673, 4674, 4728, 4732},
    "System start/stop": {6005, 6006, 6008, 6009},
    "Audit tampering": {1102, 4719},
}


# ──────────────────────────────────────────────
# Background collection thread
# ──────────────────────────────────────────────

class CollectorThread(threading.Thread):
    """Runs all collectors on a worker thread; pushes results to a queue."""

    def __init__(self, hours_back: int, q: queue.Queue):
        super().__init__(daemon=True)
        self.hours_back = hours_back
        self.q = q

    def _emit(self, kind: str, payload):
        self.q.put((kind, payload))

    def run(self):
        try:
            self._emit("status", "Collecting system info…")
            self._emit("system_info", collect_system_info())

            self._emit("status", "Collecting processes…")
            self._emit("processes", collect_processes())

            self._emit("status", "Collecting network connections…")
            self._emit("network", collect_network())

            self._emit("status", "Collecting services…")
            self._emit("services", collect_services())

            self._emit("status", "Collecting scheduled tasks…")
            self._emit("tasks", collect_scheduled_tasks())

            self._emit("status", "Collecting autoruns…")
            self._emit("autoruns", collect_autoruns())

            self._emit("status", "Collecting DNS cache…")
            self._emit("dns", collect_dns_cache())

            self._emit("status", "Collecting USB history…")
            self._emit("usb", collect_usb_history())

            self._emit("status", "Collecting installed software…")
            self._emit("software", collect_installed_software())

            self._emit("status", "Collecting recent files…")
            self._emit("recent_files", collect_recent_files())

            self._emit("status",
                       f"Collecting Windows Event Logs (last {self.hours_back}h)…")
            events = collect_events(hours_back=self.hours_back)
            self._emit("events", events)

            self._emit("status", "Running detection rules…")
            self._emit("done", None)
        except Exception as e:
            self._emit("error", str(e))


# ──────────────────────────────────────────────
# Main application
# ──────────────────────────────────────────────

class LogSentinelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        # Apply the saved theme BEFORE building any widgets
        try:
            saved_theme = preferences.get().theme
            apply_theme(saved_theme)
        except Exception:
            pass

        # Set Tk's scaling factor based on actual screen DPI so fonts
        # and widgets render at the right physical size.
        try:
            self.tk.call("tk", "scaling",
                         self.winfo_fpixels("1i") / 72.0)
        except tk.TclError:
            pass

        self.title(f"{version_label()} - System & Security Log Analyser")
        self.configure(bg=THEME["bg"])
        self.minsize(1280, 800)

        # Restore window state from preferences (size, position, maximised)
        try:
            saved_geom = preferences.get().window_geometry
            saved_zoomed = preferences.get().window_zoomed
        except Exception:
            saved_geom, saved_zoomed = "", True

        self.geometry(saved_geom if saved_geom else "1500x950")
        if saved_zoomed:
            try:
                self.state("zoomed")
            except tk.TclError:
                pass

        # Save window state on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # State
        self.events: list[LogEvent] = []
        self.findings: list[Finding] = []
        self.processes: list[Process] = []
        self.connections: list[NetConnection] = []
        self.services: list[Service] = []
        self.tasks: list[ScheduledTask] = []
        self.autoruns: list[AutorunEntry] = []
        self.dns_entries: list[DnsEntry] = []
        self.usb_devices: list[UsbDevice] = []
        self.software: list[Software] = []
        self.recent_files: list[RecentFile] = []
        self.system_info: SystemInfo | None = None

        self.q: queue.Queue = queue.Queue()
        self.collector: CollectorThread | None = None

        # Live monitor state
        self.live_q: queue.Queue = queue.Queue()
        self.live_monitor: LiveMonitor | None = None
        self.live_events: list[ActivityEvent] = []
        self.live_event_count = 0

        # Pop-out window state for the actions list
        self._popout_window: tk.Toplevel | None = None
        self._popout_inner: tk.Frame | None = None
        self._popout_filter_lbl: tk.Label | None = None
        self._hero_collapsed: bool = False

        # Demo mode flag
        self._demo_mode: bool = False
        self._license_status = licensing.status()

        self._setup_styles()
        self._build_ui()
        self.after(100, self._poll_queue)

        # Show licensing first if needed, otherwise show the first-run welcome.
        self.after(300, self._startup_gate)

        # Default to the SOC dashboard.
        self.notebook.select(3)

        # Open quickly; heavier Windows log collection starts when the user
        # clicks Scan Now.
        if self._license_status.can_run:
            self.after(250, self._render_dashboard)

    def _startup_gate(self):
        self._license_status = licensing.status()
        if not self._license_status.can_run:
            self.open_license_window(force=True)
            return
        self._maybe_show_welcome()

    def _ensure_licensed(self) -> bool:
        self._license_status = licensing.status()
        if self._license_status.can_run:
            return True
        self.open_license_window(force=True)
        return False

    def open_license_window(self, force: bool = False):
        status = licensing.status()
        win = tk.Toplevel(self)
        win.title("Activate Log Sentinel")
        win.configure(bg=THEME["bg"])
        win.geometry("620x520")
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)

        win.update_idletasks()
        x = (win.winfo_screenwidth() - 620) // 2
        y = (win.winfo_screenheight() - 520) // 2
        win.geometry(f"620x520+{x}+{y}")

        if force:
            win.protocol("WM_DELETE_WINDOW", self.destroy)

        header = tk.Frame(win, bg=THEME["accent"], height=72)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(
            header,
            text="Log Sentinel activation",
            bg=THEME["accent"],
            fg="#000",
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w", padx=24, pady=(14, 0))
        tk.Label(
            header,
            text="30-day trial, then a fresh monthly key is required.",
            bg=THEME["accent"],
            fg="#000",
            font=("Segoe UI", 10),
        ).pack(anchor="w", padx=24)

        body = tk.Frame(win, bg=THEME["bg"], padx=26, pady=22)
        body.pack(fill="both", expand=True)

        status_text = status.message
        if status.mode == "trial":
            status_text += f"\nTrial expires: {status.trial_expires}"
        elif status.mode == "licensed":
            status_text += f"\nPlan: {status.plan}"
        status_text += f"\nMachine ID: {licensing.device_fingerprint()}"
        tk.Label(
            body,
            text=status_text,
            bg=THEME["bg"],
            fg=THEME["fg"],
            font=("Segoe UI", 11, "bold"),
            justify="left",
            anchor="w",
        ).pack(anchor="w", fill="x", pady=(0, 18))

        tk.Label(body, text="Customer email", bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        email_var = tk.StringVar(value=status.licensed_email)
        email_entry = ttk.Entry(body, textvariable=email_var)
        email_entry.pack(fill="x", pady=(4, 14))

        tk.Label(body, text="30-day licence key", bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        key_var = tk.StringVar()
        key_entry = ttk.Entry(body, textvariable=key_var)
        key_entry.pack(fill="x", pady=(4, 12))

        machine_row = tk.Frame(body, bg=THEME["bg"])
        machine_row.pack(anchor="w", fill="x", pady=(0, 8))
        machine_id = licensing.device_fingerprint()
        tk.Label(
            machine_row,
            text=f"Machine ID: {machine_id}",
            bg=THEME["bg"],
            fg=THEME["fg_subtle"],
            font=("Consolas", 9),
        ).pack(side="left")
        ttk.Button(
            machine_row,
            text="Copy",
            command=lambda: (self.clipboard_clear(), self.clipboard_append(machine_id)),
        ).pack(side="left", padx=8)

        result_var = tk.StringVar(value="")
        tk.Label(body, textvariable=result_var, bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 10), justify="left").pack(anchor="w", fill="x")

        def activate_key():
            try:
                new_status = licensing.activate(email_var.get(), key_var.get())
            except Exception as exc:
                result_var.set(str(exc))
                return
            self._license_status = new_status
            result_var.set(new_status.message)
            messagebox.showinfo("Activated", new_status.message, parent=win)
            win.destroy()
            if not self.findings and not (self.collector and self.collector.is_alive()):
                self.after(250, self.refresh)

        actions = tk.Frame(body, bg=THEME["bg"])
        actions.pack(fill="x", pady=(20, 0))
        ttk.Button(actions, text="Activate key", command=activate_key).pack(side="left")
        if status.can_run and not force:
            ttk.Button(actions, text="Close", command=win.destroy).pack(side="left", padx=8)
        elif status.can_run:
            ttk.Button(actions, text="Continue trial", command=win.destroy).pack(side="left", padx=8)
        ttk.Button(
            actions,
            text="Contact WebBro",
            command=lambda: webbrowser.open("https://webbro.com.au/contact.html"),
        ).pack(side="left", padx=8)

        note = (
            "Admin note: create a customer key with:\n"
            "py -3 tools/make_license_key.py customer@example.com --days 30 --device MACHINE_ID"
        )
        tk.Label(body, text=note, bg=THEME["bg"], fg=THEME["fg_subtle"],
                 font=("Consolas", 9), justify="left").pack(anchor="w", pady=(26, 0))

    # ──────────────────────────────────────────
    # First-run welcome / walkthrough
    # ──────────────────────────────────────────
    @property
    def _welcome_marker(self) -> Path:
        return Path.home() / ".log_sentinel" / "welcomed.txt"

    def _maybe_show_welcome(self):
        if self._welcome_marker.exists():
            return
        self._show_welcome()

    def _show_welcome(self):
        """Modern multi-step onboarding tour. Visual mockups on left, text on right."""
        win = tk.Toplevel(self)
        win.title("Welcome to Log Sentinel")
        win.configure(bg=THEME["bg"])
        win.geometry("880x620")
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)

        # Center on screen
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = (sw - 880) // 2
        y = (sh - 620) // 2
        win.geometry(f"880x620+{x}+{y}")

        # ──────── STEPS ────────
        # Each step: title, body, visual_kind
        # visual_kind tells _draw_step_visual what mock to render
        steps = [
            ("welcome",
             "Welcome to Log Sentinel",
             "A 90-second security checkup for your Windows PC. "
             "It catches the stuff antivirus misses — and explains everything "
             "in plain English so you don't need an IT degree.\n\n"
             "Let's take a quick tour. Two minutes."),

            ("score",
             "Your Health Score",
             "After every scan, you get a single number (0–100) and a grade.\n\n"
             "Green is healthy. Yellow is small stuff. Orange and red mean "
             "real concerns. The cards below the score explain exactly what's "
             "wrong and how to fix it.\n\n"
             "Most first scans land in the 60–85 range. That's normal."),

            ("cards",
             "Plain-English action cards",
             "Every finding is a card with three sections:\n\n"
             "  • What's wrong — one sentence, no jargon\n"
             "  • Why it matters — what a normal person needs to know\n"
             "  • What to do — step-by-step fix, with one-click buttons\n\n"
             "You can snooze, mark fixed, or ignore each finding individually."),

            ("live",
             "Live Mode — real-time detection",
             "Click ▶ Live in the top bar and Log Sentinel starts watching.\n\n"
             "Every new process and every new network connection appears in "
             "the Live Feed within 2 seconds. Critical or High threats trigger "
             "a toast notification in the bottom-right corner — even if you're "
             "in another app."),

            ("firewall",
             "Block any IP, port, or website",
             "Go to the Firewall tab to block bad actors with two clicks.\n\n"
             "  • IPs — block a specific address or whole subnet\n"
             "  • Ports — restrict who can talk on certain ports\n"
             "  • Websites — block via the hosts file, works in every browser\n\n"
             "Everything is reversible. Click Active Rules to see / undo any change."),

            ("panic",
             "The 🚨 Panic Button",
             "If something goes very wrong — ransomware starts spreading, "
             "an alert pops up that scares you, your laptop starts beaconing "
             "to a strange IP — hit the red Panic button.\n\n"
             "In one click it disables every network adapter on the machine. "
             "Active malware can't exfiltrate. Lateral movement stops dead.\n\n"
             "Reversible. Click again to restore everything."),

            ("ready",
             "You're ready",
             "We'll start your first scan as soon as you close this window.\n\n"
             "While it runs (about 30 seconds), Log Sentinel will collect every "
             "log, every process, every connection, every persistence trick.\n\n"
             "When it finishes, head to the Health Check tab and read your score. "
             "Then click 'Fix it' on whatever needs attention.\n\n"
             "Have fun. We're glad you're here."),
        ]

        # ─── HEADER bar with brand + progress ───
        header = tk.Frame(win, bg=THEME["bg_panel"], height=64,
                          highlightthickness=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        brand = tk.Frame(header, bg=THEME["bg_panel"])
        brand.pack(side="left", padx=20)
        tk.Label(brand, text="🛡", bg=THEME["bg_panel"],
                 fg=THEME["accent"],
                 font=("Segoe UI Emoji", 18)).pack(side="left", padx=(0, 10))
        tk.Label(brand, text="Log Sentinel — Quick Tour",
                 bg=THEME["bg_panel"], fg=THEME["fg"],
                 font=("Segoe UI Semibold", 12)).pack(side="left")

        # Step label on right
        step_label_var = tk.StringVar(value=f"Step 1 of {len(steps)}")
        tk.Label(header, textvariable=step_label_var,
                 bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
                 font=("Segoe UI", 9)).pack(side="right", padx=20)

        # Bottom border of header
        tk.Frame(win, bg=THEME["border_subtle"], height=1).pack(fill="x")

        # ─── PROGRESS BAR (segments) ───
        prog = tk.Frame(win, bg=THEME["bg"], height=6)
        prog.pack(fill="x", padx=24, pady=(16, 0))
        prog.pack_propagate(False)
        segments: list[tk.Frame] = []
        for i in range(len(steps)):
            seg = tk.Frame(prog, bg=THEME["bg_active"],
                           highlightthickness=0)
            seg.pack(side="left", fill="both", expand=True,
                     padx=(0 if i == 0 else 4, 0))
            segments.append(seg)

        # ─── BODY: visual (left) + text (right) ───
        body = tk.Frame(win, bg=THEME["bg"], padx=24, pady=20)
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=THEME["bg_card"],
                        highlightthickness=1,
                        highlightbackground=THEME["border"])
        left.pack(side="left", fill="both", expand=True)

        right = tk.Frame(body, bg=THEME["bg"], width=380)
        right.pack(side="right", fill="y", padx=(24, 0))
        right.pack_propagate(False)

        # Visual canvas on the left
        visual_canvas = tk.Canvas(
            left, bg=THEME["bg_card"], highlightthickness=0,
        )
        visual_canvas.pack(fill="both", expand=True, padx=2, pady=2)

        # Text on the right
        step_num_lbl = tk.Label(
            right, text="01",
            bg=THEME["bg"], fg=THEME["accent"],
            font=("Segoe UI", 32, "bold"),
        )
        step_num_lbl.pack(anchor="w")

        title_lbl = tk.Label(right, text="",
                             bg=THEME["bg"], fg=THEME["fg"],
                             font=("Segoe UI Semibold", 18),
                             wraplength=360, justify="left", anchor="w")
        title_lbl.pack(anchor="w", pady=(8, 12), fill="x")

        text_lbl = tk.Label(right, text="",
                            bg=THEME["bg"], fg=THEME["fg_dim"],
                            font=("Segoe UI", 10),
                            wraplength=360, justify="left", anchor="nw")
        text_lbl.pack(anchor="w", fill="both", expand=True)

        # ─── FOOTER ───
        tk.Frame(win, bg=THEME["border_subtle"], height=1).pack(fill="x")
        footer = tk.Frame(win, bg=THEME["bg_panel"], height=66,
                          highlightthickness=0)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        skip_btn = tk.Button(
            footer, text="Skip tour",
            bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
            font=("Segoe UI", 9), relief="flat", borderwidth=0,
            cursor="hand2",
            activebackground=THEME["bg_panel"],
            activeforeground=THEME["fg"],
            padx=14, pady=8,
            command=lambda: _close(),
        )
        skip_btn.pack(side="left", padx=20, pady=14)

        next_btn = tk.Button(
            footer, text="Next  →",
            bg=THEME["accent"], fg="#0a0a0f",
            font=("Segoe UI", 10, "bold"),
            relief="flat", borderwidth=0, cursor="hand2",
            activebackground="#9af0db", activeforeground="#0a0a0f",
            padx=22, pady=10,
            command=lambda: _next(),
        )
        next_btn.pack(side="right", padx=20, pady=14)

        back_btn = tk.Button(
            footer, text="←  Back",
            bg=THEME["bg_panel"], fg=THEME["fg_dim"],
            font=("Segoe UI", 10), relief="flat", borderwidth=0,
            cursor="hand2",
            activebackground=THEME["bg_hover"],
            activeforeground=THEME["fg"],
            padx=18, pady=10,
            command=lambda: _back(),
        )
        back_btn.pack(side="right", pady=14, padx=(0, 4))

        # ─── STATE ───
        page_idx = [0]

        def _render():
            i = page_idx[0]
            kind, title, body_text = steps[i]
            step_label_var.set(f"Step {i+1} of {len(steps)}")
            step_num_lbl.config(text=f"{i+1:02d}")
            title_lbl.config(text=title)
            text_lbl.config(text=body_text)

            # Update progress segments
            for j, seg in enumerate(segments):
                if j <= i:
                    seg.config(bg=THEME["accent"])
                else:
                    seg.config(bg=THEME["bg_active"])

            # Back state
            if i == 0:
                back_btn.config(state="disabled", fg=THEME["fg_subtle"])
            else:
                back_btn.config(state="normal", fg=THEME["fg_dim"])

            # Next/Finish label
            if i == len(steps) - 1:
                next_btn.config(text="Start scanning  ✓")
            else:
                next_btn.config(text="Next  →")

            # Draw the visual
            self.after(20, lambda: self._draw_welcome_visual(visual_canvas, kind))

        def _next():
            if page_idx[0] >= len(steps) - 1:
                _close()
            else:
                page_idx[0] += 1
                _render()

        def _back():
            if page_idx[0] > 0:
                page_idx[0] -= 1
                _render()

        def _close():
            try:
                self._welcome_marker.parent.mkdir(parents=True, exist_ok=True)
                self._welcome_marker.write_text("welcomed", encoding="utf-8")
            except OSError:
                pass
            win.destroy()

        # Re-render on resize
        visual_canvas.bind("<Configure>",
                           lambda e: self.after(20, _render))

        _render()

    # ──────────────────────────────────────────
    # Welcome-tour visuals — each step gets a drawn mock-up
    # ──────────────────────────────────────────
    def _draw_welcome_visual(self, c: tk.Canvas, kind: str):
        try:
            c.delete("all")
            c.update_idletasks()
            w, h = c.winfo_width(), c.winfo_height()
        except tk.TclError:
            return
        if w < 50 or h < 50:
            return
        cx, cy = w // 2, h // 2

        if kind == "welcome":
            # Big shield with glow rings
            for r, color in [(160, "#1e1e2a"), (130, "#252537"),
                             (100, "#2a2a3c")]:
                c.create_oval(cx-r, cy-r, cx+r, cy+r,
                              outline=color, width=1)
            # Shield core
            c.create_oval(cx-70, cy-70, cx+70, cy+70,
                          fill=THEME["bg_active"],
                          outline=THEME["accent"], width=2)
            c.create_text(cx, cy, text="🛡",
                          font=("Segoe UI Emoji", 56),
                          fill=THEME["accent"])
            c.create_text(cx, cy + 90,
                          text="LOG SENTINEL",
                          font=("Segoe UI", 11, "bold"),
                          fill=THEME["fg_subtle"])

        elif kind == "score":
            # Big gauge mockup
            r = 100
            # Background ring
            c.create_oval(cx-r, cy-r-20, cx+r, cy+r-20,
                          outline=THEME["bg_active"], width=14)
            # 75% progress (top-left to right, 270°)
            c.create_arc(cx-r, cy-r-20, cx+r, cy+r-20,
                         start=90, extent=-270,
                         outline=THEME["accent"], width=14, style="arc")
            # Number
            c.create_text(cx, cy-30, text="87",
                          font=("Segoe UI", 48, "bold"),
                          fill=THEME["accent"])
            c.create_text(cx, cy+8, text="GRADE B",
                          font=("Segoe UI", 11),
                          fill=THEME["fg_subtle"])
            c.create_text(cx, cy + 110,
                          text="A few minor things to look at",
                          font=("Segoe UI", 10),
                          fill=THEME["fg"])

        elif kind == "cards":
            # Stacked finding cards
            card_w, card_h = min(360, w - 60), 90
            gap = 14
            top_y = cy - card_h - gap
            cards = [
                ("HIGH",   "#ff7f50", "Remote-control program is running"),
                ("MEDIUM", "#fbbf24", "New scheduled task created"),
                ("LOW",    "#7ee7d1", "5 startup programs slowing boot"),
            ]
            for i, (label, color, txt) in enumerate(cards):
                y = top_y + i * (card_h + gap)
                # accent stripe (left)
                c.create_rectangle(cx - card_w//2, y,
                                   cx - card_w//2 + 4, y + card_h,
                                   fill=color, outline="")
                # card
                c.create_rectangle(cx - card_w//2 + 4, y,
                                   cx + card_w//2, y + card_h,
                                   fill=THEME["bg_card_solid"],
                                   outline=THEME["border"], width=1)
                # severity badge
                c.create_text(cx - card_w//2 + 20, y + 22,
                              text=label, anchor="w",
                              fill=color, font=("Segoe UI", 9, "bold"))
                # title text
                c.create_text(cx - card_w//2 + 20, y + 44,
                              text=txt, anchor="w",
                              fill=THEME["fg"],
                              font=("Segoe UI Semibold", 10))
                # mock buttons
                bx = cx - card_w//2 + 20
                for bw, bcolor, btxt in [(72, THEME["accent"], "Fix it"),
                                         (68, THEME["bg_active"], "Snooze")]:
                    c.create_rectangle(bx, y + 64, bx + bw, y + 82,
                                       fill=bcolor, outline="")
                    c.create_text(bx + bw//2, y + 73, text=btxt,
                                  fill="#0a0a0f" if bcolor == THEME["accent"]
                                       else THEME["fg_dim"],
                                  font=("Segoe UI", 8, "bold"))
                    bx += bw + 6

        elif kind == "live":
            # Terminal-style live feed mock
            pad = 30
            x0, y0, x1, y1 = pad, pad, w - pad, h - pad
            # window
            c.create_rectangle(x0, y0, x1, y1,
                               fill=THEME["bg_card_solid"],
                               outline=THEME["border"], width=1)
            # title bar
            c.create_rectangle(x0, y0, x1, y0 + 32,
                               fill=THEME["bg_active"], outline="")
            for i, dot in enumerate(["#ff5f56", "#ffbd2e", "#27c93f"]):
                c.create_oval(x0 + 12 + i*16, y0 + 12,
                              x0 + 22 + i*16, y0 + 22,
                              fill=dot, outline="")
            c.create_text(x0 + 75, y0 + 17,
                          text="Live Feed", anchor="w",
                          fill=THEME["fg_subtle"],
                          font=("Consolas", 9))

            # Stream lines
            rows = [
                ("14:32:18", "new process", "curl.exe", THEME["fg_dim"]),
                ("14:32:18", "new conn", "→ 93.184.216.34:443", THEME["fg_dim"]),
                ("14:32:24", "⚠ HIGH", "encoded powershell", "#fbbf24"),
                ("14:32:31", "⚠ CRITICAL", "mimikatz.exe", "#ff4757"),
            ]
            yy = y0 + 50
            for ts, kind_lbl, msg, col in rows:
                c.create_text(x0 + 22, yy, text=ts, anchor="w",
                              fill=THEME["fg_subtle"], font=("Consolas", 9))
                c.create_text(x0 + 90, yy, text=kind_lbl, anchor="w",
                              fill=col, font=("Consolas", 9, "bold"))
                c.create_text(x0 + 200, yy, text=msg, anchor="w",
                              fill=THEME["fg"], font=("Consolas", 9))
                yy += 24

            # Toast notification overlay
            tw, th = 220, 64
            tx, ty = x1 - tw - 20, y1 - th - 20
            c.create_rectangle(tx, ty, tx + tw, ty + th,
                               fill=THEME["bg_card_solid"],
                               outline="#ff4757", width=2)
            c.create_text(tx + 14, ty + 16, anchor="w",
                          text="⚠ CRITICAL", fill="#ff4757",
                          font=("Segoe UI", 9, "bold"))
            c.create_text(tx + 14, ty + 38, anchor="w",
                          text="mimikatz.exe detected",
                          fill=THEME["fg"],
                          font=("Segoe UI", 9))
            c.create_text(tx + 14, ty + 54, anchor="w",
                          text="2 seconds ago",
                          fill=THEME["fg_subtle"],
                          font=("Segoe UI", 8))

        elif kind == "firewall":
            # Form fields mock
            form_w = min(420, w - 80)
            x0 = cx - form_w // 2
            y0 = 50

            # Title
            c.create_text(cx, y0, text="Block",
                          font=("Segoe UI Semibold", 14),
                          fill=THEME["fg"])

            y0 += 30
            # IP field
            c.create_text(x0 + 6, y0,
                          text="IP ADDRESS", anchor="w",
                          fill=THEME["fg_subtle"],
                          font=("Segoe UI", 8, "bold"))
            y0 += 16
            c.create_rectangle(x0, y0, x0 + form_w, y0 + 32,
                               fill=THEME["bg_card_solid"],
                               outline=THEME["border"], width=1)
            c.create_text(x0 + 12, y0 + 16,
                          text="185.220.101.45 ", anchor="w",
                          fill=THEME["fg"],
                          font=("Consolas", 10))

            y0 += 48
            # Website field
            c.create_text(x0 + 6, y0,
                          text="OR  WEBSITE", anchor="w",
                          fill=THEME["fg_subtle"],
                          font=("Segoe UI", 8, "bold"))
            y0 += 16
            c.create_rectangle(x0, y0, x0 + form_w, y0 + 32,
                               fill=THEME["bg_card_solid"],
                               outline=THEME["border"], width=1)
            c.create_text(x0 + 12, y0 + 16,
                          text="facebook.com", anchor="w",
                          fill=THEME["fg"],
                          font=("Consolas", 10))

            y0 += 60
            # Block button (big red)
            c.create_rectangle(x0, y0, x0 + form_w, y0 + 44,
                               fill="#ff4757", outline="")
            c.create_text(x0 + form_w // 2, y0 + 22,
                          text="🚫   BLOCK NOW",
                          fill="#fff",
                          font=("Segoe UI", 11, "bold"))

            y0 += 60
            c.create_text(cx, y0,
                          text="Reversible from the Active Rules tab",
                          fill=THEME["fg_subtle"],
                          font=("Segoe UI", 9, "italic"))

        elif kind == "panic":
            # Giant red panic button
            r = 90
            # Outer rings
            for rr, col in [(r + 24, "#1e0d10"), (r + 14, "#2a141a")]:
                c.create_oval(cx-rr, cy-rr, cx+rr, cy+rr,
                              fill=col, outline="")
            # Pulse ring
            c.create_oval(cx-r-6, cy-r-6, cx+r+6, cy+r+6,
                          outline="#ff4757", width=2)
            # Main button
            c.create_oval(cx-r, cy-r, cx+r, cy+r,
                          fill="#ff4757", outline="")
            c.create_text(cx, cy - 6, text="🚨",
                          font=("Segoe UI Emoji", 42),
                          fill="#fff")
            c.create_text(cx, cy + 36, text="PANIC",
                          font=("Segoe UI", 14, "bold"),
                          fill="#fff")
            # Label
            c.create_text(cx, cy + r + 50,
                          text="Disconnect all networks in 1 click",
                          font=("Segoe UI", 11),
                          fill=THEME["fg"])
            c.create_text(cx, cy + r + 72,
                          text="Reversible — click again to restore",
                          font=("Segoe UI", 9, "italic"),
                          fill=THEME["fg_subtle"])

        elif kind == "ready":
            # Big check + confetti dots
            r = 80
            c.create_oval(cx-r, cy-r, cx+r, cy+r,
                          fill=THEME["bg_active"], outline=THEME["accent"],
                          width=3)
            # Check mark
            c.create_line(cx-30, cy, cx-8, cy+22, cx+34, cy-24,
                          fill=THEME["accent"], width=8,
                          capstyle="round", joinstyle="round")
            # Confetti
            import random
            random.seed(42)
            colors = [THEME["accent"], "#a78bfa", "#fbbf24",
                      "#ff7f50", "#7ee7d1"]
            for _ in range(28):
                dx = random.randint(-220, 220)
                dy = random.randint(-180, 180)
                if abs(dx) < r + 30 and abs(dy) < r + 30:
                    continue
                px, py = cx + dx, cy + dy
                sz = random.randint(3, 6)
                col = random.choice(colors)
                c.create_oval(px-sz, py-sz, px+sz, py+sz,
                              fill=col, outline="")
            c.create_text(cx, cy + r + 30,
                          text="You're all set.",
                          font=("Segoe UI Semibold", 14),
                          fill=THEME["fg"])
            c.create_text(cx, cy + r + 56,
                          text="The first scan will start automatically",
                          font=("Segoe UI", 9, "italic"),
                          fill=THEME["fg_subtle"])

    # ──────────────────────────────────────────
    # Styling
    # ──────────────────────────────────────────
    def _setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        bg     = THEME["bg"]
        panel  = THEME["bg_panel"]
        card   = THEME.get("bg_card_solid", THEME["bg_card"])
        fg     = THEME["fg"]
        fg_dim = THEME["fg_dim"]
        accent = THEME["accent"]
        border = THEME["border"]
        hover  = THEME.get("bg_hover", "#1f1f2d")
        active = THEME.get("bg_active", "#262638")

        style.configure(".", background=bg, foreground=fg,
                        fieldbackground=panel, bordercolor=border,
                        focuscolor=accent, lightcolor=border, darkcolor=border)

        style.configure("TFrame", background=bg)
        style.configure("Panel.TFrame", background=panel)
        style.configure("Card.TFrame", background=card, relief="flat")

        style.configure("TLabel", background=bg, foreground=fg,
                        font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=card, foreground=fg)
        style.configure("Dim.TLabel", background=bg, foreground=fg_dim)
        style.configure("Title.TLabel", background=bg, foreground=fg,
                        font=("Segoe UI Semibold", 14))
        style.configure("Big.TLabel", background=card, foreground=fg,
                        font=("Segoe UI", 22, "bold"))

        # Modern flat buttons — subtle hover instead of bright accent
        style.configure("TButton", background=panel, foreground=fg,
                        bordercolor=border, relief="flat",
                        padding=(12, 7), font=("Segoe UI", 9))
        style.map("TButton",
                  background=[("active", hover), ("pressed", active)],
                  foreground=[("active", fg)],
                  bordercolor=[("active", THEME.get("border", border))])

        style.configure("Accent.TButton", background=accent, foreground="#0a0a0f",
                        font=("Segoe UI", 9, "bold"), padding=(14, 8),
                        bordercolor=accent)
        style.map("Accent.TButton",
                  background=[("active", "#9af0db"), ("pressed", "#5dd5b8")],
                  foreground=[("active", "#0a0a0f")])

        # Subtle entry
        style.configure("TEntry", fieldbackground=panel, foreground=fg,
                        insertcolor=fg, bordercolor=border,
                        padding=(8, 6))
        style.map("TEntry",
                  bordercolor=[("focus", accent)],
                  lightcolor=[("focus", accent)],
                  darkcolor=[("focus", accent)])

        style.configure("TCombobox", fieldbackground=panel, foreground=fg,
                        background=panel, arrowcolor=fg, bordercolor=border)
        style.map("TCombobox",
                  fieldbackground=[("readonly", panel)],
                  foreground=[("readonly", fg)],
                  bordercolor=[("focus", accent)])

        # Treeview — flat, modern row separators
        style.configure("Treeview", background=panel, foreground=fg,
                        fieldbackground=panel, bordercolor=border,
                        rowheight=28, font=("Segoe UI", 9),
                        relief="flat")
        style.configure("Treeview.Heading",
                        background=THEME.get("bg_card_solid", card),
                        foreground=fg_dim,
                        font=("Segoe UI", 8, "bold"), relief="flat",
                        padding=(10, 8))
        style.map("Treeview.Heading",
                  background=[("active", hover)],
                  foreground=[("active", fg)])
        style.map("Treeview",
                  background=[("selected", THEME["selected"])],
                  foreground=[("selected", fg)])

        # Hide the notebook tab strip — we render our own sidebar.
        # Setting an empty layout for TNotebook.Tab hides the tab buttons entirely.
        try:
            style.layout("TNotebook.Tab", [])
        except tk.TclError:
            pass
        style.configure("TNotebook", background=bg, borderwidth=0,
                        tabmargins=[0, 0, 0, 0], padding=0)

        # Progressbar
        style.configure("TProgressbar", background=accent, troughcolor=panel,
                        bordercolor=border, lightcolor=accent, darkcolor=accent)

        # Scrollbar — subtle
        style.configure("Vertical.TScrollbar",
                        background=panel, troughcolor=bg,
                        bordercolor=bg, arrowcolor=fg_dim,
                        gripcount=0, relief="flat")
        style.map("Vertical.TScrollbar",
                  background=[("active", hover)])

        # Checkbutton + Radiobutton — flatter
        style.configure("TCheckbutton", background=bg, foreground=fg,
                        focuscolor=bg)
        style.configure("TRadiobutton", background=bg, foreground=fg,
                        focuscolor=bg)

        # Paned window
        style.configure("TPanedwindow", background=bg)

    # ──────────────────────────────────────────
    # Layout
    # ──────────────────────────────────────────
    def _build_ui(self):
        # ============================================
        # TOP BAR — minimal, branded, action buttons
        # ============================================
        top = tk.Frame(self, bg=THEME["bg_panel"], height=60,
                       highlightthickness=0)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        # Brand block (icon + name + version) on the left
        brand = tk.Frame(top, bg=THEME["bg_panel"])
        brand.pack(side="left", padx=20)
        tk.Label(brand, text="🛡", bg=THEME["bg_panel"],
                 fg=THEME["accent"],
                 font=("Segoe UI Emoji", 18)).pack(side="left", padx=(0, 8))
        title_box = tk.Frame(brand, bg=THEME["bg_panel"])
        title_box.pack(side="left")
        tk.Label(title_box, text="Log Sentinel",
                 bg=THEME["bg_panel"], fg=THEME["fg"],
                 font=("Segoe UI Semibold", 12)).pack(anchor="w")
        tk.Label(title_box, text="v1.0  ·  Local-only",
                 bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
                 font=("Segoe UI", 8)).pack(anchor="w")

        # Divider
        tk.Frame(top, bg=THEME["border_subtle"], width=1).pack(
            side="left", fill="y", padx=10, pady=14)

        # Look-back selector
        tk.Label(top, text="Look back",
                 bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(6, 4))
        self.hours_var = tk.StringVar(value="24")
        ttk.Combobox(top, textvariable=self.hours_var,
                     values=["1", "6", "12", "24", "48", "72", "168"],
                     width=5, state="readonly").pack(side="left", padx=(0, 8))

        # Primary action — Scan
        ttk.Button(top, text="Scan now", style="Accent.TButton",
                   command=self.refresh).pack(side="left", padx=4)

        # Secondary actions — flat ghost buttons
        self.live_btn = ttk.Button(top, text="▶  Live",
                                   command=self.toggle_live)
        self.live_btn.pack(side="left", padx=2)
        ttk.Button(top, text="✨  Quick fix",
                   command=self.run_quick_win).pack(side="left", padx=2)

        # Firewall shortcut — jumps to the Firewall tab
        ttk.Button(top, text="🔥  Block IP / site",
                   command=lambda: self._jump_to_tab("Firewall")
                   ).pack(side="left", padx=2)

        # ── Right side: search + panic + utility ──
        right = tk.Frame(top, bg=THEME["bg_panel"])
        right.pack(side="right", padx=14)

        # Notification bell — shows count of unseen Critical/High findings
        self._notif_btn_frame = tk.Frame(right, bg=THEME["bg_panel"])
        self._notif_btn_frame.pack(side="right", padx=(0, 4))
        self._notif_btn = tk.Label(
            self._notif_btn_frame, text="🔔",
            bg=THEME["bg_panel"], fg=THEME["fg_dim"],
            font=("Segoe UI", 13), cursor="hand2",
            padx=10, pady=4,
        )
        self._notif_btn.pack()
        self._notif_btn.bind("<Button-1>",
                              lambda e: self.open_notification_center())
        self._notif_badge = tk.Label(
            self._notif_btn_frame, text="",
            bg=THEME["accent"], fg="#000",
            font=("Segoe UI", 7, "bold"),
            padx=4, pady=0,
        )
        # The badge is placed via `place` so it overlaps the bell
        # (initially hidden until count > 0)

        # Panic — always visible, red
        self.panic_btn = tk.Button(
            right, text="🚨  Panic",
            bg="#e74c3c", fg="#fff",
            font=("Segoe UI", 9, "bold"),
            padx=14, pady=6, relief="flat", cursor="hand2", borderwidth=0,
            activebackground="#c0392b", activeforeground="#fff",
            command=self.open_panic_dialog,
        )
        self.panic_btn.pack(side="right", padx=(8, 0))

        # Settings + Password as compact icon buttons
        for label, cmd in [
            ("⚙", self.open_settings),
            ("🔐", self.open_password_check),
            ("Reports", self.open_reports_window),
            ("Scan", self.scan_folder),
            ("📄", self.export_html),
        ]:
            tk.Button(right, text=label,
                      bg=THEME["bg_panel"], fg=THEME["fg_dim"],
                      font=("Segoe UI", 12),
                      relief="flat", borderwidth=0, cursor="hand2",
                      activebackground=THEME["bg_hover"],
                      activeforeground=THEME["fg"],
                      padx=10, pady=4,
                      command=cmd).pack(side="right", padx=2)

        # Search box
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._apply_filters())
        search_frame = tk.Frame(right, bg=THEME["bg_card_solid"],
                                highlightthickness=1,
                                highlightbackground=THEME["border"])
        search_frame.pack(side="right", padx=(0, 10))
        tk.Label(search_frame, text="🔍",
                 bg=THEME["bg_card_solid"], fg=THEME["fg_subtle"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(8, 4))
        e = tk.Entry(search_frame, textvariable=self.search_var,
                     width=22,
                     bg=THEME["bg_card_solid"], fg=THEME["fg"],
                     insertbackground=THEME["fg"],
                     relief="flat", borderwidth=0,
                     font=("Segoe UI", 9))
        e.pack(side="left", ipady=5, padx=(0, 4))
        # Ctrl+K hint — clickable to open the command palette
        kbd = tk.Label(search_frame, text="⌘K",
                       bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
                       font=("Segoe UI", 8, "bold"),
                       padx=6, pady=2, cursor="hand2")
        kbd.pack(side="left", padx=(0, 8))
        kbd.bind("<Button-1>", lambda e: self.open_command_palette())

        # ============================================
        # STATUS BAR — bottom
        # ============================================
        self.status_var = tk.StringVar(value="Ready.")
        status = tk.Frame(self, bg=THEME["bg_panel"], height=28,
                          highlightthickness=0)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)
        # top border line
        tk.Frame(status, bg=THEME["border_subtle"], height=1).pack(
            fill="x", side="top")
        tk.Label(status, textvariable=self.status_var,
                 bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
                 font=("Segoe UI", 9)).pack(side="left", padx=14, pady=4)
        self.progress = ttk.Progressbar(status, mode="indeterminate",
                                        length=160)
        self.progress.pack(side="right", padx=14, pady=6)

        # ============================================
        # BODY — sidebar + content
        # ============================================
        body = tk.Frame(self, bg=THEME["bg"])
        body.pack(fill="both", expand=True)

        # Sidebar container (fixed width, vertical)
        sidebar_wrap = tk.Frame(body, bg=THEME["bg_panel"], width=240,
                                highlightthickness=0)
        sidebar_wrap.pack(side="left", fill="y")
        sidebar_wrap.pack_propagate(False)

        # right border on sidebar
        tk.Frame(body, bg=THEME["border_subtle"], width=1).pack(
            side="left", fill="y")

        # ── Scrollable inner — Canvas + Frame trick ──
        sb_canvas = tk.Canvas(
            sidebar_wrap, bg=THEME["bg_panel"],
            highlightthickness=0, borderwidth=0,
        )
        sb_scroll = ttk.Scrollbar(
            sidebar_wrap, orient="vertical",
            command=sb_canvas.yview,
        )
        sb_canvas.configure(yscrollcommand=sb_scroll.set)

        sb_scroll.pack(side="right", fill="y")
        sb_canvas.pack(side="left", fill="both", expand=True)

        self._sidebar_inner = tk.Frame(sb_canvas, bg=THEME["bg_panel"])
        sb_inner_id = sb_canvas.create_window(
            (0, 0), window=self._sidebar_inner, anchor="nw",
        )

        def _sb_on_inner_resize(_e=None):
            sb_canvas.configure(scrollregion=sb_canvas.bbox("all"))

        def _sb_on_canvas_resize(e):
            # Inner frame width tracks canvas width
            sb_canvas.itemconfig(sb_inner_id, width=e.width)

        self._sidebar_inner.bind("<Configure>", _sb_on_inner_resize)
        sb_canvas.bind("<Configure>", _sb_on_canvas_resize)

        # Mouse-wheel scrolling — bound ONLY when cursor is over the sidebar,
        # so it doesn't fight with Treeview / cards canvas scrolling.
        def _sb_wheel(e):
            sb_canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        sb_canvas.bind("<Enter>",
                       lambda e: sb_canvas.bind_all("<MouseWheel>", _sb_wheel))
        sb_canvas.bind("<Leave>",
                       lambda e: sb_canvas.unbind_all("<MouseWheel>"))

        # Inner padding (applied to children, not the canvas)
        # We'll wrap real content in another frame so existing
        # `.pack(... padx=12 pady=14)` style still works.
        self._sidebar_padding = tk.Frame(self._sidebar_inner,
                                          bg=THEME["bg_panel"])
        self._sidebar_padding.pack(fill="both", expand=True, padx=12, pady=14)
        # Existing code references self._sidebar_inner — redirect:
        self._sidebar_inner = self._sidebar_padding

        # Content area to the right
        content = tk.Frame(body, bg=THEME["bg"])
        content.pack(side="left", fill="both", expand=True)

        # ── Notebook with hidden tab strip ──
        self.notebook = ttk.Notebook(content)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=14)

        # Build all the tabs (each one calls notebook.add(...))
        self._build_health_tab()
        self._build_trends_tab()
        self._build_timeline_tab()
        self._build_dashboard_tab()
        self._build_live_tab()
        self._build_findings_tab()
        self._build_events_tab()
        self._build_network_tab()
        self._build_processes_tab()
        self._build_services_tab()
        self._build_persistence_tab()
        self._build_live_monitor_tab()
        self._build_firewall_tab()
        self._build_system_tab()

        # Now build the sidebar nav (mirrors notebook tabs)
        self._build_sidebar_nav()

        # Wire right-click context menus on data tables
        self._wire_context_menus()

        # Keyboard shortcuts — Ctrl+K opens the command palette
        self.bind_all("<Control-k>", self.open_command_palette)
        self.bind_all("<Control-K>", self.open_command_palette)
        # Refresh
        self.bind_all("<Control-r>", lambda e: self.refresh())
        self.bind_all("<F5>", lambda e: self.refresh())

        # Restore last-active tab
        try:
            last_idx = preferences.get().last_tab_index
            if 0 <= last_idx < self.notebook.index("end"):
                self.notebook.select(last_idx)
        except Exception:
            pass

    # ──────────────────────────────────────────
    # Sidebar navigation
    # ──────────────────────────────────────────

    # Tab index → (section, icon, label, sublabel)
    SIDEBAR_LAYOUT = [
        ("Overview", [
            (3,  "📊", "Dashboard",     "Security overview"),
            (0, "🏥", "Health Check",  "Score + fixes"),
            (1, "📈", "Trends",        "History over time"),
            (2, "⏱",  "Timeline",       "Event chronology"),
        ]),
        ("Take action", [
            (12, "🔥", "Firewall",       "Block IPs & websites"),
            (4,  "⚡", "Live Feed",      "Real-time stream"),
        ]),
        ("Monitor", [
            (11, "💓", "System Monitor", "CPU · RAM · Disk"),
        ]),
        ("Investigate", [
            (5,  "🔎", "Findings",      "All detections"),
            (6,  "📜", "Events",        "Windows Event Log"),
            (7,  "🌐", "Network",       "Connections + GeoIP"),
            (8,  "🖥",  "Processes",      "Running + tree"),
            (9,  "⚙",  "Services",       "Windows services"),
            (10, "📌", "Persistence",   "Autoruns + tasks"),
            (13, "💻", "System Info",   "Hardware + software"),
        ]),
    ]

    def _build_sidebar_nav(self):
        # Track the currently-active sidebar item
        self._sidebar_items: dict[int, dict] = {}

        for section_label, items in self.SIDEBAR_LAYOUT:
            # Section header
            hdr = tk.Frame(self._sidebar_inner, bg=THEME["bg_panel"])
            hdr.pack(fill="x", pady=(14, 4))
            tk.Label(hdr, text=section_label.upper(),
                     bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
                     font=("Segoe UI", 8, "bold")).pack(
                anchor="w", padx=8)

            for idx, icon, primary, secondary in items:
                self._build_sidebar_item(idx, icon, primary, secondary)

        # Bottom spacer + footer
        tk.Frame(self._sidebar_inner, bg=THEME["bg_panel"]).pack(
            fill="both", expand=True)

        # Footer hint
        footer = tk.Frame(self._sidebar_inner, bg=THEME["bg_panel"])
        footer.pack(fill="x", pady=(8, 0))
        tk.Frame(footer, bg=THEME["border_subtle"], height=1).pack(
            fill="x", pady=(0, 12))
        tk.Label(footer,
                 text="100% offline · No telemetry",
                 bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=8)
        tk.Label(footer,
                 text="Tip: click 🏥 to start",
                 bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
                 font=("Segoe UI", 8, "italic")).pack(
            anchor="w", padx=8, pady=(2, 4))

        # Select first item by default
        self._select_sidebar(0)

        # Listen for notebook tab changes (e.g., from code that calls
        # notebook.select(...)) so we can keep the sidebar in sync.
        self.notebook.bind("<<NotebookTabChanged>>",
                           self._on_notebook_changed)

    def _build_sidebar_item(self, idx: int, icon: str,
                            primary: str, secondary: str):
        """Build one nav row. Click → switch to notebook tab idx."""
        row = tk.Frame(self._sidebar_inner, bg=THEME["bg_panel"],
                       cursor="hand2")
        row.pack(fill="x", pady=1)

        # Active indicator (left bar)
        bar = tk.Frame(row, bg=THEME["bg_panel"], width=3)
        bar.pack(side="left", fill="y")

        inner = tk.Frame(row, bg=THEME["bg_panel"])
        inner.pack(side="left", fill="x", expand=True, padx=(9, 8), pady=4)

        ico = tk.Label(inner, text=icon,
                       bg=THEME["bg_panel"], fg=THEME["fg_dim"],
                       font=("Segoe UI Emoji", 12))
        ico.pack(side="left", padx=(0, 10))

        text_box = tk.Frame(inner, bg=THEME["bg_panel"])
        text_box.pack(side="left", fill="x", expand=True)
        prim_lbl = tk.Label(text_box, text=primary,
                            bg=THEME["bg_panel"], fg=THEME["fg_dim"],
                            font=("Segoe UI", 10),
                            anchor="w")
        prim_lbl.pack(fill="x", pady=(4, 0))
        sub_lbl = tk.Label(text_box, text=secondary,
                           bg=THEME["bg_panel"], fg=THEME["fg_subtle"],
                           font=("Segoe UI", 8),
                           anchor="w")
        sub_lbl.pack(fill="x", pady=(0, 4))

        info = {
            "row": row, "inner": inner, "bar": bar,
            "icon": ico, "primary": prim_lbl, "secondary": sub_lbl,
            "text_box": text_box,
        }
        self._sidebar_items[idx] = info

        # Click + hover bindings on every nested widget
        def go(_e=None, _idx=idx):
            self._select_sidebar(_idx)
            try:
                self.notebook.select(_idx)
            except tk.TclError:
                pass

        for w in (row, inner, ico, prim_lbl, sub_lbl, text_box):
            w.bind("<Button-1>", go)

        def on_enter(_e=None):
            if self._sidebar_active_idx == idx:
                return
            for w in (row, inner, ico, prim_lbl, sub_lbl, text_box):
                w.configure(bg=THEME["bg_hover"])
            prim_lbl.configure(fg=THEME["fg"])
        def on_leave(_e=None):
            if self._sidebar_active_idx == idx:
                return
            for w in (row, inner, ico, prim_lbl, sub_lbl, text_box):
                w.configure(bg=THEME["bg_panel"])
            prim_lbl.configure(fg=THEME["fg_dim"])

        for w in (row, inner, ico, prim_lbl, sub_lbl, text_box):
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)

    _sidebar_active_idx: int = -1

    def _select_sidebar(self, idx: int):
        """Visually mark a sidebar item active. Doesn't change the notebook tab."""
        if idx == self._sidebar_active_idx:
            return
        # Deactivate previous
        prev = self._sidebar_items.get(self._sidebar_active_idx)
        if prev:
            for w in (prev["row"], prev["inner"], prev["icon"],
                      prev["primary"], prev["secondary"], prev["text_box"]):
                w.configure(bg=THEME["bg_panel"])
            prev["bar"].configure(bg=THEME["bg_panel"])
            prev["primary"].configure(fg=THEME["fg_dim"],
                                      font=("Segoe UI", 10))
            prev["icon"].configure(fg=THEME["fg_dim"])

        # Activate new
        cur = self._sidebar_items.get(idx)
        if cur:
            for w in (cur["row"], cur["inner"], cur["icon"],
                      cur["primary"], cur["secondary"], cur["text_box"]):
                w.configure(bg=THEME["bg_active"])
            cur["bar"].configure(bg=THEME["accent"])
            cur["primary"].configure(fg=THEME["fg"],
                                     font=("Segoe UI Semibold", 10))
            cur["icon"].configure(fg=THEME["accent"])

        self._sidebar_active_idx = idx

    def _on_notebook_changed(self, _event=None):
        try:
            idx = self.notebook.index(self.notebook.select())
        except tk.TclError:
            return
        self._select_sidebar(idx)

    def _jump_to_tab(self, name_substr: str) -> None:
        """Switch to the first notebook tab whose text contains name_substr."""
        for i in range(self.notebook.index("end")):
            if name_substr.lower() in self.notebook.tab(i, "text").lower():
                self.notebook.select(i)
                return

    # ──────────────────────────────────────────
    # Right-click context menus
    # ──────────────────────────────────────────

    def _make_menu(self, items: list[tuple[str, callable] | None]):
        """Build a tk.Menu from a list of (label, callback) tuples; None = separator."""
        m = tk.Menu(self, tearoff=0,
                    bg=THEME["bg_card_solid"], fg=THEME["fg"],
                    activebackground=THEME["bg_active"],
                    activeforeground=THEME["accent"],
                    bd=0, relief="flat",
                    font=("Segoe UI", 9))
        for entry in items:
            if entry is None:
                m.add_separator()
                continue
            label, cb = entry
            if cb is None:
                m.add_command(label=label, state="disabled")
            else:
                m.add_command(label=label, command=cb)
        return m

    def _attach_context_menu(self, tree: ttk.Treeview, build_items):
        """Wire a right-click handler that calls build_items(selected_values)."""
        def on_right_click(event):
            row = tree.identify_row(event.y)
            if not row:
                return
            tree.selection_set(row)
            vals = tree.item(row, "values")
            items = build_items(row, vals)
            if items:
                menu = self._make_menu(items)
                try:
                    menu.tk_popup(event.x_root, event.y_root)
                finally:
                    menu.grab_release()
        tree.bind("<Button-3>", on_right_click)

    # Build menus for each table after the tree exists ─────────
    def _wire_context_menus(self):
        # Processes
        if hasattr(self, "proc_tree"):
            self._attach_context_menu(self.proc_tree, self._proc_menu_items)
        # Network
        if hasattr(self, "net_tree"):
            self._attach_context_menu(self.net_tree, self._net_menu_items)
        # Findings
        if hasattr(self, "findings_tree"):
            self._attach_context_menu(self.findings_tree, self._findings_menu_items)
        # Services
        if hasattr(self, "svc_tree"):
            self._attach_context_menu(self.svc_tree, self._service_menu_items)

    # ── Process menu ──
    def _proc_menu_items(self, row, vals):
        # values: (pid, name, ppid, user, memory, path)
        try:
            pid = int(vals[0])
        except (ValueError, IndexError):
            return None
        name = vals[1] if len(vals) > 1 else ""
        path = vals[5] if len(vals) > 5 else ""

        def end_process():
            from src.remediation import end_process as _kill
            if not messagebox.askyesno(
                "End process",
                f"End process '{name}' (PID {pid})?\n\n"
                "Unsaved work in that program will be lost.",
            ):
                return
            ok, msg = _kill(pid)
            messagebox.showinfo("Done" if ok else "Failed", msg)

        def lookup_vt():
            import webbrowser, os
            if path and path != "—":
                webbrowser.open(f"https://www.virustotal.com/gui/search/{os.path.basename(path)}")
            else:
                webbrowser.open(f"https://www.virustotal.com/gui/search/{name}")

        def copy_path():
            self.clipboard_clear()
            self.clipboard_append(path or name)

        return [
            (f"⛔  End process (PID {pid})", end_process),
            None,
            ("🔍  Look up on VirusTotal", lookup_vt),
            ("📋  Copy path", copy_path),
            None,
            ("🛠  Open Task Manager", lambda: subprocess.Popen(["taskmgr"])),
        ]

    # ── Network menu ──
    def _net_menu_items(self, row, vals):
        # values: (proto, local, remote, country, state, ext, pid, process)
        if len(vals) < 8:
            return None
        remote = str(vals[2])
        process = str(vals[7]) if vals[7] else ""

        # Extract IP from remote (host:port)
        ip = ""
        if remote and ":" in remote and remote != "—":
            ip = remote.rsplit(":", 1)[0].strip("[]")

        def block_ip():
            if not ip:
                return
            from src.firewall_manager import (
                quick_block_ip, add_rule, is_admin, is_dangerous_block,
            )
            if not is_admin():
                messagebox.showwarning("Admin required",
                                       "Run via LAUNCH-as-admin.bat to add firewall rules.")
                return
            rule = quick_block_ip(ip, direction="out")
            warn = is_dangerous_block(rule)
            if warn and not messagebox.askyesno("Confirm", warn + "\n\nProceed?"):
                return
            if not messagebox.askyesno("Block IP", f"Add a firewall rule to block outbound traffic to {ip}?"):
                return
            ok, msg = add_rule(rule)
            messagebox.showinfo("Done" if ok else "Failed", msg)

        def lookup_abuse():
            if ip:
                import webbrowser
                webbrowser.open(f"https://www.abuseipdb.com/check/{ip}")

        def lookup_vt():
            if ip:
                import webbrowser
                webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{ip}")

        def copy_ip():
            if ip:
                self.clipboard_clear()
                self.clipboard_append(ip)

        items = []
        if ip:
            items += [
                (f"🚫  Block {ip} in firewall", block_ip),
                None,
                ("🔍  Look up on AbuseIPDB", lookup_abuse),
                ("🔍  Look up on VirusTotal", lookup_vt),
                ("📋  Copy IP", copy_ip),
            ]
        if process and process != "—":
            items += [None, (f"📍  Process: {process}", None)]
        return items or None

    # ── Findings menu ──
    def _findings_menu_items(self, row, vals):
        # vals: (severity, category, mitre, title, rule, time)
        title = vals[3] if len(vals) > 3 else ""
        rule = vals[4] if len(vals) > 4 else ""

        # Find the matching finding by title
        target = next((f for f in self.findings if f.title == title), None)
        if target is None:
            return None

        def mark_fixed(): self._mark_resolved(target)
        def snooze_7():   self._snooze(target, 7)
        def snooze_30():  self._snooze(target, 30)
        def do_ignore():  self._ignore(target)
        def toggle_pin():
            preferences.toggle_pin(target)
            self._render_health()
        def open_mitre():
            from src.mitre import technique_for_rule
            t = technique_for_rule(target.rule)
            if t:
                import webbrowser
                webbrowser.open(t.url)
        def copy_title():
            self.clipboard_clear()
            self.clipboard_append(target.title)

        pin_label = "📌  Unpin" if preferences.is_pinned(target) else "📌  Pin to top"

        return [
            ("✓  Mark fixed", mark_fixed),
            ("💤  Snooze 7 days", snooze_7),
            ("💤  Snooze 30 days", snooze_30),
            ("✕  Ignore forever", do_ignore),
            None,
            (pin_label, toggle_pin),
            None,
            ("🔗  Open MITRE technique", open_mitre),
            ("📋  Copy title", copy_title),
        ]

    # ── Service menu ──
    def _service_menu_items(self, row, vals):
        name = vals[0] if vals else ""
        if not name:
            return None
        from src.remediation import stop_service
        return [
            (f"⛔  Stop '{name}'",
             lambda: messagebox.showinfo("Done", stop_service(name)[1])),
            None,
            ("📋  Copy service name",
             lambda: (self.clipboard_clear(), self.clipboard_append(name))),
            ("🛠  Open services.msc",
             lambda: subprocess.Popen(["services.msc"], shell=True)),
        ]

    # ──────────────────────────────────────────
    # Command Palette (Ctrl+K)
    # ──────────────────────────────────────────

    def _command_palette_actions(self) -> list[tuple[str, str, callable]]:
        """Returns list of (label, hint, callback) tuples for the palette."""
        # Tabs
        tab_actions = [
            (f"Go to {self.notebook.tab(i, 'text').strip()}",
             f"Tab · index {i}",
             lambda i=i: self.notebook.select(i))
            for i in range(self.notebook.index("end"))
        ]
        # Primary actions
        primary = [
            ("Scan now",         "Run a fresh scan",           self.refresh),
            ("Toggle Live Mode", "Start / stop real-time",     self.toggle_live),
            ("Quick Win",        "Auto-fix safe items",        self.run_quick_win),
            ("Panic — isolate",  "Cut all network access",     self.open_panic_dialog),
            ("Block IP / website", "Jump to Firewall",         lambda: self._jump_to_tab("Firewall")),
            ("Password strength check", "Offline checker",     self.open_password_check),
            ("Export HTML report","Save scan report",          self.export_html),
            ("Settings",         "Theme · schedule · IOCs",    self.open_settings),
            ("Demo mode — load sample data",
             "Synthetic findings · no scan needed",
             self.load_demo_data),
            ("Re-run welcome tour", "Replay onboarding",
             lambda: (self._welcome_marker.unlink(missing_ok=True),
                      self._show_welcome())),
        ]
        return primary + tab_actions

    # ──────────────────────────────────────────
    # Notification center
    # ──────────────────────────────────────────

    def _update_notification_badge(self):
        """Update the bell badge with count of unseen Critical/High findings."""
        if not hasattr(self, "_notif_badge"):
            return
        seen = set(preferences.get().seen_notifications)
        unseen = [
            f for f in self.findings
            if f.severity in ("Critical", "High")
            and preferences.fingerprint(f) not in seen
            and preferences.state_for(f) == "active"
        ]
        n = len(unseen)
        if n == 0:
            self._notif_badge.place_forget()
            self._notif_btn.config(fg=THEME["fg_dim"])
        else:
            self._notif_badge.config(text=str(min(n, 99)))
            self._notif_badge.place(in_=self._notif_btn, relx=0.7, rely=0.0)
            self._notif_btn.config(fg=THEME["accent"])

    def open_notification_center(self):
        """Open a small popup showing recent Critical/High findings."""
        win = tk.Toplevel(self)
        win.title("Notifications")
        win.configure(bg=THEME["bg_card"])
        win.overrideredirect(True)
        win.attributes("-topmost", True)

        # Position below the bell icon
        self.update_idletasks()
        bx = self._notif_btn.winfo_rootx()
        by = self._notif_btn.winfo_rooty() + self._notif_btn.winfo_height() + 4
        win.geometry(f"460x420+{max(0, bx - 380)}+{by}")

        outer = tk.Frame(win, bg=THEME["accent"], padx=1, pady=1)
        outer.pack(fill="both", expand=True)
        body = tk.Frame(outer, bg=THEME["bg_card"])
        body.pack(fill="both", expand=True)

        # Header
        head = tk.Frame(body, bg=THEME["bg_card"], padx=18, pady=12)
        head.pack(fill="x")
        tk.Label(head, text="🔔  Notifications",
                 bg=THEME["bg_card"], fg=THEME["fg"],
                 font=("Segoe UI", 12, "bold")).pack(side="left")

        def mark_all_seen():
            seen = set(preferences.get().seen_notifications)
            for f in self.findings:
                if f.severity in ("Critical", "High"):
                    seen.add(preferences.fingerprint(f))
            preferences.get().seen_notifications = list(seen)
            preferences.save()
            self._update_notification_badge()
            win.destroy()

        tk.Button(head, text="Mark all read",
                  bg=THEME["bg_card"], fg=THEME["fg_subtle"],
                  font=("Segoe UI", 8), relief="flat", borderwidth=0,
                  cursor="hand2",
                  activebackground=THEME["bg_card"],
                  activeforeground=THEME["accent"],
                  command=mark_all_seen).pack(side="right")

        tk.Frame(body, bg=THEME["border_subtle"], height=1).pack(fill="x")

        # List of unseen + seen Critical/High
        scroll_canvas = tk.Canvas(body, bg=THEME["bg_card"],
                                   highlightthickness=0)
        sb = ttk.Scrollbar(body, orient="vertical",
                           command=scroll_canvas.yview)
        scroll_canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        scroll_canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(scroll_canvas, bg=THEME["bg_card"])
        win_id = scroll_canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda e: scroll_canvas.configure(
                       scrollregion=scroll_canvas.bbox("all")))
        scroll_canvas.bind("<Configure>",
                           lambda e: scroll_canvas.itemconfig(win_id, width=e.width))

        seen = set(preferences.get().seen_notifications)
        items = sorted(
            [f for f in self.findings
             if f.severity in ("Critical", "High")
             and preferences.state_for(f) == "active"],
            key=lambda f: f.timestamp, reverse=True,
        )[:30]

        if not items:
            tk.Label(inner, text="No critical or high notifications.",
                     bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 10, "italic"),
                     pady=40).pack()
        else:
            for f in items:
                is_unseen = preferences.fingerprint(f) not in seen
                row_bg = THEME["bg_card_solid"] if is_unseen else THEME["bg_card"]
                row = tk.Frame(inner, bg=row_bg, cursor="hand2")
                row.pack(fill="x", padx=8, pady=2)
                sev_color = SEVERITY_FG.get(f.severity, THEME["fg_dim"])
                tk.Frame(row, bg=sev_color, width=3).pack(side="left", fill="y")
                body_row = tk.Frame(row, bg=row_bg, padx=12, pady=10)
                body_row.pack(side="left", fill="x", expand=True)
                tk.Label(body_row,
                         text=f"{f.severity.upper()}  ·  {f.timestamp.strftime('%H:%M')}",
                         bg=row_bg, fg=sev_color,
                         font=("Segoe UI", 8, "bold"),
                         anchor="w").pack(anchor="w")
                tk.Label(body_row, text=f.title,
                         bg=row_bg, fg=THEME["fg"],
                         font=("Segoe UI Semibold", 10),
                         wraplength=380, justify="left", anchor="w").pack(
                    anchor="w", pady=(2, 0))

                def jump_to_finding(_e=None, t=f.title):
                    # Mark as seen
                    s = set(preferences.get().seen_notifications)
                    s.add(preferences.fingerprint(f))
                    preferences.get().seen_notifications = list(s)
                    preferences.save()
                    win.destroy()
                    self._update_notification_badge()
                    self.notebook.select(0)  # Health Check
                    self._card_search.set(t)
                for w in (row, body_row):
                    w.bind("<Button-1>", jump_to_finding)
                for child in body_row.winfo_children():
                    child.bind("<Button-1>", jump_to_finding)

        # Click outside to close
        win.bind("<FocusOut>", lambda e: win.destroy())
        win.focus_set()

    def load_demo_data(self, confirm: bool = True):
        """Populate the app with a curated set of synthetic findings."""
        if confirm and not messagebox.askyesno(
            "Demo mode",
            "Load synthetic findings so you can explore the app without "
            "running a real scan?\n\n"
            "This REPLACES the currently loaded data. Click 'Scan now' "
            "afterwards to get real data back.",
        ):
            return
        from src import demo_data
        self._demo_mode = True
        self.processes    = demo_data.synthetic_processes()
        self.connections  = demo_data.synthetic_connections()
        self.autoruns     = demo_data.synthetic_autoruns()
        self.events       = demo_data.synthetic_events()
        self.findings     = demo_data.synthetic_findings()
        self.services     = demo_data.synthetic_services()
        self.tasks        = demo_data.synthetic_tasks()
        self.software     = demo_data.synthetic_software()
        self.usb_devices  = demo_data.synthetic_usb()
        self.dns_entries  = demo_data.synthetic_dns()
        self.recent_files = demo_data.synthetic_recent_files()
        self.system_info  = demo_data.synthetic_system_info()

        # Re-render every tab from the synthetic data
        self._render_host_info()
        self._render_processes()
        self._render_network()
        self._render_services()
        self._render_tasks()
        self._render_autoruns()
        self._render_dns()
        self._render_usb()
        self._render_software()
        self._render_recent_files()
        self._refresh_events_table()
        self._render_dashboard()
        self._refresh_findings_table()
        self._render_health()
        self._render_timeline()

        self.status_var.set(
            "DEMO MODE — synthetic data loaded. Click 'Scan now' for real data.")
        # Switch to Health Check
        self.notebook.select(0)

    def start_guided_demo(self):
        """Load demo data and show a modern guided walkthrough."""
        self.load_demo_data(confirm=False)
        steps = [
            {
                "label": "Health",
                "tab": "Health",
                "title": "Start with the health score",
                "kicker": "The app has loaded a safe fake incident.",
                "body": (
                    "The score is the quick answer. It drops hard for Critical and High "
                    "signals, but Low and Info items are treated as review-later noise. "
                    "In a real scan, this is where a normal user starts."
                ),
                "look": "Look for the big score, the verdict, and the Recommended Actions cards below it.",
                "button": "Open Health Check",
            },
            {
                "label": "Actions",
                "tab": "Health",
                "title": "Work from the top down",
                "kicker": "Critical and High first. Low can wait.",
                "body": (
                    "Each card explains the problem, why it matters, and what to do. "
                    "This is the part built for non-technical users. No event-code treasure hunt."
                ),
                "look": "Use the severity chips to filter to Critical or High when the list is busy.",
                "button": "Show Actions",
            },
            {
                "label": "Noise",
                "tab": "Settings",
                "title": "Control Low and Info noise",
                "kicker": "Useful detail should not feel like panic.",
                "body": (
                    "In Settings, Low/Info findings can be shown, hidden, or saved for later. "
                    "Critical and High findings always stay visible, so real danger is not buried."
                ),
                "look": "Open Settings and find the Low / Info Findings section.",
                "button": "Open Settings",
            },
            {
                "label": "Investigate",
                "tab": "Findings",
                "title": "Use Findings for the full technical list",
                "kicker": "This is the analyst view.",
                "body": (
                    "The Findings tab keeps the detailed table. Sort, filter, and inspect "
                    "rules here when you want the raw list behind the plain-English cards."
                ),
                "look": "Use this view when you want everything, including Low and Info signals.",
                "button": "Open Findings",
            },
            {
                "label": "Report",
                "tab": "Reports",
                "title": "Export proof people can understand",
                "kicker": "HTML for reading. PDF for sharing.",
                "body": (
                    "Reports include a browser version, a PDF copy, and a searchable help page. "
                    "That makes it easier for a client, buyer, or family member to understand what happened."
                ),
                "look": "Open Reports to see generated HTML, PDF, JSON, and help files.",
                "button": "Open Reports",
            },
            {
                "label": "Real scan",
                "tab": "Health",
                "title": "Return to real data",
                "kicker": "The demo is fake. The next scan is real.",
                "body": (
                    "When the walkthrough is done, click Scan now. If you want full Security Event Log "
                    "coverage, launch as Administrator and approve the Windows prompt."
                ),
                "look": "Close this guide, then use Scan now for real machine data.",
                "button": "Back to Health",
            },
        ]

        win = tk.Toplevel(self)
        win.title("Guided Demo")
        win.configure(bg=THEME["bg"])
        win.geometry("960x640")
        win.transient(self)
        win.lift()

        shell = tk.Frame(win, bg=THEME["bg"], padx=22, pady=22)
        shell.pack(fill="both", expand=True)

        header = tk.Frame(shell, bg=THEME["bg"])
        header.pack(fill="x", pady=(0, 16))
        tk.Label(header, text="Guided demo",
                 bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI Semibold", 22)).pack(side="left")
        tk.Label(header, text="Safe sample incident loaded",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=14, pady=(8, 0))
        ttk.Button(header, text="Close", command=win.destroy).pack(side="right")

        body = tk.Frame(shell, bg=THEME["bg"])
        body.pack(fill="both", expand=True)

        rail = tk.Frame(body, bg=THEME["bg_panel"], width=190, padx=12, pady=12)
        rail.pack(side="left", fill="y")
        rail.pack_propagate(False)

        main = tk.Frame(body, bg=THEME["bg_card"], padx=28, pady=28)
        main.pack(side="left", fill="both", expand=True, padx=(16, 0))

        step_var = tk.IntVar(value=0)
        rail_buttons: list[tk.Label] = []

        title_lbl = tk.Label(main, text="", bg=THEME["bg_card"], fg=THEME["fg"],
                             font=("Segoe UI Semibold", 24), anchor="w", justify="left")
        title_lbl.pack(anchor="w", fill="x")
        kicker_lbl = tk.Label(main, text="", bg=THEME["bg_card"], fg=THEME["accent"],
                              font=("Segoe UI", 11, "bold"), anchor="w", justify="left")
        kicker_lbl.pack(anchor="w", fill="x", pady=(8, 20))
        body_lbl = tk.Label(main, text="", bg=THEME["bg_card"], fg=THEME["fg_dim"],
                            font=("Segoe UI", 12), wraplength=660,
                            justify="left", anchor="nw")
        body_lbl.pack(anchor="w", fill="x")

        callout = tk.Frame(main, bg=THEME["bg_card_solid"], padx=16, pady=14,
                           highlightthickness=1, highlightbackground=THEME["border"])
        callout.pack(fill="x", pady=24)
        tk.Label(callout, text="WHAT TO LOOK AT",
                 bg=THEME["bg_card_solid"], fg=THEME["fg_subtle"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        look_lbl = tk.Label(callout, text="", bg=THEME["bg_card_solid"],
                            fg=THEME["fg"], font=("Segoe UI", 11),
                            wraplength=620, justify="left", anchor="w")
        look_lbl.pack(anchor="w", fill="x", pady=(6, 0))

        progress_lbl = tk.Label(main, text="", bg=THEME["bg_card"],
                                fg=THEME["fg_subtle"], font=("Segoe UI", 9))
        progress_lbl.pack(anchor="w", pady=(4, 0))

        nav = tk.Frame(main, bg=THEME["bg_card"])
        nav.pack(side="bottom", fill="x", pady=(18, 0))
        back_btn = ttk.Button(nav, text="Back")
        next_btn = ttk.Button(nav, text="Next")
        jump_btn = ttk.Button(nav, text="Open Current Step", style="Accent.TButton")
        back_btn.pack(side="left")
        next_btn.pack(side="left", padx=8)
        jump_btn.pack(side="right")

        def jump_to(tab_name: str):
            if tab_name == "Settings":
                self.open_settings()
                return
            if tab_name == "Reports":
                self.open_reports_window()
                return
            self._jump_to_tab(tab_name)

        def render_step():
            idx = step_var.get()
            step = steps[idx]
            title_lbl.config(text=step["title"])
            kicker_lbl.config(text=step["kicker"])
            body_lbl.config(text=step["body"])
            look_lbl.config(text=step["look"])
            progress_lbl.config(text=f"Step {idx + 1} of {len(steps)}")
            jump_btn.config(text=step["button"], command=lambda s=step: jump_to(s["tab"]))
            back_btn.config(state=("disabled" if idx == 0 else "normal"))
            next_btn.config(text=("Finish" if idx == len(steps) - 1 else "Next"))
            for i, btn in enumerate(rail_buttons):
                active = i == idx
                btn.config(
                    bg=THEME["bg_active"] if active else THEME["bg_panel"],
                    fg=THEME["accent"] if active else THEME["fg_dim"],
                    font=("Segoe UI Semibold", 10) if active else ("Segoe UI", 10),
                )
            jump_to(step["tab"])

        def set_step(i: int):
            step_var.set(max(0, min(len(steps) - 1, i)))
            render_step()

        for i, step in enumerate(steps):
            row = tk.Label(rail, text=f"{i + 1}. {step['label']}",
                           bg=THEME["bg_panel"], fg=THEME["fg_dim"],
                           font=("Segoe UI", 10), anchor="w",
                           padx=10, pady=10, cursor="hand2")
            row.pack(fill="x", pady=2)
            row.bind("<Button-1>", lambda _e, n=i: set_step(n))
            rail_buttons.append(row)

        back_btn.config(command=lambda: set_step(step_var.get() - 1))
        def next_step():
            if step_var.get() >= len(steps) - 1:
                win.destroy()
            else:
                set_step(step_var.get() + 1)
        next_btn.config(command=next_step)

        render_step()

    def open_command_palette(self, _event=None):
        if hasattr(self, "_cmd_palette") and self._cmd_palette.winfo_exists():
            self._cmd_palette.lift()
            self._cmd_palette_entry.focus_set()
            return
        win = tk.Toplevel(self)
        win.title("Command Palette")
        win.configure(bg=THEME["bg_card"])
        win.overrideredirect(True)
        win.transient(self)
        win.attributes("-topmost", True)

        # Centre top of main window
        self.update_idletasks()
        w_width = 640
        x = self.winfo_rootx() + (self.winfo_width() - w_width) // 2
        y = self.winfo_rooty() + 80
        win.geometry(f"{w_width}x460+{x}+{y}")

        # Outer frame with accent border
        outer = tk.Frame(win, bg=THEME["accent"], padx=1, pady=1)
        outer.pack(fill="both", expand=True)
        body = tk.Frame(outer, bg=THEME["bg_card"])
        body.pack(fill="both", expand=True)

        # Search entry
        top = tk.Frame(body, bg=THEME["bg_card"])
        top.pack(fill="x", padx=14, pady=(14, 6))
        tk.Label(top, text="⌘", bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 12, "bold")).pack(side="left", padx=(0, 8))
        var = tk.StringVar()
        entry = tk.Entry(top, textvariable=var,
                         bg=THEME["bg_card"], fg=THEME["fg"],
                         insertbackground=THEME["fg"],
                         relief="flat", borderwidth=0,
                         font=("Segoe UI", 13))
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        tk.Label(top, text="ESC to close",
                 bg=THEME["bg_card"], fg=THEME["fg_subtle"],
                 font=("Segoe UI", 8)).pack(side="right")

        # Separator
        tk.Frame(body, bg=THEME["border"], height=1).pack(fill="x", padx=14)

        # Results
        results_frame = tk.Frame(body, bg=THEME["bg_card"])
        results_frame.pack(fill="both", expand=True, padx=4, pady=4)

        actions = self._command_palette_actions()
        rows: list[dict] = []
        selected_idx = [0]

        def render(query=""):
            q = query.lower().strip()
            for w in results_frame.winfo_children():
                w.destroy()
            rows.clear()

            # Score actions — substring match on label OR hint
            scored = []
            for label, hint, cb in actions:
                txt = (label + " " + hint).lower()
                if not q or q in txt:
                    # Higher score if query matches at word boundary in label
                    score = 0
                    if q and label.lower().startswith(q):
                        score = 10
                    elif q and q in label.lower():
                        score = 5
                    elif q and q in hint.lower():
                        score = 2
                    scored.append((score, label, hint, cb))
            scored.sort(key=lambda x: -x[0])

            for i, (_, label, hint, cb) in enumerate(scored[:14]):
                row = tk.Frame(results_frame,
                               bg=THEME["bg_card"],
                               cursor="hand2")
                row.pack(fill="x", padx=10, pady=1)
                inner = tk.Frame(row, bg=THEME["bg_card"])
                inner.pack(fill="x", padx=8, pady=6)
                lab = tk.Label(inner, text=label,
                               bg=THEME["bg_card"], fg=THEME["fg"],
                               font=("Segoe UI", 10), anchor="w")
                lab.pack(side="left")
                hint_lbl = tk.Label(inner, text=hint,
                                    bg=THEME["bg_card"], fg=THEME["fg_subtle"],
                                    font=("Segoe UI", 8), anchor="e")
                hint_lbl.pack(side="right")
                rows.append({"row": row, "inner": inner,
                             "label": lab, "hint": hint_lbl, "cb": cb})

                def go(_e=None, c=cb):
                    win.destroy()
                    c()
                for w in (row, inner, lab, hint_lbl):
                    w.bind("<Button-1>", go)
            update_highlight()

        def update_highlight():
            for i, r in enumerate(rows):
                bg = THEME["bg_active"] if i == selected_idx[0] else THEME["bg_card"]
                fg_label = THEME["accent"] if i == selected_idx[0] else THEME["fg"]
                r["row"].configure(bg=bg)
                r["inner"].configure(bg=bg)
                r["label"].configure(bg=bg, fg=fg_label)
                r["hint"].configure(bg=bg)

        def on_key(event):
            if event.keysym == "Escape":
                win.destroy()
                return "break"
            if event.keysym == "Down":
                if rows:
                    selected_idx[0] = (selected_idx[0] + 1) % len(rows)
                    update_highlight()
                return "break"
            if event.keysym == "Up":
                if rows:
                    selected_idx[0] = (selected_idx[0] - 1) % len(rows)
                    update_highlight()
                return "break"
            if event.keysym == "Return":
                if rows and 0 <= selected_idx[0] < len(rows):
                    cb = rows[selected_idx[0]]["cb"]
                    win.destroy()
                    cb()
                return "break"
            return None

        entry.bind("<Key>", on_key)
        var.trace_add("write", lambda *a: (selected_idx.__setitem__(0, 0),
                                            render(var.get())))

        # Click-outside dismiss
        win.bind("<FocusOut>", lambda e: win.destroy())
        # Initial render
        render("")
        entry.focus_set()
        self._cmd_palette = win
        self._cmd_palette_entry = entry

    def _on_close(self):
        """Save window state + last tab, then quit."""
        try:
            p = preferences.get()
            p.window_zoomed = (self.state() == "zoomed")
            if not p.window_zoomed:
                p.window_geometry = self.geometry()
            try:
                p.last_tab_index = self.notebook.index(self.notebook.select())
            except tk.TclError:
                pass
            preferences.save()
        except Exception:
            pass
        # Stop live monitor cleanly
        try:
            self._lm_running = False
            if self.live_monitor and self.live_monitor.is_alive():
                self.live_monitor.stop()
        except Exception:
            pass
        self.destroy()

    # ── Health (landing page for normal users) ────
    def _build_health_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  🏥  Health Check  ")

        # Hero strip — score gauge + headline verdict + delta vs last scan
        hero = tk.Frame(f, bg=THEME["bg_card"], padx=32, pady=24)
        hero.pack(fill="x", padx=20, pady=(20, 12))
        self._hero_frame = hero

        # Left: large gauge
        gauge_box = tk.Frame(hero, bg=THEME["bg_card"])
        gauge_box.pack(side="left", padx=(0, 32))
        self.score_canvas = tk.Canvas(
            gauge_box, width=240, height=240,
            bg=THEME["bg_card"], highlightthickness=0,
        )
        self.score_canvas.pack()
        self.score_number_lbl = tk.Label(
            gauge_box, text="0", bg=THEME["bg_card"], fg="#888",
            font=("Segoe UI", 36, "bold"),
        )
        self.score_number_lbl.place(x=0, y=78, width=240)
        self.score_grade_lbl = tk.Label(
            gauge_box, text="-", bg=THEME["bg_card"], fg=THEME["fg"],
            font=("Segoe UI", 11, "bold"),
        )
        self.score_grade_lbl.place(x=0, y=128, width=240)
        self._draw_score_gauge(0, "—", "#888")

        # Right: verdict text + delta
        text_box = tk.Frame(hero, bg=THEME["bg_card"])
        text_box.pack(side="left", fill="both", expand=True)

        tk.Label(text_box, text="YOUR PC HEALTH",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10, "bold"),
                 ).pack(anchor="w")

        self.health_verdict_lbl = tk.Label(
            text_box, text="Run a scan to see your health score.",
            bg=THEME["bg_card"], fg=THEME["fg"],
            font=("Segoe UI", 22, "bold"),
            wraplength=900, justify="left", anchor="w",
        )
        self.health_verdict_lbl.pack(anchor="w", pady=(10, 10), fill="x")

        self.health_detail_lbl = tk.Label(
            text_box, text="", bg=THEME["bg_card"], fg=THEME["fg_dim"],
            font=("Segoe UI", 11),
            wraplength=900, justify="left", anchor="w",
        )
        self.health_detail_lbl.pack(anchor="w", fill="x")

        # Delta vs last scan (green/red banner)
        self.health_delta_lbl = tk.Label(
            text_box, text="", bg=THEME["bg_card"], fg=THEME["accent"],
            font=("Segoe UI", 11, "bold"), wraplength=900,
            justify="left", anchor="w",
        )
        self.health_delta_lbl.pack(anchor="w", pady=(10, 0), fill="x")

        # Action buttons row
        btn_row = tk.Frame(text_box, bg=THEME["bg_card"])
        btn_row.pack(anchor="w", pady=(16, 0))
        ttk.Button(btn_row, text="🔄  Scan Again", style="Accent.TButton",
                   command=self.refresh).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="✨  Quick Win — fix safe items",
                   command=self.run_quick_win).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="📄  Export Report",
                   command=self.export_html).pack(side="left")
        ttk.Button(btn_row, text="Guided demo",
                   command=self.start_guided_demo).pack(side="left", padx=(8, 0))

        # Category cards row
        cats = tk.Frame(f, bg=THEME["bg"])
        cats.pack(fill="x", padx=20, pady=(0, 12))
        self._cats_frame = cats
        self.user_cat_labels: dict[str, tk.Label] = {}
        self.user_cat_buttons: dict[str, tk.Frame] = {}
        for cat in USER_CATEGORIES:
            color = USER_CATEGORY_COLORS[cat]
            icon = USER_CATEGORY_ICONS[cat]
            card = tk.Frame(cats, bg=THEME["bg_card"], padx=18, pady=14,
                            highlightthickness=3, highlightbackground=color,
                            cursor="hand2")
            card.pack(side="left", expand=True, fill="x", padx=4)
            tk.Label(card, text=icon, bg=THEME["bg_card"], fg=color,
                     font=("Segoe UI Emoji", 22)).pack(side="left", padx=(0, 12))
            text_col = tk.Frame(card, bg=THEME["bg_card"])
            text_col.pack(side="left", fill="x", expand=True)
            tk.Label(text_col, text=cat, bg=THEME["bg_card"], fg=color,
                     font=("Segoe UI", 10, "bold"),
                     anchor="w").pack(anchor="w")
            count_lbl = tk.Label(
                text_col, text="—", bg=THEME["bg_card"], fg=THEME["fg"],
                font=("Segoe UI", 16, "bold"), anchor="w",
            )
            count_lbl.pack(anchor="w")
            self.user_cat_labels[cat] = count_lbl
            self.user_cat_buttons[cat] = card
            # Click to filter cards by this category
            for w in (card, text_col, count_lbl):
                w.bind("<Button-1>",
                       lambda e, c=cat: self._set_card_filter(category=c))

        # Filter / search bar (pill-style)
        filt = tk.Frame(f, bg=THEME["bg"])
        filt.pack(fill="x", padx=20, pady=(4, 8))
        self._filter_row = filt

        tk.Label(filt, text="📋  RECOMMENDED ACTIONS",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 11, "bold")).pack(side="left")

        # Severity chips
        self._sev_filter = tk.StringVar(value="All")
        self._cat_filter = tk.StringVar(value="All")
        chip_box = tk.Frame(filt, bg=THEME["bg"])
        chip_box.pack(side="right")

        for sev in ["All", "Critical", "High", "Medium", "Low"]:
            color = SEVERITY_FG.get(sev, THEME["fg_dim"]) if sev != "All" else THEME["accent"]
            btn = tk.Label(
                chip_box, text=sev, bg=THEME["bg_panel"], fg=color,
                font=("Segoe UI", 9, "bold"),
                padx=12, pady=4, cursor="hand2",
            )
            btn.pack(side="left", padx=2)
            btn.bind("<Button-1>", lambda e, s=sev: self._set_card_filter(severity=s))

        # Search row
        search_row = tk.Frame(f, bg=THEME["bg"])
        search_row.pack(fill="x", padx=20, pady=(0, 6))
        tk.Label(search_row, text="🔍",
                 bg=THEME["bg"], fg=THEME["fg_dim"]).pack(side="left", padx=(0, 6))
        self._card_search = tk.StringVar()
        self._card_search.trace_add("write", lambda *a: self._render_action_cards())
        ttk.Entry(search_row, textvariable=self._card_search, width=40).pack(
            side="left", padx=(0, 14))

        self.health_filter_lbl = tk.Label(
            search_row, text="", bg=THEME["bg"], fg=THEME["fg_dim"],
            font=("Segoe UI", 9, "italic"))
        self.health_filter_lbl.pack(side="left")

        ttk.Button(search_row, text="↗  Open in window",
                   command=self._open_actions_popout
                   ).pack(side="right", padx=(6, 0))
        self._hero_toggle_btn = ttk.Button(
            search_row, text="▲  Hide hero",
            command=self._toggle_hero,
        )
        self._hero_toggle_btn.pack(side="right", padx=(6, 0))
        ttk.Button(search_row, text="Clear filters",
                   command=lambda: self._set_card_filter(reset=True)
                   ).pack(side="right")

        # Scrollable cards area
        canvas_frame = tk.Frame(f, bg=THEME["bg"])
        canvas_frame.pack(fill="both", expand=True, padx=20, pady=(4, 20))

        self.cards_canvas = tk.Canvas(
            canvas_frame, bg=THEME["bg"], highlightthickness=0,
        )
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical",
                                  command=self.cards_canvas.yview)
        self.cards_canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.cards_canvas.pack(side="left", fill="both", expand=True)

        self.cards_inner = tk.Frame(self.cards_canvas, bg=THEME["bg"])
        self.cards_window_id = self.cards_canvas.create_window(
            (0, 0), window=self.cards_inner, anchor="nw",
        )
        self.cards_inner.bind("<Configure>", self._on_cards_configure)
        self.cards_canvas.bind("<Configure>", self._on_canvas_resize)
        # Scope mousewheel to when cursor is over the cards canvas — avoids
        # fighting Treeview / sidebar scrolling and stops the scroll glitch.
        self.cards_canvas.bind(
            "<Enter>",
            lambda e: self.cards_canvas.bind_all(
                "<MouseWheel>", self._on_mousewheel),
        )
        self.cards_canvas.bind(
            "<Leave>",
            lambda e: self.cards_canvas.unbind_all("<MouseWheel>"),
        )

    def _toggle_hero(self):
        """Collapse / expand the hero + category cards to give the list more space."""
        if self._hero_collapsed:
            # Re-pack ABOVE the filter row so they end up in original positions
            self._hero_frame.pack(fill="x", padx=20, pady=(20, 12),
                                  before=self._filter_row)
            self._cats_frame.pack(fill="x", padx=20, pady=(0, 12),
                                  before=self._filter_row)
            self._hero_toggle_btn.config(text="▲  Hide hero")
            self._hero_collapsed = False
        else:
            self._hero_frame.pack_forget()
            self._cats_frame.pack_forget()
            self._hero_toggle_btn.config(text="▼  Show hero")
            self._hero_collapsed = True

    def _open_actions_popout(self):
        """Pop the action cards out into a dedicated full-screen window."""
        # Bring existing window to front instead of opening a duplicate
        if (self._popout_window is not None
                and self._popout_window.winfo_exists()):
            self._popout_window.lift()
            self._popout_window.focus_force()
            return

        win = tk.Toplevel(self)
        win.title("Recommended Actions — Log Sentinel")
        win.configure(bg=THEME["bg"])
        win.geometry("1500x950")
        try:
            win.state("zoomed")
        except tk.TclError:
            pass

        # Header bar
        header = tk.Frame(win, bg=THEME["bg_panel"], height=64)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="📋  Recommended Actions",
                 bg=THEME["bg_panel"], fg=THEME["accent"],
                 font=("Segoe UI", 16, "bold")).pack(side="left", padx=20)
        tk.Label(header,
                 text="Full-screen view — same filters, same actions as the Health Check tab.",
                 bg=THEME["bg_panel"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10, "italic")).pack(side="left", padx=8)

        # Filter row
        filt = tk.Frame(win, bg=THEME["bg"])
        filt.pack(fill="x", padx=24, pady=(14, 6))

        tk.Label(filt, text="Severity:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left")
        for sev in ["All", "Critical", "High", "Medium", "Low"]:
            color = SEVERITY_FG.get(sev, THEME["fg_dim"]) if sev != "All" else THEME["accent"]
            btn = tk.Label(
                filt, text=sev, bg=THEME["bg_panel"], fg=color,
                font=("Segoe UI", 9, "bold"),
                padx=12, pady=4, cursor="hand2",
            )
            btn.pack(side="left", padx=2)
            btn.bind("<Button-1>",
                     lambda e, s=sev: self._set_card_filter(severity=s))

        tk.Label(filt, text="   Category:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(12, 0))
        for cat in ["All"] + USER_CATEGORIES:
            color = (USER_CATEGORY_COLORS.get(cat, THEME["fg_dim"])
                     if cat != "All" else THEME["accent"])
            btn = tk.Label(
                filt, text=cat, bg=THEME["bg_panel"], fg=color,
                font=("Segoe UI", 9, "bold"),
                padx=12, pady=4, cursor="hand2",
            )
            btn.pack(side="left", padx=2)
            btn.bind("<Button-1>",
                     lambda e, c=cat: self._set_card_filter(
                         category=(None if c == "All" else c),
                         **({"severity": "All"} if c == "All" else {}),
                     ))

        # Search row
        srow = tk.Frame(win, bg=THEME["bg"])
        srow.pack(fill="x", padx=24, pady=(0, 6))
        tk.Label(srow, text="🔍",
                 bg=THEME["bg"], fg=THEME["fg_dim"]).pack(side="left")
        ttk.Entry(srow, textvariable=self._card_search, width=50).pack(
            side="left", padx=(6, 14))

        self._popout_filter_lbl = tk.Label(
            srow, text="", bg=THEME["bg"], fg=THEME["fg_dim"],
            font=("Segoe UI", 9, "italic"))
        self._popout_filter_lbl.pack(side="left")

        ttk.Button(srow, text="Clear filters",
                   command=lambda: self._set_card_filter(reset=True)
                   ).pack(side="right")

        # Scrollable cards area (full height)
        canvas_frame = tk.Frame(win, bg=THEME["bg"])
        canvas_frame.pack(fill="both", expand=True, padx=24, pady=(8, 18))

        canvas = tk.Canvas(canvas_frame, bg=THEME["bg"],
                           highlightthickness=0)
        sb = ttk.Scrollbar(canvas_frame, orient="vertical",
                           command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=THEME["bg"])
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_configure(_e=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def _on_canvas_resize(e):
            canvas.itemconfig(win_id, width=e.width)
        def _on_wheel(e):
            try:
                if win.winfo_exists():
                    canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
            except tk.TclError:
                pass

        inner.bind("<Configure>", _on_inner_configure)
        canvas.bind("<Configure>", _on_canvas_resize)
        win.bind("<MouseWheel>", _on_wheel)

        # Cleanup on close
        def _on_close():
            self._popout_window = None
            self._popout_inner = None
            self._popout_filter_lbl = None
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", _on_close)

        # Wire up + render
        self._popout_window = win
        self._popout_inner = inner
        self._render_action_cards()

    def _set_card_filter(self, severity: str | None = None,
                         category: str | None = None, reset: bool = False):
        if reset:
            self._sev_filter.set("All")
            self._cat_filter.set("All")
            self._card_search.set("")
        else:
            if severity is not None:
                self._sev_filter.set(severity)
            if category is not None:
                # Toggle off if already selected
                if self._cat_filter.get() == category:
                    self._cat_filter.set("All")
                else:
                    self._cat_filter.set(category)
        self._render_action_cards()

    def _sensitivity_text(self, severity: str) -> str:
        return SENSITIVITY_LABELS.get(severity, severity)

    def _sensitivity_settings_text(self, severity: str) -> str:
        return f"{SENSITIVITY_LABELS.get(severity, severity)} - {SENSITIVITY_DESCRIPTIONS.get(severity, '')}"

    def _build_sensitivity_control(self, parent, pady=(0, 8), compact=False,
                                   on_change=None):
        box = tk.Frame(
            parent,
            bg=THEME["bg_card"],
            padx=14 if compact else 18,
            pady=12 if compact else 16,
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        box.pack(fill="x", padx=20 if compact else 0, pady=pady)

        top = tk.Frame(box, bg=THEME["bg_card"])
        top.pack(fill="x")
        tk.Label(
            top,
            text="Sensitivity control",
            bg=THEME["bg_card"],
            fg=THEME["fg"],
            font=("Segoe UI", 10 if compact else 11, "bold"),
        ).pack(side="left")
        label = tk.Label(
            top,
            text="",
            bg=THEME["bg_card"],
            fg=THEME["accent"],
            font=("Segoe UI", 10, "bold"),
        )
        label.pack(side="right")

        desc = tk.Label(
            box,
            text="",
            bg=THEME["bg_card"],
            fg=THEME["fg_dim"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
        )
        desc.pack(fill="x", pady=(4, 10))

        row = tk.Frame(box, bg=THEME["bg_card"])
        row.pack(fill="x")
        buttons = []
        for sev in SENSITIVITY_LEVELS:
            color = SEVERITY_FG.get(sev, THEME["accent"])
            btn = tk.Label(
                row,
                text=SENSITIVITY_LABELS[sev],
                bg=THEME["bg_panel"],
                fg=color,
                font=("Segoe UI", 8 if compact else 9, "bold"),
                padx=10,
                pady=7,
                cursor="hand2",
                highlightthickness=2,
                highlightbackground=THEME["border_subtle"],
            )
            btn.pack(side="left", fill="x", expand=True, padx=2)
            btn.bind("<Button-1>", lambda _e, s=sev: on_change(s) if on_change else None)
            buttons.append((sev, btn))

        tick_row = tk.Frame(box, bg=THEME["bg_card"])
        tick_row.pack(fill="x", pady=(7, 0))
        for text in ["More detail", "", "", "", "Less noise"]:
            tk.Label(
                tick_row,
                text=text,
                bg=THEME["bg_card"],
                fg=THEME["fg_subtle"],
                font=("Segoe UI", 8),
            ).pack(side="left", fill="x", expand=True)

        return label, desc, buttons

    def _set_sensitivity_visuals(self, severity: str, label, desc, buttons):
        if label is not None:
            label.config(text=self._sensitivity_text(severity))
        if desc is not None:
            desc.config(text=SENSITIVITY_DESCRIPTIONS.get(severity, ""))
        selected_idx = SENSITIVITY_LEVELS.index(severity)
        for idx, (sev, btn) in enumerate(buttons or []):
            selected = idx == selected_idx
            btn.config(
                bg=SEVERITY_FG.get(sev, THEME["accent"]) if selected else THEME["bg_panel"],
                fg="#000" if selected else SEVERITY_FG.get(sev, THEME["fg"]),
                highlightbackground=SEVERITY_FG.get(sev, THEME["accent"]) if selected else THEME["border_subtle"],
            )

    def _on_sensitivity_pick(self, severity: str):
        self._sensitivity_var.set(SENSITIVITY_LEVELS.index(severity))
        self._apply_sensitivity(severity)

    def _on_sensitivity_change(self, value):
        idx = max(0, min(len(SENSITIVITY_LEVELS) - 1, int(float(value))))
        severity = SENSITIVITY_LEVELS[idx]
        self._apply_sensitivity(severity)

    def _apply_sensitivity(self, severity: str):
        if hasattr(self, "_sensitivity_label"):
            self._set_sensitivity_visuals(
                severity,
                getattr(self, "_sensitivity_label", None),
                getattr(self, "_sensitivity_desc_label", None),
                getattr(self, "_sensitivity_buttons", []),
            )
        if hasattr(self, "_settings_sensitivity_label"):
            try:
                self._settings_sensitivity_label.config(
                    text=self._sensitivity_settings_text(severity)
                )
            except tk.TclError:
                pass
        p = preferences.get()
        if p.min_severity == severity:
            return
        p.min_severity = severity
        preferences.save()
        self._render_health()
        self._refresh_findings_table()
        self._render_dashboard()
        self._update_notification_badge()

    def _on_cards_configure(self, _e=None):
        self.cards_canvas.configure(scrollregion=self.cards_canvas.bbox("all"))

    def _on_canvas_resize(self, e):
        self.cards_canvas.itemconfig(self.cards_window_id, width=e.width)

    def _on_mousewheel(self, e):
        # Only scroll when on the Health tab
        try:
            if self.notebook.tab(self.notebook.select(), "text").strip().startswith("🏥"):
                self.cards_canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        except tk.TclError:
            pass

    def _draw_score_gauge(self, score: int, grade: str, color: str):
        c = self.score_canvas
        c.delete("all")
        cx, cy, r = 100, 100, 80
        # Background ring
        c.create_oval(cx-r, cy-r, cx+r, cy+r, outline="#3d3d5c", width=14)
        # Progress arc
        if score > 0:
            extent = -(score / 100) * 360
            c.create_arc(cx-r, cy-r, cx+r, cy+r, start=90, extent=extent,
                         outline=color, width=14, style="arc")
        # Score number
        if hasattr(self, "score_number_lbl"):
            self.score_number_lbl.config(text=str(score), fg=color)
        if hasattr(self, "score_grade_lbl"):
            grade_text = f"Grade {grade}" if grade != "—" else "-"
            self.score_grade_lbl.config(text=grade_text, fg=THEME["fg"])

    def _render_health(self):
        # Filter out user-snoozed/ignored/resolved
        active_findings = preferences.filter_active(self.findings)
        health = calc_health(active_findings)
        self._draw_score_gauge(health.score, health.grade, health.color)
        self.health_verdict_lbl.config(text=health.verdict, fg=health.color)
        self.health_detail_lbl.config(text=health.detail)

        # Compute delta vs last scan
        diff = scan_history.diff_against_last(active_findings)
        delta_text = ""
        if not diff.get("is_first_scan"):
            last_score = diff.get("last_score", 0)
            change = health.score - last_score
            new_n = len(diff["new"])
            resolved_n = len(diff["resolved"])
            arrow = "↑" if change > 0 else ("↓" if change < 0 else "—")
            color = "#4ecdc4" if change >= 0 else "#ff7f50"
            parts = [f"{arrow} {abs(change)} pts vs last scan"]
            if new_n: parts.append(f"{new_n} new")
            if resolved_n: parts.append(f"{resolved_n} resolved")
            delta_text = "   ·   ".join(parts)
            self.health_delta_lbl.config(text=delta_text, fg=color)
        else:
            self.health_delta_lbl.config(
                text="First scan — we'll track changes from next time.",
                fg=THEME["fg_dim"])

        # User-category counts (active only)
        cat_counts = {c: 0 for c in USER_CATEGORIES}
        for f in active_findings:
            ucat = explain(f.rule).user_category
            cat_counts[ucat] = cat_counts.get(ucat, 0) + 1
        for cat, lbl in self.user_cat_labels.items():
            n = cat_counts[cat]
            lbl.config(text=str(n))

        # Save scan to history
        try:
            scan_history.save_scan(
                health, active_findings,
                len(self.events), len(self.processes), len(self.connections),
            )
        except Exception:
            pass

        # Render the cards with current filters
        self._render_action_cards()
        self._render_trends_chart()

    def _render_action_cards(self):
        """Render the recommended-action cards into all open card containers."""
        # Build the list of targets: main tab + pop-out window (if open)
        targets: list = []
        if hasattr(self, "cards_inner") and self.cards_inner.winfo_exists():
            targets.append(self.cards_inner)
        if (hasattr(self, "_popout_inner")
                and self._popout_inner is not None
                and self._popout_inner.winfo_exists()):
            targets.append(self._popout_inner)
        if not targets:
            return

        active = preferences.filter_active(self.findings)
        hidden_low = preferences.low_priority_hidden_count(self.findings)
        sev_f = self._sev_filter.get()
        cat_f = self._cat_filter.get()
        search = self._card_search.get().lower().strip()

        def keep(f) -> bool:
            if sev_f != "All" and f.severity != sev_f:
                return False
            if cat_f != "All" and explain(f.rule).user_category != cat_f:
                return False
            if search:
                pe = explain(f.rule)
                blob = (f.title + " " + pe.problem + " "
                        + pe.why_matters + " " + f.rule).lower()
                if search not in blob:
                    return False
            return True

        # Pinned items first, then by severity, then by timestamp
        def sort_key(f):
            pinned = 1 if preferences.is_pinned(f) else 0
            ts = f.timestamp.isoformat() if getattr(f, "timestamp", None) else ""
            return (pinned, SEVERITY_ORDER.get(f.severity, 0), ts)
        active.sort(key=sort_key, reverse=True)
        visible = [f for f in active if keep(f)]

        # Filter status labels (both windows)
        status_text = (
            f"showing {len(visible)} of {len(active)} active issues"
            if (sev_f != "All" or cat_f != "All" or search)
            else f"{len(active)} active issue{'s' if len(active)!=1 else ''}"
        )
        if hidden_low:
            status_text += f" ({hidden_low} hidden by sensitivity/settings)"
        if hasattr(self, "health_filter_lbl"):
            try:
                self.health_filter_lbl.config(text=status_text)
            except tk.TclError:
                pass
        if hasattr(self, "_popout_filter_lbl") and self._popout_filter_lbl is not None:
            try:
                self._popout_filter_lbl.config(text=status_text)
            except tk.TclError:
                pass

        for target in targets:
            for w in target.winfo_children():
                w.destroy()

            if not visible:
                empty = tk.Frame(target, bg=THEME["bg_card"], pady=40)
                empty.pack(fill="x", pady=10)
                tk.Label(empty, text="✓",
                         bg=THEME["bg_card"], fg="#4ecdc4",
                         font=("Segoe UI", 36)).pack()
                tk.Label(empty,
                         text="Nothing matches your filters."
                         if (sev_f != "All" or cat_f != "All" or search)
                         else "Your computer looks clean.",
                         bg=THEME["bg_card"], fg=THEME["fg"],
                         font=("Segoe UI", 13)).pack(pady=(8, 0))
                tk.Label(empty,
                         text="Either run a fresh scan or clear filters."
                         if (sev_f != "All" or cat_f != "All" or search)
                         else "We didn't find any active issues. Snoozed and resolved items are hidden.",
                         bg=THEME["bg_card"], fg=THEME["fg_dim"],
                         font=("Segoe UI", 10)).pack()
                continue

            # Cap rendered cards for performance — 50 was too heavy on slow machines
            CARD_CAP = 25
            for f in visible[:CARD_CAP]:
                self._build_action_card(target, f)
            if len(visible) > CARD_CAP:
                tk.Label(
                    target,
                    text=f"Showing first {CARD_CAP} of {len(visible)} — "
                         "narrow the filter to see more, or click '↗ Open in window'.",
                    bg=THEME["bg"], fg=THEME["fg_dim"],
                    font=("Segoe UI", 9, "italic"),
                ).pack(pady=10)

    def _build_action_card(self, parent, finding):
        pe = explain(finding.rule)
        sev_color = SEVERITY_FG.get(finding.severity, THEME["fg_dim"])
        ucat_color = USER_CATEGORY_COLORS.get(pe.user_category, THEME["fg_dim"])
        card_bg = THEME["bg_card"]

        # Outer wrapper — subtle border, no shadow (Tkinter limit)
        wrap = tk.Frame(parent, bg=THEME["bg"])
        wrap.pack(fill="x", pady=8)

        card = tk.Frame(wrap, bg=card_bg,
                        highlightthickness=1,
                        highlightbackground=THEME["border_subtle"])
        card.pack(fill="x")

        # Thin coloured top stripe (severity)
        stripe = tk.Frame(card, bg=sev_color, height=3)
        stripe.pack(fill="x")

        body = tk.Frame(card, bg=card_bg, padx=28, pady=22)
        body.pack(fill="x")

        # ─── Header row ───
        header = tk.Frame(body, bg=card_bg)
        header.pack(fill="x")

        # Severity pill — flatter, smaller
        sev_pill = tk.Label(
            header, text=finding.severity.upper(),
            bg=sev_color, fg="#0a0a0f",
            font=("Segoe UI", 8, "bold"),
            padx=10, pady=3,
        )
        sev_pill.pack(side="left", padx=(0, 8))

        # Category pill (outline style)
        cat_pill = tk.Label(
            header,
            text=f"{USER_CATEGORY_ICONS[pe.user_category]}  {pe.user_category}",
            bg=card_bg, fg=ucat_color,
            font=("Segoe UI", 8, "bold"),
            padx=10, pady=3,
            highlightthickness=1, highlightbackground=THEME["border"],
        )
        cat_pill.pack(side="left")

        # Pin indicator (right side, before MITRE)
        if preferences.is_pinned(finding):
            tk.Label(header, text="📌  PINNED",
                     bg=card_bg, fg=THEME["accent"],
                     font=("Segoe UI", 8, "bold")).pack(side="right", padx=(0, 10))

        # Right: MITRE tech ID (link)
        tech = technique_for_rule(finding.rule)
        if tech:
            mitre_lbl = tk.Label(
                header, text=f"MITRE  {tech.technique_id}  ↗",
                bg=card_bg, fg=THEME["fg_subtle"],
                font=("Segoe UI", 8), cursor="hand2",
            )
            mitre_lbl.pack(side="right")
            mitre_lbl.bind("<Button-1>",
                           lambda e, t=tech: webbrowser.open(t.url))
            # Hover effect
            def _on_enter(_e=None, l=mitre_lbl):
                l.configure(fg=THEME["accent"])
            def _on_leave(_e=None, l=mitre_lbl):
                l.configure(fg=THEME["fg_subtle"])
            mitre_lbl.bind("<Enter>", _on_enter)
            mitre_lbl.bind("<Leave>", _on_leave)

        # ─── Headline (problem) ───
        tk.Label(
            body, text=pe.problem,
            bg=card_bg, fg=THEME["fg"],
            font=("Segoe UI Semibold", 14),
            wraplength=1100, justify="left", anchor="w",
        ).pack(fill="x", pady=(18, 4))

        # ─── Two-column body ───
        cols = tk.Frame(body, bg=card_bg)
        cols.pack(fill="x", pady=(10, 0))
        cols.grid_columnconfigure(0, weight=1, uniform="col")
        cols.grid_columnconfigure(1, weight=1, uniform="col")

        # Why it matters
        why_col = tk.Frame(cols, bg=card_bg)
        why_col.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        tk.Label(why_col, text="WHY IT MATTERS",
                 bg=card_bg, fg=THEME["fg_subtle"],
                 font=("Segoe UI", 7, "bold")).pack(anchor="w", pady=(0, 6))
        tk.Label(why_col, text=pe.why_matters,
                 bg=card_bg, fg=THEME["fg_dim"],
                 font=("Segoe UI", 10),
                 wraplength=520, justify="left", anchor="w").pack(fill="x")

        # What to do
        do_col = tk.Frame(cols, bg=card_bg)
        do_col.grid(row=0, column=1, sticky="nsew")
        tk.Label(do_col, text="WHAT TO DO",
                 bg=card_bg, fg=THEME["accent"],
                 font=("Segoe UI", 7, "bold")).pack(anchor="w", pady=(0, 6))
        tk.Label(do_col, text=pe.what_to_do,
                 bg=card_bg, fg=THEME["fg"],
                 font=("Segoe UI", 10),
                 wraplength=520, justify="left", anchor="w").pack(fill="x")

        # ─── Divider ───
        tk.Frame(body, bg=THEME["border_subtle"], height=1).pack(
            fill="x", pady=(20, 14))

        # ─── Action row ───
        bottom = tk.Frame(body, bg=card_bg)
        bottom.pack(fill="x")

        actions = actions_for_finding(finding)
        for act in actions[:3]:
            ttk.Button(bottom, text=act.label,
                       command=lambda a=act, f=finding: self._run_action(a, f)
                       ).pack(side="left", padx=(0, 6))

        # Right-side state controls (compact)
        state_box = tk.Frame(bottom, bg=card_bg)
        state_box.pack(side="right")

        # Done = primary accent action
        ttk.Button(state_box, text="✓ Done", style="Accent.TButton",
                   command=lambda f=finding: self._mark_resolved(f)).pack(
            side="left", padx=(0, 6))
        # Secondary — flat
        for txt, fn in [
            ("Snooze 7d", lambda f=finding: self._snooze(f, 7)),
            ("Ignore",    lambda f=finding: self._ignore(f)),
            ("Details",   lambda f=finding: self._show_finding_details(f)),
        ]:
            ttk.Button(state_box, text=txt,
                       command=fn).pack(side="left", padx=(0, 4))

    def _mark_resolved(self, finding):
        preferences.resolve(finding)
        self._render_health()

    def _snooze(self, finding, days: int = 7):
        preferences.snooze(finding, days=days)
        self._render_health()

    def _ignore(self, finding):
        if messagebox.askyesno(
            "Ignore this finding",
            "We'll never show this exact finding again.\n\n"
            "If it appears in a future scan, you won't be alerted. "
            "You can clear ignored items from Settings.\n\nContinue?"
        ):
            preferences.ignore(finding)
            self._render_health()

    def _run_action(self, action, finding):
        confirm = messagebox.askyesno(
            f"Run: {action.label}",
            f"{action.description}\n\n"
            + ("⚠ Requires Administrator privileges. Run Log Sentinel as admin if this fails.\n\n"
               if action.requires_admin else "")
            + "Continue?",
        )
        if not confirm:
            return
        if action.run is None:
            messagebox.showinfo("Action", "No automatic fix — see the description.")
            return
        try:
            ok, msg = action.run()
        except Exception as e:
            ok, msg = False, str(e)
        if ok:
            messagebox.showinfo("Done", msg or "Action completed successfully.")
        else:
            messagebox.showerror("Action failed", msg or "Unknown error.")

    def _show_finding_details(self, finding):
        tech = technique_for_rule(finding.rule)
        text = (
            f"Severity   : {finding.severity}\n"
            f"Rule       : {finding.rule}\n"
            f"Time       : {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        if tech:
            text += f"MITRE      : {tech.technique_id} — {tech.name} ({tech.tactic})\n"
            text += f"Reference  : {tech.url}\n"
        text += f"\n{finding.description}\n"
        messagebox.showinfo(finding.title, text)

    # ── Trends tab ────────────────────────────────
    def _build_trends_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  📈  Trends  ")

        hero = tk.Frame(f, bg=THEME["bg_card"], padx=32, pady=24)
        hero.pack(fill="x", padx=20, pady=(20, 12))

        tk.Label(hero, text="HEALTH SCORE OVER TIME",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(hero, text="Track your PC health across scans.",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 11)).pack(anchor="w", pady=(4, 12))

        # Chart canvas
        self.trend_canvas = tk.Canvas(
            hero, height=260, bg=THEME["bg_card"], highlightthickness=0,
        )
        self.trend_canvas.pack(fill="x")
        self.trend_canvas.bind("<Configure>", lambda e: self._render_trends_chart())

        # Stats summary
        stats = tk.Frame(f, bg=THEME["bg"])
        stats.pack(fill="x", padx=20, pady=12)

        self.trend_stats_labels: dict[str, tk.Label] = {}
        for key, label in [
            ("avg",     "Average score"),
            ("best",    "Best score"),
            ("worst",   "Worst score"),
            ("scans",   "Scans recorded"),
        ]:
            card = tk.Frame(stats, bg=THEME["bg_card"], padx=20, pady=14)
            card.pack(side="left", expand=True, fill="x", padx=4)
            tk.Label(card, text=label, bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 9, "bold"),
                     anchor="w").pack(anchor="w")
            v = tk.Label(card, text="—", bg=THEME["bg_card"], fg=THEME["fg"],
                         font=("Segoe UI", 22, "bold"), anchor="w")
            v.pack(anchor="w", pady=(4, 0))
            self.trend_stats_labels[key] = v

        # ─── Compare scans (diff view) ───
        diff_card = tk.Frame(f, bg=THEME["bg_card"], padx=24, pady=18)
        diff_card.pack(fill="x", padx=20, pady=(8, 8))
        tk.Label(diff_card, text="⇄  COMPARE SCANS",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(diff_card,
                 text="See what's new / resolved / unchanged between two scans.",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 10))

        # Picker row
        pick_row = tk.Frame(diff_card, bg=THEME["bg_card"])
        pick_row.pack(fill="x")
        tk.Label(pick_row, text="From:", bg=THEME["bg_card"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(0, 6))
        self._diff_from = tk.StringVar()
        self._diff_from_cb = ttk.Combobox(
            pick_row, textvariable=self._diff_from,
            state="readonly", width=26,
        )
        self._diff_from_cb.pack(side="left", padx=(0, 14))

        tk.Label(pick_row, text="To:", bg=THEME["bg_card"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(0, 6))
        self._diff_to = tk.StringVar()
        self._diff_to_cb = ttk.Combobox(
            pick_row, textvariable=self._diff_to,
            state="readonly", width=26,
        )
        self._diff_to_cb.pack(side="left", padx=(0, 14))

        ttk.Button(pick_row, text="🔍  Compare",
                   command=self._render_diff,
                   style="Accent.TButton").pack(side="left")

        # Diff result area
        self._diff_result = tk.Frame(diff_card, bg=THEME["bg_card"])
        self._diff_result.pack(fill="both", expand=True, pady=(14, 0))

        # Recent scans list
        tk.Label(f, text="RECENT SCANS",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=20, pady=(12, 6))

        cols = ("when", "score", "grade", "findings", "events")
        self.trend_tree = ttk.Treeview(
            f, columns=cols, show="headings", height=10,
        )
        for col, w in [("when", 220), ("score", 100), ("grade", 80),
                       ("findings", 120), ("events", 120)]:
            self.trend_tree.heading(col, text=col.title())
            self.trend_tree.column(col, width=w, anchor="w")
        self.trend_tree.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    def _render_trends_chart(self):
        """Draw a simple line chart of health scores on self.trend_canvas."""
        if not hasattr(self, "trend_canvas"):
            return
        c = self.trend_canvas
        c.delete("all")
        try:
            c.update_idletasks()
            w = c.winfo_width()
            h = c.winfo_height()
        except tk.TclError:
            return
        if w < 2 or h < 2:
            return

        history = scan_history.load_history()
        if not history:
            c.create_text(w // 2, h // 2,
                          text="No scans recorded yet — run a scan to start tracking.",
                          fill=THEME["fg_dim"], font=("Segoe UI", 11, "italic"))
            return

        # Margins
        L, R, T, B = 50, 30, 30, 36
        plot_w = max(1, w - L - R)
        plot_h = max(1, h - T - B)

        # Y axis: 0-100 with grid lines at 0/25/50/75/100
        for y_val in (0, 25, 50, 75, 100):
            y = T + plot_h - (y_val / 100) * plot_h
            c.create_line(L, y, w - R, y, fill="#2d2d4a", width=1)
            c.create_text(L - 8, y, text=str(y_val), anchor="e",
                          fill=THEME["fg_dim"], font=("Segoe UI", 8))

        # X axis labels: first and last
        first_t = datetime.fromisoformat(history[0].timestamp)
        last_t = datetime.fromisoformat(history[-1].timestamp)
        c.create_text(L, h - B + 6, text=first_t.strftime("%m-%d"),
                      anchor="nw", fill=THEME["fg_dim"], font=("Segoe UI", 8))
        c.create_text(w - R, h - B + 6, text=last_t.strftime("%m-%d"),
                      anchor="ne", fill=THEME["fg_dim"], font=("Segoe UI", 8))

        # Plot points
        n = len(history)
        if n == 1:
            x = L + plot_w / 2
            y = T + plot_h - (history[0].score / 100) * plot_h
            c.create_oval(x - 6, y - 6, x + 6, y + 6,
                          fill=THEME["accent"], outline="")
            return

        # Multi-point line
        prev = None
        for i, scan in enumerate(history):
            x = L + (i / (n - 1)) * plot_w
            y = T + plot_h - (scan.score / 100) * plot_h
            color = (
                "#4ecdc4" if scan.score >= 80
                else "#ffd93d" if scan.score >= 60
                else "#ff7f50" if scan.score >= 30
                else "#ff4757"
            )
            if prev:
                px, py = prev
                c.create_line(px, py, x, y, fill=THEME["accent"], width=2,
                              smooth=True)
            c.create_oval(x - 4, y - 4, x + 4, y + 4,
                          fill=color, outline="")
            prev = (x, y)

    def _render_trends_stats(self):
        if not hasattr(self, "trend_stats_labels"):
            return
        history = scan_history.load_history()
        if not history:
            for v in self.trend_stats_labels.values():
                v.config(text="—")
            for row in self.trend_tree.get_children():
                self.trend_tree.delete(row)
            return
        scores = [s.score for s in history]
        self.trend_stats_labels["avg"].config(text=f"{sum(scores)//len(scores)}")
        self.trend_stats_labels["best"].config(text=str(max(scores)))
        self.trend_stats_labels["worst"].config(text=str(min(scores)))
        self.trend_stats_labels["scans"].config(text=str(len(history)))

        for row in self.trend_tree.get_children():
            self.trend_tree.delete(row)
        for s in reversed(history[-30:]):
            ts = datetime.fromisoformat(s.timestamp).strftime("%Y-%m-%d %H:%M")
            self.trend_tree.insert("", "end", values=(
                ts, s.score, s.grade, s.total_findings, s.total_events,
            ))

        # Populate diff dropdowns
        if hasattr(self, "_diff_from_cb"):
            labels = [
                f"{datetime.fromisoformat(s.timestamp).strftime('%Y-%m-%d %H:%M')}  ({s.score}, {s.grade})"
                for s in history
            ]
            self._diff_from_cb["values"] = labels
            self._diff_to_cb["values"] = labels
            if len(labels) >= 2:
                if not self._diff_from.get():
                    self._diff_from.set(labels[-2])
                if not self._diff_to.get():
                    self._diff_to.set(labels[-1])

    def _render_diff(self):
        """Compute and display the diff between two saved scans."""
        if not hasattr(self, "_diff_result"):
            return
        import json
        for w in self._diff_result.winfo_children():
            w.destroy()

        history = scan_history.load_history()
        if len(history) < 2:
            tk.Label(
                self._diff_result,
                text="Need at least 2 scans to compare. Run a scan to add another.",
                bg=THEME["bg_card"], fg=THEME["fg_dim"],
                font=("Segoe UI", 10, "italic"),
            ).pack(anchor="w", pady=10)
            return

        # Find selected entries from the labels (label format: TIMESTAMP  (score, grade))
        def find_scan(label: str):
            for s in history:
                ts = datetime.fromisoformat(s.timestamp).strftime("%Y-%m-%d %H:%M")
                if label.startswith(ts):
                    return s
            return None

        from_scan = find_scan(self._diff_from.get())
        to_scan   = find_scan(self._diff_to.get())
        if not from_scan or not to_scan:
            tk.Label(self._diff_result,
                     text="Pick two scans from the dropdowns above.",
                     bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 10, "italic")).pack(anchor="w")
            return

        # Load the fingerprint files for each
        from src import scan_history as sh
        try:
            f1 = json.loads((sh.HISTORY_DIR / from_scan.file).read_text(encoding="utf-8"))
            f2 = json.loads((sh.HISTORY_DIR / to_scan.file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            tk.Label(self._diff_result, text=f"Couldn't load scan files: {e}",
                     bg=THEME["bg_card"], fg="#ff7f50",
                     font=("Segoe UI", 10)).pack(anchor="w")
            return

        fps1 = {f["fp"]: f for f in f1}
        fps2 = {f["fp"]: f for f in f2}
        new      = [fps2[fp] for fp in fps2 if fp not in fps1]
        resolved = [fps1[fp] for fp in fps1 if fp not in fps2]
        unchanged = sum(1 for fp in fps2 if fp in fps1)

        # Summary banner
        summary = tk.Frame(self._diff_result, bg=THEME["bg_card"])
        summary.pack(fill="x", pady=(0, 14))
        score_diff = to_scan.score - from_scan.score
        delta_color = THEME["accent"] if score_diff >= 0 else "#ff4757"
        arrow = "↑" if score_diff > 0 else ("↓" if score_diff < 0 else "—")
        tk.Label(summary,
                 text=f"{from_scan.score} ({from_scan.grade})  →  {to_scan.score} ({to_scan.grade})",
                 bg=THEME["bg_card"], fg=THEME["fg"],
                 font=("Segoe UI", 16, "bold")).pack(side="left")
        tk.Label(summary,
                 text=f"  {arrow} {abs(score_diff)} pts",
                 bg=THEME["bg_card"], fg=delta_color,
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=(8, 0))
        tk.Label(summary,
                 text=f"    {len(new)} new   ·   {len(resolved)} resolved   ·   {unchanged} unchanged",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 11)).pack(side="left", padx=(20, 0))

        # Two columns: new (left) + resolved (right)
        cols = tk.Frame(self._diff_result, bg=THEME["bg_card"])
        cols.pack(fill="both", expand=True)
        cols.grid_columnconfigure(0, weight=1, uniform="x")
        cols.grid_columnconfigure(1, weight=1, uniform="x")

        def column(parent, title, color, items, max_show=15):
            col = tk.Frame(parent, bg=THEME["bg_card"])
            col.pack(side="left", fill="both", expand=True, padx=4)
            tk.Label(col, text=title,
                     bg=THEME["bg_card"], fg=color,
                     font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 6))
            if not items:
                tk.Label(col, text="(none)",
                         bg=THEME["bg_card"], fg=THEME["fg_subtle"],
                         font=("Segoe UI", 9, "italic")).pack(anchor="w")
                return
            for it in items[:max_show]:
                row = tk.Frame(col, bg=THEME["bg_card_solid"])
                row.pack(fill="x", pady=2)
                sev = it.get("severity", "Low")
                sev_color = SEVERITY_FG.get(sev, THEME["fg_dim"])
                tk.Label(row, text=sev,
                         bg=sev_color, fg="#000",
                         font=("Segoe UI", 7, "bold"),
                         padx=6, pady=2).pack(side="left")
                tk.Label(row, text=it.get("title", "?"),
                         bg=THEME["bg_card_solid"], fg=THEME["fg"],
                         font=("Segoe UI", 9), anchor="w",
                         wraplength=420, justify="left").pack(
                    side="left", padx=8, fill="x", expand=True, pady=3)
            if len(items) > max_show:
                tk.Label(col, text=f"+ {len(items) - max_show} more …",
                         bg=THEME["bg_card"], fg=THEME["fg_subtle"],
                         font=("Segoe UI", 9, "italic")).pack(anchor="w", pady=4)

        left = tk.Frame(cols, bg=THEME["bg_card"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        column(left, "🆕  NEW SINCE FIRST SCAN", "#ff7f50", new)

        right = tk.Frame(cols, bg=THEME["bg_card"])
        right.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        column(right, "✓  RESOLVED", THEME["accent"], resolved)

    # ── Quick Win action ──────────────────────────
    def run_quick_win(self):
        plan = quick_win.build_plan(self.findings)
        if plan.total() == 0:
            messagebox.showinfo(
                "Quick Win",
                "Nothing safe to auto-fix right now. "
                "Look at the Recommended Actions cards to take action manually.",
            )
            return

        ar = len(plan.safe_disable_autoruns)
        sn = len(plan.snooze_low_priority)
        msg = "Quick Win will automatically:\n\n"
        if ar:
            msg += f"  • Disable {ar} suspicious autorun{'s' if ar != 1 else ''} (reversible)\n"
        if sn:
            msg += f"  • Snooze {sn} low-priority informational issue{'s' if sn != 1 else ''} for 30 days\n"
        msg += "\nNothing will be deleted. Continue?"

        if not messagebox.askyesno("Quick Win", msg):
            return

        result = quick_win.run_plan(plan)
        report = (
            f"✓ {len(result.succeeded)} fixes applied\n"
            f"✗ {len(result.failed)} failed\n"
            f"💤 {result.snoozed} snoozed for 30 days\n"
        )
        if result.failed:
            report += "\nFailures:\n" + "\n".join(
                f"  • {t}: {m}" for t, m in result.failed[:5]
            )
        messagebox.showinfo("Quick Win — Done", report)
        self._render_health()

    # ── Settings dialog ───────────────────────────
    def open_settings(self):
        win = tk.Toplevel(self)
        win.title("Settings — Log Sentinel")
        win.configure(bg=THEME["bg"])
        win.geometry("680x820")
        win.transient(self)
        win.grab_set()

        # Center, but don't go larger than 90% of screen height
        win.update_idletasks()
        sh = win.winfo_screenheight()
        h = min(820, int(sh * 0.9))
        x = (win.winfo_screenwidth() - 680) // 2
        y = (sh - h) // 2
        win.geometry(f"680x{h}+{x}+{y}")

        header = tk.Frame(win, bg=THEME["accent"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="⚙  Settings", bg=THEME["accent"], fg="#000",
                 font=("Segoe UI", 16, "bold")).pack(pady=14)

        # Scrollable body so all sections fit
        outer = tk.Frame(win, bg=THEME["bg"])
        outer.pack(fill="both", expand=True)
        canvas = tk.Canvas(outer, bg=THEME["bg"], highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body = tk.Frame(canvas, bg=THEME["bg"], padx=24, pady=20)
        body_id = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>",
                  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(body_id, width=e.width))
        # Scoped wheel — only when cursor is over this canvas
        def _on_wheel(e, _c=canvas):
            _c.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind("<Enter>",
                    lambda e: canvas.bind_all("<MouseWheel>", _on_wheel))
        canvas.bind("<Leave>",
                    lambda e: canvas.unbind_all("<MouseWheel>"))

        prefs = preferences.get()

        # Snooze stats
        tk.Label(body, text="USER STATE",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        s = preferences.stats()
        info = (f"  • {s['snoozed']} finding{'s' if s['snoozed'] != 1 else ''} snoozed\n"
                f"  • {s['ignored']} finding{'s' if s['ignored'] != 1 else ''} ignored\n"
                f"  • {s['resolved']} finding{'s' if s['resolved'] != 1 else ''} marked resolved")
        tk.Label(body, text=info, bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI", 10), justify="left",
                 anchor="w").pack(anchor="w", pady=(6, 6))
        ttk.Button(body, text="Clear all snoozed / ignored / resolved",
                   command=lambda: self._reset_finding_state(win)).pack(
            anchor="w", pady=(0, 16))

        # Licence status
        lic = licensing.status()
        tk.Label(body, text="LICENCE",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(12, 4))
        lic_lines = [f"  {lic.message}"]
        if lic.mode == "trial":
            lic_lines.append(f"  Trial expires: {lic.trial_expires}")
        if lic.mode == "licensed":
            lic_lines.append(f"  Plan: {lic.plan}")
            lic_lines.append(f"  Licence expires: {lic.license_expires}")
        tk.Label(body, text="\n".join(lic_lines),
                 bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI", 10), justify="left",
                 anchor="w").pack(anchor="w", pady=(6, 6))
        ttk.Button(body, text="Open activation",
                   command=lambda: self.open_license_window()).pack(
            anchor="w", pady=(0, 16))

        # Theme toggle
        tk.Label(body, text="APPEARANCE",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(12, 4))
        self._theme_var = tk.StringVar(value=prefs.theme)
        theme_row = tk.Frame(body, bg=THEME["bg"])
        theme_row.pack(anchor="w", pady=(2, 0), fill="x")
        for val, label in [("dark", "  🌙  Dark"), ("light", "  ☀  Light")]:
            tk.Radiobutton(theme_row, text=label, variable=self._theme_var,
                           value=val,
                           command=lambda: self._on_theme_change(win),
                           bg=THEME["bg"], fg=THEME["fg"],
                           selectcolor=THEME["bg_panel"],
                           activebackground=THEME["bg"],
                           font=("Segoe UI", 10)).pack(side="left", padx=(0, 16))
        tk.Label(body, text="(Restart Log Sentinel to fully apply.)",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "italic")).pack(anchor="w", pady=(4, 12))

        # Scheduled scans
        tk.Label(body, text="SCHEDULED SCANS",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(8, 4))

        from src import scheduler
        sched_info = scheduler.info()
        if sched_info.registered:
            sched_text = (f"  ✓ Active.  Next run: {sched_info.next_run or '?'}\n"
                          f"            Last run: {sched_info.last_run or '?'}")
        else:
            sched_text = "  Not scheduled. Set an interval below to enable."
        tk.Label(body, text=sched_text,
                 bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI", 10), justify="left",
                 anchor="w").pack(anchor="w")

        sched_row = tk.Frame(body, bg=THEME["bg"])
        sched_row.pack(anchor="w", pady=(6, 0), fill="x")
        tk.Label(sched_row, text="Run every", bg=THEME["bg"],
                 fg=THEME["fg"]).pack(side="left", padx=(0, 6))
        self._sched_interval = tk.StringVar(value=str(prefs.scan_schedule_hours))
        ttk.Combobox(sched_row, textvariable=self._sched_interval,
                     values=["1", "6", "12", "24", "48", "168"],
                     state="readonly", width=6).pack(side="left")
        tk.Label(sched_row, text="hours", bg=THEME["bg"],
                 fg=THEME["fg"]).pack(side="left", padx=(6, 12))
        ttk.Button(sched_row, text="✓ Enable",
                   command=lambda: self._enable_schedule(win)).pack(
            side="left", padx=2)
        ttk.Button(sched_row, text="✕ Disable",
                   command=lambda: self._disable_schedule(win)).pack(
            side="left", padx=2)
        ttk.Button(sched_row, text="▶ Run now",
                   command=lambda: self._run_schedule_now(win)).pack(
            side="left", padx=2)

        # Custom rules
        tk.Label(body, text="CUSTOM DETECTION RULES",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(12, 4))
        from src import custom_rules, fim, honeypots, email_alerts
        rules = custom_rules.load_rules()
        enabled = sum(1 for r in rules if r.get("enabled", True))
        tk.Label(body,
                 text=f"  {len(rules)} rule(s) defined, {enabled} enabled.",
                 bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        rules_row = tk.Frame(body, bg=THEME["bg"])
        rules_row.pack(anchor="w", pady=(6, 0))
        ttk.Button(rules_row, text="Open rules editor",
                   command=lambda: self._open_rules_editor(win)).pack(
            side="left", padx=(0, 6))
        ttk.Button(rules_row, text="Edit JSON file",
                   command=self._open_rules_file).pack(side="left", padx=(0, 6))
        ttk.Button(rules_row, text="Restore defaults",
                   command=lambda: self._restore_default_rules(win)).pack(
            side="left")

        # File Integrity Monitor
        tk.Label(body, text="FILE INTEGRITY MONITOR",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(14, 4))
        watchlist = fim.load_watchlist()
        baseline_n = fim.baseline_size()
        tk.Label(body,
                 text=f"  Watching {len(watchlist)} file(s)  ·  baseline: "
                      f"{baseline_n} captured.",
                 bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        fim_row = tk.Frame(body, bg=THEME["bg"])
        fim_row.pack(anchor="w", pady=(6, 0))
        ttk.Button(fim_row, text="Manage watchlist",
                   command=lambda: self._open_fim_editor(win)).pack(
            side="left", padx=(0, 6))
        ttk.Button(fim_row, text="Reset baseline",
                   command=lambda: self._reset_fim_baseline(win)).pack(
            side="left")

        # Honeypots
        tk.Label(body, text="HONEYPOT FILES",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(14, 4))
        traps = honeypots.load()
        tk.Label(body,
                 text=f"  {len(traps)} tripwire file(s) deployed.",
                 bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        hp_row = tk.Frame(body, bg=THEME["bg"])
        hp_row.pack(anchor="w", pady=(6, 0))
        ttk.Button(hp_row, text="Deploy / manage honeypots",
                   command=lambda: self._open_honeypot_editor(win)).pack(
            side="left", padx=(0, 6))

        # Email
        tk.Label(body, text="EMAIL ALERTS (SMTP)",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(14, 4))
        ec = email_alerts.load_config()
        if ec.enabled and ec.smtp_host:
            email_text = (f"  ✓ Active.  Sends to {len(ec.to_addresses)} "
                          f"address(es) via {ec.smtp_host}:{ec.smtp_port}")
        else:
            email_text = "  Disabled."
        tk.Label(body, text=email_text,
                 bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        email_row = tk.Frame(body, bg=THEME["bg"])
        email_row.pack(anchor="w", pady=(6, 0))
        ttk.Button(email_row, text="Configure email alerts",
                   command=lambda: self._open_email_editor(win)).pack(
            side="left", padx=(0, 6))

        # Auto-open report toggle
        tk.Label(body, text="REPORTS",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(12, 4))
        self._auto_open_var = tk.BooleanVar(value=prefs.auto_open_report)
        tk.Checkbutton(body, text="Open exported report in browser automatically",
                       variable=self._auto_open_var, bg=THEME["bg"],
                       fg=THEME["fg"], selectcolor=THEME["bg_panel"],
                       activebackground=THEME["bg"],
                       font=("Segoe UI", 10),
                       command=lambda: self._save_pref("auto_open_report",
                                                      self._auto_open_var.get())
                       ).pack(anchor="w")

        # Low priority visibility
        tk.Label(body, text="LOW / INFO FINDINGS",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(16, 4))
        tk.Label(body,
                 text="Choose how much small-noise detail appears in Health Check. "
                      "Critical and High are always shown.",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9), wraplength=720, justify="left").pack(anchor="w")
        self._low_mode_var = tk.StringVar(value=prefs.low_priority_mode)
        low_row = tk.Frame(body, bg=THEME["bg"])
        low_row.pack(anchor="w", pady=(6, 0), fill="x")
        for val, label in [
            ("show", "Show Low/Info"),
            ("hide", "Hide Low/Info"),
            ("later", "Show later"),
        ]:
            tk.Radiobutton(
                low_row, text=label, variable=self._low_mode_var,
                value=val, command=self._on_low_priority_change,
                bg=THEME["bg"], fg=THEME["fg"],
                selectcolor=THEME["bg_panel"],
                activebackground=THEME["bg"],
                font=("Segoe UI", 10),
            ).pack(side="left", padx=(0, 16))

        tk.Label(body, text="GLOBAL SENSITIVITY",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(16, 4))
        tk.Label(body,
                 text="Choose the minimum severity shown in Health Check and Findings. "
                      "Move right for a quieter view; move left for more detail.",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9), wraplength=720, justify="left").pack(anchor="w")
        current_sev = prefs.min_severity if prefs.min_severity in SENSITIVITY_LEVELS else "Info"
        sens_row = tk.Frame(body, bg=THEME["bg"])
        sens_row.pack(anchor="w", fill="x", pady=(8, 8))
        self._settings_sensitivity_var = tk.StringVar(value=current_sev)
        ttk.Combobox(
            sens_row,
            textvariable=self._settings_sensitivity_var,
            values=SENSITIVITY_LEVELS,
            state="readonly",
            width=16,
        ).pack(side="left")
        self._settings_sensitivity_label = tk.Label(
            sens_row,
            text=self._sensitivity_settings_text(current_sev),
            bg=THEME["bg"],
            fg=THEME["accent"],
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        )
        self._settings_sensitivity_label.pack(side="left", padx=(12, 0))
        self._settings_sensitivity_var.trace_add(
            "write",
            lambda *a: self._on_settings_sensitivity_dropdown(),
        )

        # Scan history
        tk.Label(body, text="SCAN HISTORY",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(16, 4))
        history = scan_history.load_history()
        tk.Label(body, text=f"  {len(history)} scan{'s' if len(history) != 1 else ''} recorded",
                 bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        ttk.Button(body, text="Clear scan history",
                   command=lambda: self._clear_history(win)).pack(
            anchor="w", pady=(6, 16))

        # About
        tk.Label(body, text="ABOUT",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(16, 4))
        tk.Label(body,
                 text="Log Sentinel  ·  v1.0\n"
                      "Local-only system & security log analyser.\n"
                      "No telemetry, no cloud — your data stays on your machine.",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10),
                 justify="left").pack(anchor="w", pady=(0, 8))

        ttk.Button(body, text="Re-run welcome tour",
                   command=lambda: self._replay_welcome(win)).pack(anchor="w")
        ttk.Button(body, text="Start guided demo",
                   command=self.start_guided_demo).pack(anchor="w", pady=(6, 0))

        # Close button
        bottom = tk.Frame(win, bg=THEME["bg"], pady=14)
        bottom.pack(fill="x", side="bottom")
        ttk.Button(bottom, text="Close", style="Accent.TButton",
                   command=win.destroy).pack(side="right", padx=18)

    def _save_pref(self, key, value):
        p = preferences.get()
        setattr(p, key, value)
        preferences.save()

    def _on_low_priority_change(self):
        mode = self._low_mode_var.get()
        self._save_pref("low_priority_mode", mode)
        if mode == "later":
            messagebox.showinfo(
                "Low/Info set to show later",
                "Low and Info findings are hidden from Health Check for now. "
                "They still remain visible in the full Findings tab.",
            )
        self._render_health()
        self._render_dashboard()
        self._update_notification_badge()

    def _on_settings_sensitivity_change(self, value):
        idx = max(0, min(len(SENSITIVITY_LEVELS) - 1, int(float(value))))
        severity = SENSITIVITY_LEVELS[idx]
        if hasattr(self, "_sensitivity_var"):
            self._sensitivity_var.set(idx)
        self._apply_sensitivity(severity)

    def _on_settings_sensitivity_pick(self, severity: str):
        idx = SENSITIVITY_LEVELS.index(severity)
        if hasattr(self, "_settings_sensitivity_var"):
            self._settings_sensitivity_var.set(idx)
        if hasattr(self, "_sensitivity_var"):
            self._sensitivity_var.set(idx)
        self._apply_sensitivity(severity)

    def _on_settings_sensitivity_dropdown(self):
        severity = self._settings_sensitivity_var.get()
        if severity not in SENSITIVITY_LEVELS:
            severity = "Info"
        self._apply_sensitivity(severity)

    def _on_theme_change(self, parent):
        choice = self._theme_var.get()
        self._save_pref("theme", choice)
        apply_theme(choice)
        messagebox.showinfo(
            "Theme changed",
            f"Theme set to {choice.title()}. Close and re-open Log Sentinel "
            "to apply the new theme everywhere.",
            parent=parent,
        )

    def _enable_schedule(self, parent):
        from src import scheduler
        try:
            hours = int(self._sched_interval.get())
        except ValueError:
            hours = 24
        ok, msg = scheduler.register(hours)
        if ok:
            self._save_pref("scan_schedule_enabled", True)
            self._save_pref("scan_schedule_hours", hours)
            messagebox.showinfo("Scheduled", msg, parent=parent)
        else:
            messagebox.showerror("Failed", msg, parent=parent)

    def _disable_schedule(self, parent):
        from src import scheduler
        ok, msg = scheduler.unregister()
        self._save_pref("scan_schedule_enabled", False)
        if ok:
            messagebox.showinfo("Disabled",
                                "Scheduled scan removed.", parent=parent)
        else:
            messagebox.showerror("Failed", msg, parent=parent)

    def _run_schedule_now(self, parent):
        from src import scheduler
        if not scheduler.is_registered():
            messagebox.showinfo(
                "Not scheduled",
                "Enable scheduled scans first, then you can trigger one.",
                parent=parent)
            return
        ok, msg = scheduler.run_now()
        if ok:
            messagebox.showinfo(
                "Triggered",
                "Scheduled scan triggered — it'll run in the background. "
                "Open Trends tab in a few minutes to see the result.",
                parent=parent)
        else:
            messagebox.showerror("Failed", msg, parent=parent)

    def _reset_finding_state(self, parent):
        if messagebox.askyesno("Clear user state",
                               "Forget every snoozed, ignored, and resolved finding?",
                               parent=parent):
            preferences.reset()
            messagebox.showinfo("Done", "Cleared.", parent=parent)
            self._render_health()

    def _clear_history(self, parent):
        if messagebox.askyesno("Clear history",
                               "Delete all saved scan history?",
                               parent=parent):
            scan_history.clear_history()
            messagebox.showinfo("Done", "Scan history cleared.", parent=parent)
            self._render_trends_chart()
            self._render_trends_stats()

    def _replay_welcome(self, parent):
        if self._welcome_marker.exists():
            self._welcome_marker.unlink()
        parent.destroy()
        self._show_welcome()

    # ──────────────────────────────────────────
    # Custom rules editor
    # ──────────────────────────────────────────
    def _open_rules_editor(self, parent):
        from src import custom_rules
        win = tk.Toplevel(self)
        win.title("Custom Detection Rules — Log Sentinel")
        win.configure(bg=THEME["bg"])
        win.geometry("980x700")
        win.transient(self)
        win.grab_set()

        header = tk.Frame(win, bg=THEME["accent"], height=56)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="🛠  Custom Detection Rules",
                 bg=THEME["accent"], fg="#000",
                 font=("Segoe UI", 14, "bold")).pack(pady=14)

        body = tk.Frame(win, bg=THEME["bg"], padx=18, pady=14)
        body.pack(fill="both", expand=True)

        tk.Label(body,
                 text="Each rule fires when ANY condition in its match block "
                      "matches. Toggle Enabled / edit the JSON / save to apply "
                      "from the next scan.",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10),
                 wraplength=900, justify="left").pack(anchor="w", pady=(0, 10))

        # Two-column layout: rules list left, JSON editor right
        cols = tk.Frame(body, bg=THEME["bg"])
        cols.pack(fill="both", expand=True)

        # Left: rules list
        list_frame = tk.Frame(cols, bg=THEME["bg_card"], padx=10, pady=10)
        list_frame.pack(side="left", fill="y", padx=(0, 8))
        tk.Label(list_frame, text="RULES",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")

        cols2 = ("enabled", "name", "severity")
        rules_tree = ttk.Treeview(list_frame, columns=cols2,
                                  show="headings", height=18,
                                  selectmode="browse")
        for col, w in [("enabled", 60), ("name", 240), ("severity", 90)]:
            rules_tree.heading(col, text=col.title())
            rules_tree.column(col, width=w, anchor="w")
        rules_tree.pack(fill="y", pady=(8, 0))

        # Right: JSON editor
        editor_frame = tk.Frame(cols, bg=THEME["bg_card"], padx=10, pady=10)
        editor_frame.pack(side="left", fill="both", expand=True)
        tk.Label(editor_frame, text="RULE JSON",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        editor = tk.Text(editor_frame, bg=THEME["bg_panel"], fg=THEME["fg"],
                         insertbackground=THEME["fg"],
                         font=("Consolas", 10), wrap="word",
                         relief="flat", padx=10, pady=8)
        editor.pack(fill="both", expand=True, pady=(8, 0))

        # Buttons
        btns = tk.Frame(body, bg=THEME["bg"])
        btns.pack(fill="x", pady=(10, 0))

        rules_state = {"items": custom_rules.load_rules(),
                        "selected_idx": None}

        def refresh_list():
            for r in rules_tree.get_children():
                rules_tree.delete(r)
            for i, rule in enumerate(rules_state["items"]):
                rules_tree.insert("", "end", iid=str(i), values=(
                    "✓" if rule.get("enabled", True) else "✗",
                    rule.get("name", rule.get("id", "?")),
                    rule.get("severity", "Medium"),
                ))

        def show_selected(_e=None):
            sel = rules_tree.selection()
            if not sel:
                return
            idx = int(sel[0])
            rules_state["selected_idx"] = idx
            rule = rules_state["items"][idx]
            editor.delete("1.0", "end")
            editor.insert("1.0", json.dumps(rule, indent=2))

        def save_current():
            idx = rules_state["selected_idx"]
            if idx is None:
                messagebox.showinfo("Save",
                                    "Select a rule first.", parent=win)
                return
            try:
                rule = json.loads(editor.get("1.0", "end").strip())
            except json.JSONDecodeError as e:
                messagebox.showerror("Invalid JSON", str(e), parent=win)
                return
            rules_state["items"][idx] = rule
            custom_rules.save_rules(rules_state["items"])
            refresh_list()
            messagebox.showinfo("Saved",
                                "Rule saved. It applies from the next scan.",
                                parent=win)

        def toggle_enabled():
            idx = rules_state["selected_idx"]
            if idx is None:
                return
            rule = rules_state["items"][idx]
            rule["enabled"] = not rule.get("enabled", True)
            custom_rules.save_rules(rules_state["items"])
            refresh_list()
            show_selected()

        def add_new():
            new_rule = {
                "id":         f"my-rule-{len(rules_state['items']) + 1}",
                "enabled":    True,
                "name":       "My new rule",
                "severity":   "Medium",
                "category":   "Process Activity",
                "user_category": "Security",
                "problem":    "Description of what was detected.",
                "why_matters": "Why the user should care.",
                "what_to_do":  "Step-by-step remediation.",
                "match": {
                    "type": "process",
                    "name_in": ["something.exe"],
                },
            }
            rules_state["items"].append(new_rule)
            custom_rules.save_rules(rules_state["items"])
            refresh_list()
            rules_tree.selection_set(str(len(rules_state["items"]) - 1))
            show_selected()

        def delete_current():
            idx = rules_state["selected_idx"]
            if idx is None:
                return
            if not messagebox.askyesno("Delete rule",
                                       "Delete this rule?", parent=win):
                return
            rules_state["items"].pop(idx)
            custom_rules.save_rules(rules_state["items"])
            rules_state["selected_idx"] = None
            editor.delete("1.0", "end")
            refresh_list()

        rules_tree.bind("<<TreeviewSelect>>", show_selected)

        ttk.Button(btns, text="➕  Add rule", command=add_new).pack(
            side="left", padx=(0, 6))
        ttk.Button(btns, text="✓  Toggle enabled",
                   command=toggle_enabled).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="💾  Save changes",
                   style="Accent.TButton",
                   command=save_current).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="🗑  Delete",
                   command=delete_current).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Close",
                   command=win.destroy).pack(side="right")

        refresh_list()
        if rules_state["items"]:
            rules_tree.selection_set("0")
            show_selected()

    def _open_rules_file(self):
        from src import custom_rules
        custom_rules._ensure_rules_file()
        path = custom_rules.RULES_FILE
        try:
            os.startfile(str(path))  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            messagebox.showinfo("Rules file", f"Rules are stored at:\n{path}")

    def _restore_default_rules(self, parent):
        if not messagebox.askyesno(
            "Restore defaults",
            "Replace your custom rules with the built-in defaults?\n\n"
            "Your existing rules will be overwritten.",
            parent=parent,
        ):
            return
        from src import custom_rules
        custom_rules.restore_defaults()
        messagebox.showinfo("Restored",
                            "Default rules loaded.", parent=parent)

    # ──────────────────────────────────────────
    # File Integrity Monitor editor
    # ──────────────────────────────────────────
    def _open_fim_editor(self, parent):
        from src import fim
        win = tk.Toplevel(self)
        win.title("File Integrity Monitor — Watchlist")
        win.configure(bg=THEME["bg"])
        win.geometry("780x520")
        win.transient(self)
        win.grab_set()

        header = tk.Frame(win, bg=THEME["accent"], height=56)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="🔍  File Integrity Monitor",
                 bg=THEME["accent"], fg="#000",
                 font=("Segoe UI", 14, "bold")).pack(pady=14)

        body = tk.Frame(win, bg=THEME["bg"], padx=18, pady=16)
        body.pack(fill="both", expand=True)

        tk.Label(body,
                 text=("On every scan, every file in this list is hashed and "
                       "compared against the recorded baseline. Any change "
                       "shows up as a Finding."),
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10),
                 wraplength=720, justify="left").pack(anchor="w", pady=(0, 12))

        cols = ("path", "note")
        tree = ttk.Treeview(body, columns=cols, show="headings",
                            selectmode="browse", height=10)
        for col, w in [("path", 460), ("note", 280)]:
            tree.heading(col, text=col.title())
            tree.column(col, width=w, anchor="w")
        tree.pack(fill="both", expand=True, pady=(0, 10))

        def refresh():
            for r in tree.get_children():
                tree.delete(r)
            for w in fim.load_watchlist():
                tree.insert("", "end", iid=w.path,
                            values=(w.path, w.note or "—"))

        # Add controls
        add_row = tk.Frame(body, bg=THEME["bg"])
        add_row.pack(fill="x", pady=(0, 8))
        tk.Label(add_row, text="Path:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(0, 6))
        path_var = tk.StringVar()
        ttk.Entry(add_row, textvariable=path_var).pack(
            side="left", fill="x", expand=True, padx=(0, 6), ipady=3)
        def browse():
            p = filedialog.askopenfilename(parent=win,
                                            title="Pick a file to monitor")
            if p:
                path_var.set(p)
        ttk.Button(add_row, text="Browse…", command=browse).pack(side="left")

        note_row = tk.Frame(body, bg=THEME["bg"])
        note_row.pack(fill="x", pady=(0, 8))
        tk.Label(note_row, text="Note:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(0, 6))
        note_var = tk.StringVar()
        ttk.Entry(note_row, textvariable=note_var).pack(
            side="left", fill="x", expand=True, ipady=3)

        # Action buttons
        btns = tk.Frame(body, bg=THEME["bg"])
        btns.pack(fill="x")

        def add_clicked():
            ok, msg = fim.add_path(path_var.get().strip(),
                                    note_var.get().strip())
            if ok:
                path_var.set("")
                note_var.set("")
                refresh()
                messagebox.showinfo("Added", msg, parent=win)
            else:
                messagebox.showerror("Failed", msg, parent=win)

        def remove_clicked():
            sel = tree.selection()
            if not sel:
                return
            ok, msg = fim.remove_path(sel[0])
            refresh()

        def reset_clicked():
            if not messagebox.askyesno(
                "Reset baseline",
                "Re-snapshot every watched file? This treats their CURRENT "
                "state as the new baseline. Future changes will be detected "
                "from this point forward.",
                parent=win,
            ):
                return
            done, miss = fim.reset_baseline()
            messagebox.showinfo(
                "Done",
                f"Captured {done} file(s) into baseline."
                + (f" {miss} unreachable." if miss else ""),
                parent=win,
            )

        ttk.Button(btns, text="➕  Add", style="Accent.TButton",
                   command=add_clicked).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="🗑  Remove",
                   command=remove_clicked).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="📸  Reset baseline",
                   command=reset_clicked).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Close",
                   command=win.destroy).pack(side="right")

        refresh()

    def _reset_fim_baseline(self, parent):
        if not messagebox.askyesno(
            "Reset FIM baseline",
            "Capture every monitored file's CURRENT state as the baseline?\n\n"
            "Use this after you legitimately update Windows or apps — anything "
            "that changes from now on will be flagged.",
            parent=parent,
        ):
            return
        from src import fim
        done, miss = fim.reset_baseline()
        messagebox.showinfo(
            "Baseline reset",
            f"Captured {done} file(s)."
            + (f" {miss} unreachable." if miss else ""),
            parent=parent,
        )

    # ──────────────────────────────────────────
    # Honeypot editor
    # ──────────────────────────────────────────
    def _open_honeypot_editor(self, parent):
        from src import honeypots
        win = tk.Toplevel(self)
        win.title("Honeypot tripwires")
        win.configure(bg=THEME["bg"])
        win.geometry("820x600")
        win.transient(self)
        win.grab_set()

        header = tk.Frame(win, bg=THEME["accent"], height=56)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="🍯  Honeypot Tripwires",
                 bg=THEME["accent"], fg="#000",
                 font=("Segoe UI", 14, "bold")).pack(pady=14)

        body = tk.Frame(win, bg=THEME["bg"], padx=18, pady=16)
        body.pack(fill="both", expand=True)

        tk.Label(body,
                 text=("Drop fake juicy files (passwords.txt, wallet_backup.txt, "
                       "etc.) in folders. If anything modifies, deletes, or "
                       "even READS them, you get a Critical alert. Real users "
                       "ignore them — attackers and ransomware cannot resist."),
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10),
                 wraplength=760, justify="left").pack(anchor="w", pady=(0, 12))

        # Deploy form
        form_card = tk.Frame(body, bg=THEME["bg_card"], padx=16, pady=12)
        form_card.pack(fill="x", pady=(0, 12))
        tk.Label(form_card, text="DEPLOY A NEW TRIPWIRE",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")

        # Folder selection
        f_row = tk.Frame(form_card, bg=THEME["bg_card"])
        f_row.pack(fill="x", pady=(8, 6))
        tk.Label(f_row, text="Folder:",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 width=10, anchor="w").pack(side="left")
        folder_var = tk.StringVar(value=str(Path.home() / "Documents"))
        ttk.Entry(f_row, textvariable=folder_var).pack(
            side="left", fill="x", expand=True, padx=(0, 6), ipady=3)
        def browse_folder():
            p = filedialog.askdirectory(parent=win)
            if p:
                folder_var.set(p)
        ttk.Button(f_row, text="Browse…", command=browse_folder).pack(side="left")

        # Quick presets
        quick_row = tk.Frame(form_card, bg=THEME["bg_card"])
        quick_row.pack(fill="x", pady=(0, 8))
        tk.Label(quick_row, text="Quick:",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 width=10, anchor="w").pack(side="left")
        for label, path in honeypots.common_locations():
            ttk.Button(quick_row, text=label,
                       command=lambda p=path: folder_var.set(p)
                       ).pack(side="left", padx=(0, 4))

        # Template
        t_row = tk.Frame(form_card, bg=THEME["bg_card"])
        t_row.pack(fill="x", pady=(0, 8))
        tk.Label(t_row, text="Template:",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 width=10, anchor="w").pack(side="left")
        template_var = tk.StringVar(value="passwords.txt")
        templates = list(honeypots.HONEYPOT_TEMPLATES.keys())
        ttk.Combobox(t_row, textvariable=template_var,
                     values=templates, state="readonly").pack(
            side="left", fill="x", expand=True, ipady=2)

        deploy_btns = tk.Frame(form_card, bg=THEME["bg_card"])
        deploy_btns.pack(fill="x", pady=(8, 0))

        def deploy_clicked():
            ok, msg = honeypots.place(folder_var.get().strip(),
                                       template_var.get())
            if ok:
                refresh_list()
                messagebox.showinfo("Deployed", msg, parent=win)
            else:
                messagebox.showerror("Failed", msg, parent=win)

        ttk.Button(deploy_btns, text="🪤  Deploy tripwire",
                   style="Accent.TButton",
                   command=deploy_clicked).pack(side="left")

        # List
        tk.Label(body, text="ACTIVE TRIPWIRES",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(8, 4))

        cols = ("path", "placed_at", "rationale")
        tree = ttk.Treeview(body, columns=cols, show="headings",
                            selectmode="browse", height=8)
        for col, w in [("path", 480), ("placed_at", 140), ("rationale", 260)]:
            tree.heading(col, text=col.replace("_", " ").title())
            tree.column(col, width=w, anchor="w")
        tree.pack(fill="both", expand=True, pady=(0, 10))

        def refresh_list():
            for r in tree.get_children():
                tree.delete(r)
            for h in honeypots.load():
                placed = h.placed_at[:16].replace("T", " ")
                tree.insert("", "end", iid=h.path,
                            values=(h.path, placed, h.rationale or "—"))

        bb = tk.Frame(body, bg=THEME["bg"])
        bb.pack(fill="x")

        def remove_clicked():
            sel = tree.selection()
            if not sel:
                return
            if not messagebox.askyesno(
                "Remove honeypot",
                "Remove this tripwire and DELETE the file from disk?",
                parent=win,
            ):
                return
            ok, msg = honeypots.remove(sel[0])
            refresh_list()

        def remove_all_clicked():
            if not messagebox.askyesno(
                "Remove all",
                "Remove every tripwire?",
                parent=win,
            ):
                return
            d, e = honeypots.remove_all()
            refresh_list()
            messagebox.showinfo("Done",
                                f"Removed {d} file(s)"
                                + (f", {e} errors." if e else "."),
                                parent=win)

        ttk.Button(bb, text="🗑  Remove selected",
                   command=remove_clicked).pack(side="left", padx=(0, 6))
        ttk.Button(bb, text="🧹  Remove all",
                   command=remove_all_clicked).pack(side="left", padx=(0, 6))
        ttk.Button(bb, text="Close",
                   command=win.destroy).pack(side="right")

        refresh_list()

    # ──────────────────────────────────────────
    # Email config editor
    # ──────────────────────────────────────────
    def _open_email_editor(self, parent):
        from src import email_alerts
        win = tk.Toplevel(self)
        win.title("Email alerts (SMTP)")
        win.configure(bg=THEME["bg"])
        win.geometry("640x720")
        win.transient(self)
        win.grab_set()

        header = tk.Frame(win, bg=THEME["accent"], height=56)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="✉  Email Alerts",
                 bg=THEME["accent"], fg="#000",
                 font=("Segoe UI", 14, "bold")).pack(pady=14)

        body = tk.Frame(win, bg=THEME["bg"], padx=20, pady=16)
        body.pack(fill="both", expand=True)

        tk.Label(body,
                 text=("Email is sent after every scan if Critical or High "
                       "findings show up. For Gmail / Outlook / Yahoo: "
                       "enable 2FA and use an APP PASSWORD, not your real password."),
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10),
                 wraplength=580, justify="left").pack(anchor="w", pady=(0, 12))

        cfg = email_alerts.load_config()
        vars_: dict[str, tk.Variable] = {
            "enabled":      tk.BooleanVar(value=cfg.enabled),
            "smtp_host":    tk.StringVar(value=cfg.smtp_host),
            "smtp_port":    tk.StringVar(value=str(cfg.smtp_port)),
            "use_tls":      tk.BooleanVar(value=cfg.use_tls),
            "username":     tk.StringVar(value=cfg.username),
            "password":     tk.StringVar(value=cfg.password),
            "from_address": tk.StringVar(value=cfg.from_address),
            "to_addresses": tk.StringVar(value=", ".join(cfg.to_addresses)),
            "only_critical_high": tk.BooleanVar(value=cfg.only_critical_high),
        }

        # Enabled toggle
        tk.Checkbutton(body, text="  Enable email alerts",
                       variable=vars_["enabled"],
                       bg=THEME["bg"], fg=THEME["fg"],
                       selectcolor=THEME["bg_panel"],
                       activebackground=THEME["bg"],
                       font=("Segoe UI", 11, "bold")).pack(anchor="w")

        # Preset row
        preset_row = tk.Frame(body, bg=THEME["bg"])
        preset_row.pack(fill="x", pady=(10, 0))
        tk.Label(preset_row, text="Preset:",
                 bg=THEME["bg"], fg=THEME["fg_dim"]).pack(side="left", padx=(0, 6))
        for name, vals in email_alerts.PRESETS.items():
            def apply_preset(v=vals):
                vars_["smtp_host"].set(v.get("smtp_host", ""))
                vars_["smtp_port"].set(str(v.get("smtp_port", 587)))
                vars_["use_tls"].set(v.get("use_tls", True))
            ttk.Button(preset_row, text=name,
                       command=apply_preset).pack(side="left", padx=2)

        def field(label, key, show=None, hint=""):
            tk.Label(body, text=label,
                     bg=THEME["bg"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 9, "bold")).pack(
                anchor="w", pady=(10, 2))
            kw = {"show": show} if show else {}
            ttk.Entry(body, textvariable=vars_[key], **kw).pack(
                fill="x", ipady=3)
            if hint:
                tk.Label(body, text=hint,
                         bg=THEME["bg"], fg=THEME["fg_dim"],
                         font=("Segoe UI", 8, "italic")).pack(anchor="w")

        field("SMTP HOST", "smtp_host", hint="e.g. smtp.gmail.com")

        port_row = tk.Frame(body, bg=THEME["bg"])
        port_row.pack(fill="x", pady=(10, 0))
        port_box = tk.Frame(port_row, bg=THEME["bg"])
        port_box.pack(side="left", fill="x", expand=True)
        tk.Label(port_box, text="PORT",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ttk.Entry(port_box, textvariable=vars_["smtp_port"], width=8).pack(
            anchor="w", ipady=3)
        tls_box = tk.Frame(port_row, bg=THEME["bg"])
        tls_box.pack(side="left", padx=(20, 0))
        tk.Label(tls_box, text="TLS",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        tk.Checkbutton(tls_box, text="  Use STARTTLS (recommended)",
                       variable=vars_["use_tls"],
                       bg=THEME["bg"], fg=THEME["fg"],
                       selectcolor=THEME["bg_panel"],
                       activebackground=THEME["bg"],
                       font=("Segoe UI", 10)).pack(anchor="w")

        field("USERNAME", "username", hint="usually your email address")
        field("APP PASSWORD", "password", show="•",
              hint="ALWAYS use an app password, not your main password")
        field("FROM ADDRESS", "from_address",
              hint="(optional — defaults to username)")
        field("TO (comma-separated)", "to_addresses",
              hint="who should receive alerts. you@example.com, team@example.com")

        tk.Checkbutton(body,
                       text="  Only send for Critical / High findings (recommended)",
                       variable=vars_["only_critical_high"],
                       bg=THEME["bg"], fg=THEME["fg"],
                       selectcolor=THEME["bg_panel"],
                       activebackground=THEME["bg"],
                       font=("Segoe UI", 10)).pack(anchor="w", pady=(10, 0))

        btns = tk.Frame(win, bg=THEME["bg"], pady=12)
        btns.pack(fill="x", side="bottom")

        def save_clicked():
            try:
                port = int(vars_["smtp_port"].get())
            except ValueError:
                messagebox.showerror("Invalid", "Port must be a number.",
                                     parent=win)
                return
            tos = [t.strip() for t in vars_["to_addresses"].get().split(",")
                   if t.strip()]
            new_cfg = email_alerts.EmailConfig(
                enabled=vars_["enabled"].get(),
                smtp_host=vars_["smtp_host"].get().strip(),
                smtp_port=port,
                use_tls=vars_["use_tls"].get(),
                username=vars_["username"].get().strip(),
                password=vars_["password"].get(),
                from_address=vars_["from_address"].get().strip(),
                to_addresses=tos,
                only_critical_high=vars_["only_critical_high"].get(),
            )
            email_alerts.save_config(new_cfg)
            messagebox.showinfo("Saved", "Email config saved.", parent=win)

        def test_clicked():
            save_clicked()
            ok, msg = email_alerts.send_test()
            if ok:
                messagebox.showinfo("Sent", msg, parent=win)
            else:
                messagebox.showerror("Failed", msg, parent=win)

        ttk.Button(btns, text="✉  Send test email",
                   command=test_clicked).pack(side="left", padx=18)
        ttk.Button(btns, text="💾  Save", style="Accent.TButton",
                   command=save_clicked).pack(side="right", padx=18)
        ttk.Button(btns, text="Close",
                   command=win.destroy).pack(side="right")

    # ──────────────────────────────────────────
    # Attack Timeline tab
    # ──────────────────────────────────────────
    def _build_timeline_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  ⏱  Timeline  ")

        hero = tk.Frame(f, bg=THEME["bg_card"], padx=28, pady=20)
        hero.pack(fill="x", padx=20, pady=(20, 10))

        tk.Label(hero, text="⏱  ATTACK TIMELINE",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(hero,
                 text=("Every event and finding plotted on one time axis. "
                       "Spot bursts of activity, lateral movement patterns, "
                       "and the moment something went wrong."),
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10),
                 wraplength=1200, justify="left").pack(anchor="w", pady=(6, 12))

        # Filter controls
        filt = tk.Frame(hero, bg=THEME["bg_card"])
        filt.pack(fill="x")
        tk.Label(filt, text="Show:",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"]).pack(side="left", padx=(0, 6))
        self._tl_show_findings = tk.BooleanVar(value=True)
        self._tl_show_events = tk.BooleanVar(value=True)
        for label, var in [("Findings", self._tl_show_findings),
                           ("Events", self._tl_show_events)]:
            tk.Checkbutton(filt, text=label, variable=var,
                           command=self._render_timeline,
                           bg=THEME["bg_card"], fg=THEME["fg"],
                           selectcolor=THEME["bg_panel"],
                           activebackground=THEME["bg_card"],
                           font=("Segoe UI", 10)).pack(side="left", padx=4)

        tk.Label(filt, text="    Range:",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"]).pack(side="left", padx=(12, 6))
        self._tl_range = tk.StringVar(value="24h")
        ttk.Combobox(filt, textvariable=self._tl_range,
                     values=["1h", "6h", "12h", "24h", "48h", "72h", "168h"],
                     state="readonly", width=6).pack(side="left")
        self._tl_range.trace_add("write", lambda *a: self._render_timeline())

        # Canvas
        chart_card = tk.Frame(f, bg=THEME["bg_card"], padx=12, pady=12)
        chart_card.pack(fill="both", expand=True, padx=20, pady=(0, 8))

        self.timeline_canvas = tk.Canvas(
            chart_card, bg=THEME["bg_card"], highlightthickness=0, height=420,
        )
        self.timeline_canvas.pack(fill="both", expand=True)
        self.timeline_canvas.bind("<Configure>",
                                  lambda e: self._render_timeline())
        self.timeline_canvas.bind("<Button-1>", self._on_timeline_click)
        self.timeline_canvas.bind("<Motion>", self._on_timeline_hover)

        # Detail box (shown on hover/click)
        self.timeline_detail = tk.Label(
            f, text="Hover over a marker for details, click to filter Findings.",
            bg=THEME["bg_panel"], fg=THEME["fg"],
            font=("Segoe UI", 10), justify="left", anchor="w",
            wraplength=1200, padx=14, pady=10,
        )
        self.timeline_detail.pack(fill="x", padx=20, pady=(0, 20))

        # Markers + tooltip cache
        self._tl_markers: list[dict] = []  # each: {x, y, severity, kind, title, time, item}

    def _render_timeline(self):
        """Plot findings + events on a horizontal time axis."""
        if not hasattr(self, "timeline_canvas"):
            return
        c = self.timeline_canvas
        c.delete("all")
        try:
            c.update_idletasks()
            w = c.winfo_width()
            h = c.winfo_height()
        except tk.TclError:
            return
        if w < 50 or h < 50:
            return

        # Time range
        range_str = self._tl_range.get()
        try:
            range_h = int(range_str.rstrip("h"))
        except ValueError:
            range_h = 24
        end = datetime.now()
        start = end.replace(microsecond=0) - timedelta(hours=range_h)

        # Margins
        L, R, T, B = 70, 30, 30, 50
        plot_w = max(1, w - L - R)
        plot_h = max(1, h - T - B)

        # Three rows by severity bucket — Critical/High top, Med/Low middle, Info bottom
        rows = [
            ("Critical / High", ["Critical", "High"], T + 30),
            ("Medium / Low",    ["Medium", "Low"],    T + plot_h * 0.5),
            ("Info / Events",   ["Info"],             T + plot_h * 0.85),
        ]

        # Row dividers + labels
        for i, (label, sevs, y) in enumerate(rows):
            c.create_line(L, y, w - R, y, fill=THEME["border"], width=1)
            c.create_text(L - 8, y, text=label, anchor="e",
                          fill=THEME["fg_dim"], font=("Segoe UI", 9))

        # X axis: hour ticks
        n_ticks = 6
        for i in range(n_ticks + 1):
            x = L + i * (plot_w / n_ticks)
            tick_time = start + (end - start) * (i / n_ticks)
            c.create_line(x, T, x, h - B, fill=THEME["border"], width=1)
            c.create_text(x, h - B + 16,
                          text=tick_time.strftime("%H:%M"),
                          fill=THEME["fg_dim"], font=("Segoe UI", 8))
        # Date label
        c.create_text(L, h - B + 32,
                      text=start.strftime("%Y-%m-%d"),
                      anchor="w", fill=THEME["fg_dim"], font=("Segoe UI", 8))
        c.create_text(w - R, h - B + 32,
                      text=end.strftime("%Y-%m-%d %H:%M"),
                      anchor="e", fill=THEME["fg_dim"], font=("Segoe UI", 8))

        markers: list[dict] = []

        def x_for(ts: datetime) -> float | None:
            # Treat naive datetimes as local
            try:
                if ts.tzinfo is not None:
                    ts = ts.replace(tzinfo=None)
            except Exception:
                pass
            if ts < start or ts > end:
                return None
            frac = (ts - start).total_seconds() / max(1, (end - start).total_seconds())
            return L + frac * plot_w

        def row_for(severity: str) -> float:
            for label, sevs, y in rows:
                if severity in sevs:
                    return y
            return rows[-1][2]

        # Plot findings
        if self._tl_show_findings.get():
            for f in self.findings:
                x = x_for(f.timestamp)
                if x is None:
                    continue
                y = row_for(f.severity)
                color = SEVERITY_FG.get(f.severity, "#888")
                r = 7 if f.severity in ("Critical", "High") else 5
                c.create_oval(x - r, y - r, x + r, y + r,
                              fill=color, outline=THEME["bg_card"], width=1)
                markers.append({
                    "x": x, "y": y, "r": r,
                    "severity": f.severity, "kind": "finding",
                    "title": f.title, "time": f.timestamp,
                    "item": f,
                })

        # Plot events (smaller, ringed)
        if self._tl_show_events.get():
            for e in self.events[:1500]:
                x = x_for(e.timestamp)
                if x is None:
                    continue
                y = row_for("Info")
                c.create_oval(x - 2, y - 2, x + 2, y + 2,
                              fill=THEME["fg_dim"], outline="")
                markers.append({
                    "x": x, "y": y, "r": 4,
                    "severity": "Info", "kind": "event",
                    "title": f"EID {e.event_id} · {e.channel}",
                    "time": e.timestamp,
                    "item": e,
                })

        self._tl_markers = markers

        # Empty state
        if not markers:
            c.create_text(w // 2, h // 2,
                          text="No events or findings in this range.",
                          fill=THEME["fg_dim"], font=("Segoe UI", 11, "italic"))

    def _hit_marker(self, x: int, y: int) -> dict | None:
        # Find the closest marker within 8px
        best = None
        best_d = 999
        for m in self._tl_markers:
            dx, dy = x - m["x"], y - m["y"]
            d = (dx * dx + dy * dy) ** 0.5
            if d < 8 and d < best_d:
                best, best_d = m, d
        return best

    def _on_timeline_hover(self, event):
        m = self._hit_marker(event.x, event.y)
        if not m:
            self.timeline_detail.config(
                text="Hover over a marker for details, click to filter Findings.",
                fg=THEME["fg_dim"])
            self.timeline_canvas.config(cursor="")
            return
        self.timeline_canvas.config(cursor="hand2")
        ts = m["time"].strftime("%Y-%m-%d %H:%M:%S")
        text = (f"[{m['severity']}] {m['title']}    ·    {ts}    ·    "
                f"({m['kind']})")
        color = SEVERITY_FG.get(m["severity"], THEME["fg"])
        self.timeline_detail.config(text=text, fg=color)

    def _on_timeline_click(self, event):
        m = self._hit_marker(event.x, event.y)
        if not m:
            return
        if m["kind"] == "finding":
            # Switch to Findings tab and select this finding
            for i in range(self.notebook.index("end")):
                tab = self.notebook.tab(i, "text").strip()
                if tab.startswith("Findings"):
                    self.notebook.select(i)
                    break
        elif m["kind"] == "event":
            for i in range(self.notebook.index("end")):
                tab = self.notebook.tab(i, "text").strip()
                if tab.startswith("Events") or tab.startswith("Logs"):
                    self.notebook.select(i)
                    break

    # ── Dashboard ────────────────────────────────
    def _build_dashboard_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  Dashboard  ")

        # Top: 5 stat cards
        cards = ttk.Frame(f, style="TFrame")
        cards.pack(fill="x", padx=20, pady=(20, 10))

        self.card_labels: dict[str, tk.Label] = {}
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            card = tk.Frame(cards, bg=THEME["bg_card"], padx=20, pady=14,
                            highlightthickness=2,
                            highlightbackground=SEVERITY_FG[sev])
            card.pack(side="left", expand=True, fill="both", padx=4)
            num = tk.Label(card, text="0", bg=THEME["bg_card"],
                           fg=SEVERITY_FG[sev],
                           font=("Segoe UI", 26, "bold"))
            num.pack()
            tk.Label(card, text=sev, bg=THEME["bg_card"], fg=THEME["fg"],
                     font=("Segoe UI", 10)).pack()
            self.card_labels[sev] = num

        # Middle: host info + category breakdown
        middle = ttk.Frame(f, style="TFrame")
        middle.pack(fill="x", padx=20, pady=10)

        # Host info card
        host_card = tk.Frame(middle, bg=THEME["bg_card"], padx=16, pady=12)
        host_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(host_card, text="HOST INFORMATION",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.host_info_label = tk.Label(
            host_card, text="…", bg=THEME["bg_card"], fg=THEME["fg"],
            justify="left", font=("Consolas", 9), anchor="w",
        )
        self.host_info_label.pack(anchor="w", fill="x", pady=(8, 0))

        # Category breakdown card
        cat_card = tk.Frame(middle, bg=THEME["bg_card"], padx=16, pady=12)
        cat_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
        tk.Label(cat_card, text="EVENTS BY CATEGORY",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.cat_breakdown_frame = tk.Frame(cat_card, bg=THEME["bg_card"])
        self.cat_breakdown_frame.pack(fill="x", pady=(8, 0))

        # Bottom: Top critical findings
        bottom = ttk.Frame(f, style="TFrame")
        bottom.pack(fill="both", expand=True, padx=20, pady=10)
        tk.Label(bottom, text="TOP CRITICAL FINDINGS",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 6))

        self.top_findings_frame = tk.Frame(bottom, bg=THEME["bg"])
        self.top_findings_frame.pack(fill="both", expand=True)

    # ── Findings tab ─────────────────────────────
    def _build_findings_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  Findings  ")

        # Filter bar
        filt = ttk.Frame(f, style="TFrame")
        filt.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(filt, text="Severity:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(4, 6))
        self.sev_filter_var = tk.StringVar(value="All")
        ttk.Combobox(filt, textvariable=self.sev_filter_var,
                     values=["All", "Critical", "High", "Medium", "Low", "Info"],
                     width=10, state="readonly").pack(side="left")
        self.sev_filter_var.trace_add("write", lambda *a: self._refresh_findings_table())

        tk.Label(filt, text="Category:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(16, 6))
        self.cat_filter_var = tk.StringVar(value="All")
        ttk.Combobox(filt, textvariable=self.cat_filter_var,
                     values=["All"] + CATEGORIES,
                     width=20, state="readonly").pack(side="left")
        self.cat_filter_var.trace_add("write", lambda *a: self._refresh_findings_table())

        # Table — now with MITRE technique column
        cols = ("severity", "category", "mitre", "title", "rule", "time")
        self.findings_tree = ttk.Treeview(
            f, columns=cols, show="headings", selectmode="browse",
        )
        for col, w, anchor in [
            ("severity", 90, "w"),
            ("category", 150, "w"),
            ("mitre", 90, "w"),
            ("title", 540, "w"),
            ("rule", 200, "w"),
            ("time", 160, "w"),
        ]:
            self.findings_tree.heading(col, text=col.upper() if col == "mitre" else col.title(),
                                       command=lambda c=col: self._sort_tree(self.findings_tree, c))
            self.findings_tree.column(col, width=w, anchor=anchor)

        # Severity-coloured rows
        for sev, color in SEVERITY_FG.items():
            self.findings_tree.tag_configure(f"sev_{sev}", foreground=color)

        self.findings_tree.pack(fill="both", expand=True, padx=10, pady=4)
        self.findings_tree.bind("<<TreeviewSelect>>", self._on_finding_select)

        # Detail panel
        self.finding_detail = tk.Text(
            f, height=8, bg=THEME["bg_panel"], fg=THEME["fg"],
            insertbackground=THEME["fg"], font=("Consolas", 9),
            relief="flat", padx=10, pady=8, wrap="word",
        )
        self.finding_detail.pack(fill="x", padx=10, pady=(4, 10))
        self.finding_detail.config(state="disabled")

    # ── Events tab ───────────────────────────────
    def _build_events_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  Logs  ")

        intro = tk.Frame(f, bg=THEME["bg_card"], padx=16, pady=12)
        intro.pack(fill="x", padx=10, pady=(10, 6))
        tk.Label(
            intro,
            text="Windows Log Viewer",
            bg=THEME["bg_card"],
            fg=THEME["accent"],
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")
        self.events_help_label = tk.Label(
            intro,
            text=(
                "Shows collected Windows Security, System, and Application logs. "
                "Wrong password attempts appear as Event ID 4625, 4771, or 4776. "
                "Run as Administrator to read the Security log."
            ),
            bg=THEME["bg_card"],
            fg=THEME["fg_dim"],
            font=("Segoe UI", 9),
            wraplength=1200,
            justify="left",
        )
        self.events_help_label.pack(anchor="w", fill="x", pady=(4, 0))

        # Filter bar
        filt = ttk.Frame(f, style="TFrame")
        filt.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(filt, text="Channel:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(4, 6))
        self.channel_filter_var = tk.StringVar(value="All")
        ttk.Combobox(filt, textvariable=self.channel_filter_var,
                     values=["All", "Security", "System", "Application"],
                     width=12, state="readonly").pack(side="left")
        self.channel_filter_var.trace_add("write", lambda *a: self._refresh_events_table())

        tk.Label(filt, text="Type:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(16, 6))
        self.event_type_var = tk.StringVar(value="All")
        ttk.Combobox(filt, textvariable=self.event_type_var,
                     values=list(EVENT_TYPE_FILTERS.keys()),
                     width=18, state="readonly").pack(side="left")
        self.event_type_var.trace_add("write", lambda *a: self._refresh_events_table())

        tk.Label(filt, text="Category:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(16, 6))
        self.event_cat_var = tk.StringVar(value="All")
        ttk.Combobox(filt, textvariable=self.event_cat_var,
                     values=["All"] + CATEGORIES,
                     width=20, state="readonly").pack(side="left")
        self.event_cat_var.trace_add("write", lambda *a: self._refresh_events_table())

        ttk.Button(
            filt,
            text="Show failed passwords",
            command=lambda: self._set_event_type_filter("Failed passwords"),
        ).pack(side="right", padx=(6, 0))
        ttk.Button(
            filt,
            text="All logs",
            command=lambda: self._set_event_type_filter("All"),
        ).pack(side="right")

        cols = ("time", "channel", "id", "type", "category", "user", "source", "message")
        self.events_tree = ttk.Treeview(
            f, columns=cols, show="headings", selectmode="browse",
        )
        for col, w in [
            ("time", 140), ("channel", 90), ("id", 60),
            ("type", 180), ("category", 140), ("user", 130), ("source", 220),
            ("message", 700),
        ]:
            self.events_tree.heading(col, text=col.title(),
                                     command=lambda c=col: self._sort_tree(self.events_tree, c))
            self.events_tree.column(col, width=w, anchor="w")
        self.events_tree.tag_configure("failed_login", foreground="#ff7f50")
        self.events_tree.tag_configure("success_login", foreground="#4ecdc4")
        self.events_tree.tag_configure("danger_log", foreground="#ff4757")
        self.events_tree.pack(fill="both", expand=True, padx=10, pady=4)
        self.events_tree.bind("<<TreeviewSelect>>", self._on_event_select)

        self.event_detail = tk.Text(
            f, height=9, bg=THEME["bg_panel"], fg=THEME["fg"],
            insertbackground=THEME["fg"], font=("Consolas", 9),
            relief="flat", padx=10, pady=8, wrap="word",
        )
        self.event_detail.pack(fill="x", padx=10, pady=(4, 10))
        self.event_detail.config(state="disabled")

    # ── Network tab ──────────────────────────────
    def _build_network_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  🌐  Network  ")

        info = tk.Label(f, text="All TCP/UDP connections. External = non-private remote IP. Country resolved from offline IP table.",
                        bg=THEME["bg"], fg=THEME["fg_dim"],
                        font=("Segoe UI", 9, "italic"))
        info.pack(anchor="w", padx=14, pady=(10, 4))

        # Summary card showing connection breakdown by country
        self._geo_summary_card = tk.Frame(
            f, bg=THEME["bg_card"], padx=18, pady=12,
        )
        self._geo_summary_card.pack(fill="x", padx=10, pady=(6, 4))
        tk.Label(self._geo_summary_card, text="🗺  EXTERNAL CONNECTIONS BY COUNTRY",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self._geo_summary_lbl = tk.Label(
            self._geo_summary_card, text="—",
            bg=THEME["bg_card"], fg=THEME["fg"],
            font=("Consolas", 10), justify="left", anchor="w",
        )
        self._geo_summary_lbl.pack(anchor="w", pady=(6, 0), fill="x")

        cols = ("proto", "local", "remote", "country", "state",
                "ext", "pid", "process")
        self.net_tree = ttk.Treeview(f, columns=cols, show="headings",
                                     selectmode="browse")
        for col, w in [
            ("proto", 60), ("local", 180), ("remote", 200),
            ("country", 140), ("state", 100), ("ext", 60),
            ("pid", 70), ("process", 220),
        ]:
            self.net_tree.heading(col, text=col.title(),
                                  command=lambda c=col: self._sort_tree(self.net_tree, c))
            self.net_tree.column(col, width=w, anchor="w")
        self.net_tree.tag_configure("external", foreground="#ffd93d")
        self.net_tree.tag_configure("listening", foreground="#6dd5ed")
        self.net_tree.tag_configure("threat", foreground="#ff4757")
        self.net_tree.pack(fill="both", expand=True, padx=10, pady=4)

    # ── Processes tab (now with Tree view) ─────────
    def _build_processes_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  Processes  ")

        # Toolbar with view-mode toggle
        bar = tk.Frame(f, bg=THEME["bg"])
        bar.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(bar, text="View:",
                 bg=THEME["bg"], fg=THEME["fg_dim"]).pack(side="left", padx=(4, 6))
        self._proc_view = tk.StringVar(value="flat")
        for val, lbl in [("flat", "Flat list"), ("tree", "Process tree (parent → child)")]:
            tk.Radiobutton(bar, text=lbl, variable=self._proc_view, value=val,
                           command=self._render_processes,
                           bg=THEME["bg"], fg=THEME["fg"],
                           selectcolor=THEME["bg_panel"],
                           activebackground=THEME["bg"],
                           font=("Segoe UI", 10)).pack(side="left", padx=4)
        self.proc_view_status = tk.Label(
            bar, text="", bg=THEME["bg"], fg=THEME["fg_dim"],
            font=("Segoe UI", 9, "italic"))
        self.proc_view_status.pack(side="right", padx=8)

        cols = ("pid", "name", "ppid", "user", "memory", "path")
        # Use 'tree' display so we can nest children under parents
        self.proc_tree = ttk.Treeview(f, columns=cols, selectmode="browse",
                                      show="tree headings")
        self.proc_tree.heading("#0", text="Tree")
        self.proc_tree.column("#0", width=320, anchor="w")
        for col, w in [("pid", 70), ("name", 200), ("ppid", 80),
                       ("user", 180), ("memory", 100), ("path", 500)]:
            self.proc_tree.heading(col, text=col.upper(),
                                   command=lambda c=col: self._sort_tree(self.proc_tree, c))
            self.proc_tree.column(col, width=w, anchor="w")
        self.proc_tree.tag_configure("suspicious", foreground="#ff7f50")
        self.proc_tree.tag_configure("system", foreground=THEME["fg_dim"])
        self.proc_tree.pack(fill="both", expand=True, padx=10, pady=4)

    # ── Services tab ─────────────────────────────
    def _build_services_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  Services  ")

        cols = ("name", "display", "state")
        self.svc_tree = ttk.Treeview(f, columns=cols, show="headings",
                                     selectmode="browse")
        for col, w in [("name", 240), ("display", 400), ("state", 120)]:
            self.svc_tree.heading(col, text=col.title(),
                                  command=lambda c=col: self._sort_tree(self.svc_tree, c))
            self.svc_tree.column(col, width=w, anchor="w")
        self.svc_tree.tag_configure("running", foreground="#4ecdc4")
        self.svc_tree.pack(fill="both", expand=True, padx=10, pady=10)

    # ── Persistence (tasks + autoruns + USB) ─────
    def _build_persistence_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  Persistence  ")

        # Use a paned window to split tasks / autoruns / USB
        paned = ttk.PanedWindow(f, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        # Autoruns
        ar_frame = ttk.Frame(paned, style="TFrame")
        tk.Label(ar_frame, text="REGISTRY AUTORUNS",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        cols = ("location", "name", "command")
        self.autorun_tree = ttk.Treeview(ar_frame, columns=cols,
                                         show="headings", selectmode="browse",
                                         height=6)
        for col, w in [("location", 320), ("name", 180), ("command", 700)]:
            self.autorun_tree.heading(col, text=col.title())
            self.autorun_tree.column(col, width=w, anchor="w")
        self.autorun_tree.tag_configure("suspicious", foreground="#ff7f50")
        self.autorun_tree.pack(fill="both", expand=True)
        paned.add(ar_frame, weight=1)

        # Scheduled tasks
        st_frame = ttk.Frame(paned, style="TFrame")
        tk.Label(st_frame, text="SCHEDULED TASKS",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        cols2 = ("name", "next_run", "status")
        self.task_tree = ttk.Treeview(st_frame, columns=cols2,
                                      show="headings", selectmode="browse",
                                      height=6)
        for col, w in [("name", 600), ("next_run", 220), ("status", 120)]:
            self.task_tree.heading(col, text=col.replace("_", " ").title())
            self.task_tree.column(col, width=w, anchor="w")
        self.task_tree.pack(fill="both", expand=True)
        paned.add(st_frame, weight=1)

        # USB
        usb_frame = ttk.Frame(paned, style="TFrame")
        tk.Label(usb_frame, text="USB DEVICE HISTORY",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        cols3 = ("device_id", "friendly")
        self.usb_tree = ttk.Treeview(usb_frame, columns=cols3,
                                     show="headings", selectmode="browse",
                                     height=4)
        for col, w in [("device_id", 500), ("friendly", 500)]:
            self.usb_tree.heading(col, text=col.replace("_", " ").title())
            self.usb_tree.column(col, width=w, anchor="w")
        self.usb_tree.pack(fill="both", expand=True)
        paned.add(usb_frame, weight=1)

    # ── Firewall tab ─────────────────────────────
    def _build_firewall_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  🔥  Firewall  ")

        # ── Hero / status banner ───────────────────────────
        hero = tk.Frame(f, bg=THEME["bg_card"], padx=28, pady=18)
        hero.pack(fill="x", padx=20, pady=(20, 12))

        title_row = tk.Frame(hero, bg=THEME["bg_card"])
        title_row.pack(fill="x")
        tk.Label(title_row, text="🔥  Firewall & Domain Blocker",
                 bg=THEME["bg_card"], fg=THEME["fg"],
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        self._fw_admin_lbl = tk.Label(
            title_row, text="",
            bg=THEME["bg_card"], fg=THEME["fg_dim"],
            font=("Segoe UI", 10, "bold"))
        self._fw_admin_lbl.pack(side="right")

        tk.Label(hero,
                 text=("Block or allow IP addresses, ports, and websites. "
                       "IP/port rules go into Windows Firewall; website blocks "
                       "go into the Windows hosts file. Every change is "
                       "labelled 'LogSentinel' so you can undo any of it."),
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10),
                 wraplength=1200, justify="left").pack(anchor="w", pady=(8, 0))

        # ── Sub-notebook: IPs & Ports / Websites / Active rules ─────────
        sub = ttk.Notebook(f)
        sub.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self._build_fw_ip_panel(sub)
        self._build_fw_web_panel(sub)
        self._build_fw_active_panel(sub)

        self._refresh_fw_admin_status()
        self.after(500, self._refresh_fw_rules)
        self.after(550, self._refresh_hosts_blocks)

    # ──────────────────────────────────────────
    # IP & Port panel
    # ──────────────────────────────────────────
    def _build_fw_ip_panel(self, parent):
        p = ttk.Frame(parent, style="TFrame")
        parent.add(p, text="  🚫  IPs & Ports  ")

        wrap = tk.Frame(p, bg=THEME["bg"])
        wrap.pack(fill="both", expand=True, padx=4, pady=4)

        card = tk.Frame(wrap, bg=THEME["bg_card"], padx=32, pady=24)
        card.pack(fill="x", padx=4, pady=10)

        tk.Label(card, text="BLOCK OR ALLOW AN IP",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        tk.Label(card, text="Stops traffic to or from a specific IP, range, or CIDR block.",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 18))

        grid = tk.Frame(card, bg=THEME["bg_card"])
        grid.pack(fill="x")
        for c in range(4):
            grid.grid_columnconfigure(c, weight=1, uniform="x")

        def field_label(text, row, col, span=1):
            tk.Label(grid, text=text,
                     bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 9, "bold")).grid(
                row=row, column=col, columnspan=span,
                sticky="w", padx=(0, 14), pady=(0, 6))

        def hint(text, row, col, span=1):
            tk.Label(grid, text=text,
                     bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 8, "italic")).grid(
                row=row, column=col, columnspan=span,
                sticky="w", padx=(0, 14), pady=(0, 12))

        # IP
        self._fw_ip = tk.StringVar()
        field_label("IP ADDRESS *", 0, 0, span=2)
        ttk.Entry(grid, textvariable=self._fw_ip).grid(
            row=1, column=0, columnspan=2, sticky="ew",
            padx=(0, 14), pady=(0, 4), ipady=4)
        hint("e.g. 1.2.3.4    ·    10.0.0.0/24    ·    1.2.3.4-1.2.3.20",
             2, 0, span=2)

        # Port
        self._fw_port = tk.StringVar(value="any")
        field_label("PORT (optional)", 0, 2)
        ttk.Entry(grid, textvariable=self._fw_port).grid(
            row=1, column=2, sticky="ew", padx=(0, 14), pady=(0, 4), ipady=4)
        hint("e.g. 80    ·    8000-9000    ·    80,443    ·    any",
             2, 2)

        # Direction
        self._fw_direction = tk.StringVar(value="out")
        field_label("DIRECTION", 0, 3)
        dir_box = tk.Frame(grid, bg=THEME["bg_card"])
        dir_box.grid(row=1, column=3, rowspan=2, sticky="nw", pady=(0, 12))
        for val, lbl in [("in", "  Incoming"), ("out", "  Outgoing"),
                         ("both", "  Both")]:
            tk.Radiobutton(dir_box, text=lbl, variable=self._fw_direction,
                           value=val, bg=THEME["bg_card"], fg=THEME["fg"],
                           selectcolor=THEME["bg_panel"],
                           activebackground=THEME["bg_card"],
                           font=("Segoe UI", 10)).pack(anchor="w")

        # Protocol
        self._fw_protocol = tk.StringVar(value="any")
        field_label("PROTOCOL", 3, 0)
        ttk.Combobox(grid, textvariable=self._fw_protocol,
                     values=["any", "TCP", "UDP"],
                     state="readonly", width=10).grid(
            row=4, column=0, sticky="w", padx=(0, 14), pady=(0, 12))

        # Description
        self._fw_description = tk.StringVar()
        field_label("NOTE (optional)", 3, 1, span=3)
        ttk.Entry(grid, textvariable=self._fw_description).grid(
            row=4, column=1, columnspan=3, sticky="ew",
            padx=(0, 14), pady=(0, 4), ipady=4)
        hint("Why are you adding this rule? (saved with the rule for later reference)",
             5, 1, span=3)

        # Action buttons
        btns = tk.Frame(card, bg=THEME["bg_card"])
        btns.pack(fill="x", pady=(20, 0))
        tk.Button(btns, text="🚫   BLOCK THIS IP",
                  bg="#ff4757", fg="#000",
                  font=("Segoe UI", 11, "bold"),
                  padx=22, pady=12, relief="flat", cursor="hand2",
                  activebackground="#e83b4d",
                  command=lambda: self._submit_fw_rule(action="block")
                  ).pack(side="left", padx=(0, 10))
        tk.Button(btns, text="✓   ALLOW THIS IP",
                  bg="#4ecdc4", fg="#000",
                  font=("Segoe UI", 11, "bold"),
                  padx=22, pady=12, relief="flat", cursor="hand2",
                  activebackground="#3aa89f",
                  command=lambda: self._submit_fw_rule(action="allow")
                  ).pack(side="left", padx=(0, 10))
        ttk.Button(btns, text="Reset form",
                   command=self._reset_fw_form).pack(side="left")

        # Sample shortcuts
        shortcut_card = tk.Frame(wrap, bg=THEME["bg_card"], padx=24, pady=14)
        shortcut_card.pack(fill="x", padx=4, pady=(0, 10))
        tk.Label(shortcut_card, text="QUICK PRESETS",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        sh_row = tk.Frame(shortcut_card, bg=THEME["bg_card"])
        sh_row.pack(fill="x")
        for label, ip, port, direction in [
            ("Block all RDP from internet",   "any",      "3389",  "in"),
            ("Block all SMB from internet",   "any",      "445",   "in"),
            ("Allow LAN only (192.168.0.0/16)", "192.168.0.0/16", "any", "in"),
        ]:
            ttk.Button(sh_row, text=label,
                       command=lambda i=ip, p=port, d=direction:
                       self._fill_fw_form(i, p, d)
                       ).pack(side="left", padx=(0, 8))

    def _fill_fw_form(self, ip, port, direction):
        self._fw_ip.set(ip)
        self._fw_port.set(port)
        self._fw_direction.set(direction)

    # ──────────────────────────────────────────
    # Website panel (hosts file)
    # ──────────────────────────────────────────
    def _build_fw_web_panel(self, parent):
        p = ttk.Frame(parent, style="TFrame")
        parent.add(p, text="  🌐  Websites  ")

        wrap = tk.Frame(p, bg=THEME["bg"])
        wrap.pack(fill="both", expand=True, padx=4, pady=4)

        card = tk.Frame(wrap, bg=THEME["bg_card"], padx=32, pady=24)
        card.pack(fill="x", padx=4, pady=10)

        tk.Label(card, text="BLOCK A WEBSITE",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        tk.Label(card,
                 text=("Add a domain to the Windows hosts file so it stops "
                       "resolving — works in every browser and most apps. "
                       "Reversible from the Active Rules tab."),
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10), wraplength=1100,
                 justify="left").pack(anchor="w", pady=(0, 18))

        grid = tk.Frame(card, bg=THEME["bg_card"])
        grid.pack(fill="x")
        for c in range(2):
            grid.grid_columnconfigure(c, weight=1, uniform="x")

        # Domain
        self._web_domain = tk.StringVar()
        tk.Label(grid, text="WEBSITE / DOMAIN *",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))
        ttk.Entry(grid, textvariable=self._web_domain).grid(
            row=1, column=0, columnspan=2, sticky="ew", pady=(0, 4), ipady=4)
        tk.Label(grid,
                 text="e.g. facebook.com    ·    twitter.com    ·    badsite.example.com",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 8, "italic")).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(0, 12))

        # Note
        self._web_note = tk.StringVar()
        tk.Label(grid, text="REASON (optional)",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "bold")).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(0, 6))
        ttk.Entry(grid, textvariable=self._web_note).grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(0, 4), ipady=4)
        tk.Label(grid,
                 text="Why are you blocking it? (kept as a comment)",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 8, "italic")).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(0, 12))

        # Options
        self._web_include_www = tk.BooleanVar(value=True)
        self._web_ipv4 = tk.BooleanVar(value=True)
        self._web_ipv6 = tk.BooleanVar(value=True)

        opts = tk.Frame(card, bg=THEME["bg_card"])
        opts.pack(fill="x", pady=(8, 0))
        tk.Checkbutton(opts, text="  Also block www. variant",
                       variable=self._web_include_www,
                       bg=THEME["bg_card"], fg=THEME["fg"],
                       selectcolor=THEME["bg_panel"],
                       activebackground=THEME["bg_card"],
                       font=("Segoe UI", 10)).pack(side="left", padx=(0, 18))
        tk.Checkbutton(opts, text="  IPv4",
                       variable=self._web_ipv4,
                       bg=THEME["bg_card"], fg=THEME["fg"],
                       selectcolor=THEME["bg_panel"],
                       activebackground=THEME["bg_card"],
                       font=("Segoe UI", 10)).pack(side="left", padx=(0, 12))
        tk.Checkbutton(opts, text="  IPv6",
                       variable=self._web_ipv6,
                       bg=THEME["bg_card"], fg=THEME["fg"],
                       selectcolor=THEME["bg_panel"],
                       activebackground=THEME["bg_card"],
                       font=("Segoe UI", 10)).pack(side="left")

        # Action buttons
        btns = tk.Frame(card, bg=THEME["bg_card"])
        btns.pack(fill="x", pady=(20, 0))
        tk.Button(btns, text="🚫   BLOCK THIS WEBSITE",
                  bg="#ff4757", fg="#000",
                  font=("Segoe UI", 11, "bold"),
                  padx=22, pady=12, relief="flat", cursor="hand2",
                  activebackground="#e83b4d",
                  command=self._submit_web_block
                  ).pack(side="left", padx=(0, 10))
        ttk.Button(btns, text="Reset form",
                   command=self._reset_web_form).pack(side="left")

        # Quick block presets — common social/distraction sites
        preset_card = tk.Frame(wrap, bg=THEME["bg_card"], padx=24, pady=14)
        preset_card.pack(fill="x", padx=4, pady=(0, 10))
        tk.Label(preset_card, text="ONE-CLICK PRESETS",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        tk.Label(preset_card,
                 text="Common distraction or risk-categories. Click to "
                      "fill the form — you still have to confirm.",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))

        sh_row = tk.Frame(preset_card, bg=THEME["bg_card"])
        sh_row.pack(fill="x")
        for label, dom in [
            ("Facebook",  "facebook.com"),
            ("Twitter/X", "twitter.com"),
            ("Instagram", "instagram.com"),
            ("TikTok",    "tiktok.com"),
            ("Reddit",    "reddit.com"),
            ("YouTube",   "youtube.com"),
        ]:
            ttk.Button(sh_row, text=label,
                       command=lambda d=dom: self._fill_web_form(d)
                       ).pack(side="left", padx=(0, 6))

    def _fill_web_form(self, domain: str):
        self._web_domain.set(domain)

    def _reset_web_form(self):
        self._web_domain.set("")
        self._web_note.set("")
        self._web_include_www.set(True)
        self._web_ipv4.set(True)
        self._web_ipv6.set(True)

    def _submit_web_block(self):
        domain = self._web_domain.get().strip()
        if not domain:
            messagebox.showwarning("Block website",
                                   "Please type a website / domain.")
            return
        ok, canonical = hosts_manager.canonicalize(domain)
        if not ok:
            messagebox.showerror("Block website", canonical)
            return
        if not hosts_manager.is_admin():
            messagebox.showwarning(
                "Administrator required",
                "Editing the hosts file requires Administrator.\n\n"
                "Close this app, then double-click LAUNCH-as-admin.bat "
                "and try again.",
            )
            return
        confirm_msg = (
            f"Going to block this website system-wide:\n\n"
            f"  {canonical}"
            + (f"\n  www.{canonical}"
               if self._web_include_www.get() else "")
            + "\n\nThis edits C:\\Windows\\System32\\drivers\\etc\\hosts. "
              "All browsers and most apps will fail to reach it. "
              "Reversible from the Active Rules tab.\n\nContinue?"
        )
        if not messagebox.askyesno("Confirm block", confirm_msg):
            return
        ok, msg = hosts_manager.add_block(
            domain,
            note=self._web_note.get().strip(),
            include_www=self._web_include_www.get(),
            ipv4=self._web_ipv4.get(),
            ipv6=self._web_ipv6.get(),
        )
        if ok:
            messagebox.showinfo("Done", msg)
            self._reset_web_form()
            self._refresh_hosts_blocks()
        else:
            messagebox.showerror("Failed", msg)

    # ──────────────────────────────────────────
    # Active rules panel
    # ──────────────────────────────────────────
    def _build_fw_active_panel(self, parent):
        p = ttk.Frame(parent, style="TFrame")
        parent.add(p, text="  📋  Active Rules  ")

        wrap = tk.Frame(p, bg=THEME["bg"])
        wrap.pack(fill="both", expand=True, padx=4, pady=4)

        # Two cards side-by-side using a paned window
        paned = ttk.PanedWindow(wrap, orient="vertical")
        paned.pack(fill="both", expand=True)

        # ── IP rules card ───────────────────────────────
        ip_card = tk.Frame(paned, bg=THEME["bg_card"], padx=24, pady=20)
        head = tk.Frame(ip_card, bg=THEME["bg_card"])
        head.pack(fill="x", pady=(0, 10))
        tk.Label(head, text="🚫  IP & PORT RULES",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(head, text="🔄  Refresh",
                   command=self._refresh_fw_rules).pack(side="right")
        ttk.Button(head, text="🗑  Delete selected",
                   command=self._delete_selected_fw_rule).pack(
            side="right", padx=(0, 6))
        ttk.Button(head, text="🧹  Delete all",
                   command=self._delete_all_fw_rules).pack(
            side="right", padx=(0, 6))

        cols = ("name", "action", "direction", "protocol", "remote_ip",
                "remote_port", "enabled")
        self.fw_tree = ttk.Treeview(
            ip_card, columns=cols, show="headings", selectmode="browse",
        )
        for col, w in [
            ("name", 320), ("action", 80), ("direction", 100),
            ("protocol", 90), ("remote_ip", 200), ("remote_port", 110),
            ("enabled", 80),
        ]:
            self.fw_tree.heading(col, text=col.replace("_", " ").title())
            self.fw_tree.column(col, width=w, anchor="w")
        self.fw_tree.tag_configure("block", foreground="#ff7f50")
        self.fw_tree.tag_configure("allow", foreground="#4ecdc4")
        self.fw_tree.pack(fill="both", expand=True)
        paned.add(ip_card, weight=1)

        # ── Website blocks card ─────────────────────────
        web_card = tk.Frame(paned, bg=THEME["bg_card"], padx=24, pady=20)
        head = tk.Frame(web_card, bg=THEME["bg_card"])
        head.pack(fill="x", pady=(0, 10))
        tk.Label(head, text="🌐  BLOCKED WEBSITES",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(head, text="🔄  Refresh",
                   command=self._refresh_hosts_blocks).pack(side="right")
        ttk.Button(head, text="🗑  Unblock selected",
                   command=self._delete_selected_hosts_block).pack(
            side="right", padx=(0, 6))
        ttk.Button(head, text="🧹  Unblock all",
                   command=self._delete_all_hosts_blocks).pack(
            side="right", padx=(0, 6))

        cols2 = ("domain", "added", "families", "variants", "note")
        self.hosts_tree = ttk.Treeview(
            web_card, columns=cols2, show="headings", selectmode="browse",
        )
        for col, w in [
            ("domain", 280), ("added", 110), ("families", 120),
            ("variants", 280), ("note", 280),
        ]:
            self.hosts_tree.heading(col, text=col.replace("_", " ").title())
            self.hosts_tree.column(col, width=w, anchor="w")
        self.hosts_tree.pack(fill="both", expand=True)
        paned.add(web_card, weight=1)

    def _refresh_fw_admin_status(self):
        if firewall_manager.is_admin():
            self._fw_admin_lbl.config(
                text="✓ Admin — you can add/delete rules", fg="#4ecdc4")
        else:
            self._fw_admin_lbl.config(
                text="⚠ Not Admin — re-launch via LAUNCH-as-admin.bat to add rules",
                fg="#ff7f50")

    def _refresh_fw_rules(self):
        for row in self.fw_tree.get_children():
            self.fw_tree.delete(row)
        try:
            rules = firewall_manager.list_sentinel_rules()
        except Exception as e:
            messagebox.showerror("Firewall", f"Couldn't list rules:\n{e}")
            return
        for r in rules:
            self.fw_tree.insert("", "end", iid=r.name, values=(
                r.name, r.action.upper(), r.direction.upper(),
                r.protocol, r.remote_ip, r.remote_port,
                "Yes" if r.enabled else "No",
            ), tags=(r.action,))

    def _reset_fw_form(self):
        self._fw_ip.set("")
        self._fw_port.set("any")
        self._fw_direction.set("out")
        self._fw_protocol.set("any")
        self._fw_description.set("")

    def _submit_fw_rule(self, action: str):
        ip = self._fw_ip.get().strip()
        if not ip:
            messagebox.showwarning("Firewall", "Please enter an IP address.")
            return
        port = self._fw_port.get().strip() or "any"
        direction = self._fw_direction.get()
        protocol = self._fw_protocol.get()
        desc = self._fw_description.get().strip()

        # Validate first
        ok, msg = firewall_manager.validate_ip(ip)
        if not ok:
            messagebox.showerror("Firewall", msg)
            return
        ok, msg = firewall_manager.validate_port(port)
        if not ok:
            messagebox.showerror("Firewall", msg)
            return

        if not firewall_manager.is_admin():
            messagebox.showwarning(
                "Administrator required",
                "Adding firewall rules requires Administrator.\n\n"
                "Close this app, then double-click LAUNCH-as-admin.bat "
                "and try again.",
            )
            return

        builder = (firewall_manager.quick_block_ip
                   if action == "block"
                   else firewall_manager.quick_allow_ip)
        rule = builder(ip, port=port, direction=direction, protocol=protocol)
        if desc:
            rule.description = desc

        warning = firewall_manager.is_dangerous_block(rule)
        if warning:
            if not messagebox.askyesno(
                "Are you sure?",
                f"⚠  {warning}\n\nProceed anyway?"
            ):
                return

        # Show what we're about to do
        confirm_msg = (
            f"Going to add a Windows Firewall rule:\n\n"
            f"  Action      : {action.upper()}\n"
            f"  Direction   : {direction.upper()}\n"
            f"  Protocol    : {protocol.upper()}\n"
            f"  Remote IP   : {ip}\n"
            f"  Remote Port : {port}\n"
            f"  Rule name   : {rule.name}\n\n"
            f"This is reversible — you can delete the rule from this tab "
            "or wf.msc at any time. Continue?"
        )
        if not messagebox.askyesno("Confirm", confirm_msg):
            return

        ok, msg = firewall_manager.add_rule(rule)
        if ok:
            messagebox.showinfo("Done", msg)
            self._reset_fw_form()
            self._refresh_fw_rules()
        else:
            messagebox.showerror("Failed", msg)

    def _delete_selected_fw_rule(self):
        sel = self.fw_tree.selection()
        if not sel:
            messagebox.showinfo("Firewall",
                                "Select a rule from the list first.")
            return
        name = sel[0]
        if not firewall_manager.is_admin():
            messagebox.showwarning(
                "Administrator required",
                "Deleting firewall rules requires Administrator.")
            return
        if not messagebox.askyesno(
            "Delete rule",
            f"Delete this rule?\n\n  {name}\n\nThis cannot be undone "
            "(but you can re-create it).",
        ):
            return
        ok, msg = firewall_manager.delete_rule(name)
        if ok:
            messagebox.showinfo("Done", msg)
            self._refresh_fw_rules()
        else:
            messagebox.showerror("Failed", msg)

    def _delete_all_fw_rules(self):
        if not firewall_manager.is_admin():
            messagebox.showwarning(
                "Administrator required",
                "Deleting firewall rules requires Administrator.")
            return
        rules = firewall_manager.list_sentinel_rules()
        if not rules:
            messagebox.showinfo("Firewall",
                                "No Log Sentinel rules to delete.")
            return
        if not messagebox.askyesno(
            "Delete ALL Log Sentinel rules",
            f"Delete every rule whose name starts with 'LogSentinel_' "
            f"({len(rules)} rule{'s' if len(rules) != 1 else ''})?",
        ):
            return
        succ, fail = firewall_manager.delete_all_sentinel_rules()
        messagebox.showinfo(
            "Done",
            f"Deleted {succ} rule{'s' if succ != 1 else ''}."
            + (f" {fail} failed." if fail else ""))
        self._refresh_fw_rules()

    # ──────────────────────────────────────────
    # Hosts file (website blocks)
    # ──────────────────────────────────────────
    def _refresh_hosts_blocks(self):
        if not hasattr(self, "hosts_tree"):
            return
        for row in self.hosts_tree.get_children():
            self.hosts_tree.delete(row)
        try:
            blocks = hosts_manager.list_blocks()
        except Exception as e:
            messagebox.showerror("Hosts file",
                                 f"Couldn't read hosts file:\n{e}")
            return
        for b in blocks:
            self.hosts_tree.insert("", "end", iid=b.domain, values=(
                b.domain,
                b.added or "—",
                "/".join(b.families) or "—",
                ", ".join(b.variants) or "—",
                b.note or "—",
            ))

    def _delete_selected_hosts_block(self):
        sel = self.hosts_tree.selection()
        if not sel:
            messagebox.showinfo("Block website",
                                "Select a blocked website from the list first.")
            return
        domain = sel[0]
        if not hosts_manager.is_admin():
            messagebox.showwarning(
                "Administrator required",
                "Editing the hosts file requires Administrator.")
            return
        if not messagebox.askyesno(
            "Unblock website",
            f"Unblock {domain}?\n\nWe'll remove the related entries from "
            "your hosts file. The website will work again.",
        ):
            return
        ok, msg = hosts_manager.remove_block(domain)
        if ok:
            messagebox.showinfo("Done", msg)
            self._refresh_hosts_blocks()
        else:
            messagebox.showerror("Failed", msg)

    def _delete_all_hosts_blocks(self):
        if not hosts_manager.is_admin():
            messagebox.showwarning(
                "Administrator required",
                "Editing the hosts file requires Administrator.")
            return
        blocks = hosts_manager.list_blocks()
        if not blocks:
            messagebox.showinfo("Block website",
                                "No Log Sentinel hosts entries to remove.")
            return
        if not messagebox.askyesno(
            "Unblock all websites",
            f"Remove every website blocked by Log Sentinel "
            f"({len(blocks)} domain{'s' if len(blocks) != 1 else ''})?",
        ):
            return
        removed, _ = hosts_manager.remove_all_blocks()
        messagebox.showinfo("Done",
                            f"Removed {removed} hosts line"
                            f"{'s' if removed != 1 else ''}.")
        self._refresh_hosts_blocks()

    # ──────────────────────────────────────────
    # Live Monitor tab — real-time system gauges
    # ──────────────────────────────────────────
    def _build_live_monitor_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  📊  Live Monitor  ")

        # ── Top: 4 gauges in a row ──
        gauges = tk.Frame(f, bg=THEME["bg"])
        gauges.pack(fill="x", padx=20, pady=(20, 10))

        self._lm_canvases: dict[str, dict] = {}
        for label, key, color in [
            ("CPU",     "cpu",  "#4ecdc4"),
            ("Memory",  "ram",  "#6dd5ed"),
            ("Disk",    "disk", "#ffd93d"),
            ("Battery", "batt", "#ff7f50"),
        ]:
            card = tk.Frame(gauges, bg=THEME["bg_card"], padx=18, pady=14)
            card.pack(side="left", expand=True, fill="x", padx=4)

            tk.Label(card, text=label.upper(),
                     bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 9, "bold")).pack(anchor="w")

            cv = tk.Canvas(card, width=200, height=120,
                           bg=THEME["bg_card"], highlightthickness=0)
            cv.pack(pady=(8, 0))

            sub = tk.Label(card, text="—",
                           bg=THEME["bg_card"], fg=THEME["fg_dim"],
                           font=("Segoe UI", 9))
            sub.pack(pady=(4, 0))
            self._lm_canvases[key] = {
                "canvas": cv, "color": color, "sub": sub,
            }
            self._draw_arc_gauge(cv, 0, color, "—")

        # ── Middle: Wi-Fi / Internet / Antivirus cards ──
        mid = tk.Frame(f, bg=THEME["bg"])
        mid.pack(fill="x", padx=20, pady=(8, 8))

        # Wi-Fi
        wifi_card = tk.Frame(mid, bg=THEME["bg_card"], padx=20, pady=14)
        wifi_card.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(wifi_card, text="📶  WI-FI",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self._wifi_lbl = tk.Label(
            wifi_card, text="—", bg=THEME["bg_card"], fg=THEME["fg"],
            font=("Consolas", 10), justify="left", anchor="w",
        )
        self._wifi_lbl.pack(anchor="w", pady=(8, 0), fill="x")

        # Internet
        inet_card = tk.Frame(mid, bg=THEME["bg_card"], padx=20, pady=14)
        inet_card.pack(side="left", fill="both", expand=True, padx=6)
        tk.Label(inet_card, text="🌐  INTERNET",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self._inet_lbl = tk.Label(
            inet_card, text="—", bg=THEME["bg_card"], fg=THEME["fg"],
            font=("Consolas", 10), justify="left", anchor="w",
        )
        self._inet_lbl.pack(anchor="w", pady=(8, 0), fill="x")

        # Antivirus
        av_card = tk.Frame(mid, bg=THEME["bg_card"], padx=20, pady=14)
        av_card.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(av_card, text="🛡  ANTIVIRUS",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self._av_lbl = tk.Label(
            av_card, text="—", bg=THEME["bg_card"], fg=THEME["fg"],
            font=("Consolas", 10), justify="left", anchor="w",
        )
        self._av_lbl.pack(anchor="w", pady=(8, 0), fill="x")

        # ── Hardware inventory + isolation status ──
        bottom = tk.Frame(f, bg=THEME["bg"])
        bottom.pack(fill="both", expand=True, padx=20, pady=(8, 20))

        # Hardware
        hw_card = tk.Frame(bottom, bg=THEME["bg_card"], padx=20, pady=14)
        hw_card.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(hw_card, text="💻  HARDWARE",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self._hw_lbl = tk.Label(
            hw_card, text="Loading…", bg=THEME["bg_card"], fg=THEME["fg"],
            font=("Consolas", 10), justify="left", anchor="w",
        )
        self._hw_lbl.pack(anchor="w", pady=(8, 0), fill="x")

        # Disks (any extra past C:)
        disk_card = tk.Frame(bottom, bg=THEME["bg_card"], padx=20, pady=14)
        disk_card.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(disk_card, text="💾  DISKS",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self._disk_lbl = tk.Label(
            disk_card, text="—", bg=THEME["bg_card"], fg=THEME["fg"],
            font=("Consolas", 10), justify="left", anchor="w",
        )
        self._disk_lbl.pack(anchor="w", pady=(8, 0), fill="x")

        # Start the polling loop
        self._lm_running = True
        self._lm_tick_count = 0
        self.after(500, self._lm_poll)

    def _draw_arc_gauge(self, canvas: tk.Canvas, pct: float,
                        color: str, label: str):
        canvas.delete("all")
        cx, cy, r = 100, 70, 56
        # Background arc (180° at top)
        canvas.create_arc(cx-r, cy-r, cx+r, cy+r, start=180, extent=-180,
                          outline="#3d3d5c", width=10, style="arc")
        # Progress arc
        if pct > 0:
            canvas.create_arc(cx-r, cy-r, cx+r, cy+r,
                              start=180, extent=-(pct/100)*180,
                              outline=color, width=10, style="arc")
        # Number
        canvas.create_text(cx, cy-4, text=f"{pct:.0f}%",
                          fill=color, font=("Segoe UI", 22, "bold"))
        # Label (below)
        canvas.create_text(cx, cy+24, text=label,
                          fill=THEME["fg_dim"], font=("Segoe UI", 9))

    def _lm_poll(self):
        if not getattr(self, "_lm_running", False):
            return
        self._lm_tick_count += 1
        try:
            # CPU
            cpu = sysmon.get_cpu_percent()
            self._draw_arc_gauge(self._lm_canvases["cpu"]["canvas"],
                                 cpu, self._lm_canvases["cpu"]["color"],
                                 f"{sysmon.get_cpu_count()} cores")
            self._lm_canvases["cpu"]["sub"].config(
                text=f"{cpu:.1f}% used")

            # RAM
            mem = sysmon.get_memory()
            self._draw_arc_gauge(self._lm_canvases["ram"]["canvas"],
                                 mem.used_pct, self._lm_canvases["ram"]["color"],
                                 f"{mem.used_gb:.1f} GB / {mem.total_gb:.1f} GB")
            self._lm_canvases["ram"]["sub"].config(
                text=f"{mem.available_gb:.1f} GB free")

            # Disk (system drive)
            disks = sysmon.get_disks()
            primary = next((d for d in disks if d.drive.startswith("C")),
                           disks[0] if disks else None)
            if primary:
                self._draw_arc_gauge(
                    self._lm_canvases["disk"]["canvas"],
                    primary.used_pct, self._lm_canvases["disk"]["color"],
                    f"{primary.drive[:2]} drive")
                self._lm_canvases["disk"]["sub"].config(
                    text=f"{primary.free_gb:.0f} GB free / {primary.total_gb:.0f} GB total")

            # Battery
            batt = sysmon.get_battery()
            if batt.has_battery:
                color = (self._lm_canvases["batt"]["color"]
                         if batt.percent > 30 else "#ff4757")
                self._draw_arc_gauge(
                    self._lm_canvases["batt"]["canvas"],
                    batt.percent, color,
                    "Plugged in" if batt.plugged_in else "On battery")
                if batt.minutes_remaining > 0:
                    sub = (f"{batt.minutes_remaining // 60}h "
                           f"{batt.minutes_remaining % 60}m left")
                else:
                    sub = "Charging" if batt.plugged_in else "Discharging"
                self._lm_canvases["batt"]["sub"].config(text=sub)
            else:
                self._draw_arc_gauge(
                    self._lm_canvases["batt"]["canvas"], 0, "#888",
                    "No battery")
                self._lm_canvases["batt"]["sub"].config(text="Desktop / no battery")
        except Exception:
            pass

        # Wi-Fi (poll every 5 ticks ≈ 5 seconds)
        if self._lm_tick_count % 5 == 0:
            try:
                w = sysmon.get_wifi()
                if w.connected:
                    bars = "▰" * (w.signal // 20) + "▱" * (5 - w.signal // 20)
                    text = (f"SSID    : {w.ssid}\n"
                            f"Signal  : {w.signal}%  {bars}\n"
                            f"State   : {w.state}\n"
                            f"Adapter : {w.interface}")
                else:
                    text = "Not connected to Wi-Fi"
                self._wifi_lbl.config(text=text)
            except Exception:
                pass

            try:
                i = sysmon.get_internet()
                if i.online:
                    text = (f"Status  : ✓ Online\n"
                            f"Latency : {i.latency_ms:.0f} ms (to 1.1.1.1)\n"
                            f"Hostname: {socket.gethostname()}")
                else:
                    text = "✗ Offline — no internet reachable"
                self._inet_lbl.config(text=text)
            except Exception:
                pass

        # Antivirus (poll every 30 ticks)
        if self._lm_tick_count == 1 or self._lm_tick_count % 30 == 0:
            try:
                av = sysmon.get_antivirus_status()
                rt = "✓ ON" if av.realtime_protection else "✗ OFF"
                tp = "✓ ON" if av.tamper_protection else "✗ OFF"
                age = (f"{av.av_signature_age_days}d ago"
                       if av.av_signature_age_days >= 0 else "?")
                text = (f"Real-time      : {rt}\n"
                        f"Tamper protect : {tp}\n"
                        f"Signatures     : {age}\n"
                        f"Engine         : {av.av_engine_version or '?'}\n"
                        f"Last quick scan: {av.last_quick_scan or 'never'}")
                self._av_lbl.config(text=text)
            except Exception:
                pass

        # Hardware (once)
        if self._lm_tick_count == 2:
            try:
                hw = sysmon.get_hardware()
                text = (f"CPU         : {hw.cpu_name}\n"
                        f"Cores/threads: {hw.cpu_cores} / {hw.cpu_threads}\n"
                        f"GPU         : {hw.gpu or '?'}\n"
                        f"RAM total   : {hw.total_ram_gb:.1f} GB\n"
                        f"BIOS        : {hw.bios_version} ({hw.bios_date})")
                self._hw_lbl.config(text=text)
            except Exception:
                pass

        # Disks (every 10 ticks)
        if self._lm_tick_count == 1 or self._lm_tick_count % 10 == 0:
            try:
                disks = sysmon.get_disks()
                lines = []
                for d in disks:
                    bar_n = int(d.used_pct / 5)
                    bar = "█" * bar_n + "░" * (20 - bar_n)
                    lines.append(
                        f"{d.drive:<5} {bar}  "
                        f"{d.used_gb:.0f}/{d.total_gb:.0f} GB"
                    )
                self._disk_lbl.config(text="\n".join(lines) if lines else "—")
            except Exception:
                pass

        # Re-schedule
        if self._lm_running:
            self.after(1500, self._lm_poll)

    # ──────────────────────────────────────────
    # 🚨 Panic Button — Device Isolation
    # ──────────────────────────────────────────
    def open_panic_dialog(self):
        info = panic.isolation_info()
        if info:
            # Already isolated — offer restore
            adapters = "\n  • " + "\n  • ".join(info.get("disabled_adapters", []))
            isolated_at = info.get("isolated_at", "")[:16].replace("T", " ")
            reason = info.get("reason", "") or "(no reason given)"
            msg = (f"This PC is in ISOLATION MODE.\n\n"
                   f"Isolated at : {isolated_at}\n"
                   f"Reason      : {reason}\n"
                   f"Disabled    : {len(info.get('disabled_adapters', []))} adapter(s)"
                   f"{adapters}\n\n"
                   "Re-enable the network now?")
            if messagebox.askyesno("Restore network", msg):
                ok, m = panic.restore()
                messagebox.showinfo("Restore" if ok else "Failed", m)
                self._update_panic_button()
            return

        # Build the panic dialog
        win = tk.Toplevel(self)
        win.title("🚨 PANIC — Isolate this device")
        win.configure(bg=THEME["bg"])
        win.geometry("560x520")
        win.transient(self)
        win.grab_set()
        win.update_idletasks()
        x = (win.winfo_screenwidth() - 560) // 2
        y = (win.winfo_screenheight() - 520) // 2
        win.geometry(f"560x520+{x}+{y}")

        # Header
        header = tk.Frame(win, bg="#ff4757", height=70)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="🚨  PANIC — Isolate this device",
                 bg="#ff4757", fg="#fff",
                 font=("Segoe UI", 16, "bold")).pack(pady=18)

        body = tk.Frame(win, bg=THEME["bg"], padx=24, pady=18)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="WHAT THIS DOES",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(
            body,
            text=("Disables every enabled network adapter on this PC right now. "
                  "All internet, Wi-Fi, Ethernet, VPN — gone in one click.\n\n"
                  "Use this when you suspect malware is exfiltrating data, "
                  "ransomware is spreading, or any active intrusion. The faster "
                  "you cut the network, the less damage they do."),
            bg=THEME["bg"], fg=THEME["fg"],
            font=("Segoe UI", 10),
            wraplength=500, justify="left").pack(anchor="w", pady=(6, 16))

        # List adapters
        tk.Label(body, text="ADAPTERS TO BE DISABLED",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")

        adapters = panic.list_adapters()
        enabled = [a for a in adapters if a["admin_state"].lower() == "enabled"]
        adapter_text = (
            "  • " + "\n  • ".join(a["name"] for a in enabled)
            if enabled else "  (no enabled adapters detected)"
        )
        tk.Label(body, text=adapter_text,
                 bg=THEME["bg"], fg=THEME["fg"],
                 font=("Consolas", 10),
                 justify="left").pack(anchor="w", pady=(4, 16))

        # Reason field
        tk.Label(body, text="REASON (optional)",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        reason_var = tk.StringVar()
        ttk.Entry(body, textvariable=reason_var, width=60).pack(
            fill="x", pady=(4, 8), ipady=4)
        tk.Label(body,
                 text="e.g. 'Saw a Critical alert' — saved alongside the action.",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 8, "italic")).pack(anchor="w", pady=(0, 12))

        # Admin warning
        if not panic.is_isolated() and not firewall_manager.is_admin():
            tk.Label(body,
                     text="⚠  Requires Administrator. Re-launch via "
                          "LAUNCH-as-admin.bat first.",
                     bg=THEME["bg"], fg="#ff7f50",
                     font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(4, 8))

        # Buttons
        btns = tk.Frame(body, bg=THEME["bg"])
        btns.pack(fill="x", pady=(8, 0))
        tk.Button(btns, text="🚨   ISOLATE NOW",
                  bg="#ff4757", fg="#fff",
                  font=("Segoe UI", 11, "bold"),
                  padx=22, pady=12, relief="flat", cursor="hand2",
                  activebackground="#e83b4d",
                  command=lambda: self._do_isolate(win, reason_var.get())
                  ).pack(side="left", padx=(0, 10))
        ttk.Button(btns, text="Cancel",
                   command=win.destroy).pack(side="left")

    def _do_isolate(self, win, reason):
        if not firewall_manager.is_admin():
            messagebox.showwarning(
                "Administrator required",
                "Disabling network adapters requires Administrator.\n\n"
                "Re-launch via LAUNCH-as-admin.bat.",
                parent=win,
            )
            return
        if not messagebox.askyesno(
            "Last chance",
            "Are you sure? This will disconnect you immediately.\n\n"
            "(You can restore the network from the same Panic button.)",
            parent=win,
        ):
            return
        ok, msg = panic.isolate(reason=reason)
        if ok:
            messagebox.showinfo("Isolated", msg, parent=win)
            self._update_panic_button()
            win.destroy()
        else:
            messagebox.showerror("Failed", msg, parent=win)

    def _update_panic_button(self):
        if panic.is_isolated():
            self.panic_btn.config(text="🔌  RESTORE NETWORK", bg="#ffd93d", fg="#000")
        else:
            self.panic_btn.config(text="🚨  PANIC", bg="#ff4757", fg="#fff")

    # ──────────────────────────────────────────
    # 🔐 Password Strength Checker
    # ──────────────────────────────────────────
    def open_password_check(self):
        win = tk.Toplevel(self)
        win.title("Password Strength Checker — Log Sentinel")
        win.configure(bg=THEME["bg"])
        win.geometry("620x600")
        win.transient(self)
        win.grab_set()
        win.update_idletasks()
        x = (win.winfo_screenwidth() - 620) // 2
        y = (win.winfo_screenheight() - 600) // 2
        win.geometry(f"620x600+{x}+{y}")

        header = tk.Frame(win, bg=THEME["accent"], height=64)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="🔐  Password Strength Checker",
                 bg=THEME["accent"], fg="#000",
                 font=("Segoe UI", 16, "bold")).pack(pady=16)

        body = tk.Frame(win, bg=THEME["bg"], padx=24, pady=20)
        body.pack(fill="both", expand=True)

        tk.Label(body,
                 text="Type a password — we score it offline. "
                      "Nothing leaves your computer.",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 10, "italic")).pack(anchor="w", pady=(0, 12))

        # Entry + show/hide
        entry_row = tk.Frame(body, bg=THEME["bg"])
        entry_row.pack(fill="x", pady=(0, 12))
        pw_var = tk.StringVar()
        show_var = tk.BooleanVar(value=False)
        entry = ttk.Entry(entry_row, textvariable=pw_var, show="•",
                          font=("Consolas", 13))
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        entry.focus_set()

        def toggle_show():
            entry.config(show="" if show_var.get() else "•")
        tk.Checkbutton(entry_row, text="  Show",
                       variable=show_var, command=toggle_show,
                       bg=THEME["bg"], fg=THEME["fg"],
                       selectcolor=THEME["bg_panel"],
                       activebackground=THEME["bg"],
                       font=("Segoe UI", 10)).pack(side="left", padx=(8, 0))

        # Score display
        score_card = tk.Frame(body, bg=THEME["bg_card"], padx=20, pady=14)
        score_card.pack(fill="x", pady=(0, 12))

        tk.Label(score_card, text="STRENGTH",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")

        score_row = tk.Frame(score_card, bg=THEME["bg_card"])
        score_row.pack(fill="x", pady=(6, 4))
        score_lbl = tk.Label(score_row, text="—",
                             bg=THEME["bg_card"], fg=THEME["fg_dim"],
                             font=("Segoe UI", 24, "bold"))
        score_lbl.pack(side="left")
        rating_lbl = tk.Label(score_row, text="",
                              bg=THEME["bg_card"], fg=THEME["fg_dim"],
                              font=("Segoe UI", 14, "bold"))
        rating_lbl.pack(side="left", padx=(12, 0))

        # Progress bar (canvas)
        bar_canvas = tk.Canvas(score_card, height=12,
                               bg=THEME["bg_panel"], highlightthickness=0)
        bar_canvas.pack(fill="x", pady=(6, 8))
        bar_canvas.bind("<Configure>",
                        lambda e: _redraw_bar(pw_var.get()))

        meta_lbl = tk.Label(score_card, text="",
                            bg=THEME["bg_card"], fg=THEME["fg_dim"],
                            font=("Segoe UI", 10))
        meta_lbl.pack(anchor="w")

        # Issues + Tips
        issues_lbl = tk.Label(body, text="",
                              bg=THEME["bg"], fg="#ff7f50",
                              font=("Segoe UI", 10),
                              wraplength=560, justify="left", anchor="w")
        issues_lbl.pack(fill="x", pady=(8, 4))

        tips_lbl = tk.Label(body, text="",
                            bg=THEME["bg"], fg=THEME["accent"],
                            font=("Segoe UI", 10),
                            wraplength=560, justify="left", anchor="w")
        tips_lbl.pack(fill="x", pady=(2, 6))

        def _redraw_bar(pw):
            bar_canvas.delete("all")
            r = password_check.check(pw)
            w = bar_canvas.winfo_width() or 540
            h = bar_canvas.winfo_height() or 12
            bar_canvas.create_rectangle(0, 0, w, h, fill="#3d3d5c", outline="")
            fill_w = int(w * (r.score / 100))
            bar_canvas.create_rectangle(0, 0, fill_w, h,
                                        fill=r.color, outline="")

        def _update_score(*_a):
            pw = pw_var.get()
            r = password_check.check(pw)
            score_lbl.config(text=f"{r.score}", fg=r.color)
            rating_lbl.config(text=r.label, fg=r.color)
            _redraw_bar(pw)
            meta_lbl.config(
                text=f"Entropy: {r.entropy_bits:.0f} bits   ·   "
                     f"Crack time (offline GPU): {r.crack_time}")
            issues_lbl.config(
                text=("⚠  " + "\n⚠  ".join(r.issues)) if r.issues else ""
            )
            tips_lbl.config(
                text=("💡  " + "\n💡  ".join(r.tips)) if r.tips else ""
            )

        pw_var.trace_add("write", _update_score)
        _update_score()

        # Footer
        footer = tk.Frame(win, bg=THEME["bg"], pady=12)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer,
                 text="Tip: a long passphrase like 'morning-coffee-blue-39' "
                      "beats a short complex password every time.",
                 bg=THEME["bg"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "italic"),
                 wraplength=560).pack(side="left", padx=18)
        ttk.Button(footer, text="Close", style="Accent.TButton",
                   command=win.destroy).pack(side="right", padx=18)

    # ── System tab ──────────────────────────────
    def _build_system_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  System  ")

        system_card = tk.Frame(f, bg=THEME["bg_card"], padx=18, pady=14)
        system_card.pack(fill="x", padx=10, pady=(10, 6))
        header = tk.Frame(system_card, bg=THEME["bg_card"])
        header.pack(fill="x")
        title_col = tk.Frame(header, bg=THEME["bg_card"])
        title_col.pack(side="left", fill="x", expand=True)
        tk.Label(title_col, text="SYSTEM INFO",
                 bg=THEME["bg_card"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(title_col,
                 text="Hardware, storage, battery, and buyer-check details.",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))
        ttk.Button(header, text="Refresh",
                   command=self.refresh).pack(side="right", padx=(8, 0))

        self.system_metric_row = tk.Frame(system_card, bg=THEME["bg_card"])
        self.system_metric_row.pack(fill="x", pady=(12, 8))

        details_wrap = tk.Frame(system_card, bg=THEME["bg_panel"],
                                highlightthickness=1,
                                highlightbackground=THEME["border"])
        details_wrap.pack(fill="x")
        self.system_summary_text = tk.Text(
            details_wrap, height=9, bg=THEME["bg_panel"], fg=THEME["fg"],
            insertbackground=THEME["fg"], relief="flat", wrap="word",
            font=("Consolas", 9), padx=10, pady=8,
        )
        self.system_summary_scroll = ttk.Scrollbar(
            details_wrap, orient="vertical",
            command=self.system_summary_text.yview,
        )
        self.system_summary_text.configure(
            yscrollcommand=self.system_summary_scroll.set,
        )
        self.system_summary_text.pack(side="left", fill="both", expand=True)
        self.system_summary_scroll.pack(side="right", fill="y")
        self.system_summary_text.insert(
            "1.0",
            "Run a scan to collect hardware, storage, battery, and system details.",
        )
        self.system_summary_text.config(state="disabled")

        paned = ttk.PanedWindow(f, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        # Software
        sw_frame = ttk.Frame(paned, style="TFrame")
        tk.Label(sw_frame, text="INSTALLED SOFTWARE",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        cols = ("name", "version", "publisher", "installed")
        self.sw_tree = ttk.Treeview(sw_frame, columns=cols, show="headings",
                                    selectmode="browse")
        for col, w in [("name", 260), ("version", 110),
                       ("publisher", 200), ("installed", 100)]:
            self.sw_tree.heading(col, text=col.title())
            self.sw_tree.column(col, width=w, anchor="w")
        self.sw_tree.pack(fill="both", expand=True)
        paned.add(sw_frame, weight=2)

        # Right side: DNS + recent files
        right = ttk.Frame(paned, style="TFrame")
        paned.add(right, weight=1)

        tk.Label(right, text="DNS CACHE",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        cols2 = ("name", "data")
        self.dns_tree = ttk.Treeview(right, columns=cols2, show="headings",
                                     height=10, selectmode="browse")
        for col, w in [("name", 280), ("data", 200)]:
            self.dns_tree.heading(col, text=col.title())
            self.dns_tree.column(col, width=w, anchor="w")
        self.dns_tree.pack(fill="x", pady=(0, 12))

        tk.Label(right, text="RECENT FILES",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        cols3 = ("name", "modified")
        self.recent_tree = ttk.Treeview(right, columns=cols3, show="headings",
                                        selectmode="browse")
        for col, w in [("name", 320), ("modified", 160)]:
            self.recent_tree.heading(col, text=col.title())
            self.recent_tree.column(col, width=w, anchor="w")
        self.recent_tree.pack(fill="both", expand=True)

    # ── Live Activity Feed tab ────────────────────────
    def _build_live_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  ⚡ Live Feed  ")

        # Status bar at top of tab
        bar = tk.Frame(f, bg=THEME["bg_card"], padx=14, pady=10)
        bar.pack(fill="x", padx=10, pady=(10, 0))

        self.live_status_lbl = tk.Label(
            bar, text="●  STOPPED", bg=THEME["bg_card"], fg="#888",
            font=("Segoe UI", 10, "bold"))
        self.live_status_lbl.pack(side="left")

        tk.Label(bar, text="   Polling every 2s — diffs against previous snapshot",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "italic")).pack(side="left", padx=8)

        self.live_count_lbl = tk.Label(
            bar, text="0 events", bg=THEME["bg_card"], fg=THEME["accent"],
            font=("Segoe UI", 10, "bold"))
        self.live_count_lbl.pack(side="right")

        # Filter row
        filt = ttk.Frame(f, style="TFrame")
        filt.pack(fill="x", padx=10, pady=(8, 4))
        tk.Label(filt, text="Filter:", bg=THEME["bg"],
                 fg=THEME["fg_dim"]).pack(side="left", padx=(4, 6))

        self.live_filter_var = tk.StringVar(value="All")
        ttk.Combobox(filt, textvariable=self.live_filter_var,
                     values=["All", "Process events", "Network events",
                             "Threats only", "Critical+High only"],
                     width=22, state="readonly").pack(side="left")
        self.live_filter_var.trace_add("write",
                                        lambda *a: self._refresh_live_table())

        ttk.Button(filt, text="🗑  Clear",
                   command=self._clear_live).pack(side="right")

        # Activity table — newest at top
        cols = ("time", "kind", "severity", "mitre", "title", "tags")
        self.live_tree = ttk.Treeview(
            f, columns=cols, show="headings", selectmode="browse",
        )
        for col, w in [
            ("time", 90), ("kind", 110), ("severity", 90),
            ("mitre", 80), ("title", 700), ("tags", 200),
        ]:
            self.live_tree.heading(col, text=col.upper() if col == "mitre" else col.title())
            self.live_tree.column(col, width=w, anchor="w")

        for sev, color in SEVERITY_FG.items():
            self.live_tree.tag_configure(f"sev_{sev}", foreground=color)
        self.live_tree.tag_configure("new", background="#1a3d2c")

        self.live_tree.pack(fill="both", expand=True, padx=10, pady=4)
        self.live_tree.bind("<<TreeviewSelect>>", self._on_live_select)

        # Detail panel
        self.live_detail = tk.Text(
            f, height=6, bg=THEME["bg_panel"], fg=THEME["fg"],
            insertbackground=THEME["fg"], font=("Consolas", 9),
            relief="flat", padx=10, pady=8, wrap="word",
        )
        self.live_detail.pack(fill="x", padx=10, pady=(4, 10))
        self.live_detail.config(state="disabled")
        self.live_detail.insert("1.0", "")

    def toggle_live(self):
        if self.live_monitor and self.live_monitor.is_alive():
            self.live_monitor.stop()
            self.live_monitor = None
            self.live_btn.config(text="▶  Live Mode")
            self.live_status_lbl.config(text="●  STOPPED", fg="#888")
            self.status_var.set("Live mode stopped.")
        else:
            self.live_q = queue.Queue()
            self.live_monitor = LiveMonitor(self.live_q, interval=2.0)
            self.live_monitor.start()
            self.live_btn.config(text="⏸  Stop Live")
            self.live_status_lbl.config(text="●  LIVE", fg="#4ecdc4")
            self.status_var.set("Live monitoring — polling every 2s")
            # Switch to Live Feed tab (Health=0, Dashboard=1, Live=2)
            for i in range(self.notebook.index("end")):
                if "Live Feed" in self.notebook.tab(i, "text"):
                    self.notebook.select(i)
                    break
            self.after(200, self._poll_live_queue)

    def _poll_live_queue(self):
        if not self.live_monitor or not self.live_monitor.is_alive():
            return
        new_items: list[ActivityEvent] = []
        try:
            while True:
                ev = self.live_q.get_nowait()
                new_items.append(ev)
        except queue.Empty:
            pass

        if new_items:
            self.live_events.extend(new_items)
            # Cap memory at 5000 events
            if len(self.live_events) > 5000:
                self.live_events = self.live_events[-5000:]
            self._add_live_rows(new_items)
            self.live_count_lbl.config(text=f"{len(self.live_events)} events")

            # Toast for any Critical or High
            for ev in new_items:
                if ev.severity in ("Critical", "High"):
                    self._show_toast(ev)

        self.after(300, self._poll_live_queue)

    def _add_live_rows(self, new_items: list[ActivityEvent]):
        sel_filter = self.live_filter_var.get()

        def keep(ev: ActivityEvent) -> bool:
            if sel_filter == "All":
                return True
            if sel_filter == "Process events":
                return ev.kind.startswith("process")
            if sel_filter == "Network events":
                return ev.kind.startswith("net")
            if sel_filter == "Threats only":
                return ev.ioc is not None
            if sel_filter == "Critical+High only":
                return ev.severity in ("Critical", "High")
            return True

        for ev in new_items:
            if not keep(ev):
                continue
            mitre = ""
            # No rule field on activity events; map a few kinds heuristically
            if ev.kind == "process_start":
                mitre = "T1059"
            elif ev.kind == "net_new":
                mitre = "T1071"
            tags = ", ".join(ev.tags) if ev.tags else ""
            row = self.live_tree.insert(
                "", 0,  # insert at top — newest first
                values=(
                    ev.timestamp.strftime("%H:%M:%S"),
                    ev.kind, ev.severity, mitre,
                    ev.title, tags,
                ),
                tags=(f"sev_{ev.severity}", "new"),
            )

        # Cap visible rows at 1000
        children = self.live_tree.get_children()
        if len(children) > 1000:
            for child in children[1000:]:
                self.live_tree.delete(child)

    def _refresh_live_table(self):
        for row in self.live_tree.get_children():
            self.live_tree.delete(row)
        self._add_live_rows(self.live_events)

    def _on_live_select(self, _event=None):
        sel = self.live_tree.selection()
        if not sel:
            return
        row = self.live_tree.item(sel[0])
        vals = row["values"]
        if not vals or len(vals) < 5:
            return
        # Find matching event by time + title
        time_s, kind, sev, mitre, title, tags = vals[:6]
        match = None
        for ev in reversed(self.live_events):
            if ev.title == title and ev.timestamp.strftime("%H:%M:%S") == time_s:
                match = ev
                break
        if not match:
            return

        self.live_detail.config(state="normal")
        self.live_detail.delete("1.0", "end")
        text = (
            f"Time     : {match.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Kind     : {match.kind}\n"
            f"Severity : {match.severity}\n"
            f"Tags     : {', '.join(match.tags) or '—'}\n"
        )
        if match.ioc:
            text += (
                f"\nIOC MATCH:\n"
                f"  Type        : {match.ioc.ioc_type}\n"
                f"  Indicator   : {match.ioc.indicator}\n"
                f"  Description : {match.ioc.description}\n"
            )
        text += f"\nDetails:\n{match.detail}\n"
        self.live_detail.insert("1.0", text)
        self.live_detail.config(state="disabled")

    def _clear_live(self):
        self.live_events.clear()
        for row in self.live_tree.get_children():
            self.live_tree.delete(row)
        self.live_count_lbl.config(text="0 events")
        self.live_detail.config(state="normal")
        self.live_detail.delete("1.0", "end")
        self.live_detail.config(state="disabled")

    def _show_toast(self, ev: ActivityEvent):
        """Slide-in toast notification for high-severity live events."""
        toast = tk.Toplevel(self)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        try:
            toast.attributes("-alpha", 0.95)
        except tk.TclError:
            pass

        color = SEVERITY_FG.get(ev.severity, "#888")
        frame = tk.Frame(toast, bg=THEME["bg_card"],
                         highlightthickness=2, highlightbackground=color)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text=ev.severity.upper(),
                 bg=color, fg="#000",
                 font=("Segoe UI", 8, "bold"),
                 padx=8, pady=2).pack(anchor="w", padx=10, pady=(10, 4))
        tk.Label(frame, text=ev.title,
                 bg=THEME["bg_card"], fg=THEME["fg"],
                 font=("Segoe UI", 10, "bold"),
                 wraplength=320, justify="left").pack(
            anchor="w", padx=10, pady=(0, 4))
        tk.Label(frame, text=ev.detail[:200],
                 bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Consolas", 8),
                 wraplength=320, justify="left").pack(
            anchor="w", padx=10, pady=(0, 10))

        # Position bottom-right of screen
        self.update_idletasks()
        toast.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = 360
        h = max(110, toast.winfo_reqheight())
        x = sw - w - 24
        y = sh - h - 80
        toast.geometry(f"{w}x{h}+{x}+{y}")
        toast.after(5000, toast.destroy)

    # ──────────────────────────────────────────
    # Refresh / collection
    # ──────────────────────────────────────────
    def refresh(self):
        if not self._ensure_licensed():
            self.status_var.set("Trial expired. Enter a new 30-day licence key.")
            return
        if self.collector and self.collector.is_alive():
            return
        try:
            hours = int(self.hours_var.get())
        except ValueError:
            hours = 24

        self.progress.start(10)
        self.status_var.set("Starting collection…")
        self.q = queue.Queue()
        self.collector = CollectorThread(hours, self.q)
        self.collector.start()

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                self._handle_message(kind, payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_message(self, kind: str, payload):
        if kind == "status":
            self.status_var.set(payload)
        elif kind == "system_info":
            self.system_info = payload
            self._render_host_info()
            self._render_dashboard()
        elif kind == "processes":
            self.processes = payload
            self._render_processes()
        elif kind == "network":
            self.connections = payload
            self._render_network()
            self._render_dashboard()
        elif kind == "services":
            self.services = payload
            self._render_services()
        elif kind == "tasks":
            self.tasks = payload
            self._render_tasks()
        elif kind == "autoruns":
            self.autoruns = payload
            self._render_autoruns()
        elif kind == "dns":
            self.dns_entries = payload
            self._render_dns()
        elif kind == "usb":
            self.usb_devices = payload
            self._render_usb()
        elif kind == "software":
            self.software = payload
            self._render_software()
        elif kind == "recent_files":
            self.recent_files = payload
            self._render_recent_files()
        elif kind == "events":
            self.events = payload
            self._refresh_events_table()
            self._render_dashboard()
        elif kind == "done":
            # Register custom + FIM + honeypot explanations once
            from src import custom_rules, fim, honeypots
            try:
                custom_rules.register_explanations()
                fim.register_explanations()
                honeypots.register_explanations()
            except Exception:
                pass

            # Run all detection rules through the shared pipeline used by
            # both GUI and scheduled/headless scans.
            from src.detection_pipeline import run_detection
            self.findings = run_detection(
                events=self.events,
                processes=self.processes,
                connections=self.connections,
                autoruns=self.autoruns,
                services=self.services,
                tasks=self.tasks,
            )

            # Send email alert if any Critical/High and email is enabled
            try:
                from src import email_alerts
                from src.health_score import calculate as _calc
                cfg = email_alerts.load_config()
                if cfg.enabled and cfg.smtp_host and cfg.to_addresses:
                    active = preferences.filter_active(self.findings)
                    crits = [f for f in active
                             if f.severity in ("Critical", "High")]
                    if crits:
                        h = _calc(active)
                        ok, msg = email_alerts.send_findings_alert(
                            active, h.score, h.grade,
                        )
                        if ok:
                            print(f"[email] Alert sent: {msg}")
                        else:
                            print(f"[email] {msg}")
            except Exception as e:
                print(f"[email] error: {e}")
            self._render_health()
            self._render_dashboard()
            self._refresh_findings_table()
            self._render_trends_chart()
            self._render_trends_stats()
            self._render_timeline()
            self._update_notification_badge()
            self.progress.stop()
            self.status_var.set(
                f"✓ Collected {len(self.events)} events, "
                f"{len(self.processes)} processes, "
                f"{len(self.connections)} connections — "
                f"{len(self.findings)} findings."
            )
        elif kind == "error":
            self.progress.stop()
            self.status_var.set(f"Error: {payload}")
            messagebox.showerror("Collection error", str(payload))

    # ──────────────────────────────────────────
    # Renderers
    # ──────────────────────────────────────────
    def _render_host_info(self):
        si = self.system_info
        if not si:
            return
        ips = ", ".join(si.ip_addresses[:4]) or "—"
        text = (
            f"Hostname  : {si.hostname}\n"
            f"User      : {si.user}\n"
            f"Domain    : {si.domain or '(workgroup)'}\n"
            f"OS        : {si.os}\n"
            f"Boot time : {si.boot_time or 'unknown'}\n"
            f"IPs       : {ips}"
        )
        self.host_info_label.config(text=text)
        if hasattr(self, "system_summary_text"):
            if hasattr(self, "system_metric_row"):
                for w in self.system_metric_row.winfo_children():
                    w.destroy()
                disk_free = sum(float(d.get("free_gb") or 0) for d in si.disks)
                disk_total = sum(float(d.get("size_gb") or 0) for d in si.disks)
                metrics = [
                    ("CPU", f"{si.cpu_cores}C/{si.cpu_logical_processors}T" if si.cpu_cores else "Unknown"),
                    ("RAM", f"{si.ram_total_gb:g} GB" if si.ram_total_gb else "Unknown"),
                    ("Free RAM", f"{si.ram_free_gb:g} GB" if si.ram_free_gb else "Unknown"),
                    ("Storage", f"{disk_free:.0f}/{disk_total:.0f} GB free" if disk_total else "Unknown"),
                    ("GPU", f"{len(si.gpus)} detected" if si.gpus else "Unknown"),
                    ("Battery", f"{si.battery.get('charge_pct')}%" if si.battery else "Desktop/none"),
                ]
                for label, value in metrics:
                    chip = tk.Frame(
                        self.system_metric_row, bg=THEME["bg_card_solid"],
                        padx=12, pady=8, highlightthickness=1,
                        highlightbackground=THEME["border_subtle"],
                    )
                    chip.pack(side="left", fill="x", expand=True, padx=(0, 6))
                    tk.Label(chip, text=label.upper(),
                             bg=THEME["bg_card_solid"], fg=THEME["fg_subtle"],
                             font=("Segoe UI", 8, "bold")).pack(anchor="w")
                    tk.Label(chip, text=value,
                             bg=THEME["bg_card_solid"], fg=THEME["fg"],
                             font=("Segoe UI Semibold", 11)).pack(anchor="w", pady=(2, 0))
            used_ram = round(max(si.ram_total_gb - si.ram_free_gb, 0), 1) if si.ram_total_gb else 0
            ram_pct = round((used_ram / si.ram_total_gb) * 100, 1) if si.ram_total_gb else 0
            lines = [
                "IDENTITY",
                f"  Brand/model : {(si.manufacturer + ' ' + si.model).strip() or 'Unknown'}",
                f"  Serial      : {si.serial_number or 'Unknown'}",
                f"  BIOS        : {si.bios_version or 'Unknown'}",
                f"  OS          : {si.os}",
                f"  Boot time   : {si.boot_time or 'Unknown'}",
                "",
                "PERFORMANCE",
                f"  CPU         : {si.cpu or 'Unknown'}",
                f"  Cores       : {si.cpu_cores} physical / {si.cpu_logical_processors} logical",
                f"  RAM         : {si.ram_total_gb or 0} GB total, {si.ram_free_gb or 0} GB free ({ram_pct}% used)",
            ]
            if si.ram_modules:
                sticks = []
                for m in si.ram_modules:
                    sticks.append(
                        f"{m.get('capacity_gb')} GB {m.get('speed_mhz') or ''}MHz {m.get('manufacturer') or ''}".strip()
                    )
                lines.append("  RAM sticks  : " + "; ".join(sticks))
            lines.extend(["", "GRAPHICS"])
            if si.gpus:
                for gpu in si.gpus:
                    vram = f", {gpu.get('vram_gb')} GB VRAM" if gpu.get("vram_gb") else ""
                    res = f", {gpu.get('resolution')}" if gpu.get("resolution") else ""
                    lines.append(f"  GPU         : {gpu.get('name') or 'Unknown'}{vram}{res}")
                    if gpu.get("driver"):
                        lines.append(f"  Driver      : {gpu.get('driver')}")
            else:
                lines.append("  GPU         : Unknown")
            lines.extend(["", "STORAGE / PARTITIONS"])
            if si.disks:
                for disk in si.disks:
                    label = f" ({disk.get('label')})" if disk.get("label") else ""
                    lines.append(
                        f"  {disk.get('drive')}{label}: {disk.get('size_gb')} GB total, "
                        f"{disk.get('free_gb')} GB free, {disk.get('used_pct')}% used, {disk.get('fs')}"
                    )
            else:
                lines.append("  No fixed disks reported.")
            lines.extend(["", "BATTERY"])
            if si.battery:
                runtime = si.battery.get("runtime_min")
                runtime_txt = f", runtime estimate {runtime} min" if runtime not in ("", None, 71582788) else ""
                lines.append(
                    f"  {si.battery.get('name') or 'Battery'}: "
                    f"{si.battery.get('charge_pct', 'unknown')}% charge, "
                    f"status code {si.battery.get('status', 'unknown')}{runtime_txt}"
                )
            else:
                lines.append("  No battery detected. This is normal for desktop PCs.")
            lines.extend(["", "SYSTEM CHECK NOTES"])
            lines.append("  Check serial/model matches seller listing. Check disk free space and RAM amount.")
            lines.append("  On laptops, confirm battery charges normally and does not drain too fast.")
            self.system_summary_text.config(state="normal")
            self.system_summary_text.delete("1.0", "end")
            self.system_summary_text.insert("1.0", "\n".join(lines))
            self.system_summary_text.config(state="disabled")

    def _render_dashboard(self):
        # Update severity cards
        counts = {s: 0 for s in SEVERITY_FG}
        for f in preferences.filter_active(self.findings):
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for sev, lbl in self.card_labels.items():
            lbl.config(text=str(counts.get(sev, 0)))

        # Update category breakdown
        for w in self.cat_breakdown_frame.winfo_children():
            w.destroy()
        cat_counts: dict[str, int] = {c: 0 for c in CATEGORIES}
        for e in self.events:
            cat = category_for_event_id(e.event_id)
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        # Show non-zero categories sorted by count desc
        items = sorted(
            [(c, n) for c, n in cat_counts.items() if n > 0],
            key=lambda x: x[1], reverse=True,
        )
        max_count = max((n for _, n in items), default=1)
        for cat, n in items:
            row = tk.Frame(self.cat_breakdown_frame, bg=THEME["bg_card"])
            row.pack(fill="x", pady=2)
            color = CATEGORY_COLORS.get(cat, "#888")
            tk.Label(row, text=cat, bg=THEME["bg_card"], fg=THEME["fg"],
                     width=20, anchor="w",
                     font=("Segoe UI", 9)).pack(side="left")
            bar = tk.Frame(row, bg=color, height=12,
                           width=int(200 * n / max_count))
            bar.pack(side="left", padx=4)
            bar.pack_propagate(False)
            tk.Label(row, text=str(n), bg=THEME["bg_card"], fg=THEME["fg"],
                     font=("Segoe UI", 9, "bold")).pack(side="left", padx=4)

        # Top critical findings (Critical + High)
        for w in self.top_findings_frame.winfo_children():
            w.destroy()
        top = [f for f in self.findings if f.severity in ("Critical", "High")][:8]
        if not top:
            tk.Label(self.top_findings_frame,
                     text="✓  No critical or high findings.",
                     bg=THEME["bg"], fg="#4ecdc4",
                     font=("Segoe UI", 11)).pack(anchor="w", pady=10)
        for f in top:
            row = tk.Frame(self.top_findings_frame, bg=THEME["bg_card"])
            row.pack(fill="x", pady=2)
            color = SEVERITY_FG[f.severity]
            tk.Label(row, text=f.severity.upper(), bg=color, fg="#000",
                     font=("Segoe UI", 8, "bold"),
                     width=10, padx=4, pady=2).pack(side="left", padx=2, pady=2)
            cat = category_for_rule(f.rule)
            tk.Label(row, text=cat, bg=THEME["bg_card"],
                     fg=CATEGORY_COLORS.get(cat, "#888"),
                     font=("Segoe UI", 9, "bold"),
                     width=18, anchor="w").pack(side="left", padx=6)
            tk.Label(row, text=f.title, bg=THEME["bg_card"], fg=THEME["fg"],
                     font=("Segoe UI", 9), anchor="w").pack(
                side="left", fill="x", expand=True, padx=4)

    def _dashboard_panel(self, parent, title: str, row: int | None = None,
                         col: int | None = None, packed: bool = False):
        card = tk.Frame(
            parent, bg=THEME["bg_card"], padx=14, pady=12,
            highlightthickness=1, highlightbackground="#24415f",
        )
        if packed:
            card.pack(fill="x", pady=(0, 10))
        else:
            card.grid(row=row, column=col, sticky="nsew", padx=6, pady=6)
        tk.Label(card, text=title, bg=THEME["bg_card"], fg=THEME["fg"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        return card

    def _dashboard_metric_card(self, parent, col: int, title: str, key: str,
                               value: str, detail: str, color: str):
        card = tk.Frame(
            parent, bg=THEME["bg_card"], padx=18, pady=14,
            highlightthickness=1, highlightbackground="#24415f",
        )
        card.grid(row=0, column=col, sticky="nsew", padx=6)
        tk.Label(card, text=title, bg=THEME["bg_card"], fg=THEME["fg_dim"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        value_lbl = tk.Label(card, text=value, bg=THEME["bg_card"], fg=THEME["fg"],
                             font=("Segoe UI Semibold", 22))
        value_lbl.pack(anchor="w", pady=(6, 0))
        detail_lbl = tk.Label(card, text=detail, bg=THEME["bg_card"], fg=color,
                              font=("Segoe UI", 9))
        detail_lbl.pack(anchor="w", pady=(2, 0))
        self.dashboard_widgets[key] = (value_lbl, detail_lbl)

    def _build_dashboard_tab(self):
        f = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(f, text="  Dashboard  ")
        self.dashboard_widgets = {}

        canvas = tk.Canvas(f, bg=THEME["bg"], highlightthickness=0)
        sb = ttk.Scrollbar(f, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        root = tk.Frame(canvas, bg=THEME["bg"], padx=18, pady=16)
        win_id = canvas.create_window((0, 0), window=root, anchor="nw")
        root.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win_id, width=e.width))

        header = tk.Frame(root, bg=THEME["bg"])
        header.pack(fill="x", pady=(0, 14))
        title_col = tk.Frame(header, bg=THEME["bg"])
        title_col.pack(side="left", fill="x", expand=True)
        tk.Label(title_col, text="Dashboard", bg=THEME["bg"], fg=THEME["fg"],
                 font=("Segoe UI Semibold", 18)).pack(anchor="w")
        tk.Label(title_col, text="Overview of system security, logs, and host health.",
                 bg=THEME["bg"], fg=THEME["fg_dim"], font=("Segoe UI", 10)
                 ).pack(anchor="w", pady=(2, 0))
        ttk.Button(header, text="Export Report", command=self.export_html
                   ).pack(side="right", padx=(8, 0))
        ttk.Button(header, text="Scan Now", style="Accent.TButton",
                   command=self.refresh).pack(side="right")

        metrics = tk.Frame(root, bg=THEME["bg"])
        metrics.pack(fill="x", pady=(0, 14))
        for i in range(4):
            metrics.grid_columnconfigure(i, weight=1, uniform="metric")
        self._dashboard_metric_card(metrics, 0, "Total Findings", "total_findings", "0", "No active findings", "#3aa0ff")
        self._dashboard_metric_card(metrics, 1, "System Health", "health_score", "0 /100", "Run a scan", "#5cc96b")
        self._dashboard_metric_card(metrics, 2, "Logs Analyzed", "logs_analyzed", "0", "Windows Event Logs", "#3aa0ff")
        self._dashboard_metric_card(metrics, 3, "Last Scan", "last_scan", "-", "Not scanned yet", "#a875ff")

        main = tk.Frame(root, bg=THEME["bg"])
        main.pack(fill="both", expand=True)
        for i in range(4):
            main.grid_columnconfigure(i, weight=1, uniform="dash")

        severity_card = self._dashboard_panel(main, "Severity Overview", row=0, col=0)
        self.dashboard_severity_canvas = tk.Canvas(
            severity_card, height=230, bg=THEME["bg_card"], highlightthickness=0,
        )
        self.dashboard_severity_canvas.pack(fill="x")

        cat_card = self._dashboard_panel(main, "Top Finding Categories", row=0, col=1)
        self.cat_breakdown_frame = tk.Frame(cat_card, bg=THEME["bg_card"])
        self.cat_breakdown_frame.pack(fill="both", expand=True, pady=(8, 0))

        findings_card = self._dashboard_panel(main, "Recent High Severity Findings", row=0, col=2)
        self.top_findings_frame = tk.Frame(findings_card, bg=THEME["bg_card"])
        self.top_findings_frame.pack(fill="both", expand=True, pady=(8, 0))
        ttk.Button(findings_card, text="View All Findings",
                   command=lambda: self.notebook.select(5)).pack(anchor="w", pady=(8, 0))

        right_col = tk.Frame(main, bg=THEME["bg"])
        right_col.grid(row=0, column=3, rowspan=2, sticky="nsew", padx=(6, 0), pady=6)
        system_card = self._dashboard_panel(right_col, "System Information", packed=True)
        self.host_info_label = tk.Label(
            system_card, text="-", bg=THEME["bg_card"], fg=THEME["fg"],
            justify="left", font=("Consolas", 9), anchor="nw",
        )
        self.host_info_label.pack(fill="x", pady=(8, 0))

        net_card = self._dashboard_panel(right_col, "Network / GeoIP Context", packed=True)
        self.dashboard_network_label = tk.Label(
            net_card, text="-", bg=THEME["bg_card"], fg=THEME["fg"],
            justify="left", font=("Consolas", 9), anchor="nw",
        )
        self.dashboard_network_label.pack(fill="x", pady=(8, 0))

        export_card = self._dashboard_panel(right_col, "Export Report", packed=True)
        tk.Label(export_card, text="Generate a report for findings and system information.",
                 bg=THEME["bg_card"], fg=THEME["fg_dim"], font=("Segoe UI", 9),
                 wraplength=300, justify="left").pack(anchor="w", pady=(2, 10))
        ttk.Button(export_card, text="Export HTML Report", style="Accent.TButton",
                   command=self.export_html).pack(fill="x", pady=2)
        ttk.Button(export_card, text="Open Reports",
                   command=self.open_reports_window).pack(fill="x", pady=2)

        timeline_card = self._dashboard_panel(main, "Timeline Activity", row=1, col=0)
        self.dashboard_timeline_frame = tk.Frame(timeline_card, bg=THEME["bg_card"])
        self.dashboard_timeline_frame.pack(fill="both", expand=True, pady=(8, 0))
        ttk.Button(timeline_card, text="View Full Timeline",
                   command=lambda: self.notebook.select(2)).pack(anchor="w", pady=(8, 0))

        health_card = self._dashboard_panel(main, "System Health Indicators", row=1, col=1)
        self.dashboard_health_frame = tk.Frame(health_card, bg=THEME["bg_card"])
        self.dashboard_health_frame.pack(fill="both", expand=True, pady=(8, 0))
        ttk.Button(health_card, text="View System Info",
                   command=lambda: self.notebook.select(13)).pack(anchor="w", pady=(8, 0))

        actions_card = self._dashboard_panel(main, "Quick Actions", row=1, col=2)
        for label, command in [
            ("View Windows Logs", lambda: self.notebook.select(6)),
            ("Open Task Manager", remediation.open_task_manager),
            ("Firewall & Network", lambda: self.notebook.select(12)),
            ("Manage Autoruns", lambda: self.notebook.select(10)),
        ]:
            ttk.Button(actions_card, text=label, command=command).pack(fill="x", pady=3)
        ttk.Button(actions_card, text="Panic Button (Isolate Network)",
                   command=self.open_panic_dialog).pack(fill="x", pady=(8, 3))

        coverage = self._dashboard_panel(root, "Detection Coverage", packed=True)
        cov_row = tk.Frame(coverage, bg=THEME["bg_card"])
        cov_row.pack(fill="x", pady=(8, 0))
        for title, sub, color in [
            ("Authentication", "Logons, lockouts", "#3aa0ff"),
            ("Privilege Activity", "Admin, elevation", "#ff9f1a"),
            ("Persistence", "Services, tasks", "#52c41a"),
            ("Process Behavior", "Processes, paths", "#82aaff"),
            ("Network", "Connections, GeoIP", "#3aa0ff"),
            ("Defense Evasion", "Tampering, clearing", "#ff4757"),
            ("Ransomware", "Honeypots, integrity", "#ff4757"),
            ("Privacy", "Camera, browser", "#5cc96b"),
            ("System Health", "Performance, hardware", "#5cc96b"),
        ]:
            item = tk.Frame(cov_row, bg=THEME["bg_card"])
            item.pack(side="left", fill="x", expand=True, padx=4)
            tk.Label(item, text=title, bg=THEME["bg_card"], fg=color,
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(item, text=sub, bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 7)).pack(anchor="w")

    def _render_dashboard(self):
        if not hasattr(self, "dashboard_widgets"):
            return

        active = preferences.filter_active(self.findings)
        counts = {s: 0 for s in SEVERITY_FG}
        for f in active:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        health = calc_health(active)

        metric = self.dashboard_widgets.get("total_findings")
        if metric:
            metric[0].config(text=str(len(active)))
            metric[1].config(
                text=f"{counts.get('Critical', 0)} Critical   {counts.get('High', 0)} High   {counts.get('Medium', 0)} Medium"
            )
        metric = self.dashboard_widgets.get("health_score")
        if metric:
            metric[0].config(text=f"{health.score} /100")
            metric[1].config(text=health.grade + " - " + health.verdict, fg=health.color)
        metric = self.dashboard_widgets.get("logs_analyzed")
        if metric:
            metric[0].config(text=f"{len(self.events):,}")
            security_logs = sum(1 for e in self.events if e.channel == "Security")
            metric[1].config(text=f"{security_logs:,} Security logs")
        metric = self.dashboard_widgets.get("last_scan")
        if metric:
            metric[0].config(text=datetime.now().strftime("%I:%M %p").lstrip("0"))
            metric[1].config(text=datetime.now().strftime("%Y-%m-%d"))

        if hasattr(self, "dashboard_severity_canvas"):
            c = self.dashboard_severity_canvas
            c.delete("all")
            total = max(1, len(active))
            x0, y0, x1, y1 = 35, 25, 185, 175
            start = 90
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                n = counts.get(sev, 0)
                if not n:
                    continue
                extent = -(n / total) * 360
                c.create_arc(x0, y0, x1, y1, start=start, extent=extent,
                             fill=SEVERITY_FG.get(sev, "#888"),
                             outline=THEME["bg_card"], width=2)
                start += extent
            c.create_oval(72, 62, 148, 138, fill=THEME["bg_card"],
                          outline=THEME["bg_card"])
            c.create_text(110, 92, text=str(len(active)), fill=THEME["fg"],
                          font=("Segoe UI", 24, "bold"))
            c.create_text(110, 118, text="Total", fill=THEME["fg_dim"],
                          font=("Segoe UI", 9))
            y = 35
            for sev in ["Critical", "High", "Medium", "Low"]:
                c.create_oval(220, y + 4, 230, y + 14,
                              fill=SEVERITY_FG[sev], outline="")
                c.create_text(242, y + 9, text=f"{counts.get(sev, 0)}  {sev}",
                              fill=THEME["fg"], anchor="w",
                              font=("Segoe UI", 9))
                y += 34

        for w in self.cat_breakdown_frame.winfo_children():
            w.destroy()
        cat_counts: dict[str, int] = {}
        for f in active:
            cat = explain(f.rule).user_category
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        items = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:6]
        max_count = max((n for _, n in items), default=1)
        if not items:
            tk.Label(self.cat_breakdown_frame, text="No findings yet.",
                     bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 10)).pack(anchor="w", pady=8)
        for cat, n in items:
            row = tk.Frame(self.cat_breakdown_frame, bg=THEME["bg_card"])
            row.pack(fill="x", pady=5)
            tk.Label(row, text=cat, bg=THEME["bg_card"], fg=THEME["fg"],
                     width=16, anchor="w", font=("Segoe UI", 9)).pack(side="left")
            bar_bg = tk.Frame(row, bg=THEME["bg_panel"], height=5)
            bar_bg.pack(side="left", fill="x", expand=True, padx=8)
            bar = tk.Frame(bar_bg, bg=USER_CATEGORY_COLORS.get(cat, THEME["accent"]), height=5)
            bar.place(relx=0, rely=0, relwidth=max(0.08, n / max_count), relheight=1)
            tk.Label(row, text=str(n), bg=THEME["bg_card"], fg=THEME["fg"],
                     width=3, anchor="e", font=("Segoe UI", 9)).pack(side="left")

        for w in self.top_findings_frame.winfo_children():
            w.destroy()
        top = [f for f in active if f.severity in ("Critical", "High", "Medium")][:5]
        if not top:
            tk.Label(self.top_findings_frame, text="No high severity findings.",
                     bg=THEME["bg_card"], fg="#4ecdc4",
                     font=("Segoe UI", 10)).pack(anchor="w", pady=8)
        for f in top:
            row = tk.Frame(self.top_findings_frame, bg=THEME["bg_card"])
            row.pack(fill="x", pady=5)
            tk.Label(row, text="●", bg=THEME["bg_card"], fg=SEVERITY_FG[f.severity],
                     font=("Segoe UI", 12, "bold")).pack(side="left", padx=(0, 6))
            text = tk.Frame(row, bg=THEME["bg_card"])
            text.pack(side="left", fill="x", expand=True)
            tk.Label(text, text=f.title[:58], bg=THEME["bg_card"], fg=THEME["fg"],
                     anchor="w", font=("Segoe UI", 9)).pack(anchor="w", fill="x")
            tk.Label(text, text=f"{f.severity} · {explain(f.rule).user_category}",
                     bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     anchor="w", font=("Segoe UI", 8)).pack(anchor="w")

        if self.system_info:
            si = self.system_info
            ram = f"{si.ram_total_gb:.1f} GB" if si.ram_total_gb else "-"
            disk_free = "-"
            if si.disks:
                free = sum(float(d.get("free_gb") or 0) for d in si.disks)
                total = sum(float(d.get("size_gb") or 0) for d in si.disks)
                disk_free = f"{free:.0f} / {total:.0f} GB free" if total else f"{free:.0f} GB free"
            self.host_info_label.config(text="\n".join([
                f"Host Name : {si.hostname}",
                f"OS        : {si.os}",
                f"CPU       : {si.cpu[:36] or '-'}",
                f"RAM       : {ram}",
                f"Disk      : {disk_free}",
                f"Last Boot : {si.boot_time or '-'}",
                f"User      : {si.user or '-'}",
            ]))
        else:
            mem = sysmon.get_memory()
            disks = sysmon.get_disks()
            primary_disk = next((d for d in disks if d.drive.upper().startswith("C:")),
                                disks[0] if disks else None)
            battery = sysmon.get_battery()
            battery_text = (
                f"{battery.percent}% {'plugged in' if battery.plugged_in else 'on battery'}"
                if battery.has_battery else "Desktop / no battery"
            )
            disk_text = (
                f"{primary_disk.free_gb:.0f} / {primary_disk.total_gb:.0f} GB free"
                if primary_disk else "Not detected yet"
            )
            self.host_info_label.config(text="\n".join([
                f"Host Name : {socket.gethostname()}",
                f"OS        : {platform.system()} {platform.release()}",
                f"CPU       : {sysmon.get_cpu_count()} logical processor(s)",
                f"RAM       : {mem.available_gb:.1f} / {mem.total_gb:.1f} GB free",
                f"Disk      : {disk_text}",
                f"Battery   : {battery_text}",
                "Scan      : Click Scan Now for full buyer-check details",
            ]))

        if hasattr(self, "dashboard_network_label"):
            external = [c for c in self.connections if getattr(c, "is_external", False)]
            if external:
                conn = external[0]
                try:
                    from src import geoip
                    match = geoip.lookup(conn.remote_addr)
                    geo = f"{geoip.flag(match.country)} {match.country_name}"
                except Exception:
                    geo = "-"
                self.dashboard_network_label.config(text="\n".join([
                    f"IP Address : {conn.remote_addr}",
                    f"Country    : {geo}",
                    f"Port       : {conn.remote_port}",
                    f"Process    : {conn.process_name or '-'}",
                    f"External   : {len(external)} connection(s)",
                ]))
            else:
                try:
                    local_ip = socket.gethostbyname(socket.gethostname())
                except OSError:
                    local_ip = "Not detected"
                self.dashboard_network_label.config(text="\n".join([
                    f"Local IP   : {local_ip}",
                    "External   : Waiting for scan",
                    "GeoIP      : Available after network collection",
                    "Privacy    : Camera/browser checks show in Findings",
                ]))

        for w in self.dashboard_timeline_frame.winfo_children():
            w.destroy()
        recent_events = sorted(self.events, key=lambda e: e.timestamp, reverse=True)[:5]
        for e in recent_events:
            row = tk.Frame(self.dashboard_timeline_frame, bg=THEME["bg_card"])
            row.pack(fill="x", pady=4)
            tk.Label(row, text=e.timestamp.strftime("%H:%M"), bg=THEME["bg_card"],
                     fg=THEME["fg_dim"], width=7, anchor="w",
                     font=("Consolas", 9)).pack(side="left")
            tk.Label(row, text=f"{EVENT_LABELS.get(e.event_id, 'Windows event')} ({e.event_id})",
                     bg=THEME["bg_card"], fg=THEME["fg"],
                     anchor="w", font=("Segoe UI", 9)).pack(side="left", fill="x", expand=True)
        if not recent_events:
            tk.Label(self.dashboard_timeline_frame, text="No logs collected yet.",
                     bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 10)).pack(anchor="w", pady=8)

        for w in self.dashboard_health_frame.winfo_children():
            w.destroy()
        mem = sysmon.get_memory()
        disks = sysmon.get_disks()
        primary_disk = next((d for d in disks if d.drive.upper().startswith("C:")),
                            disks[0] if disks else None)
        battery = sysmon.get_battery()
        memory_state = f"{mem.used_pct:.0f}% used" if mem.total_gb else "Checking"
        memory_color = "#ff4757" if mem.used_pct >= 90 else "#ff9f1a" if mem.used_pct >= 75 else "#5cc96b"
        if primary_disk:
            disk_state = f"{primary_disk.used_pct:.0f}% used"
            disk_color = "#ff4757" if primary_disk.used_pct >= 92 else "#ff9f1a" if primary_disk.used_pct >= 80 else "#5cc96b"
        else:
            disk_state, disk_color = "Checking", THEME["fg_dim"]
        battery_state = (
            f"{battery.percent}%"
            if battery.has_battery else "Desktop"
        )
        indicators = [
            ("Startup Impact", "Scan needed" if not self.autoruns else "Review", "#ff9f1a" if self.autoruns else "#3aa0ff"),
            ("Disk Space", disk_state, disk_color),
            ("Memory Usage", memory_state, memory_color),
            ("Battery", battery_state, "#5cc96b" if not battery.has_battery or battery.percent >= 40 else "#ff9f1a"),
            ("Windows Updates", "Scan needed", "#3aa0ff"),
            ("Antivirus Status", "Scan needed", "#3aa0ff"),
        ]
        for label, state, color in indicators:
            row = tk.Frame(self.dashboard_health_frame, bg=THEME["bg_card"])
            row.pack(fill="x", pady=5)
            tk.Label(row, text=label, bg=THEME["bg_card"], fg=THEME["fg"],
                     font=("Segoe UI", 9), anchor="w").pack(side="left", fill="x", expand=True)
            tk.Label(row, text="●", bg=THEME["bg_card"], fg=color,
                     font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 8))
            tk.Label(row, text=state, bg=THEME["bg_card"], fg=THEME["fg_dim"],
                     font=("Segoe UI", 9), width=10, anchor="w").pack(side="left")

    def _refresh_findings_table(self):
        for row in self.findings_tree.get_children():
            self.findings_tree.delete(row)

        sev_f = self.sev_filter_var.get()
        cat_f = self.cat_filter_var.get()
        search = self.search_var.get().lower()

        for f in preferences.filter_active(self.findings):
            cat = category_for_rule(f.rule)
            if sev_f != "All" and f.severity != sev_f:
                continue
            if cat_f != "All" and cat != cat_f:
                continue
            if search and search not in f.title.lower() and search not in f.description.lower():
                continue
            self.findings_tree.insert(
                "", "end",
                values=(
                    f.severity, cat, technique_short(f.rule),
                    f.title, f.rule,
                    f.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                ),
                tags=(f"sev_{f.severity}",),
            )

    def _on_finding_select(self, _event=None):
        sel = self.findings_tree.selection()
        if not sel:
            return
        idx = self.findings_tree.index(sel[0])
        # Filter findings same way as displayed
        sev_f = self.sev_filter_var.get()
        cat_f = self.cat_filter_var.get()
        search = self.search_var.get().lower()
        visible = []
        for f in self.findings:
            cat = category_for_rule(f.rule)
            if sev_f != "All" and f.severity != sev_f:
                continue
            if cat_f != "All" and cat != cat_f:
                continue
            if search and search not in f.title.lower() and search not in f.description.lower():
                continue
            visible.append(f)
        if idx >= len(visible):
            return
        f = visible[idx]
        self.finding_detail.config(state="normal")
        self.finding_detail.delete("1.0", "end")
        tech = technique_for_rule(f.rule)
        mitre_line = (
            f"MITRE      : {tech.technique_id} — {tech.name} ({tech.tactic})\n"
            f"Reference  : {tech.url}\n"
            if tech else ""
        )
        text = (
            f"Severity   : {f.severity}\n"
            f"Rule       : {f.rule}\n"
            f"Category   : {category_for_rule(f.rule)}\n"
            f"{mitre_line}"
            f"Time       : {f.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Title      : {f.title}\n"
            f"\n"
            f"Description:\n{f.description}\n"
        )
        if f.events:
            text += f"\nRelated events ({len(f.events)}):\n"
            for e in f.events[:5]:
                text += f"  • {e.timestamp.strftime('%H:%M:%S')} "
                text += f"EID {e.event_id} ({e.channel}) — {e.message[:120]}\n"
        self.finding_detail.insert("1.0", text)
        self.finding_detail.config(state="disabled")

    def _refresh_events_table(self):
        for row in self.events_tree.get_children():
            self.events_tree.delete(row)
        ch_f = self.channel_filter_var.get()
        cat_f = self.event_cat_var.get()
        search = self.search_var.get().lower()

        # Show newest first, cap at 2000 rows for responsiveness
        for e in sorted(self.events, key=lambda x: x.timestamp, reverse=True)[:2000]:
            cat = category_for_event_id(e.event_id)
            if ch_f != "All" and e.channel != ch_f:
                continue
            if cat_f != "All" and cat != cat_f:
                continue
            if search:
                blob = f"{e.message} {e.user or ''} {e.source}".lower()
                if search not in blob:
                    continue
            self.events_tree.insert("", "end", values=(
                e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                e.channel, e.event_id, cat,
                e.user or "—", e.source[:40], e.message[:160],
            ))

    def _refresh_events_table(self):
        for row in self.events_tree.get_children():
            self.events_tree.delete(row)
        ch_f = self.channel_filter_var.get()
        cat_f = self.event_cat_var.get()
        type_f = self.event_type_var.get()
        type_ids = EVENT_TYPE_FILTERS.get(type_f, set())
        search = self.search_var.get().lower()

        self._visible_events = []
        for e in sorted(self.events, key=lambda x: x.timestamp, reverse=True)[:2000]:
            cat = category_for_event_id(e.event_id)
            if ch_f != "All" and e.channel != ch_f:
                continue
            if type_ids and e.event_id not in type_ids:
                continue
            if cat_f != "All" and cat != cat_f:
                continue
            if search:
                blob = f"{e.message} {e.user or ''} {e.source} {e.event_id} {EVENT_LABELS.get(e.event_id, '')}".lower()
                if search not in blob:
                    continue
            tags = ()
            if e.event_id in (4625, 4771, 4776):
                tags = ("failed_login",)
            elif e.event_id == 4624:
                tags = ("success_login",)
            elif e.event_id in (1102, 4719):
                tags = ("danger_log",)
            self._visible_events.append(e)
            self.events_tree.insert("", "end", values=(
                e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                e.channel, e.event_id, EVENT_LABELS.get(e.event_id, "Windows event"), cat,
                e.user or "-", e.source[:40], e.message[:160],
            ), tags=tags)

        if hasattr(self, "events_help_label"):
            total_security = sum(1 for e in self.events if e.channel == "Security")
            self.events_help_label.config(
                text=(
                    f"Showing {len(getattr(self, '_visible_events', []))} of {len(self.events)} collected logs. "
                    f"Security logs loaded: {total_security}. "
                    "Wrong password attempts appear as Event ID 4625, 4771, or 4776. "
                    "If Security logs are 0, run Log Sentinel as Administrator."
                )
            )

    def _set_event_type_filter(self, value: str):
        self.event_type_var.set(value)
        self._refresh_events_table()

    def _on_event_select(self, _event=None):
        sel = self.events_tree.selection()
        if not sel:
            return
        idx = self.events_tree.index(sel[0])
        events = getattr(self, "_visible_events", [])
        if idx >= len(events):
            return
        e = events[idx]
        self.event_detail.config(state="normal")
        self.event_detail.delete("1.0", "end")
        lines = [
            f"Time       : {e.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Channel    : {e.channel}",
            f"Event ID   : {e.event_id} ({EVENT_LABELS.get(e.event_id, 'Windows event')})",
            f"Level      : {e.level}",
            f"Source     : {e.source}",
            f"Computer   : {e.computer}",
            f"User       : {e.user or '-'}",
            "",
            "Message:",
            e.message,
        ]
        if e.extra:
            lines.extend(["", "Raw fields:"])
            for key, value in sorted(e.extra.items()):
                lines.append(f"  {key}: {value}")
        if e.event_id in (4625, 4771, 4776):
            lines.extend([
                "",
                "Plain English:",
                "This usually means somebody typed the wrong password, a saved password is old, or someone is trying to guess the password.",
            ])
        self.event_detail.insert("1.0", "\n".join(lines))
        self.event_detail.config(state="disabled")

    def _render_network(self):
        from src import geoip
        for row in self.net_tree.get_children():
            self.net_tree.delete(row)
        for c in self.connections:
            local = f"{c.local_addr}:{c.local_port}"
            remote = f"{c.remote_addr}:{c.remote_port}" if c.remote_addr != "*" else "—"

            country_cell = "—"
            tags = ()
            if c.is_external and c.remote_addr:
                m = geoip.lookup(c.remote_addr)
                country_cell = f"{geoip.flag(m.country)} {m.country_name}"
                if m.region:
                    country_cell += f" · {m.region}"
                if m.region == "TOR" or m.country == "??":
                    tags = ("threat",)
                else:
                    tags = ("external",)
            elif c.state == "LISTENING":
                tags = ("listening",)
            elif c.is_external:
                tags = ("external",)

            self.net_tree.insert("", "end", values=(
                c.proto, local, remote, country_cell, c.state,
                "yes" if c.is_external else "no",
                c.pid, c.process,
            ), tags=tags)

        # Update summary card
        try:
            summary = geoip.summarize(self.connections)
            lines = [
                f"Active external connections: {summary['total_external']}"
            ]
            for code, count, samples in summary["by_country"][:8]:
                name = geoip.COUNTRY_NAMES.get(code, "Unknown")
                pct = (count / max(1, summary["total_external"])) * 100
                bar = "█" * max(1, int(pct / 5))
                lines.append(
                    f"  {geoip.flag(code)} {name:<22} {count:>4}  {bar}  ({pct:.0f}%)"
                )
            if summary["total_external"] == 0:
                lines = ["No active external connections."]
            self._geo_summary_lbl.config(text="\n".join(lines))
        except Exception:
            pass

    def _render_processes(self):
        from src.system_analyzer import SUSPICIOUS_PATHS, SYSTEM_PROCESSES
        for row in self.proc_tree.get_children():
            self.proc_tree.delete(row)

        def tag_for(p):
            path_l = (p.path or "").lower()
            name_l = (p.name or "").lower()
            if path_l and any(s in path_l for s in SUSPICIOUS_PATHS):
                return ("suspicious",)
            if name_l in SYSTEM_PROCESSES and path_l:
                allowed = SYSTEM_PROCESSES[name_l]
                if not any(a in path_l for a in allowed):
                    return ("suspicious",)
            if name_l in {"system", "system idle process", "registry"}:
                return ("system",)
            return ()

        def mem(p):
            return f"{p.memory_kb / 1024:.1f} MB" if p.memory_kb else "—"

        view_mode = getattr(self, "_proc_view", None)
        view_mode = view_mode.get() if view_mode else "flat"

        if view_mode == "flat":
            for p in self.processes:
                self.proc_tree.insert(
                    "", "end", iid=f"flat_{p.pid}",
                    text=p.name,
                    values=(p.pid, p.name, p.parent_pid or "—",
                            p.user, mem(p), p.path or "—"),
                    tags=tag_for(p),
                )
            self.proc_view_status.config(
                text=f"{len(self.processes)} processes")
            return

        # Tree view: build parent → children index
        by_pid = {p.pid: p for p in self.processes}
        children: dict[int, list] = {}
        for p in self.processes:
            children.setdefault(p.parent_pid or 0, []).append(p)

        # A "root" is any process whose parent isn't in our process list,
        # OR whose parent is itself (Windows quirks)
        roots = [p for p in self.processes
                 if (not p.parent_pid
                     or p.parent_pid == p.pid
                     or p.parent_pid not in by_pid)]

        # Sort children by name for stable display
        for k in children:
            children[k].sort(key=lambda x: (x.name or "").lower())
        roots.sort(key=lambda x: (x.name or "").lower())

        # Counter-based unique iids — avoids "Item already exists" errors
        # caused by PID collisions / cycles
        counter = [0]
        seen_pids: set[int] = set()

        def insert(p, parent_iid: str = "", depth: int = 0):
            if p.pid in seen_pids or depth > 30:
                return
            seen_pids.add(p.pid)
            counter[0] += 1
            iid = f"tree_{counter[0]}"
            self.proc_tree.insert(
                parent_iid, "end", iid=iid,
                text=p.name,
                values=(p.pid, p.name, p.parent_pid or "—",
                        p.user, mem(p), p.path or "—"),
                tags=tag_for(p),
                open=False,
            )
            for child in children.get(p.pid, []):
                insert(child, iid, depth + 1)

        for r in roots:
            insert(r)

        # Auto-expand top 2 levels for better discoverability
        for top in self.proc_tree.get_children(""):
            self.proc_tree.item(top, open=True)
            for second in self.proc_tree.get_children(top):
                self.proc_tree.item(second, open=False)

        self.proc_view_status.config(
            text=f"{len(self.processes)} processes  ·  {len(roots)} root processes")

    def _render_services(self):
        for row in self.svc_tree.get_children():
            self.svc_tree.delete(row)
        for s in self.services:
            tags = ("running",) if s.state == "RUNNING" else ()
            self.svc_tree.insert("", "end", values=(
                s.name, s.display_name, s.state,
            ), tags=tags)

    def _render_tasks(self):
        for row in self.task_tree.get_children():
            self.task_tree.delete(row)
        for t in self.tasks:
            self.task_tree.insert("", "end",
                                  values=(t.name, t.next_run, t.status))

    def _render_autoruns(self):
        from src.system_analyzer import SUSPICIOUS_AUTORUN_KEYWORDS
        for row in self.autorun_tree.get_children():
            self.autorun_tree.delete(row)
        for a in self.autoruns:
            cmd_l = a.command.lower()
            tags = ()
            if any(k.lower() in cmd_l for k in SUSPICIOUS_AUTORUN_KEYWORDS):
                tags = ("suspicious",)
            self.autorun_tree.insert("", "end",
                                     values=(a.location, a.name, a.command),
                                     tags=tags)

    def _render_dns(self):
        for row in self.dns_tree.get_children():
            self.dns_tree.delete(row)
        seen: set[str] = set()
        for d in self.dns_entries:
            if d.name in seen or not d.name:
                continue
            seen.add(d.name)
            self.dns_tree.insert("", "end", values=(d.name, d.data))

    def _render_usb(self):
        for row in self.usb_tree.get_children():
            self.usb_tree.delete(row)
        for u in self.usb_devices:
            self.usb_tree.insert("", "end",
                                 values=(u.device_id, u.friendly_name))

    def _render_software(self):
        for row in self.sw_tree.get_children():
            self.sw_tree.delete(row)
        for s in self.software:
            self.sw_tree.insert("", "end", values=(
                s.name, s.version, s.publisher, s.install_date,
            ))

    def _render_recent_files(self):
        for row in self.recent_tree.get_children():
            self.recent_tree.delete(row)
        for r in self.recent_files:
            self.recent_tree.insert("", "end", values=(r.name, r.modified))

    # ──────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────
    def _apply_filters(self):
        self._refresh_findings_table()
        self._refresh_events_table()

    def _sort_tree(self, tree: ttk.Treeview, col: str):
        items = [(tree.set(k, col), k) for k in tree.get_children("")]
        # Try numeric sort
        try:
            items.sort(key=lambda x: float(x[0].split()[0]))
        except (ValueError, IndexError):
            items.sort(key=lambda x: x[0].lower())
        # Toggle direction by inspecting header
        current = tree.heading(col, "text")
        reverse = "▼" in current
        if reverse:
            items.reverse()
        for i, (_, k) in enumerate(items):
            tree.move(k, "", i)
        # Update arrow
        for c in tree["columns"]:
            tree.heading(c, text=tree.heading(c, "text").replace(" ▲", "").replace(" ▼", ""))
        arrow = " ▲" if reverse else " ▼"
        base = tree.heading(col, "text").rstrip(" ▲▼")
        tree.heading(col, text=base + arrow)

    # ──────────────────────────────────────────
    # Export
    # ──────────────────────────────────────────
    def _open_path(self, path: Path):
        try:
            if path.is_dir():
                subprocess.Popen(["explorer", str(path)])
            else:
                webbrowser.open(path.resolve().as_uri())
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def open_reports_window(self):
        reports_dir = Path(__file__).parent / "reports"
        reports_dir.mkdir(exist_ok=True)
        from src.reporter import ensure_help_center
        help_path = ensure_help_center(reports_dir)

        win = tk.Toplevel(self)
        win.title("Reports")
        win.geometry("780x460")
        win.configure(bg=THEME["bg"])
        win.transient(self)

        header = tk.Frame(win, bg=THEME["bg_panel"], padx=16, pady=12)
        header.pack(fill="x")
        tk.Label(header, text="Saved reports",
                 bg=THEME["bg_panel"], fg=THEME["fg"],
                 font=("Segoe UI Semibold", 14)).pack(side="left")
        ttk.Button(header, text="Export new report",
                   command=self.export_html).pack(side="right", padx=4)
        ttk.Button(header, text="Open folder",
                   command=lambda: self._open_path(reports_dir)).pack(side="right", padx=4)
        ttk.Button(header, text="Search help",
                   command=lambda: self._open_path(help_path)).pack(side="right", padx=4)

        cols = ("name", "type", "modified", "size")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for col, title, width in [
            ("name", "Name", 360),
            ("type", "Type", 80),
            ("modified", "Modified", 170),
            ("size", "Size", 90),
        ]:
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor="w")
        tree.pack(fill="both", expand=True, padx=12, pady=12)

        files = sorted(
            [p for p in reports_dir.glob("*") if p.suffix.lower() in {".html", ".pdf", ".json"}],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        path_by_item: dict[str, Path] = {}
        for p in files:
            try:
                st = p.stat()
            except OSError:
                continue
            item = tree.insert(
                "", "end",
                values=(
                    p.name,
                    p.suffix.upper().lstrip("."),
                    datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                    f"{st.st_size // 1024} KB",
                ),
            )
            path_by_item[item] = p

        def open_selected(_event=None):
            sel = tree.selection()
            if sel:
                self._open_path(path_by_item[sel[0]])

        tree.bind("<Double-1>", open_selected)
        footer = tk.Frame(win, bg=THEME["bg"], padx=12, pady=10)
        footer.pack(fill="x")
        ttk.Button(footer, text="Open selected", command=open_selected).pack(side="left")
        tk.Label(
            footer,
            text="Tip: HTML is easiest to read. PDF is easiest to send.",
            bg=THEME["bg"], fg=THEME["fg_subtle"],
            font=("Segoe UI", 9),
        ).pack(side="left", padx=12)

    def scan_folder(self):
        if not self._ensure_licensed():
            return
        folder = filedialog.askdirectory(title="Choose a folder to scan")
        if not folder:
            return
        try:
            from src.file_scanner import scan_paths
            findings = scan_paths([folder])
        except Exception as e:
            messagebox.showerror("Scan failed", str(e))
            return

        if findings:
            self.findings = sorted(
                self.findings + findings,
                key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.timestamp.isoformat()),
                reverse=True,
            )
            self._render_health()
            self._render_dashboard()
            self._refresh_findings_table()
            self._update_notification_badge()
            summary = "\n".join(f"[{f.severity}] {f.title}" for f in findings[:8])
            if len(findings) > 8:
                summary += f"\n... and {len(findings) - 8} more"
            messagebox.showwarning(
                "Folder scan findings",
                f"Found {len(findings)} suspicious item(s):\n\n{summary}",
            )
        else:
            messagebox.showinfo(
                "Folder scan clean",
                "No suspicious test markers, tool names, or script patterns were found.",
            )

    def export_html(self):
        if not self.findings and not self.events:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            initialfile=f"sentinel_{datetime.now():%Y%m%d_%H%M%S}.html",
            filetypes=[("HTML Report", "*.html")],
        )
        if not path:
            return
        try:
            hours = int(self.hours_var.get())
        except ValueError:
            hours = 24
        active = preferences.filter_active(self.findings)
        health = calc_health(active)
        generate_html(active, self.events, path,
                      hours_back=hours, health_score=health)
        pdf_path = str(Path(path).with_suffix(".pdf"))
        generate_pdf(active, self.events, pdf_path,
                     hours_back=hours, health_score=health)
        if preferences.get().auto_open_report:
            webbrowser.open(Path(path).resolve().as_uri())
            messagebox.showinfo(
                "Exported",
                f"Browser report saved to:\n{path}\n\n"
                f"PDF copy saved to:\n{pdf_path}\n\n"
                "Tip: in your browser press Ctrl+P → 'Save as PDF' for a "
                "shareable PDF copy.",
            )
        else:
            if messagebox.askyesno("Exported",
                                   f"Saved to:\n{path}\n\nOpen in browser?"):
                webbrowser.open(Path(path).resolve().as_uri())

    def export_json(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=f"sentinel_{datetime.now():%Y%m%d_%H%M%S}.json",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        data = {
            "host": asdict(self.system_info) if self.system_info else {},
            "scan_time": datetime.utcnow().isoformat(),
            "findings": [
                {
                    "rule": f.rule,
                    "severity": f.severity,
                    "category": category_for_rule(f.rule),
                    "title": f.title,
                    "description": f.description,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in self.findings
            ],
            "summary": {
                "events": len(self.events),
                "processes": len(self.processes),
                "connections": len(self.connections),
                "services": len(self.services),
                "scheduled_tasks": len(self.tasks),
                "autoruns": len(self.autoruns),
                "installed_software": len(self.software),
                "usb_devices": len(self.usb_devices),
            },
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        messagebox.showinfo("Exported", f"Saved to:\n{path}")


# ──────────────────────────────────────────────
# Entry
# ──────────────────────────────────────────────

def headless_scan() -> int:
    """
    Run a single scan with no GUI. Saves to scan history. Writes an
    alert file if any Critical or High finding shows up.

    Used by Windows Task Scheduler. Exits 0 on success, non-zero on error.
    """
    from src.collector import collect as collect_events
    from src.system_collector import (
        collect_processes, collect_network, collect_autoruns,
        collect_services, collect_scheduled_tasks,
    )
    from src.everyday_scanner import scan_everyday
    from src import scan_history, scheduler, preferences
    from src.health_score import calculate as calc_health
    from src.detection_pipeline import run_detection
    from src import licensing

    print("[scan] Headless scan starting...")
    lic = licensing.status()
    if not lic.can_run:
        print(f"[scan] Licence required: {lic.message}")
        return 2
    try:
        processes = collect_processes()
        connections = collect_network()
        autoruns = collect_autoruns()
        services = collect_services()
        tasks = collect_scheduled_tasks()
        events = collect_events(hours_back=24)
    except Exception as e:
        print(f"[scan] Collection error: {e}")
        return 1

    from src import email_alerts

    findings = run_detection(
        events=events,
        processes=processes,
        connections=connections,
        autoruns=autoruns,
        services=services,
        tasks=tasks,
    )
    findings = [f for f in findings if preferences.state_for(f) == "active"]
    health = calc_health(findings)

    # Email alert on Critical/High
    try:
        cfg = email_alerts.load_config()
        if cfg.enabled and cfg.smtp_host and cfg.to_addresses:
            crits = [f for f in findings if f.severity in ("Critical", "High")]
            if crits:
                ok, msg = email_alerts.send_findings_alert(
                    findings, health.score, health.grade,
                )
                print(f"[scan] Email: {msg}")
    except Exception as e:
        print(f"[scan] Email error: {e}")

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    try:
        scan_history.save_scan(
            health, findings, len(events),
            len(processes), len(connections),
        )
    except Exception as e:
        print(f"[scan] Couldn't save history: {e}")

    crit = counts.get("Critical", 0)
    hi = counts.get("High", 0)
    if crit or hi:
        scheduler.write_alert(
            critical=crit, high=hi,
            total=len(findings), score=health.score,
        )
        print(f"[scan] ⚠ Alert written: {crit} Critical, {hi} High.")
    print(f"[scan] Done. Score {health.score} ({health.grade}). "
          f"{len(findings)} active findings.")
    return 0


def main():
    if "--scan" in sys.argv:
        sys.exit(headless_scan())

    if platform.system() != "Windows":
        # Still let it open; tabs that need Windows-only data will be empty.
        print("[!] Non-Windows OS — most collectors will return empty.")
    app = LogSentinelApp()
    app.mainloop()


if __name__ == "__main__":
    main()
