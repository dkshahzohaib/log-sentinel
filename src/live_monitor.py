"""
Live monitoring: polls system state every N seconds, computes diffs against
the previous snapshot, and emits ActivityEvents for anything new.

This is what gives the GUI its "you typed a command and we caught it" feel.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .system_collector import (
    NetConnection, Process,
    collect_network, collect_processes,
)
from . import threat_intel
from .threat_intel import IocMatch
from .system_analyzer import SUSPICIOUS_PATHS, SYSTEM_PROCESSES


# ──────────────────────────────────────────────
# Activity event model
# ──────────────────────────────────────────────

@dataclass
class ActivityEvent:
    """One thing that happened — emitted by the live monitor."""
    timestamp: datetime
    kind: str                 # process_start | process_end | net_new | net_close | alert
    severity: str             # Critical / High / Medium / Low / Info
    title: str
    detail: str
    tags: list[str] = field(default_factory=list)
    ioc: Optional[IocMatch] = None


# ──────────────────────────────────────────────
# Monitor thread
# ──────────────────────────────────────────────

class LiveMonitor(threading.Thread):
    """
    Background thread that polls processes + network connections every
    `interval` seconds, diffs against the previous snapshot, and pushes
    ActivityEvents into `out_queue` for the GUI to consume.
    """

    def __init__(self, out_queue: queue.Queue, interval: float = 2.0):
        super().__init__(daemon=True)
        self.out_queue = out_queue
        self.interval = interval
        self._stop_flag = threading.Event()

        # Previous snapshots (PID → Process, conn-key → NetConnection)
        self._prev_procs: dict[int, Process] = {}
        self._prev_conns: dict[str, NetConnection] = {}
        self._first_pass = True

    def stop(self):
        self._stop_flag.set()

    def _conn_key(self, c: NetConnection) -> str:
        return f"{c.proto}|{c.local_addr}:{c.local_port}|{c.remote_addr}:{c.remote_port}|{c.pid}"

    def _process_severity(self, p: Process) -> tuple[str, list[str], Optional[IocMatch]]:
        """Risk-rate a newly-spawned process. Returns (severity, tags, ioc)."""
        sev = "Info"
        tags: list[str] = []
        ioc = threat_intel.check_process(p.name, p.cmdline)
        if ioc:
            return ioc.severity, [ioc.ioc_type, "ioc"], ioc

        path_l = (p.path or "").lower()
        name_l = p.name.lower()
        cmd_l = (p.cmdline or "").lower()

        if path_l and any(s in path_l for s in SUSPICIOUS_PATHS):
            sev = "High"
            tags.append("temp-path")

        if name_l in SYSTEM_PROCESSES and path_l:
            allowed = SYSTEM_PROCESSES[name_l]
            if not any(a in path_l for a in allowed):
                return "Critical", ["impersonation"], None

        if name_l in {"powershell.exe", "pwsh.exe", "cmd.exe"}:
            tags.append("shell")
            if any(arg in cmd_l for arg in ("-enc", "-encodedcommand", "downloadstring", "iex(")):
                return "High", tags + ["encoded"], None
            if sev == "Info":
                sev = "Low"

        if name_l in {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe"}:
            tags.append("lolbas")
            if sev == "Info":
                sev = "Medium"

        return sev, tags, None

    def _connection_severity(self, c: NetConnection) -> tuple[str, list[str], Optional[IocMatch]]:
        """Risk-rate a newly-observed network connection."""
        tags: list[str] = []
        ioc = threat_intel.check_ip(c.remote_addr) if c.is_external else None
        if ioc:
            return ioc.severity, [ioc.ioc_type], ioc

        if c.state == "LISTENING":
            tags.append("listening")
            if c.local_port in {1337, 4444, 4445, 5555, 6666, 31337}:
                return "High", tags + ["suspicious-port"], None
            return "Info", tags, None

        if c.is_external:
            tags.append("outbound")
            # SSH, RDP, SMB to external IPs is highly suspicious
            if c.remote_port in {22, 23, 445, 3389}:
                return "High", tags + ["unusual-protocol"], None
            return "Low", tags, None

        return "Info", tags, None

    def run(self):
        while not self._stop_flag.is_set():
            try:
                self._poll_once()
            except Exception as e:
                self.out_queue.put(ActivityEvent(
                    timestamp=datetime.now(),
                    kind="error",
                    severity="Info",
                    title="Live monitor error",
                    detail=str(e),
                ))
            # Sleep but wake quickly on stop
            for _ in range(int(self.interval * 10)):
                if self._stop_flag.is_set():
                    return
                time.sleep(0.1)

    def _poll_once(self):
        now = datetime.now()

        # ── Processes ──────────────────────────────────────────
        current_procs = collect_processes()
        cur_proc_map = {p.pid: p for p in current_procs}

        if not self._first_pass:
            # New processes
            for pid, p in cur_proc_map.items():
                if pid in self._prev_procs:
                    continue
                sev, tags, ioc = self._process_severity(p)
                detail = f"PID {p.pid}"
                if p.path:
                    detail += f"  path={p.path}"
                if p.cmdline and p.cmdline.strip() != p.path.strip():
                    detail += f"\ncmd: {p.cmdline}"
                title = f"Process started: {p.name}"
                if ioc:
                    title = f"⚠ THREAT: {p.name} — {ioc.description}"
                self.out_queue.put(ActivityEvent(
                    timestamp=now,
                    kind="process_start",
                    severity=sev,
                    title=title,
                    detail=detail,
                    tags=tags,
                    ioc=ioc,
                ))

            # Ended processes (low priority, info only)
            for pid, p in self._prev_procs.items():
                if pid in cur_proc_map:
                    continue
                self.out_queue.put(ActivityEvent(
                    timestamp=now,
                    kind="process_end",
                    severity="Info",
                    title=f"Process exited: {p.name}",
                    detail=f"PID {p.pid}",
                ))

        # ── Network ────────────────────────────────────────────
        current_conns = collect_network()
        cur_conn_map = {self._conn_key(c): c for c in current_conns}

        if not self._first_pass:
            for key, c in cur_conn_map.items():
                if key in self._prev_conns:
                    continue
                sev, tags, ioc = self._connection_severity(c)
                local = f"{c.local_addr}:{c.local_port}"
                remote = f"{c.remote_addr}:{c.remote_port}" if c.remote_addr != "*" else "—"
                proc_label = c.process or f"PID {c.pid}"
                if c.state == "LISTENING":
                    title = f"New listener: {c.proto}/{c.local_port} ({proc_label})"
                    detail = f"{local} listening — {proc_label}"
                else:
                    title = f"New connection → {remote} ({proc_label})"
                    if ioc:
                        title = f"⚠ THREAT: {remote} — {ioc.description}"
                    detail = f"{c.proto}  {local} → {remote}  state={c.state}  proc={proc_label}"
                self.out_queue.put(ActivityEvent(
                    timestamp=now,
                    kind="net_new",
                    severity=sev,
                    title=title,
                    detail=detail,
                    tags=tags,
                    ioc=ioc,
                ))

            # Closed connections — only emit for established/external ones
            for key, c in self._prev_conns.items():
                if key in cur_conn_map:
                    continue
                if c.state != "ESTABLISHED" or not c.is_external:
                    continue
                self.out_queue.put(ActivityEvent(
                    timestamp=now,
                    kind="net_close",
                    severity="Info",
                    title=f"Connection closed → {c.remote_addr}:{c.remote_port}",
                    detail=f"{c.proto}  was: {c.local_addr}:{c.local_port} → {c.remote_addr}:{c.remote_port}",
                ))

        self._prev_procs = cur_proc_map
        self._prev_conns = cur_conn_map
        self._first_pass = False
