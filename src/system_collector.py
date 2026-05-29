"""
System-wide collectors that don't rely on Windows Event Log.
These give a real-time snapshot of:
  - Active network connections (netstat)
  - Running processes (tasklist + wmic)
  - Services (sc query)
  - Scheduled tasks (schtasks)
  - Autoruns / startup entries (registry)
  - DNS resolver cache (ipconfig)
  - ARP table
  - Listening ports
  - Recent files
  - Installed software
  - System info
  - USB device history (registry)

All collectors return a list of dataclasses for easy consumption by the GUI.
Most do NOT require Administrator privileges.
"""

from __future__ import annotations

import csv
import io
import json
import os
import platform
import socket
import subprocess
import winreg
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────────────
# Common helpers
# ──────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 30) -> str:
    """Run a shell command, return stdout. Returns '' on error."""
    try:
        # CREATE_NO_WINDOW so we don't pop a console window in the GUI app
        flags = 0x08000000 if platform.system() == "Windows" else 0
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=flags,
        )
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


# ──────────────────────────────────────────────
# Network connections
# ──────────────────────────────────────────────

@dataclass
class NetConnection:
    proto: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int = 0
    process: str = ""

    @property
    def is_external(self) -> bool:
        ra = self.remote_addr
        if ra in ("0.0.0.0", "*", "::", "[::]", "127.0.0.1", "[::1]"):
            return False
        if ra.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.",
                          "172.24.", "172.25.", "172.26.", "172.27.",
                          "172.28.", "172.29.", "172.30.", "172.31.",
                          "192.168.", "169.254.", "fe80:", "fd")):
            return False
        return True


def _parse_addr(s: str) -> tuple[str, int]:
    """Parse 'ip:port' or '[ipv6]:port'."""
    if not s or s == "*:*":
        return "*", 0
    if s.startswith("["):
        # IPv6 [::1]:port
        end = s.find("]")
        if end == -1:
            return s, 0
        addr = s[1:end]
        port = s[end+2:] if len(s) > end+2 else "0"
    else:
        if ":" not in s:
            return s, 0
        addr, _, port = s.rpartition(":")
    try:
        return addr, int(port) if port and port != "*" else 0
    except ValueError:
        return addr, 0


def collect_network() -> list[NetConnection]:
    """Snapshot of TCP/UDP connections via netstat -ano."""
    out = _run(["netstat", "-ano"])
    if not out:
        return []

    pid_to_name = _pid_to_process_name()
    connections: list[NetConnection] = []

    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith(("Active", "Proto")):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue

        proto = parts[0].upper()
        if proto not in ("TCP", "UDP"):
            continue

        local = parts[1]
        remote = parts[2]
        if proto == "TCP" and len(parts) >= 5:
            state = parts[3]
            pid_s = parts[4]
        else:
            state = "—"
            pid_s = parts[3] if len(parts) > 3 else "0"

        try:
            pid = int(pid_s)
        except ValueError:
            pid = 0

        la, lp = _parse_addr(local)
        ra, rp = _parse_addr(remote)

        connections.append(NetConnection(
            proto=proto,
            local_addr=la, local_port=lp,
            remote_addr=ra, remote_port=rp,
            state=state, pid=pid,
            process=pid_to_name.get(pid, ""),
        ))

    return connections


def _pid_to_process_name() -> dict[int, str]:
    """Cheap PID→name lookup via tasklist."""
    out = _run(["tasklist", "/FO", "CSV", "/NH"])
    mapping: dict[int, str] = {}
    if not out:
        return mapping
    reader = csv.reader(io.StringIO(out))
    for row in reader:
        if len(row) >= 2:
            try:
                mapping[int(row[1])] = row[0]
            except ValueError:
                continue
    return mapping


# ──────────────────────────────────────────────
# Running processes
# ──────────────────────────────────────────────

@dataclass
class Process:
    pid: int
    name: str
    user: str = ""
    memory_kb: int = 0
    path: str = ""
    cmdline: str = ""
    parent_pid: int = 0


def collect_processes() -> list[Process]:
    """Snapshot of running processes. Uses plain tasklist for speed."""
    out = _run(["tasklist", "/FO", "CSV"], timeout=20)
    if not out:
        return []

    processes: list[Process] = []
    reader = csv.reader(io.StringIO(out))
    headers = next(reader, None)
    if not headers:
        return []

    # Plain tasklist columns: Image Name, PID, Session Name, Session#, Mem Usage
    h = {name.strip().lower(): i for i, name in enumerate(headers)}
    name_i = h.get("image name", 0)
    pid_i = h.get("pid", 1)
    sess_i = h.get("session name", 2)
    mem_i = h.get("mem usage", 4)

    for row in reader:
        if len(row) <= max(name_i, pid_i, mem_i):
            continue
        try:
            pid = int(row[pid_i])
        except ValueError:
            continue
        mem_str = row[mem_i].replace(",", "").replace(" K", "").strip()
        try:
            mem_kb = int(mem_str)
        except ValueError:
            mem_kb = 0

        processes.append(Process(
            pid=pid,
            name=row[name_i],
            user=row[sess_i] if sess_i < len(row) else "",
            memory_kb=mem_kb,
        ))

    # Enrich with parent PID + executable path + command line via PowerShell.
    try:
        ps_out = _run([
            "powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine | "
            "ConvertTo-Csv -NoTypeInformation"
        ], timeout=15)
        if ps_out:
            reader2 = csv.reader(io.StringIO(ps_out))
            hdrs = next(reader2, None)
            if hdrs:
                def idx(name: str, default: int) -> int:
                    return hdrs.index(name) if name in hdrs else default
                pid_j   = idx("ProcessId", 0)
                ppid_j  = idx("ParentProcessId", 1)
                ep_j    = idx("ExecutablePath", 2)
                cl_j    = idx("CommandLine", 3)
                pid_to_proc = {p.pid: p for p in processes}
                for r in reader2:
                    if len(r) <= max(pid_j, ppid_j, ep_j, cl_j):
                        continue
                    try:
                        pid_v = int(r[pid_j])
                    except ValueError:
                        continue
                    p = pid_to_proc.get(pid_v)
                    if p is None:
                        continue
                    try:
                        p.parent_pid = int(r[ppid_j]) if r[ppid_j] else 0
                    except ValueError:
                        p.parent_pid = 0
                    p.path = r[ep_j] or ""
                    p.cmdline = r[cl_j] or ""
    except Exception:
        pass

    return processes


# ──────────────────────────────────────────────
# Services
# ──────────────────────────────────────────────

@dataclass
class Service:
    name: str
    display_name: str
    state: str
    start_type: str = ""
    path: str = ""


def collect_services() -> list[Service]:
    out = _run(["sc", "query", "type=", "service", "state=", "all"], timeout=30)
    services: list[Service] = []
    if not out:
        return services

    current: dict[str, str] = {}
    for line in out.splitlines():
        line = line.rstrip()
        if line.startswith("SERVICE_NAME:"):
            if current.get("name"):
                services.append(Service(
                    name=current.get("name", ""),
                    display_name=current.get("display", ""),
                    state=current.get("state", ""),
                ))
            current = {"name": line.split(":", 1)[1].strip()}
        elif "DISPLAY_NAME" in line:
            current["display"] = line.split(":", 1)[1].strip()
        elif "STATE" in line and ":" in line:
            parts = line.split(":", 1)[1].strip().split()
            if len(parts) >= 2:
                current["state"] = parts[1]

    if current.get("name"):
        services.append(Service(
            name=current.get("name", ""),
            display_name=current.get("display", ""),
            state=current.get("state", ""),
        ))

    return services


# ──────────────────────────────────────────────
# Scheduled tasks
# ──────────────────────────────────────────────

@dataclass
class ScheduledTask:
    name: str
    next_run: str
    status: str
    author: str = ""


def collect_scheduled_tasks() -> list[ScheduledTask]:
    out = _run(["schtasks", "/query", "/FO", "CSV"], timeout=60)
    tasks: list[ScheduledTask] = []
    if not out:
        return tasks

    reader = csv.reader(io.StringIO(out))
    headers = next(reader, None)
    for row in reader:
        if len(row) < 3:
            continue
        if row[0] == "TaskName":  # skip repeated headers
            continue
        tasks.append(ScheduledTask(
            name=row[0],
            next_run=row[1] if len(row) > 1 else "",
            status=row[2] if len(row) > 2 else "",
        ))
    return tasks


# ──────────────────────────────────────────────
# Autoruns (registry-based)
# ──────────────────────────────────────────────

@dataclass
class AutorunEntry:
    location: str
    name: str
    command: str


AUTORUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


def _hive_name(hive: int) -> str:
    return {
        winreg.HKEY_LOCAL_MACHINE: "HKLM",
        winreg.HKEY_CURRENT_USER:  "HKCU",
    }.get(hive, "?")


def collect_autoruns() -> list[AutorunEntry]:
    entries: list[AutorunEntry] = []
    for hive, subkey in AUTORUN_KEYS:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    entries.append(AutorunEntry(
                        location=f"{_hive_name(hive)}\\{subkey}",
                        name=name,
                        command=str(value),
                    ))
                    i += 1
        except OSError:
            continue
    return entries


# ──────────────────────────────────────────────
# DNS cache + ARP
# ──────────────────────────────────────────────

@dataclass
class DnsEntry:
    name: str
    type: str
    data: str


def collect_dns_cache() -> list[DnsEntry]:
    out = _run(["ipconfig", "/displaydns"], timeout=30)
    entries: list[DnsEntry] = []
    if not out:
        return entries

    current: dict[str, str] = {}
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            if current.get("name"):
                entries.append(DnsEntry(
                    name=current.get("name", ""),
                    type=current.get("type", ""),
                    data=current.get("data", ""),
                ))
            current = {}
            continue
        if "Record Name" in line:
            current["name"] = line.split(":", 1)[1].strip()
        elif "Record Type" in line:
            current["type"] = line.split(":", 1)[1].strip()
        elif ("A (Host) Record" in line) or ("AAAA Record" in line) or ("CNAME Record" in line):
            current["data"] = line.split(":", 1)[1].strip()
    if current.get("name"):
        entries.append(DnsEntry(
            name=current.get("name", ""),
            type=current.get("type", ""),
            data=current.get("data", ""),
        ))
    return entries


# ──────────────────────────────────────────────
# USB device history
# ──────────────────────────────────────────────

@dataclass
class UsbDevice:
    device_id: str
    friendly_name: str = ""


def collect_usb_history() -> list[UsbDevice]:
    """Read USB devices that have ever been connected."""
    devices: list[UsbDevice] = []
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
        ) as root:
            i = 0
            while True:
                try:
                    cls = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, cls) as cls_key:
                        j = 0
                        while True:
                            try:
                                instance = winreg.EnumKey(cls_key, j)
                            except OSError:
                                break
                            j += 1
                            friendly = ""
                            try:
                                with winreg.OpenKey(cls_key, instance) as ik:
                                    try:
                                        friendly, _ = winreg.QueryValueEx(ik, "FriendlyName")
                                    except OSError:
                                        pass
                            except OSError:
                                pass
                            devices.append(UsbDevice(
                                device_id=f"{cls}\\{instance}",
                                friendly_name=friendly,
                            ))
                except OSError:
                    continue
    except OSError:
        pass
    return devices


# ──────────────────────────────────────────────
# Installed software
# ──────────────────────────────────────────────

@dataclass
class Software:
    name: str
    version: str = ""
    publisher: str = ""
    install_date: str = ""


_UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def collect_installed_software() -> list[Software]:
    seen: set[str] = set()
    out: list[Software] = []
    for hive, sub in _UNINSTALL_KEYS:
        try:
            with winreg.OpenKey(hive, sub) as root:
                i = 0
                while True:
                    try:
                        sk = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    try:
                        with winreg.OpenKey(root, sk) as k:
                            def _g(name: str) -> str:
                                try:
                                    v, _ = winreg.QueryValueEx(k, name)
                                    return str(v) if v is not None else ""
                                except OSError:
                                    return ""
                            name = _g("DisplayName")
                            if not name or name in seen:
                                continue
                            seen.add(name)
                            out.append(Software(
                                name=name,
                                version=_g("DisplayVersion"),
                                publisher=_g("Publisher"),
                                install_date=_g("InstallDate"),
                            ))
                    except OSError:
                        continue
        except OSError:
            continue
    return sorted(out, key=lambda s: s.name.lower())


# ──────────────────────────────────────────────
# System info / user sessions
# ──────────────────────────────────────────────

@dataclass
class SystemInfo:
    hostname: str
    os: str
    user: str
    boot_time: str
    domain: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    bios_version: str = ""
    cpu: str = ""
    cpu_cores: int = 0
    cpu_logical_processors: int = 0
    ram_total_gb: float = 0.0
    ram_free_gb: float = 0.0
    ram_slots: int = 0
    ram_modules: list[dict] = field(default_factory=list)
    gpus: list[dict] = field(default_factory=list)
    disks: list[dict] = field(default_factory=list)
    battery: dict = field(default_factory=dict)


def _ps_json(script: str, timeout: int = 25):
    out = _run([
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ], timeout=timeout)
    if not out.strip():
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _gb(value) -> float:
    try:
        return round(float(value) / (1024 ** 3), 1)
    except (TypeError, ValueError):
        return 0.0


def collect_system_info() -> SystemInfo:
    hostname = socket.gethostname()
    ips: list[str] = []
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass

    boot_time = ""
    out = _run(["systeminfo"], timeout=60)
    domain = ""
    for line in out.splitlines():
        if line.startswith("System Boot Time"):
            boot_time = line.split(":", 1)[1].strip()
        elif line.startswith("Domain"):
            domain = line.split(":", 1)[1].strip()

    computer = _ps_json(
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object Manufacturer,Model,TotalPhysicalMemory,NumberOfLogicalProcessors | "
        "ConvertTo-Json -Compress"
    ) or {}
    bios = _ps_json(
        "Get-CimInstance Win32_BIOS | "
        "Select-Object SerialNumber,SMBIOSBIOSVersion,ReleaseDate | "
        "ConvertTo-Json -Compress"
    ) or {}
    cpu_obj = _ps_json(
        "Get-CimInstance Win32_Processor | Select-Object -First 1 "
        "Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | "
        "ConvertTo-Json -Compress"
    ) or {}
    os_obj = _ps_json(
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object FreePhysicalMemory,TotalVisibleMemorySize,LastBootUpTime | "
        "ConvertTo-Json -Compress"
    ) or {}

    gpus = []
    for gpu in _as_list(_ps_json(
        "Get-CimInstance Win32_VideoController | "
        "Select-Object Name,AdapterRAM,DriverVersion,VideoProcessor,CurrentHorizontalResolution,CurrentVerticalResolution | "
        "ConvertTo-Json -Compress"
    )):
        if not isinstance(gpu, dict):
            continue
        gpus.append({
            "name": gpu.get("Name", ""),
            "vram_gb": _gb(gpu.get("AdapterRAM")),
            "driver": gpu.get("DriverVersion", ""),
            "processor": gpu.get("VideoProcessor", ""),
            "resolution": (
                f"{gpu.get('CurrentHorizontalResolution')}x{gpu.get('CurrentVerticalResolution')}"
                if gpu.get("CurrentHorizontalResolution") else ""
            ),
        })

    disks = []
    for disk in _as_list(_ps_json(
        "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | "
        "Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace | "
        "ConvertTo-Json -Compress"
    )):
        if not isinstance(disk, dict):
            continue
        size_gb = _gb(disk.get("Size"))
        free_gb = _gb(disk.get("FreeSpace"))
        used_gb = round(max(size_gb - free_gb, 0), 1) if size_gb else 0.0
        used_pct = round((used_gb / size_gb) * 100, 1) if size_gb else 0.0
        disks.append({
            "drive": disk.get("DeviceID", ""),
            "label": disk.get("VolumeName", ""),
            "fs": disk.get("FileSystem", ""),
            "size_gb": size_gb,
            "free_gb": free_gb,
            "used_gb": used_gb,
            "used_pct": used_pct,
        })

    ram_modules = []
    for mem in _as_list(_ps_json(
        "Get-CimInstance Win32_PhysicalMemory | "
        "Select-Object BankLabel,Capacity,Speed,Manufacturer,PartNumber | "
        "ConvertTo-Json -Compress"
    )):
        if not isinstance(mem, dict):
            continue
        ram_modules.append({
            "bank": mem.get("BankLabel", ""),
            "capacity_gb": _gb(mem.get("Capacity")),
            "speed_mhz": mem.get("Speed", ""),
            "manufacturer": mem.get("Manufacturer", ""),
            "part": str(mem.get("PartNumber", "")).strip(),
        })

    battery = {}
    bat = _ps_json(
        "Get-CimInstance Win32_Battery | Select-Object -First 1 "
        "Name,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,DesignVoltage | "
        "ConvertTo-Json -Compress"
    )
    if isinstance(bat, dict):
        battery = {
            "name": bat.get("Name", ""),
            "status": bat.get("BatteryStatus", ""),
            "charge_pct": bat.get("EstimatedChargeRemaining", ""),
            "runtime_min": bat.get("EstimatedRunTime", ""),
            "design_voltage": bat.get("DesignVoltage", ""),
        }

    total_ram_gb = _gb(computer.get("TotalPhysicalMemory")) or _gb(os_obj.get("TotalVisibleMemorySize", 0) * 1024 if os_obj.get("TotalVisibleMemorySize") else 0)
    free_ram_gb = _gb(os_obj.get("FreePhysicalMemory", 0) * 1024 if os_obj.get("FreePhysicalMemory") else 0)

    return SystemInfo(
        hostname=hostname,
        os=f"{platform.system()} {platform.release()} ({platform.version()})",
        user=os.environ.get("USERNAME", ""),
        boot_time=boot_time,
        domain=domain,
        ip_addresses=ips,
        manufacturer=computer.get("Manufacturer", ""),
        model=computer.get("Model", ""),
        serial_number=bios.get("SerialNumber", ""),
        bios_version=bios.get("SMBIOSBIOSVersion", ""),
        cpu=cpu_obj.get("Name", ""),
        cpu_cores=int(cpu_obj.get("NumberOfCores") or 0),
        cpu_logical_processors=int(cpu_obj.get("NumberOfLogicalProcessors") or computer.get("NumberOfLogicalProcessors") or 0),
        ram_total_gb=total_ram_gb,
        ram_free_gb=free_ram_gb,
        ram_slots=len(ram_modules),
        ram_modules=ram_modules,
        gpus=gpus,
        disks=disks,
        battery=battery,
    )


# ──────────────────────────────────────────────
# Recent files
# ──────────────────────────────────────────────

@dataclass
class RecentFile:
    name: str
    modified: str


def collect_recent_files(limit: int = 50) -> list[RecentFile]:
    recent_dir = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
    out: list[RecentFile] = []
    if not recent_dir.exists():
        return out
    try:
        files = sorted(
            recent_dir.iterdir(),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:limit]
        for f in files:
            try:
                mtime = datetime.fromtimestamp(f.stat().st_mtime)
                out.append(RecentFile(
                    name=f.stem,
                    modified=mtime.strftime("%Y-%m-%d %H:%M:%S"),
                ))
            except OSError:
                continue
    except OSError:
        pass
    return out


# ──────────────────────────────────────────────
# Listening ports (subset of network)
# ──────────────────────────────────────────────

def collect_listening_ports(connections: list[NetConnection] | None = None) -> list[NetConnection]:
    if connections is None:
        connections = collect_network()
    return [c for c in connections if c.state == "LISTENING"]
