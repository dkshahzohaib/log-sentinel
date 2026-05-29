"""
Real-time system metrics — CPU, RAM, disks, battery, Wi-Fi, internet.

Pure standard library (ctypes for Windows performance APIs). No psutil
dependency, so the app stays zero-dep.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import platform
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field


# ──────────────────────────────────────────────
# CPU / RAM via Windows APIs
# ──────────────────────────────────────────────

class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength",                 wt.DWORD),
        ("dwMemoryLoad",             wt.DWORD),
        ("ullTotalPhys",             ctypes.c_ulonglong),
        ("ullAvailPhys",             ctypes.c_ulonglong),
        ("ullTotalPageFile",         ctypes.c_ulonglong),
        ("ullAvailPageFile",         ctypes.c_ulonglong),
        ("ullTotalVirtual",          ctypes.c_ulonglong),
        ("ullAvailVirtual",          ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual",  ctypes.c_ulonglong),
    ]


@dataclass
class MemoryInfo:
    used_pct: float = 0.0
    total_gb: float = 0.0
    used_gb: float = 0.0
    available_gb: float = 0.0


def get_memory() -> MemoryInfo:
    if platform.system() != "Windows":
        return MemoryInfo()
    stat = _MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        return MemoryInfo()
    total = stat.ullTotalPhys / (1024 ** 3)
    avail = stat.ullAvailPhys / (1024 ** 3)
    used = total - avail
    return MemoryInfo(
        used_pct=stat.dwMemoryLoad,
        total_gb=total,
        used_gb=used,
        available_gb=avail,
    )


# ── CPU usage ──────────────────────────────────
# Use GetSystemTimes — diff between two snapshots = % busy.

class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]


def _ft_to_int(ft: _FILETIME) -> int:
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


_last_cpu_sample: tuple[int, int, int] | None = None  # (idle, kernel, user)


def get_cpu_percent() -> float:
    """Cumulative CPU usage between this call and the last call."""
    global _last_cpu_sample
    if platform.system() != "Windows":
        return 0.0
    idle = _FILETIME()
    kernel = _FILETIME()
    user = _FILETIME()
    if not ctypes.windll.kernel32.GetSystemTimes(
        ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)
    ):
        return 0.0
    i, k, u = _ft_to_int(idle), _ft_to_int(kernel), _ft_to_int(user)
    if _last_cpu_sample is None:
        _last_cpu_sample = (i, k, u)
        time.sleep(0.1)
        return get_cpu_percent()
    pi, pk, pu = _last_cpu_sample
    di, dk, du = i - pi, k - pk, u - pu
    total = dk + du
    busy = total - di
    _last_cpu_sample = (i, k, u)
    return max(0.0, min(100.0, (busy / total) * 100)) if total > 0 else 0.0


def get_cpu_count() -> int:
    return os.cpu_count() or 1


# ──────────────────────────────────────────────
# Disks
# ──────────────────────────────────────────────

@dataclass
class DiskInfo:
    drive: str
    used_pct: float
    used_gb: float
    total_gb: float
    free_gb: float


def get_disks() -> list[DiskInfo]:
    out: list[DiskInfo] = []
    if platform.system() != "Windows":
        return out
    drives_bits = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if drives_bits & (1 << i):
            letter = chr(ord("A") + i) + ":\\"
            try:
                usage = shutil.disk_usage(letter)
            except (OSError, PermissionError):
                continue
            total = usage.total / (1024 ** 3)
            used = (usage.total - usage.free) / (1024 ** 3)
            free = usage.free / (1024 ** 3)
            pct = (used / total) * 100 if total > 0 else 0
            out.append(DiskInfo(
                drive=letter, used_pct=pct,
                used_gb=used, total_gb=total, free_gb=free,
            ))
    return out


# ──────────────────────────────────────────────
# Battery
# ──────────────────────────────────────────────

class _SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus",        wt.BYTE),
        ("BatteryFlag",         wt.BYTE),
        ("BatteryLifePercent",  wt.BYTE),
        ("SystemStatusFlag",    wt.BYTE),
        ("BatteryLifeTime",     wt.DWORD),
        ("BatteryFullLifeTime", wt.DWORD),
    ]


@dataclass
class BatteryInfo:
    has_battery: bool = False
    percent: int = 0
    plugged_in: bool = False
    minutes_remaining: int = 0


def get_battery() -> BatteryInfo:
    if platform.system() != "Windows":
        return BatteryInfo()
    sps = _SYSTEM_POWER_STATUS()
    if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(sps)):
        return BatteryInfo()
    if sps.BatteryFlag == 128:  # No system battery
        return BatteryInfo(has_battery=False)
    plugged = sps.ACLineStatus == 1
    pct = sps.BatteryLifePercent if 0 <= sps.BatteryLifePercent <= 100 else 0
    mins = sps.BatteryLifeTime // 60 if sps.BatteryLifeTime != 0xFFFFFFFF else 0
    return BatteryInfo(
        has_battery=True,
        percent=pct,
        plugged_in=plugged,
        minutes_remaining=mins,
    )


# ──────────────────────────────────────────────
# Wi-Fi info
# ──────────────────────────────────────────────

@dataclass
class WifiInfo:
    connected: bool = False
    ssid: str = ""
    signal: int = 0          # 0–100
    interface: str = ""
    state: str = ""


def get_wifi() -> WifiInfo:
    info = WifiInfo()
    if platform.system() != "Windows":
        return info
    try:
        flags = 0x08000000
        out = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=8,
            creationflags=flags,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return info

    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("Name "):
            info.interface = line.split(":", 1)[1].strip()
        elif line.startswith("State "):
            info.state = line.split(":", 1)[1].strip()
            if info.state.lower() in ("connected",):
                info.connected = True
        elif line.startswith("SSID "):  # not BSSID
            v = line.split(":", 1)[1].strip()
            if not info.ssid:
                info.ssid = v
        elif line.startswith("Signal"):
            v = line.split(":", 1)[1].strip().rstrip("%")
            try:
                info.signal = int(v)
            except ValueError:
                pass
    return info


# ──────────────────────────────────────────────
# Internet connectivity / latency
# ──────────────────────────────────────────────

@dataclass
class InternetInfo:
    online: bool = False
    latency_ms: float = 0.0
    public_ip: str = ""


def get_internet(test_host: str = "1.1.1.1", timeout: float = 2.0) -> InternetInfo:
    info = InternetInfo()
    t = time.time()
    try:
        with socket.create_connection((test_host, 53), timeout=timeout):
            info.online = True
            info.latency_ms = (time.time() - t) * 1000
    except (OSError, socket.timeout):
        return info
    return info


# ──────────────────────────────────────────────
# Hardware inventory (cached after first call)
# ──────────────────────────────────────────────

@dataclass
class HardwareInfo:
    cpu_name: str = ""
    cpu_cores: int = 0
    cpu_threads: int = 0
    total_ram_gb: float = 0.0
    gpu: str = ""
    motherboard: str = ""
    bios_version: str = ""
    bios_date: str = ""


_hw_cache: HardwareInfo | None = None


def get_hardware() -> HardwareInfo:
    global _hw_cache
    if _hw_cache is not None:
        return _hw_cache
    info = HardwareInfo()
    if platform.system() != "Windows":
        _hw_cache = info
        return info
    flags = 0x08000000
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Processor | "
             "Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | "
             "ConvertTo-Csv -NoTypeInformation"],
            capture_output=True, text=True, timeout=10,
            creationflags=flags,
        ).stdout
        lines = out.strip().splitlines()
        if len(lines) >= 2:
            import csv, io
            row = next(csv.reader(io.StringIO(lines[1])))
            info.cpu_name = row[0]
            info.cpu_cores = int(row[1]) if row[1].isdigit() else 0
            info.cpu_threads = int(row[2]) if row[2].isdigit() else 0
    except Exception:
        pass

    info.total_ram_gb = get_memory().total_gb

    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_VideoController | "
             "Select-Object -First 1 Name | "
             "ConvertTo-Csv -NoTypeInformation"],
            capture_output=True, text=True, timeout=10,
            creationflags=flags,
        ).stdout
        lines = out.strip().splitlines()
        if len(lines) >= 2:
            info.gpu = lines[1].strip().strip('"')
    except Exception:
        pass

    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_BIOS | "
             "Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate | "
             "ConvertTo-Csv -NoTypeInformation"],
            capture_output=True, text=True, timeout=10,
            creationflags=flags,
        ).stdout
        lines = out.strip().splitlines()
        if len(lines) >= 2:
            import csv, io
            row = next(csv.reader(io.StringIO(lines[1])))
            info.motherboard = row[0]
            info.bios_version = row[1]
            info.bios_date = row[2][:10] if len(row) > 2 else ""
    except Exception:
        pass

    _hw_cache = info
    return info


# ──────────────────────────────────────────────
# Antivirus / Windows Defender status
# ──────────────────────────────────────────────

@dataclass
class AntivirusStatus:
    realtime_protection: bool = False
    av_signature_age_days: int = -1
    av_signature_version: str = ""
    av_engine_version: str = ""
    last_quick_scan: str = ""
    last_full_scan: str = ""
    tamper_protection: bool = False
    is_running: bool = False


def get_antivirus_status() -> AntivirusStatus:
    s = AntivirusStatus()
    if platform.system() != "Windows":
        return s
    flags = 0x08000000
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-MpComputerStatus | "
             "Select-Object RealTimeProtectionEnabled,"
             "AntivirusSignatureAge,"
             "AntivirusSignatureVersion,"
             "AMEngineVersion,"
             "QuickScanEndTime,"
             "FullScanEndTime,"
             "IsTamperProtected,"
             "AntivirusEnabled | "
             "ConvertTo-Csv -NoTypeInformation"],
            capture_output=True, text=True, timeout=15,
            creationflags=flags,
        ).stdout
    except Exception:
        return s

    lines = out.strip().splitlines()
    if len(lines) < 2:
        return s
    import csv, io
    try:
        row = next(csv.reader(io.StringIO(lines[1])))
    except Exception:
        return s

    def b(v: str) -> bool:
        return v.strip().lower() in ("true", "yes")

    if len(row) >= 8:
        s.realtime_protection = b(row[0])
        try:
            s.av_signature_age_days = int(row[1]) if row[1] else -1
        except ValueError:
            s.av_signature_age_days = -1
        s.av_signature_version = row[2]
        s.av_engine_version = row[3]
        s.last_quick_scan = row[4][:16] if row[4] else ""
        s.last_full_scan = row[5][:16] if row[5] else ""
        s.tamper_protection = b(row[6])
        s.is_running = b(row[7])
    return s
