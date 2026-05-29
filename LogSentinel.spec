# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Log Sentinel.

Build:
    pip install pyinstaller
    pyinstaller --clean LogSentinel.spec

Result:
    dist/LogSentinel.exe   (single-file portable, ~25–30 MB)
"""

from pathlib import Path

block_cipher = None
HERE = Path(SPECPATH)


a = Analysis(
    [str(HERE / "app.py")],
    pathex=[str(HERE)],
    binaries=[],
    datas=[
        # Bundle the src package files (mostly Python, but include any data files)
        (str(HERE / "src"), "src"),
        (str(HERE / "USER_GUIDE.md"),  "."),
        (str(HERE / "README.md"),      "."),
    ],
    hiddenimports=[
        # Tkinter sub-modules occasionally missed by static analysis
        "tkinter", "tkinter.ttk", "tkinter.filedialog",
        "tkinter.messagebox", "tkinter.scrolledtext",
        # Our own packages so PyInstaller follows them
        "src", "src.collector", "src.analyzer", "src.reporter",
        "src.categorizer", "src.system_collector", "src.system_analyzer",
        "src.live_monitor", "src.mitre", "src.threat_intel",
        "src.plain_english", "src.health_score", "src.remediation",
        "src.everyday_scanner", "src.preferences", "src.scan_history",
        "src.quick_win", "src.firewall_manager", "src.hosts_manager",
        "src.system_monitor", "src.panic", "src.password_check",
        "src.scheduler", "src.custom_rules",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Trim the binary — these are big and we don't need them
        "matplotlib", "numpy", "scipy", "PIL", "PyQt5", "PyQt6",
        "PySide2", "PySide6", "test", "unittest",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)


exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="LogSentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,                 # Compress (skipped automatically if UPX missing)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # Hide the black terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Embed an icon if you ship one. Drop a 256x256 ICO at brand/icon.ico
    # icon=str(HERE / "brand" / "icon.ico"),
    uac_admin=False,          # Don't force UAC; admin elevation handled by LAUNCH-as-admin.bat
)
