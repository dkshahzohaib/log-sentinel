# Building a portable LogSentinel.exe

A single-file `.exe` that runs on any modern Windows machine. No Python
required on target machines. ~30 MB. Drop on a USB stick, ship anywhere.

## One-time setup

1. Make sure you have Python 3.10+ installed on the *build* machine.
2. Open a terminal in this folder.

## Build

Double-click **`BUILD.bat`** — that's it.

It:
1. Installs / upgrades PyInstaller via `pip`
2. Runs `pyinstaller --clean LogSentinel.spec`
3. Spits out `dist\LogSentinel.exe`

Build time: 1–3 minutes.

## Distribute

Just copy `dist\LogSentinel.exe` to wherever you want to ship.

| Distribution channel | What to ship |
|---|---|
| USB stick / OneDrive / direct download | `LogSentinel.exe` (one file) |
| ZIP archive | `LogSentinel.exe` + `USER_GUIDE.md` |
| Installer (next step) | Inno Setup script — see below |

## Recommended next steps

### 1. Code-sign the .exe (~$90/year)

Without signing, Windows SmartScreen will scare users with a big blue warning.
With a code-signing certificate from Sectigo, SSL.com, or Certum:

```cmd
signtool sign /tr http://timestamp.digicert.com /td SHA256 /fd SHA256 /a dist\LogSentinel.exe
```

Now Windows shows your company name as "Verified publisher". Massively
increases trust and conversion.

### 2. Build a proper installer with Inno Setup

[Download Inno Setup](https://jrsoftware.org/isinfo.php) (free, MIT-licensed).

Create `installer.iss`:

```inno
[Setup]
AppName=Log Sentinel
AppVersion=1.0
DefaultDirName={autopf}\LogSentinel
DefaultGroupName=Log Sentinel
OutputBaseFilename=LogSentinel-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Files]
Source: "dist\LogSentinel.exe"; DestDir: "{app}"
Source: "USER_GUIDE.md"; DestDir: "{app}"

[Icons]
Name: "{group}\Log Sentinel"; Filename: "{app}\LogSentinel.exe"
Name: "{group}\User Guide"; Filename: "{app}\USER_GUIDE.md"
Name: "{commondesktop}\Log Sentinel"; Filename: "{app}\LogSentinel.exe"
```

Compile → `LogSentinel-Setup.exe` (proper installer with Start menu, uninstaller,
desktop shortcut).

### 3. Add an icon (optional)

1. Drop a 256×256 `.ico` file at `brand/icon.ico`
2. Open `LogSentinel.spec`
3. Uncomment the line: `# icon=str(HERE / "brand" / "icon.ico"),`
4. Re-run `BUILD.bat`

## Troubleshooting

| Problem | Fix |
|---|---|
| `pyinstaller: command not found` | `python -m pip install pyinstaller` |
| `tkinter` missing in build | Install Python with the Tk option ticked (default) |
| Antivirus flags the .exe | Normal for unsigned PyInstaller binaries — sign it (see above) |
| .exe is 100+ MB | Make sure UPX is installed (`choco install upx`) — gets it to ~30 MB |
| Slow startup | Switch from one-file to one-folder: change `runtime_tmpdir=None` (one-file is slower because it unpacks to %TEMP% on each launch) |

## Switching to one-folder (faster startup)

Edit `LogSentinel.spec`, change the `EXE(...)` block to use `COLLECT(...)`:

```python
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="LogSentinel",
          debug=False, console=False)

coll = COLLECT(exe, a.binaries, a.zipfiles, a.datas,
               strip=False, upx=True, upx_exclude=[], name="LogSentinel")
```

Result: `dist/LogSentinel/` folder with `.exe` + DLLs. Starts ~10× faster.
Slightly worse for distribution (it's a folder, not a single file), but better
for everyday use.
