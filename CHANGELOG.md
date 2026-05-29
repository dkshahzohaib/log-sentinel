# Changelog

## 1.3.0

- Added local 30-day trial enforcement.
- Added monthly licence keys that expire automatically after their encoded expiry date.
- Added activation dialog in the desktop app and licence status in Settings.
- Added headless/scheduled scan blocking when the trial and licence are expired.
- Added admin helper `tools/make_license_key.py` for issuing 30-day customer keys.
- Added global severity sensitivity control for Health Check and Findings.
- Upgraded the Windows log viewer with failed-password filters, event labels, and raw event detail fields.
- Added licensing unit tests.

## 1.2.0

- Added baseline diffing for new autoruns, services, scheduled tasks, and listening ports.
- Added local action audit logging at `~/.log_sentinel/change_log.jsonl`.
- Added shared detection pipeline for GUI and headless scans.
- Added unit tests for core analyzers, health scoring, validators, baseline diffing, and change logging.
- Added a harmless fake malware lab and static file scanner for EICAR-style markers, suspicious tool names, and suspicious script content.
- Added toolbar access for saved reports and folder scanning.
- Added report/PDF/help generation tests.
- Expanded System Info into a buyer-check summary with model, serial, BIOS, CPU, RAM, GPU, disks/partitions, and battery details.
- Added `TEST-THREAT-PORT-4444.bat`, a harmless local listener test that should create a High suspicious-port finding.
- Added Low/Info visibility controls: Show, Hide, or Show Later.
- Replaced the old message-box guided demo with a modern step-by-step walkthrough window.
- Added explicit source-available license, security policy, testing guide, and release checklist.
- Added `src/version.py` as the single version source.
