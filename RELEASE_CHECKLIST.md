# Release Checklist

Use this before shipping a build to users.

## Code Quality

- Run `python -m compileall -q app.py main.py demo.py src tests`
- Run `python -m unittest discover -s tests -v`
- Run the app normally with `python app.py`
- Run a headless scan with `python app.py --scan`
- Confirm first-run baseline creation does not produce noisy findings
- Confirm second scan can report new autoruns/listeners/services/tasks

## Windows Safety

- Test without Administrator rights
- Test with Administrator rights
- Verify firewall add/delete writes to `~\.log_sentinel\change_log.jsonl`
- Verify hosts block/unblock writes to `~\.log_sentinel\change_log.jsonl`
- Verify panic mode restores adapters on the test machine
- Verify scheduled scan registration and unregistration

## Packaging

- Update `src/version.py`
- Run `BUILD.bat`
- Smoke-test `dist\LogSentinel.exe`
- Code-sign the executable
- Re-run after signing to confirm SmartScreen trust path is acceptable
- Archive the exact source tree used for the build

## Documentation

- Confirm README, USER_GUIDE, SECURITY, and LICENSE match the build
- Confirm screenshots match the current UI
- Confirm pricing/licensing language is consistent everywhere

## Privacy

- Confirm no telemetry endpoints were added
- Confirm SMTP email only sends when explicitly enabled
- Confirm local scan data is documented as stored under `~\.log_sentinel\`
