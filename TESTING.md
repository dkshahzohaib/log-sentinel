# Testing

The project uses Python's standard-library `unittest` runner.

```powershell
python -m compileall -q app.py main.py demo.py src tests
python -m unittest discover -s tests -v
```

Current test coverage focuses on:

- Event-log detection rules
- Snapshot detection rules
- Health scoring
- Firewall and hosts validators
- Baseline diffing
- Action change logging
- Shared detection pipeline orchestration

The tests avoid requiring Administrator rights or changing Windows state.
