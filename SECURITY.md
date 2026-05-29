# Security Policy

## Supported Version

The maintained development line is `1.1.x`.

## Reporting a Vulnerability

Please report vulnerabilities privately to the project owner before public
disclosure. Include:

- Affected version or commit
- Reproduction steps
- Expected vs actual behavior
- Potential impact
- Suggested fix, if known

## Local Data

Log Sentinel stores local settings, scan history, baselines, and action logs in:

```text
C:\Users\<you>\.log_sentinel\
```

The app is designed to run offline. Email alerts only leave the machine if the
user explicitly configures SMTP.

## Safety Expectations

Actions that change Windows state should:

- Ask for user confirmation in the GUI
- Require Administrator rights where Windows requires it
- Record an entry in `change_log.jsonl`
- Include an undo hint whenever possible
- Avoid deleting user data
