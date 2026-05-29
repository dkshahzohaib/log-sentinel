"""Single source of truth for the application version."""

APP_NAME = "Log Sentinel"
APP_VERSION = "1.3.0"
BUILD_CHANNEL = "local"


def version_label() -> str:
    """Human-readable app/version label used by reports and support bundles."""
    return f"{APP_NAME} {APP_VERSION} ({BUILD_CHANNEL})"
