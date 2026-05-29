"""Local trial and monthly licence handling for Log Sentinel.

This is a practical offline gate for early sales. It is not a replacement for
server-side activation, because any local-only Python check can be patched by a
determined attacker.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import platform
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .preferences import PREFS_DIR


TRIAL_DAYS = 30
KEY_DAYS = 30
LICENSE_FILE = PREFS_DIR / "license.json"

# For a real public release, keep this secret only on your licence server.
_SIGNING_SECRET = b"change-this-before-public-log-sentinel-licensing-v1"


@dataclass
class LicenseStatus:
    can_run: bool
    mode: str
    message: str
    days_left: int
    trial_started: str = ""
    trial_expires: str = ""
    licensed_email: str = ""
    license_expires: str = ""
    plan: str = ""
    machine_id: str = ""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _today() -> date:
    return _now().date()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def device_fingerprint() -> str:
    raw = "|".join([
        platform.node().lower(),
        platform.system().lower(),
        platform.machine().lower(),
        hex(uuid.getnode()),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _read_state() -> dict:
    if not LICENSE_FILE.exists():
        return {}
    try:
        return json.loads(LICENSE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(data: dict) -> None:
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    LICENSE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _ensure_trial(data: dict | None = None) -> dict:
    data = dict(data or _read_state())
    if not data.get("trial_started"):
        started = _today().isoformat()
        data["trial_started"] = started
        data["trial_device"] = device_fingerprint()
        _write_state(data)
    return data


def _sign(payload_text: str) -> str:
    digest = hmac.new(
        _SIGNING_SECRET,
        payload_text.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return _b64(digest[:16])


def create_license_key(
    email: str,
    *,
    expires: date | None = None,
    days: int = KEY_DAYS,
    plan: str = "Monthly",
    device: str = "",
) -> str:
    """Create a 30-day key. Keep this admin-side for real sales."""
    clean_email = email.strip().lower()
    if not clean_email or "@" not in clean_email:
        raise ValueError("Enter a customer email address.")
    exp = expires or (_today() + timedelta(days=days))
    payload = {
        "email": clean_email,
        "exp": exp.isoformat(),
        "plan": plan,
        "v": 1,
    }
    clean_device = device.strip().lower()
    if clean_device:
        payload["device"] = clean_device
    payload_text = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    sig = _sign(payload_text)
    return f"LS30.{payload_text}.{sig}"


def decode_license_key(key: str) -> dict:
    parts = key.strip().split(".")
    if len(parts) != 3 or parts[0].upper() != "LS30":
        raise ValueError("Key must look like LS30.xxxxx.yyyyy.")
    payload_text, sig = parts[1], parts[2]
    expected = _sign(payload_text)
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Licence key signature is not valid.")
    try:
        payload = json.loads(_unb64(payload_text).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Licence key payload is damaged.") from exc
    return payload


def activate(email: str, key: str) -> LicenseStatus:
    clean_email = email.strip().lower()
    payload = decode_license_key(key)
    key_email = str(payload.get("email", "")).strip().lower()
    if clean_email != key_email:
        raise ValueError("This key was issued for a different email address.")
    key_device = str(payload.get("device", "")).strip().lower()
    current_device = device_fingerprint().lower()
    if key_device and key_device != current_device:
        raise ValueError(
            "This licence key was issued for a different PC. "
            f"This PC Machine ID is {current_device}."
        )
    exp = date.fromisoformat(str(payload.get("exp", "")))
    if exp < _today():
        raise ValueError("This licence key has expired. Ask for a new 30-day key.")

    data = _ensure_trial()
    data["license"] = {
        "email": clean_email,
        "key": key.strip(),
        "expires": exp.isoformat(),
        "plan": str(payload.get("plan", "Monthly")),
        "activated_at": _now().isoformat(),
        "device": current_device,
        "key_device": key_device,
    }
    _write_state(data)
    return status()


def status() -> LicenseStatus:
    data = _ensure_trial()
    lic = data.get("license") or {}
    if lic.get("key"):
        try:
            payload = decode_license_key(str(lic["key"]))
            exp = date.fromisoformat(str(payload.get("exp", "")))
            email = str(payload.get("email", "")).lower()
            if exp >= _today() and email == str(lic.get("email", "")).lower():
                key_device = str(payload.get("device", "")).strip().lower()
                if key_device and key_device != device_fingerprint().lower():
                    raise ValueError("Device does not match licence key.")
                days = max(0, (exp - _today()).days)
                return LicenseStatus(
                    can_run=True,
                    mode="licensed",
                    message=f"Licensed to {email}. Expires {exp.isoformat()}.",
                    days_left=days,
                    licensed_email=email,
                    license_expires=exp.isoformat(),
                    plan=str(payload.get("plan", "Monthly")),
                    machine_id=device_fingerprint(),
                    trial_started=str(data.get("trial_started", "")),
                    trial_expires=_trial_expiry(data).isoformat(),
                )
        except Exception:
            pass

    trial_exp = _trial_expiry(data)
    if trial_exp >= _today():
        days = max(0, (trial_exp - _today()).days)
        return LicenseStatus(
            can_run=True,
            mode="trial",
            message=f"Trial active. {days} day(s) left.",
            days_left=days,
            trial_started=str(data.get("trial_started", "")),
            trial_expires=trial_exp.isoformat(),
            machine_id=device_fingerprint(),
        )

    return LicenseStatus(
        can_run=False,
        mode="expired",
        message="Trial expired. Enter a new 30-day licence key to continue.",
        days_left=0,
        trial_started=str(data.get("trial_started", "")),
        trial_expires=trial_exp.isoformat(),
        machine_id=device_fingerprint(),
    )


def _trial_expiry(data: dict) -> date:
    try:
        started = date.fromisoformat(str(data.get("trial_started", "")))
    except ValueError:
        started = _today()
    return started + timedelta(days=TRIAL_DAYS)


def clear_license() -> None:
    data = _ensure_trial()
    data.pop("license", None)
    _write_state(data)
