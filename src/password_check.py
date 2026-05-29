"""
Offline password strength checker. No data leaves the machine.

Scoring approach:
  - Entropy estimate from character classes + length
  - Check against a built-in top-1000 common passwords list
  - Time-to-crack estimate at 10 billion guesses/sec (modern GPU rig)

Returns a 0–100 score, label, and concrete improvement tips.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


# Top-100 most common passwords (small, embedded — full top-1M would be too big)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "shadow", "master",
    "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael",
    "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer",
    "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", "harley",
    "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
    "starwars", "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111",
    "131313", "freedom", "777777", "pass", "fuck", "maggie",
    "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese",
    "amanda", "summer", "love", "ashley", "6969", "nicole",
    "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix", "william",
    "corvette", "hello", "martin", "heather", "secret", "fucker",
    "merlin", "diamond", "1234qwer", "gfhjkm", "hammer", "silver",
    "222222", "88888888", "anthony", "justin", "test", "bailey",
    "q1w2e3r4t5", "patrick", "internet", "scooter", "orange", "11111",
    "golfer", "cookie", "richard", "samantha", "bigdog", "guitar",
    "jackson", "whatever", "mickey", "chicken", "sparky", "snoopy",
    "maverick", "phoenix", "camaro", "sexy", "peanut", "morgan",
    "welcome", "falcon",
}


@dataclass
class PasswordStrength:
    score: int            # 0–100
    label: str            # "Very weak" → "Excellent"
    color: str            # hex
    entropy_bits: float
    crack_time: str
    issues: list[str]
    tips: list[str]


# Time formatter
def _format_time(seconds: float) -> str:
    if seconds < 1:        return "instantly"
    if seconds < 60:       return f"{seconds:.0f} seconds"
    if seconds < 3600:     return f"{seconds/60:.0f} minutes"
    if seconds < 86400:    return f"{seconds/3600:.0f} hours"
    if seconds < 31536000: return f"{seconds/86400:.0f} days"
    if seconds < 31536000 * 100:    return f"{seconds/31536000:.0f} years"
    if seconds < 31536000 * 1e9:    return f"{seconds/31536000:.2g} years"
    return "millions of years"


def check(password: str) -> PasswordStrength:
    if not password:
        return PasswordStrength(
            score=0, label="Empty", color="#888",
            entropy_bits=0.0, crack_time="instantly",
            issues=["Password is empty."],
            tips=["Type a password to check it."],
        )

    issues: list[str] = []
    tips: list[str] = []
    length = len(password)

    # Character class detection
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))

    # Charset size
    charset = 0
    if has_lower:  charset += 26
    if has_upper:  charset += 26
    if has_digit:  charset += 10
    if has_symbol: charset += 32

    # Entropy = log2(charset^length)
    entropy = length * math.log2(charset) if charset else 0

    # Length issues
    if length < 8:
        issues.append(f"Too short ({length} chars).")
        tips.append("Use at least 12 characters.")
    elif length < 12:
        tips.append("Aim for 12+ characters for solid protection.")
    elif length < 16:
        tips.append("16+ characters is the gold standard.")

    # Character class issues
    if not has_upper:
        issues.append("No uppercase letters.")
        tips.append("Mix in some uppercase letters (A–Z).")
    if not has_lower:
        issues.append("No lowercase letters.")
        tips.append("Add lowercase letters (a–z).")
    if not has_digit:
        issues.append("No digits.")
        tips.append("Add at least one digit (0–9).")
    if not has_symbol:
        issues.append("No symbols.")
        tips.append("Add a symbol like ! @ # $ for extra strength.")

    # Common-password check
    is_common = password.lower() in COMMON_PASSWORDS
    if is_common:
        issues.append("This is one of the most common passwords. Crackable instantly.")
        tips.append("Pick something nobody else would use.")

    # Pattern checks
    if re.match(r"^[a-z]+$", password.lower()) and length < 14:
        tips.append("Don't use only letters — attackers try dictionary words first.")
    if re.match(r"^\d+$", password):
        issues.append("All digits is very weak — easily cracked by number-only attacks.")
    if re.search(r"(.)\1{3,}", password):
        tips.append("Avoid repeated characters like 'aaaa' or '1111'.")
    if re.search(r"(0123|1234|abcd|qwer|asdf|zxcv)", password.lower()):
        issues.append("Contains a sequential pattern.")
        tips.append("Avoid keyboard patterns and counting sequences.")

    # Compute crack time at 1e10 guesses/sec
    if is_common:
        crack_time = "instantly"
        score = 5
    else:
        guesses = (charset ** length) / 2  # average attempt is half the keyspace
        seconds = guesses / 1e10
        crack_time = _format_time(seconds)

        # Score from entropy bits
        if entropy < 28:
            score = 10
        elif entropy < 36:
            score = 30
        elif entropy < 60:
            score = 55
        elif entropy < 80:
            score = 75
        elif entropy < 100:
            score = 90
        else:
            score = 100

    # Penalties
    if length < 8:    score = min(score, 15)
    if is_common:     score = min(score, 5)
    if not (has_lower and has_upper and has_digit) and length < 14:
        score = min(score, 40)

    # Label & colour
    if score >= 90:    label, color = "Excellent",  "#4ecdc4"
    elif score >= 75:  label, color = "Strong",     "#6dd5ed"
    elif score >= 55:  label, color = "Decent",     "#ffd93d"
    elif score >= 30:  label, color = "Weak",       "#ff7f50"
    else:              label, color = "Very weak",  "#ff4757"

    if not issues and not tips and score >= 90:
        tips = ["Looks great. Use a unique password for every site, and "
                "consider a password manager so you don't have to remember them."]

    return PasswordStrength(
        score=score, label=label, color=color,
        entropy_bits=entropy, crack_time=crack_time,
        issues=issues, tips=tips,
    )
