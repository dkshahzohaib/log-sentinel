"""
Lightweight, offline IP-to-country lookup.

We ship a small built-in table of major IP ranges (cloud providers,
known ASNs, and well-known threat zones). It's not authoritative — for
serious GeoIP, ship a MaxMind GeoLite2 binary database. But for a
"where are my connections going?" view, this gives ~70% accurate
country attribution with zero data dependencies.

Users can extend the table by dropping entries into
~/.log_sentinel/geoip_extra.json:
    [
      { "cidr": "1.2.3.0/24", "country": "DE", "country_name": "Germany" }
    ]
"""

from __future__ import annotations

import bisect
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

from .preferences import PREFS_DIR


EXTRA_FILE = PREFS_DIR / "geoip_extra.json"


@dataclass
class GeoMatch:
    country: str          # ISO-3166 alpha-2
    country_name: str
    region: str = ""      # cloud provider region or "TOR"


# ──────────────────────────────────────────────
# Country data — codes, names, and (very rough) flags via emoji
# ──────────────────────────────────────────────

COUNTRY_NAMES = {
    "US": "United States", "CN": "China", "RU": "Russia",
    "DE": "Germany", "GB": "United Kingdom", "FR": "France",
    "NL": "Netherlands", "JP": "Japan", "KR": "South Korea",
    "IN": "India", "BR": "Brazil", "AU": "Australia",
    "CA": "Canada", "IE": "Ireland", "SG": "Singapore",
    "HK": "Hong Kong", "TW": "Taiwan", "ZA": "South Africa",
    "AE": "UAE", "TR": "Turkey", "IT": "Italy", "ES": "Spain",
    "PL": "Poland", "MX": "Mexico", "CH": "Switzerland",
    "SE": "Sweden", "NO": "Norway", "FI": "Finland",
    "RO": "Romania", "UA": "Ukraine", "BG": "Bulgaria",
    "VN": "Vietnam", "TH": "Thailand", "ID": "Indonesia",
    "PH": "Philippines", "MY": "Malaysia", "PK": "Pakistan",
    "BD": "Bangladesh", "EG": "Egypt", "IL": "Israel",
    "SA": "Saudi Arabia", "IR": "Iran", "AR": "Argentina",
    "CL": "Chile", "CO": "Colombia", "PE": "Peru",
    "??": "Unknown / private",
}

# Compact flag emoji from country code
def flag(code: str) -> str:
    if not code or len(code) != 2 or code == "??":
        return "🏳"
    base = 127397
    return chr(ord(code[0].upper()) + base) + chr(ord(code[1].upper()) + base)


# ──────────────────────────────────────────────
# Static ranges — well-known cloud + threat zones
# ──────────────────────────────────────────────

_BUILTIN_RANGES: list[tuple[str, str, str]] = [
    # (CIDR, country_code, region/tag)
    # Cloudflare
    ("1.1.1.0/24",       "US", "Cloudflare DNS"),
    ("1.0.0.0/24",       "US", "Cloudflare DNS"),
    ("104.16.0.0/12",    "US", "Cloudflare CDN"),
    ("172.64.0.0/13",    "US", "Cloudflare CDN"),
    ("162.158.0.0/15",   "US", "Cloudflare CDN"),
    ("190.93.240.0/20",  "US", "Cloudflare CDN"),
    # Google
    ("8.8.8.0/24",       "US", "Google DNS"),
    ("8.8.4.0/24",       "US", "Google DNS"),
    ("142.250.0.0/15",   "US", "Google"),
    ("172.217.0.0/16",   "US", "Google"),
    ("216.58.192.0/19",  "US", "Google"),
    ("64.233.160.0/19",  "US", "Google"),
    ("74.125.0.0/16",    "US", "Google"),
    # AWS major regions (very rough)
    ("3.0.0.0/8",        "US", "AWS"),
    ("13.32.0.0/15",     "US", "AWS CloudFront"),
    ("13.224.0.0/14",    "US", "AWS CloudFront"),
    ("18.130.0.0/16",    "GB", "AWS eu-west-2"),
    ("18.196.0.0/15",    "DE", "AWS eu-central-1"),
    ("18.184.0.0/15",    "DE", "AWS eu-central-1"),
    ("13.114.0.0/16",    "JP", "AWS ap-northeast-1"),
    ("13.112.0.0/16",    "JP", "AWS ap-northeast-1"),
    ("13.124.0.0/16",    "KR", "AWS ap-northeast-2"),
    ("13.228.0.0/15",    "SG", "AWS ap-southeast-1"),
    ("13.236.0.0/14",    "AU", "AWS ap-southeast-2"),
    # Azure
    ("13.64.0.0/11",     "US", "Azure"),
    ("13.96.0.0/13",     "US", "Azure"),
    ("13.104.0.0/14",    "US", "Azure"),
    ("20.0.0.0/8",       "US", "Azure"),
    ("40.64.0.0/10",     "US", "Azure"),
    ("52.96.0.0/12",     "US", "Azure"),
    ("65.52.0.0/14",     "US", "Azure"),
    ("104.40.0.0/13",    "US", "Azure"),
    ("137.116.0.0/15",   "US", "Azure"),
    # Microsoft
    ("131.107.0.0/16",   "US", "Microsoft"),
    # GitHub
    ("140.82.112.0/20",  "US", "GitHub"),
    ("185.199.108.0/22", "US", "GitHub Pages"),
    # Akamai
    ("23.32.0.0/11",     "US", "Akamai CDN"),
    ("23.64.0.0/14",     "US", "Akamai CDN"),
    ("104.64.0.0/10",    "US", "Akamai CDN"),
    # Hetzner / OVH (lots of bots)
    ("116.202.0.0/16",   "DE", "Hetzner"),
    ("78.46.0.0/15",     "DE", "Hetzner"),
    ("88.99.0.0/16",     "DE", "Hetzner"),
    ("136.243.0.0/16",   "DE", "Hetzner"),
    ("46.4.0.0/16",      "DE", "Hetzner"),
    ("51.38.0.0/16",     "FR", "OVH"),
    ("51.68.0.0/16",     "FR", "OVH"),
    ("54.36.0.0/16",     "FR", "OVH"),
    ("178.32.0.0/15",    "FR", "OVH"),
    ("198.27.64.0/18",   "CA", "OVH Canada"),
    # DigitalOcean
    ("104.131.0.0/16",   "US", "DigitalOcean"),
    ("104.236.0.0/16",   "US", "DigitalOcean"),
    ("159.203.0.0/16",   "US", "DigitalOcean"),
    ("167.71.0.0/16",    "US", "DigitalOcean"),
    ("178.62.0.0/16",    "GB", "DigitalOcean"),
    # Linode
    ("45.79.0.0/16",     "US", "Linode"),
    ("139.162.0.0/16",   "JP", "Linode"),
    # Comcast / Verizon (US ISPs)
    ("96.224.0.0/11",    "US", "Comcast"),
    ("69.240.0.0/12",    "US", "Verizon"),
    # Asia broadband
    ("180.0.0.0/8",      "JP", "JP ISPs"),
    ("183.232.0.0/13",   "CN", "China Mobile"),
    ("221.0.0.0/8",      "CN", "China Telecom"),
    ("117.0.0.0/8",      "CN", "China Telecom"),
    ("120.0.0.0/8",      "CN", "China Telecom"),
    ("116.0.0.0/8",      "CN", "China Telecom"),
    # Russia
    ("31.13.144.0/21",   "RU", "Yandex"),
    ("77.88.0.0/16",     "RU", "Yandex"),
    ("87.250.224.0/19",  "RU", "Yandex"),
    ("178.140.0.0/14",   "RU", "Rostelecom"),
    ("212.176.0.0/12",   "RU", "Rostelecom"),
    # TOR exit nodes (small sample)
    ("185.220.100.0/22", "??", "TOR"),
    ("185.220.101.0/24", "??", "TOR"),
    ("185.220.102.0/24", "??", "TOR"),
    ("23.129.64.0/24",   "??", "TOR"),
    ("171.25.193.0/24",  "??", "TOR"),
]


# ──────────────────────────────────────────────
# Build sorted list for fast bisect lookup
# ──────────────────────────────────────────────

_NETWORKS: list[tuple[ipaddress.IPv4Network, str, str]] = []


def _build():
    if _NETWORKS:
        return
    for cidr, code, region in _BUILTIN_RANGES:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            _NETWORKS.append((net, code, region))
        except ValueError:
            continue
    # Load extras
    if EXTRA_FILE.exists():
        try:
            extras = json.loads(EXTRA_FILE.read_text(encoding="utf-8"))
            for e in extras:
                try:
                    net = ipaddress.ip_network(e["cidr"], strict=False)
                    _NETWORKS.append((net, e.get("country", "??"),
                                      e.get("country_name", "")))
                except (ValueError, KeyError):
                    continue
        except (OSError, json.JSONDecodeError):
            pass
    # Sort by network address for binary search
    _NETWORKS.sort(key=lambda x: int(x[0].network_address))


# ──────────────────────────────────────────────
# Public lookup
# ──────────────────────────────────────────────

def lookup(ip: str) -> GeoMatch:
    """Resolve an IPv4 address to a GeoMatch. Returns ?? if unknown/private."""
    _build()
    if not ip or ":" in ip:        # Skip IPv6 / empty
        return GeoMatch("??", "Unknown / IPv6")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return GeoMatch("??", "Invalid")
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return GeoMatch("??", "Private network")

    # Linear scan is fine for ~80 entries
    for net, code, region in _NETWORKS:
        if addr in net:
            return GeoMatch(
                country=code,
                country_name=COUNTRY_NAMES.get(code, "Unknown"),
                region=region,
            )

    # Fallback: very rough by first octet
    first = int(addr.packed[0])
    rough = _rough_first_octet(first)
    return GeoMatch(
        country=rough,
        country_name=COUNTRY_NAMES.get(rough, "Unknown"),
        region="(approx)",
    )


def _rough_first_octet(first: int) -> str:
    """Last-resort guess based on first octet allocation by RIR."""
    # ARIN (US/Canada-leaning)
    if first in range(3, 24) or first in range(50, 76) or first in range(96, 109):
        return "US"
    # RIPE (Europe)
    if first in range(78, 96) or first in range(176, 196):
        return "DE"
    # APNIC (Asia)
    if first in range(110, 127) or first in range(180, 224):
        return "CN"
    # LACNIC (Latin America)
    if first in range(177, 200):
        return "BR"
    # AFRINIC (Africa)
    if first in range(196, 198):
        return "ZA"
    return "??"


def summarize(connections: list) -> dict:
    """
    Group a list of NetConnection objects by country.
    Returns: {
      'by_country': [(country, count, sample_ips), ...],
      'total_external': int,
    }
    """
    _build()
    counts: dict[str, list] = {}
    for c in connections:
        if not c.is_external or c.state != "ESTABLISHED":
            continue
        m = lookup(c.remote_addr)
        key = m.country
        counts.setdefault(key, []).append(c)

    by_country = []
    for code, items in counts.items():
        sample = list({c.remote_addr for c in items})[:3]
        by_country.append((code, len(items), sample))
    by_country.sort(key=lambda x: x[1], reverse=True)

    return {
        "by_country": by_country,
        "total_external": sum(n for _, n, _ in by_country),
    }
