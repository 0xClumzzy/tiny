"""Domain posture: password policy, lockout, machine quota, trusts."""

import re
from typing import Optional

from .ldif import Entry
from .score import get_int

TICKS_PER_SECOND = 10_000_000

FUNCTIONAL_LEVELS = {
    0: "2000",
    1: "2003 interim",
    2: "2003",
    3: "2008",
    4: "2008 R2",
    5: "2012",
    6: "2012 R2",
    7: "2016",
    10: "2025",
}

TRUST_DIRECTIONS = {1: "inbound", 2: "outbound", 3: "bidirectional"}
TRUST_TYPES = {1: "downlevel", 2: "uplevel", 3: "MIT"}

TRUST_ATTRIBUTES = {
    0x1: "non-transitive",
    0x4: "quarantined",
    0x8: "forest-transitive",
    0x10: "cross-organization",
    0x20: "within-forest",
    0x40: "treat-as-external",
    0x80: "RC4",
    0x400: "PIM",
}


def _format_seconds(seconds: float) -> str:
    if seconds >= 86400:
        days = seconds / 86400
        return f"{days:.0f} days" if days >= 2 else "1 day"
    if seconds >= 3600:
        hours = seconds / 3600
        return f"{hours:.0f} hours" if hours >= 2 else "1 hour"
    if seconds >= 60:
        minutes = seconds / 60
        return f"{minutes:.0f} minutes" if minutes >= 2 else "1 minute"
    return f"{seconds:.0f} seconds"


def format_timespan(value: Optional[int]) -> Optional[str]:
    """Format a Windows 100ns interval; negative means never/indefinite."""
    if value is None:
        return None
    if value < 0:
        return "never"
    return _format_seconds(value / TICKS_PER_SECOND)


def guess_domain(entries: list[Entry]) -> Optional[str]:
    for entry in entries:
        parts = re.findall(r"(?:^|,)\s*DC=([^,]+)", entry.dn, re.IGNORECASE)
        if parts:
            return ".".join(part.strip() for part in parts)
    return None


def _describe_trust(entry: Entry) -> dict[str, object]:
    attrs = get_int(entry, "trustattributes") or 0
    return {
        "partner": entry.get("trustpartner") or entry.get("name") or "",
        "flat_name": entry.get("flatname") or "",
        "direction": TRUST_DIRECTIONS.get(get_int(entry, "trustdirection") or 0, "unknown"),
        "type": TRUST_TYPES.get(get_int(entry, "trusttype") or 0, "unknown"),
        "attributes": [label for bit, label in TRUST_ATTRIBUTES.items() if attrs & bit],
    }


def collect_posture(entries: list[Entry]) -> dict[str, object]:
    """Extract domain password/lockout policy, quota and trusts."""
    domain_entry = None
    for entry in entries:
        ocs = {oc.lower() for oc in entry.all("objectclass")}
        if "domaindns" in ocs or ("domain" in ocs and entry.get("lockoutthreshold")):
            domain_entry = entry
            break

    posture: dict[str, object] = {
        "domain": guess_domain(entries),
        "available": False,
        "machine_account_quota": None,
        "lockout_threshold": None,
        "lockout_duration": None,
        "lockout_window": None,
        "min_password_length": None,
        "max_password_age": None,
        "password_history": None,
        "complexity": None,
        "functional_level": None,
        "trusts": [
            _describe_trust(e)
            for e in entries
            if "trusteddomain" in {oc.lower() for oc in e.all("objectclass")}
        ],
    }
    if domain_entry is None:
        return posture

    threshold = get_int(domain_entry, "lockoutthreshold")
    max_age = get_int(domain_entry, "maxpwdage")
    properties = get_int(domain_entry, "pwdproperties") or 0
    level = get_int(domain_entry, "domainfunctionality")

    posture.update(
        {
            "available": True,
            "machine_account_quota": get_int(domain_entry, "ms-ds-machineaccountquota"),
            "lockout_threshold": threshold,
            "lockout_duration": format_timespan(get_int(domain_entry, "lockoutduration")),
            "lockout_window": format_timespan(get_int(domain_entry, "lockoutobservationwindow")),
            "min_password_length": get_int(domain_entry, "minpwdlength"),
            "max_password_age": format_timespan(max_age),
            "password_history": get_int(domain_entry, "pwdhistorylength"),
            "complexity": bool(properties & 0x1) if properties is not None else None,
            "functional_level": FUNCTIONAL_LEVELS.get(level, str(level))
            if level is not None
            else None,
        }
    )
    return posture


def posture_rows(posture: dict[str, object]) -> list[tuple]:
    """(label, value) rows for display, omitting missing values."""
    rows = []
    quota = posture.get("machine_account_quota")
    if quota is not None:
        rows.append(
            (
                "machine account quota",
                f"{quota} (RBCD viable)" if quota else "0 (no machine accounts)",
            )
        )
    threshold = posture.get("lockout_threshold")
    if threshold is not None:
        rows.append(
            (
                "lockout threshold",
                "0 (never — spraying safe)" if threshold == 0 else f"{threshold} attempts",
            )
        )
    if posture.get("lockout_duration"):
        rows.append(("lockout duration", posture["lockout_duration"]))
    if posture.get("lockout_window"):
        rows.append(("lockout window", posture["lockout_window"]))
    if posture.get("min_password_length") is not None:
        rows.append(("min password length", posture["min_password_length"]))
    if posture.get("max_password_age"):
        rows.append(("max password age", posture["max_password_age"]))
    if posture.get("password_history") is not None:
        rows.append(("password history", posture["password_history"]))
    if posture.get("complexity") is not None:
        rows.append(("complexity", "enabled" if posture["complexity"] else "disabled"))
    if posture.get("functional_level"):
        rows.append(("functional level", posture["functional_level"]))
    for trust in posture.get("trusts", []):
        label = f"trust {trust['direction']}"
        value = trust["partner"]
        if trust["attributes"]:
            value += f" ({', '.join(trust['attributes'])})"
        rows.append((label, value))
    return rows
