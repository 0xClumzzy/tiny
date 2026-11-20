"""LDIF parsing and entry merging."""

import base64
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Entry:
    """A single LDAP object."""

    dn: str
    attrs: dict[str, list[str]] = field(default_factory=dict)

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        values = self.attrs.get(name.lower())
        return values[0] if values else default

    def all(self, name: str) -> list[str]:
        return self.attrs.get(name.lower(), [])


def parse_ldif(text: str) -> list[Entry]:
    """Parse LDIF text into entries.

    Handles line folding, base64 values and attribute options such as
    ``objectGUID;binary::``. Comments and blank lines are ignored.
    """
    entries: list[Entry] = []
    current: Optional[Entry] = None
    last_attr: Optional[str] = None

    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not line:
            if current is not None and current.dn:
                entries.append(current)
            current = None
            last_attr = None
            continue
        if line.startswith("#"):
            continue
        if line[:1] in (" ", "\t") and current is not None and last_attr:
            if current.attrs.get(last_attr):
                current.attrs[last_attr][-1] += line[1:]
            continue

        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9;-]*)\s*(::?)\s*(.*)$", line)
        if not match:
            continue
        attr = match.group(1).lower().split(";")[0]
        separator = match.group(2)
        value = match.group(3)

        if attr == "dn":
            if current is not None and current.dn:
                entries.append(current)
            current = Entry(dn=value.strip())
            last_attr = None
            continue
        if current is None:
            current = Entry(dn="")
        if separator == "::":
            try:
                raw_bytes = base64.b64decode(value)
            except Exception:
                raw_bytes = value.encode("utf-8", "replace")
            if attr in ("objectsid", "objectguid"):
                # store as latin1 string to preserve bytes roundtrip
                value = raw_bytes.decode("latin1")
            else:
                value = raw_bytes.decode("utf-8", "replace")
        current.attrs.setdefault(attr, []).append(value)
        last_attr = attr

    if current is not None and current.dn:
        entries.append(current)
    return entries


def merge_entries(entries: Iterable[Entry]) -> list[Entry]:
    """Merge duplicate DNs, useful when several dump files overlap."""
    merged: dict[str, Entry] = {}
    order: list[str] = []
    for entry in entries:
        key = entry.dn.strip().lower()
        if key not in merged:
            merged[key] = Entry(dn=entry.dn, attrs={k: list(v) for k, v in entry.attrs.items()})
            order.append(key)
            continue
        target = merged[key]
        for attr, values in entry.attrs.items():
            bucket = target.attrs.setdefault(attr, [])
            for value in values:
                if value not in bucket:
                    bucket.append(value)
    return [merged[key] for key in order]
