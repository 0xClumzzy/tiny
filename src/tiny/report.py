"""Terminal report, JSON report and file exports."""

import datetime
import hashlib
import json
import os
import re
import shutil
import sys
import textwrap
import unicodedata
from collections import Counter
from typing import Dict, List, Optional, Tuple

from . import __version__
from .ldif import Entry
from .playbook import password_hints, render_playbook
from .posture import collect_posture, posture_rows
from .score import Obj
from .banner import render_banner as render_banner

NO_COLOR_ENV = os.environ.get("NO_COLOR")


class C:
    """ANSI colour codes."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"


TIERS = [
    ("CROWN JEWELS", "direct path to domain takeover", C.BRIGHT_RED),
    ("HIGH VALUE", "privilege-escalation primitives", C.BRIGHT_YELLOW),
    ("MEDIUM", "useful targets and context", C.BRIGHT_CYAN),
    ("LOW", "background noise", C.GRAY),
]

KEY_ATTRS = [
    "samaccountname", "cn", "displayname", "mail", "userprincipalname",
    "description", "admincount", "useraccountcontrol", "pwdlastset",
    "lastlogon", "serviceprincipalname", "msds-allowedtodelegateto",
    "msds-allowedtoactonbehalfofotheridentity", "objectsid", "sidhistory",
    "memberof", "member", "dnshostname", "operatingsystem",
    "ms-mcs-admpwd", "mslaps-password", "msds-keycredentiallink",
    "primarygroupid", "whencreated", "whenchanged",
]


def use_color(disabled: bool) -> bool:
    if disabled or NO_COLOR_ENV:
        return False
    return sys.stdout.isatty()


def paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{C.RESET}" if enabled else text


def terminal_width() -> int:
    return max(80, min(140, shutil.get_terminal_size((100, 24)).columns))


def display_width(text: str) -> int:
    """Terminal cell width of a string (wide chars count as two)."""
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def guess_domain(entries: List[Entry]) -> Optional[str]:
    for entry in entries:
        parts = re.findall(r"(?:^|,)\s*DC=([^,]+)", entry.dn, re.IGNORECASE)
        if parts:
            return ".".join(part.strip() for part in parts)
    return None


def tier_counts(objects: List[Obj]) -> List[int]:
    counts = [0, 0, 0, 0]
    for obj in objects:
        counts[obj.tier] += 1
    return counts


def render_pyramid(counts: List[int], color: bool) -> List[str]:
    labels = [f"TIER {t} · {TIERS[t][0]}  {counts[t]}" for t in range(4)]
    max_width = max(len(label) for label in labels) + 8
    lines: List[str] = []
    for t, label in enumerate(labels):
        width = max(len(label) + 4, int(max_width * (0.55 + 0.15 * t)))
        pad = (max_width - width) // 2
        code = TIERS[t][2] if color else ""
        lines.append(" " * pad + paint("┌" + label.center(width - 2, "─") + "┐", code, color))
        lines.append(" " * pad + paint("└" + "─" * (width - 2) + "┘", code, color))
    return lines


def wrap_reason(prefix: str, reason: str, width: int) -> List[str]:
    available = max(30, width - len(prefix))
    wrapped = textwrap.wrap(reason, width=available) or [""]
    return [prefix + wrapped[0]] + [" " * len(prefix) + line for line in wrapped[1:]]


def quick_wins(objects: List[Obj]) -> List[Tuple[str, str, List[str]]]:
    """(label, description, matching names) groups worth acting on immediately."""
    def names(tag, limit: int = 6) -> List[str]:
        tags = {tag} if isinstance(tag, str) else tag
        found = [o.name for o in objects if o.tags & tags]
        return found[:limit] + ([f"+{len(found) - limit} more"] if len(found) > limit else [])

    rows = [
        ("kerberoastable", "users with an SPN", names("kerberoastable")),
        ("asrep", "no Kerberos pre-auth", names("asrep")),
        ("unconstrained", "unconstrained delegation", names("unconstrained")),
        ("rbcd", "resource-based delegation", names("rbcd")),
        ("shadowcreds", "KeyCredentialLink abuse", names("shadowcreds")),
        ("adcs", "ESC candidate templates",
         names({"adcs-esc1", "adcs-esc2", "adcs-esc3", "adcs-esc9"})),
        ("creds", "LAPS / cleartext / hints", names("creds")),
        ("sidhistory", "SID history present", names("sidhistory")),
    ]
    return [row for row in rows if row[2]]


def attack_paths(objects: List[Obj], limit: int = 8,
                 tier: int = 0) -> List[Tuple[Obj, List[str]]]:
    """Shortest known membership chains from an object to a privileged group."""
    rows: List[Tuple[Obj, List[str]]] = []
    seen = set()
    for obj in objects:
        if obj.kind not in ("user", "computer"):
            continue
        for membership in obj.memberships:
            if membership.tier != tier:
                continue
            chain = [obj.name] + list(reversed(membership.path)) + [membership.group]
            key = tuple(chain)
            if key in seen:
                continue
            seen.add(key)
            rows.append((obj, chain))
    rows.sort(key=lambda row: (-row[0].score, len(row[1])))
    return rows[:limit] if limit else rows


def render_report(objects: List[Obj], sources: List[str], color: bool,
                  top: int, show_all: bool,
                  brief: bool = False, verbose: bool = False) -> str:
    width = terminal_width()
    counts = tier_counts(objects)
    domain = guess_domain([o.entry for o in objects])
    kinds = Counter(o.kind for o in objects)
    lines: List[str] = []

    title = "tiny · ldap triage"
    subtitle = f"{len(objects)} objects  ·  {counts[0]} crown jewels"
    if domain:
        subtitle += f"  ·  {domain}"
    lines.append("")
    lines.extend(render_banner(domain, len(objects), counts[0], color, width))
    lines.append("")

    others = sum(1 for o in objects if o.kind == "other")
    if others and others / max(len(objects), 1) > 0.3:
        lines.append(paint(f"  ⚠  {others}/{len(objects)} entries classified as 'other' "
                           "(partial/missing objectClass) — results may be unreliable",
                           C.YELLOW, color))
        lines.append("")

    lines.append(paint("  PYRAMID", C.BOLD, color))
    lines.extend(render_pyramid(counts, color))
    lines.append("")

    queue = objects if show_all else objects[:top]
    header = "  PRIORITY QUEUE"
    if not show_all:
        header += f"  {paint('(top ' + str(len(queue)) + ', use --all for full list)', C.DIM, color)}"
    lines.append(paint("  " + ("PRIORITY QUEUE" if show_all else "PRIORITY QUEUE"),
                       C.BOLD, color)
                 + ("" if show_all else paint(f"  (top {len(queue)}" + (", brief" if brief else ", use --all") + ")", C.DIM, color)))
    if brief:
        lines[-1] += paint(" — use --verbose to expand reasons, omit --brief for full", C.DIM, color)
    lines.append("")
    if not queue:
        lines.append("    nothing to rank")
    for obj in queue:
        code = TIERS[obj.tier][2] if color else ""
        tier_badge = paint(f"[T{obj.tier}]", code, color)
        name = obj.name[:36]
        reasons = obj.reasons
        if reasons:
            shown = reasons if verbose else [reasons[0]]
            if not verbose and len(reasons) > 1:
                shown = shown + [f"(+{len(reasons)-1} more)"]
            reason = "; ".join(shown)
        else:
            reason = "no escalation signals"
        lines.append(f"    {obj.score:>3}  {tier_badge}  {name:<36}  {paint(obj.kind, C.DIM, color)}")
        for wline in textwrap.wrap(reason, width=max(40, width - 10)):
            lines.append(f"         {paint('↳', C.DIM, color)} {wline}")
    hidden = len(objects) - len(queue)
    if hidden > 0:
        lines.append(paint(f"         … {hidden} more", C.DIM, color))
    lines.append("")

    if not brief:
        paths = attack_paths(objects, limit=8)
        if paths:
            lines.append(paint("  ATTACK PATHS → TIER 0", C.BOLD, color))
            for _, chain in paths:
                lines.append("    " + paint(" → ", C.DIM, color).join(chain))
            lines.append("")

        wins = quick_wins(objects)
        if wins:
            lines.append(paint("  QUICK WINS", C.BOLD, color))
            for label, description, found in wins:
                lines.append(f"    {paint('•', C.CYAN, color)} {paint(label, C.BOLD, color):<{15 + (10 if color else 0)}} {paint(description, C.DIM, color)}")
                lines.append(f"      {', '.join(found)}")
            lines.append("")

        posture = collect_posture([o.entry for o in objects])
        rows = posture_rows(posture)
        if rows:
            lines.append(paint("  DOMAIN POSTURE", C.BOLD, color))
            for label, value in rows:
                lines.append(f"    {label:<24} {value}")
            lines.append("")

    inventory = "  ·  ".join(f"{kind}s: {count}" for kind, count in
                             sorted(kinds.items(), key=lambda kv: -kv[1]))
    lines.append(paint("  INVENTORY", C.BOLD, color))
    lines.append(f"    {inventory}")
    lines.append(f"    {paint('sources:', C.DIM, color)} {', '.join(sources) if sources else 'stdin'}")
    lines.append("")
    lines.append(paint("    heuristics only — no ACL/nTSecurityDescriptor analysis", C.DIM, color))
    lines.append("")
    return "\n".join(lines)


def render_markdown(objects: List[Obj], sources: List[str]) -> str:
    counts = tier_counts(objects)
    domain = guess_domain([o.entry for o in objects])
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        "# tiny — LDAP triage report",
        "",
        f"_{len(objects)} objects"
        + (f" · {domain}" if domain else "")
        + f" · generated {stamp}_",
        "",
        "## Pyramid",
        "",
        "| Tier | Objects | Meaning |",
        "|------|---------|---------|",
    ]
    for t in range(4):
        lines.append(f"| {t} · {TIERS[t][0]} | {counts[t]} | {TIERS[t][1]} |")

    lines += ["", "## Priority queue", "",
              "| Score | Tier | Object | Type | Why |",
              "|-------|------|--------|------|-----|"]
    for obj in objects:
        reason = "; ".join(obj.reasons).replace("|", "\\|")
        name = obj.name.replace("|", "\\|")
        lines.append(f"| {obj.score} | T{obj.tier} | `{name}` | {obj.kind} | {reason} |")

    paths = attack_paths(objects, limit=0)
    if paths:
        lines += ["", "## Attack paths to tier 0", ""]
        for _, chain in paths:
            lines.append("- " + " → ".join(f"`{part}`" for part in chain))

    wins = quick_wins(objects)
    if wins:
        lines += ["", "## Quick wins", ""]
        for label, description, found in wins:
            lines.append(f"- **{label}** ({description}): {', '.join(found)}")

    posture = collect_posture([o.entry for o in objects])
    rows = posture_rows(posture)
    if rows:
        lines += ["", "## Domain posture", "",
                  "| Setting | Value |", "|---------|-------|"]
        for label, value in rows:
            lines.append(f"| {label} | {str(value).replace('|', chr(92) + '|')} |")

    lines += ["", "## Sources", ""]
    lines += [f"- `{source}`" for source in sources]
    lines += ["", "---", "",
              "Scoring is heuristic and based solely on attributes present in the dump. "
              "ACL edges (`nTSecurityDescriptor`) are not analysed."]
    return "\n".join(lines) + "\n"


def format_entry(obj: Obj, full: bool = False, max_value: int = 200) -> str:
    entry = obj.entry
    lines = [f"dn: {entry.dn}", f"  kind: {obj.kind}", f"  name: {obj.name}"]
    seen = {"dn", "kind", "name", "objectclass"}

    def emit(attr: str) -> None:
        values = entry.all(attr)
        if not values:
            return
        short = []
        for value in values[:5]:
            if len(value) > max_value:
                value = value[:max_value - 3] + "..."
            short.append(value)
        suffix = f" (+{len(values) - 5} more)" if len(values) > 5 else ""
        lines.append(f"  {attr}: {', '.join(short)}{suffix}")

    for attr in KEY_ATTRS:
        if attr in seen:
            continue
        emit(attr)
        seen.add(attr)
    if full:
        for attr in sorted(entry.attrs):
            if attr not in seen:
                emit(attr)
                seen.add(attr)
    return "\n".join(lines)


def user_names(objects: List[Obj], tag: Optional[str] = None,
               enabled_only: bool = False) -> List[str]:
    names = []
    for obj in objects:
        if obj.kind != "user":
            continue
        if enabled_only and "disabled" in obj.tags:
            continue
        if tag and tag not in obj.tags:
            continue
        sam = obj.entry.get("samaccountname")
        if not sam or sam.lower() == "krbtgt":
            continue
        names.append(sam)
    return sorted(dict.fromkeys(names), key=str.lower)


def computer_names(objects: List[Obj], tag: Optional[str] = None) -> List[str]:
    names = []
    for obj in objects:
        if obj.kind != "computer":
            continue
        if tag and tag not in obj.tags:
            continue
        name = (obj.entry.get("dnshostname") or obj.name).rstrip("$")
        names.append(name)
    return sorted(dict.fromkeys(names), key=str.lower)


def da_members(objects: List[Obj]) -> List[str]:
    names = []
    for obj in objects:
        if any(m.group in ("Domain Admins", "Enterprise Admins")
               for m in obj.memberships):
            names.append(obj.name)
    return sorted(dict.fromkeys(names), key=str.lower)


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def render_dot(objects: List[Obj]) -> str:
    """Graphviz graph of tier 0/1 group memberships."""
    lines = [
        "digraph ad {",
        '  rankdir=LR;',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10];',
    ]
    declared = set()
    edges = set()
    for obj in objects:
        for membership in obj.memberships:
            if membership.tier > 1:
                continue
            gid = "g" + hashlib.sha1(
                membership.group.encode()).hexdigest()[:10]
            uid = "u" + hashlib.sha1(obj.entry.dn.encode()).hexdigest()[:10]
            if gid not in declared:
                declared.add(gid)
                lines.append(f'  "{gid}" [label="{_dot_escape(membership.group)}", '
                             f'fillcolor="#d9c2e9"];')
            if uid not in declared:
                declared.add(uid)
                fill = "#f4b6b6" if membership.tier == 0 else "#f7dfa5"
                lines.append(f'  "{uid}" [label="{_dot_escape(obj.name)}", '
                             f'fillcolor="{fill}"];')
            edge = (uid, gid)
            if edge not in edges:
                edges.add(edge)
                lines.append(f'  "{uid}" -> "{gid}";')
    if not edges:
        return ""
    lines.append("}")
    return "\n".join(lines) + "\n"


def export(objects: List[Obj], outdir: str, sources: List[str],
           full: bool) -> List[Tuple[str, int]]:
    os.makedirs(outdir, exist_ok=True)
    written: List[Tuple[str, int]] = []

    def write_file(filename: str, note: str, items: List[Obj]) -> None:
        with open(os.path.join(outdir, filename), "w", encoding="utf-8") as handle:
            handle.write(f"# {note}\n# {len(items)} entries · tiny {__version__}\n\n")
            for obj in items:
                handle.write(f"# score={obj.score} tier={obj.tier} "
                             f"({TIERS[obj.tier][0]}) | {'; '.join(obj.reasons)}\n")
                handle.write(format_entry(obj, full=full) + "\n\n")
        written.append((filename, len(items)))

    def write_list(filename: str, values: List[str]) -> None:
        with open(os.path.join(outdir, filename), "w", encoding="utf-8") as handle:
            handle.write("\n".join(values) + ("\n" if values else ""))
        written.append((filename, len(values)))

    def write_doc(filename: str, note: str, values: List[str]) -> None:
        with open(os.path.join(outdir, filename), "w", encoding="utf-8") as handle:
            handle.write(f"# {note}\n\n" + "\n".join(values) + "\n")
        written.append((filename, len(values)))

    users = [o for o in objects if o.kind == "user"]
    groups = [o for o in objects if o.kind == "group"]
    computers = [o for o in objects if o.kind == "computer"]

    write_file("tier0-crown-jewels.txt", "Tier 0 — direct path to domain takeover",
               [o for o in objects if o.tier == 0])
    write_file("tier1-high-value.txt", "Tier 1 — privilege-escalation primitives",
               [o for o in objects if o.tier == 1])
    write_file("tier2-medium.txt", "Tier 2 — useful targets and context",
               [o for o in objects if o.tier == 2])
    write_file("tier3-low.txt", "Tier 3 — background noise",
               [o for o in objects if o.tier == 3])
    write_file("users.txt", "All user objects", users)
    write_file("privileged-users.txt", "Users in tier 0 or 1",
               [o for o in users if o.tier <= 1])
    write_file("groups.txt", "All group objects", groups)
    write_file("computers.txt", "All computer objects", computers)
    write_file("service-accounts.txt", "User objects flagged as service accounts",
               [o for o in users if "service" in o.tags or "gmsa" in o.tags])
    write_file("kerberoastable.txt", "Users with a servicePrincipalName",
               [o for o in users if "kerberoastable" in o.tags])
    write_file("asrep-roastable.txt", "Users without Kerberos pre-authentication",
               [o for o in users if "asrep" in o.tags])
    write_file("delegation.txt", "Unconstrained, constrained and resource-based delegation",
               [o for o in objects if "delegation" in o.tags])
    write_file("credentials.txt", "LAPS, cleartext passwords and credential hints",
               [o for o in objects if "creds" in o.tags])
    write_file("disabled.txt", "Disabled accounts",
               [o for o in objects if "disabled" in o.tags])
    write_file("stale.txt", "Old passwords or no recent logon",
               [o for o in objects if "stale" in o.tags])
    write_file("adcs.txt", "AD CS certificate templates with ESC signals",
               [o for o in objects if "adcs" in o.tags])

    write_list("usernames.txt", user_names(objects))
    write_list("hostnames.txt", computer_names(objects))
    write_list("dcs.txt", computer_names(objects, "dc"))
    write_list("da-members.txt", da_members(objects))
    write_list("kerberoast-users.txt",
               user_names(objects, "kerberoastable", enabled_only=True))
    write_list("asrep-users.txt", user_names(objects, "asrep", enabled_only=True))
    write_list("spray-users.txt", user_names(objects, enabled_only=True))
    write_list("password-candidates.txt",
               list(dict.fromkeys(h["candidate"] for h in password_hints(objects))))

    write_doc("attack-paths.txt", "Membership paths to tier-0 groups",
              [" -> ".join(chain) for _, chain in attack_paths(objects, limit=0)])
    posture = collect_posture([o.entry for o in objects])
    write_doc("domain-posture.txt", "Domain password, lockout and trust posture",
              [f"{label}: {value}" for label, value in posture_rows(posture)])

    dot = render_dot(objects)
    if dot:
        with open(os.path.join(outdir, "attack-graph.dot"), "w",
                  encoding="utf-8") as handle:
            handle.write(dot)
        written.append(("attack-graph.dot", 1))

    with open(os.path.join(outdir, "playbook.md"), "w", encoding="utf-8") as handle:
        handle.write(render_playbook(objects, sources, posture))
    written.append(("playbook.md", 1))

    with open(os.path.join(outdir, "tiny.json"), "w", encoding="utf-8") as handle:
        json.dump(json_report(objects, sources), handle, indent=2)
    written.append(("tiny.json", len(objects)))

    with open(os.path.join(outdir, "report.md"), "w", encoding="utf-8") as handle:
        handle.write(render_markdown(objects, sources))
    written.append(("report.md", 1))

    counts = tier_counts(objects)
    lines = [f"tiny export · {len(objects)} objects", "", "Pyramid", "-------"]
    for t in range(4):
        lines.append(f"  tier {t} · {TIERS[t][0]:<13} {counts[t]}")
    lines += ["", "Files", "-----"]
    for filename, count in written:
        lines.append(f"  {filename:<26} {count:>6}")
    lines.append(f"  {'README.txt':<26} {1:>6}")
    with open(os.path.join(outdir, "README.txt"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    written.append(("README.txt", 1))
    return written


def json_report(objects: List[Obj], sources: List[str]) -> Dict[str, object]:
    counts = tier_counts(objects)
    return {
        "tool": "tiny",
        "version": __version__,
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "sources": sources,
        "domain": guess_domain([o.entry for o in objects]),
        "counts": {
            "total": len(objects),
            "tiers": {str(t): counts[t] for t in range(4)},
            "kinds": dict(Counter(o.kind for o in objects)),
        },
        "quick_wins": {label: found for label, _, found in quick_wins(objects)},
        "posture": collect_posture([o.entry for o in objects]),
        "objects": [{
            "dn": o.entry.dn,
            "name": o.name,
            "kind": o.kind,
            "score": o.score,
            "tier": o.tier,
            "tier_label": TIERS[o.tier][0],
            "reasons": o.reasons,
            "tags": sorted(o.tags),
            "memberships": [{
                "group": m.group,
                "direct": m.direct,
                "path": m.path,
            } for m in o.memberships],
            "attributes": {k: (v[0] if len(v) == 1 else v)
                           for k, v in o.entry.attrs.items()},
        } for o in objects],
    }
