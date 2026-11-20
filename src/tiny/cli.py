"""Command-line interface for tiny."""

import argparse
import getpass
import glob
import json
import os
import sys
from typing import Optional

from . import __version__
from .ldif import Entry, merge_entries, parse_ldif
from .playbook import render_playbook
from .posture import collect_posture
from .report import export, json_report, render_markdown, render_report, use_color
from .score import score_entries
from .windap import (
    COMPUTER_ATTRS,
    FILTER_ASREP,
    FILTER_COMPUTERS,
    FILTER_CONSTRAINED,
    FILTER_GROUPS,
    FILTER_RBCD,
    FILTER_UNCONSTRAINED,
    FILTER_USER_SPN,
    FILTER_USERS,
    GROUP_ATTRS,
    USER_ATTRS,
    domain_to_base_dn,
    enumerate_query,
)


def read_inputs(paths: list[str]) -> tuple[list[Entry], list[str]]:
    """Read LDIF from files/directories, or stdin when nothing was given."""
    files: list[str] = []
    for path in paths:
        if os.path.isdir(path):
            found = sorted(glob.glob(os.path.join(path, "**", "*.ldif"), recursive=True))
            if not found:
                raise SystemExit(f"tiny: no .ldif files under {path}")
            files.extend(found)
        elif os.path.isfile(path):
            files.append(path)
        else:
            raise SystemExit(f"tiny: no such file or directory: {path}")

    entries: list[Entry] = []
    sources: list[str] = []
    if not files:
        text = sys.stdin.read()
        if not text.strip():
            raise SystemExit("tiny: no input (pass LDIF files, a directory, or pipe stdin)")
        entries.extend(parse_ldif(text))
        sources.append("stdin")
    else:
        for path in files:
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    entries.extend(parse_ldif(handle.read()))
            except OSError as exc:
                raise SystemExit(f"tiny: cannot read {path}: {exc}")
            sources.append(path)
    return merge_entries(entries), sources


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tiny",
        description="Rank LDAP dumps into a crown-jewel pyramid and split them into useful files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  tiny dump.ldif
  tiny dump.ldif -o tiny-out/
  tiny ldapdomaindump/ --all
  ldapsearch -x -b dc=corp,dc=local | tiny
  tiny dump.ldif --json | jq '.objects[:5]'
  tiny --dc-ip 10.10.10.10 --domain corp.local --bind-dn user@corp.local --users --spns -o live-out/
  tiny --dc-ip 10.10.10.10 --domain corp.local --unconstrained --asrep --out enum/
        """,
    )
    parser.add_argument(
        "inputs", nargs="*", metavar="LDIF", help="LDIF files or directories (default: stdin)"
    )
    parser.add_argument(
        "-o", "--out", metavar="DIR", help="export tier/category files, report.md and tiny.json"
    )
    parser.add_argument(
        "--top",
        type=int,
        default=12,
        metavar="N",
        help="priority rows to show, 0 = all (default: 12)",
    )
    parser.add_argument(
        "--all", action="store_true", help="show every object in the priority queue"
    )
    parser.add_argument(
        "--json", action="store_true", help="print the JSON report instead of the terminal report"
    )
    parser.add_argument("--md", metavar="FILE", help="also write a markdown report to FILE")
    parser.add_argument(
        "--playbook", metavar="FILE", help="write an environment-specific attack playbook to FILE"
    )
    parser.add_argument(
        "--brief", action="store_true", help="minimize output (top 5, hide paths/quickwins/posture)"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="show all reasons for each queued object"
    )
    parser.add_argument(
        "--full", action="store_true", help="export every attribute, not just key ones"
    )
    parser.add_argument("--no-color", action="store_true", help="disable colour")
    parser.add_argument(
        "--quiet", action="store_true", help="suppress the terminal report (still writes files)"
    )
    parser.add_argument("--version", action="version", version=f"tiny {__version__}")

    # Windapsearch-style live enumeration
    parser.add_argument("--dc-ip", help="Domain Controller IP for live LDAP enumeration")
    parser.add_argument("--domain", help="Domain FQDN (e.g. corp.local) for base DN generation")
    parser.add_argument("--base-dn", help="LDAP base DN (overrides --domain)")
    parser.add_argument("--bind-dn", help="LDAP bind DN for enumeration")
    parser.add_argument("--bind-pass", help="LDAP bind password (will prompt if omitted)")
    parser.add_argument("--users", action="store_true", help="Enumerate AD Users (windapsearch -U)")
    parser.add_argument(
        "--groups", action="store_true", help="Enumerate AD Groups (windapsearch -G)"
    )
    parser.add_argument(
        "--computers", action="store_true", help="Enumerate AD Computers (windapsearch -C)"
    )
    parser.add_argument(
        "--spns", action="store_true", help="Enumerate users with SPNs (kerberoastable)"
    )
    parser.add_argument(
        "--unconstrained", action="store_true", help="Enumerate unconstrained delegation accounts"
    )
    parser.add_argument(
        "--asrep",
        action="store_true",
        help="Enumerate AS-REP roastable accounts (DONT_REQ_PREAUTH)",
    )
    parser.add_argument(
        "--constrained", action="store_true", help="Enumerate constrained delegation candidates"
    )
    parser.add_argument(
        "--rbcd", action="store_true", help="Enumerate resource-based constrained delegation"
    )
    parser.add_argument(
        "--da", action="store_true", help="Enumerate members of Domain Admins (nested)"
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # Helper to determine if enumeration mode is active
    enum_flags = [
        args.users,
        args.groups,
        args.computers,
        args.spns,
        args.unconstrained,
        args.asrep,
        args.constrained,
        args.rbcd,
        args.da,
    ]
    doing_enum = any(enum_flags)
    entries: list[Entry] = []
    sources: list[str] = []

    if doing_enum:
        if not args.dc_ip:
            print("tiny: --dc-ip is required for live enumeration", file=sys.stderr)
            return 2
        base_dn = args.base_dn
        if not base_dn:
            if not args.domain:
                print("tiny: --domain or --base-dn is required for enumeration", file=sys.stderr)
                return 2
            base_dn = domain_to_base_dn(args.domain)

        bind_dn = args.bind_dn
        bind_pass = args.bind_pass
        if bind_dn and not bind_pass:
            try:
                bind_pass = getpass.getpass("LDAP password: ")
            except Exception:
                bind_pass = ""

        queries = []
        if args.users:
            queries.append((FILTER_USERS, USER_ATTRS, "users"))
        if args.groups:
            queries.append((FILTER_GROUPS, GROUP_ATTRS, "groups"))
        if args.computers:
            queries.append((FILTER_COMPUTERS, COMPUTER_ATTRS, "computers"))
        if args.spns:
            queries.append((FILTER_USER_SPN, USER_ATTRS, "spns"))
        if args.unconstrained:
            queries.append((FILTER_UNCONSTRAINED, USER_ATTRS, "unconstrained"))
        if args.asrep:
            queries.append((FILTER_ASREP, USER_ATTRS, "asrep"))
        if args.constrained:
            queries.append((FILTER_CONSTRAINED, USER_ATTRS, "constrained"))
        if args.rbcd:
            queries.append((FILTER_RBCD, USER_ATTRS, "rbcd"))
        if args.da:
            # Domain Admins nested – use memberOf chain
            # Build filter via windapsearch logic: we need base DN to construct group DN
            # Assume Domain Admins is in CN=Users, adjust if needed
            # For simplicity, require user to provide group DN via filter; we provide a default
            da_filter = f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,{base_dn}))"
            queries.append((da_filter, USER_ATTRS, "da"))

        # Execute queries and merge results
        all_entries: list[Entry] = []
        all_sources: list[str] = []
        for ldap_filter, attrs, label in queries:
            try:
                ldif_text = enumerate_query(
                    args.dc_ip, bind_dn, bind_pass, base_dn, ldap_filter, attrs
                )
                parsed = parse_ldif(ldif_text)
                all_entries.extend(parsed)
                all_sources.append(f"ldap:{label}@{args.dc_ip}")
            except Exception as exc:
                print(f"tiny: enumeration {label} failed: {exc}", file=sys.stderr)
                return 2
        entries = merge_entries(all_entries)
        sources = all_sources
    else:
        entries, sources = read_inputs(args.inputs)

    if not entries:
        print("tiny: no LDAP entries found", file=sys.stderr)
        return 2

    objects = score_entries(entries)
    color = use_color(args.no_color)

    if args.json:
        print(json.dumps(json_report(objects, sources), indent=2))
    elif not args.quiet:
        show_all = args.all or args.top <= 0
        top_n = 5 if args.brief else max(args.top, 0)
        print(
            render_report(
                objects,
                sources,
                color,
                top=top_n,
                show_all=show_all,
                brief=args.brief,
                verbose=args.verbose,
            )
        )

    if args.out:
        written = export(objects, args.out, sources, full=args.full)
        if not args.quiet:
            total = sum(count for _, count in written)
            print(
                f"\nWrote {len(written)} files to {args.out} ({total} records incl. summary files)"
            )
    if args.md:
        with open(args.md, "w", encoding="utf-8") as handle:
            handle.write(render_markdown(objects, sources))
        if not args.quiet:
            print(f"Wrote markdown report to {args.md}")
    if args.playbook:
        posture = collect_posture([o.entry for o in objects])
        with open(args.playbook, "w", encoding="utf-8") as handle:
            handle.write(render_playbook(objects, sources, posture))
        if not args.quiet:
            print(f"Wrote attack playbook to {args.playbook}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
