"""Suzzy-inspired ANSI banner for tiny."""

from __future__ import annotations

import os
import platform
import re
import shutil
import sys

from . import __version__


# ANSI colour helpers
def _term_truecolor() -> bool:
    ct = os.environ.get("COLORTERM", "")
    return "truecolor" in ct or "24bit" in ct


TRUE_COLOR = _term_truecolor()


def _rgb_to_256(r: int, g: int, b: int) -> int:
    return 16 + 36 * (r * 5 // 255) + 6 * (g * 5 // 255) + (b * 5 // 255)


def _fg_rgb(r: int, g: int, b: int) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return ""
    if TRUE_COLOR:
        return f"\033[38;2;{r};{g};{b}m"
    idx = _rgb_to_256(r, g, b)
    return f"\033[38;5;{idx}m"


def _reset() -> str:
    return "\033[0m" if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else ""


def _dim(text: str) -> str:
    return (
        f"\033[2m{text}\033[22m" if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else text
    )


# Suzzy gradient cyan -> red -> amber
def _grad_rgb(p: int) -> tuple[int, int, int]:
    if p <= 70:
        r = 255 * p // 70
        g = 240 - 181 * p // 70
        b = 255 - 196 * p // 70
    else:
        q = p - 70
        r = 255
        g = 59 + 120 * q // 30
        b = 59 + 12 * q // 30
    return r, g, b


# Tiny ANSI Shadow logo — T I N Y
LOGO = [
    "████████╗  ██╗ ██╗  ███╗   ██╗  ██╗   ██╗",
    "╚══██╔══╝  ╚███╔╝   ████╗  ██║  ╚██╗ ██╔╝",
    "   ██║      ███╔╝   ██╔██╗ ██║   ╚████╔╝ ",
    "   ██║      ███╔╝   ██║╚██╗██║    ╚██╔╝  ",
    "   ██║     ███╔╝    ██║ ╚████║     ██║   ",
    "   ╚═╝     ╚══╝     ╚═╝  ╚═══╝     ╚═╝   ",
]


def _logo_row(line: str) -> str:
    out = []
    # gradient per character position
    for i, ch in enumerate(line):
        if ch == " ":
            out.append(" ")
            continue
        # progress 0-100 across characters ignoring spaces
        # approximate with i
        p = min(100, max(0, int(i * 100 / max(len(line), 1))))
        r, g, b = _grad_rgb(p)
        # shadow: non-block chars dimmed 42%
        if ch != "█":
            r = int(r * 0.42)
            g = int(g * 0.42)
            b = int(b * 0.42)
        col = _fg_rgb(r, g, b)
        out.append(f"{col}{ch}{_reset()}")
    return "".join(out)


def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def _frame_line(
    content: str, inner: int, left: str = "│", right: str = "│", color: str = ""
) -> str:
    visible = len(_strip_ansi(content))
    pad = max(inner - visible, 0)
    line = f"{color}{left}{_reset()}{content}{' ' * pad}{color}{right}{_reset()}"
    return line


def render_banner(
    domain: str | None, objects: int, crowns: int, color: bool = True, width: int | None = None
) -> list[str]:
    # Quotes
    top_quote = '  "i had strings, now I\'m free"'
    bottom_quote = '  "worrying is worshipping the problem"'

    cols = width or shutil.get_terminal_size((100, 24)).columns
    cols = max(80, min(140, cols))
    inner = cols - 2
    # Keep banner reasonably sized
    if inner < 70:
        # Mini mode
        lines = [
            _dim(top_quote),
            "",
            f"  TINY · LDAP TRIAGE  {objects} objects · {crowns} crowns · {domain or '?'}",
            _dim(bottom_quote),
        ]
        return lines

    version = __version__
    user = os.environ.get("USER") or "user"
    host = platform.node().split(".")[0]
    kern = platform.release()[:24]

    # Frame labels
    top_left = "─[ 0x ]"
    top_right = f"[ v{version} ]─"
    bottom_left = f"─[ ● {user[:16]}@{host[:16]} ]"
    bottom_right = f"[ {kern} ]─"

    # Build frame edges
    def frame_edge(c1: str, c2: str, left: str, right: str) -> str:
        inner_fill = inner - len(_strip_ansi(left)) - len(_strip_ansi(right))
        dashes = "─" * max(inner_fill, 0)
        return f"{c1}{left}{dashes}{right}{c2}"

    # Gradient bar
    bar_len = min(40, inner - 10)
    bar_chars = []
    for i in range(bar_len):
        p = int(i * 100 / max(bar_len - 1, 1))
        r, g, b = _grad_rgb(p)
        bar_chars.append(f"{_fg_rgb(r, g, b)}━{_reset()}")
    bar = "".join(bar_chars)

    lines = []
    lines.append(_dim(top_quote))
    lines.append("")

    # Top border
    lines.append(frame_edge("╭", "╮", top_left, top_right))

    # Empty spacer
    lines.append(_frame_line("", inner))

    # Logo + content
    # We'll render logo 6 rows, right column empty for simplicity
    logo_indent = 3
    for ln in LOGO:
        logo = _logo_row(ln)
        padded = " " * logo_indent + logo
        lines.append(_frame_line(padded, inner))

    lines.append(_frame_line("", inner))

    # Role line
    role = "0x  LDAP   TRIAGE   /   TINY"
    lines.append(_frame_line("   " + role, inner))

    lines.append(_frame_line("", inner))

    # Stats line
    meta = f"◈ {objects} objects  ·  {crowns} crown jewels  ·  {domain or 'unknown'}"
    lines.append(_frame_line("   " + meta, inner))

    # Attribution
    attr = "● from TINY ◈ by 0xClumzZy"
    lines.append(_frame_line("   " + attr, inner))

    # Tagline
    tag = _dim("the engine with a name on it")
    lines.append(_frame_line("   " + tag, inner))

    lines.append(_frame_line("", inner))
    lines.append(_frame_line("   " + bar, inner))
    lines.append(_frame_line("", inner))

    # Bottom border
    lines.append(frame_edge("╰", "╯", bottom_left, bottom_right))

    lines.append("")
    lines.append(_dim(bottom_quote))
    return lines
