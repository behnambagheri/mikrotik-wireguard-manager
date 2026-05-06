#!/usr/bin/env python3
import time
from typing import Any, Optional


def now_ts() -> int:
    return int(time.time())


def bytes_h(n: int) -> str:
    if n < 0:
        n = 0
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    for u in units:
        if x < 1024.0 or u == units[-1]:
            return f"{x:.1f} {u}" if u != "B" else f"{int(x)} B"
        x /= 1024.0
    return f"{n} B"


def bps_h(n: float) -> str:
    if n < 0:
        n = 0.0
    units = [(1e9, "Gbps"), (1e6, "Mbps"), (1e3, "Kbps")]
    for m, u in units:
        if n >= m:
            return f"{n / m:.2f} {u}"
    return f"{n:.0f} bps"


def mbps_to_bps(mbps: float) -> int:
    return int(mbps * 1_000_000)


def gb_to_bytes(gb: float) -> int:
    return int(gb * 1024 * 1024 * 1024)


def period_to_seconds(label: str) -> int:
    s = (label or "").strip().lower()
    if s in ("hour", "1h", "h"):
        return 3600
    if s in ("day", "1d", "d"):
        return 86400
    if s in ("week", "1w", "w"):
        return 7 * 86400
    return 0


def parse_period_input(text: str) -> int:
    s = (text or "").strip().lower()
    if s in ("", "0", "none", "off"):
        return 0
    fixed = period_to_seconds(s)
    if fixed > 0:
        return fixed
    if s.endswith("s"):
        return int(float(s[:-1]))
    if s.endswith("m"):
        return int(float(s[:-1]) * 60)
    if s.endswith("h"):
        return int(float(s[:-1]) * 3600)
    if s.endswith("d"):
        return int(float(s[:-1]) * 86400)
    if s.endswith("w"):
        return int(float(s[:-1]) * 7 * 86400)
    # Plain number is treated as hours to avoid accidental tiny windows.
    return int(float(s) * 3600)


def first_ip(allowed: str) -> str:
    s = (allowed or "").split(",", 1)[0].strip()
    if "/" in s:
        s = s.split("/", 1)[0]
    return s


def parse_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() == "true"


def safe_id(peer_id: str) -> str:
    out = []
    for ch in peer_id:
        if ch.isalnum():
            out.append(ch.lower())
    return "".join(out) or "peer"


def slug(text: str, max_len: int = 24) -> str:
    out = []
    prev_dash = False
    for ch in (text or "").strip().lower():
        if ch.isalnum():
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    s = "".join(out).strip("-")
    if not s:
        s = "peer"
    return s[:max_len].strip("-") or "peer"


def ros_q(text: str) -> str:
    s = str(text or "")
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def pdf_escape_text(text: str) -> str:
    s = str(text or "")
    s = s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    # Built-in Helvetica encoding is Latin-1-like; replace unsupported chars.
    return s.encode("latin-1", "replace").decode("latin-1")


def parse_ros_duration_to_seconds(text: str) -> Optional[int]:
    s = (text or "").strip().lower()
    if not s:
        return None
    total = 0
    num = ""
    units = {"w": 7 * 86400, "d": 86400, "h": 3600, "m": 60, "s": 1}
    for ch in s:
        if ch.isdigit():
            num += ch
            continue
        if ch in units and num:
            total += int(num) * units[ch]
            num = ""
        else:
            return None
    if num:
        return None
    return total
