#!/usr/bin/env python3
import curses
import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib import error, parse, request

STATE_FILE = os.environ.get("WG_TUI_STATE_FILE", ".wg_tui_state.json")
DEFAULT_POLL_SECONDS = 2.0
MARKER_PREFIX = "wg-tui"
CFG_DNS = "100.100.100.100, 100.100.100.101"
CFG_ALLOWED_IPS = "0.0.0.0/0"
CFG_ENDPOINT_HOST = "77.74.202.60"
CFG_KEEPALIVE = "25"


def env_file_path() -> str:
    return os.environ.get("WG_TUI_ENV_FILE", ".env")


def load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


def parse_router_profiles(path: str = ".env") -> Dict[str, Dict[str, str]]:
    # Parse profile-style .env lines:
    # Name={ key=value, key=value, ... }
    # We split on commas that start a new key to preserve csv-like values.
    profiles: Dict[str, Dict[str, str]] = {}
    if not os.path.exists(path):
        return profiles
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, rest = line.split("=", 1)
            name = name.strip()
            rest = rest.strip()
            if not (rest.startswith("{") and rest.endswith("}")):
                continue
            inner = rest[1:-1].strip()
            if not inner:
                continue
            chunks = re.split(r",\s*(?=[a-zA-Z_][a-zA-Z0-9_]*\s*=)", inner)
            kv: Dict[str, str] = {}
            for c in chunks:
                if "=" not in c:
                    continue
                k, v = c.split("=", 1)
                k = k.strip().lower()
                v = v.strip().strip('"').strip("'")
                if k:
                    kv[k] = v
            if kv:
                profiles[name] = kv
    return profiles


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


@dataclass
class PeerView:
    peer_id: str
    interface: str
    ip: str
    comment: str
    rx: int
    tx: int
    disabled: bool
    last_handshake: str = ""
    up_speed_bps: float = 0.0
    down_speed_bps: float = 0.0


class RouterOSClient:
    def __init__(self, host: str, user: str, password: str, use_https: bool = False, timeout_sec: float = 30.0):
        self.host = host
        self.user = user
        self.password = password
        scheme = "https" if use_https else "http"
        self.base = f"{scheme}://{host}/rest"
        self.timeout_sec = timeout_sec
        creds = f"{user}:{password}".encode("utf-8")
        import base64

        self.auth_header = "Basic " + base64.b64encode(creds).decode("ascii")
        self.ssl_ctx = ssl._create_unverified_context()

    @staticmethod
    def _rid(raw: str) -> str:
        # RouterOS resource IDs contain "*" and must keep it in the path.
        return parse.quote(raw, safe="*")

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        # Thin REST wrapper with consistent auth + JSON behavior.
        if not path.startswith("/"):
            path = "/" + path
        url = self.base + path
        data = None
        headers = {
            "Authorization": self.auth_header,
            "Accept": "application/json",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(url, data=data, method=method, headers=headers)
        try:
            if self.base.startswith("https://"):
                resp = request.urlopen(req, timeout=self.timeout_sec, context=self.ssl_ctx)
            else:
                resp = request.urlopen(req, timeout=self.timeout_sec)
            with resp:
                raw = resp.read().decode("utf-8")
                if not raw:
                    return None
                return json.loads(raw)
        except error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8")
            except Exception:
                pass
            raise RuntimeError(f"HTTP {e.code} {method} {path}: {body}") from e
        except Exception as e:
            raise RuntimeError(f"Request failed {method} {path}: {e}") from e

    def list_peers(self) -> List[PeerView]:
        rows = self._request("GET", "/interface/wireguard/peers") or []
        peers: List[PeerView] = []
        for r in rows:
            peers.append(
                PeerView(
                    peer_id=str(r.get(".id", "")),
                    interface=str(r.get("interface", "")),
                    ip=first_ip(str(r.get("allowed-address", ""))),
                    comment=str(r.get("comment", "")),
                    rx=int(r.get("rx", 0) or 0),
                    tx=int(r.get("tx", 0) or 0),
                    disabled=parse_bool(r.get("disabled", False)),
                    last_handshake=str(r.get("last-handshake", "")),
                )
            )
        peers.sort(key=lambda p: (p.interface, p.comment.lower(), p.ip))
        return peers

    def list_queue_tree(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/queue/tree") or []

    def list_mangle(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/ip/firewall/mangle") or []

    def list_filter(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/ip/firewall/filter") or []

    def list_wireguard_interfaces(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/interface/wireguard") or []

    def list_ip_addresses(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/ip/address") or []

    def list_scheduler(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/system/scheduler") or []

    def set_peer_disabled(self, peer_id: str, disabled: bool) -> None:
        pid = self._rid(peer_id)
        self._request("PATCH", f"/interface/wireguard/peers/{pid}", {"disabled": "true" if disabled else "false"})

    def create_peer(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/interface/wireguard/peers", payload)

    def delete_peer(self, peer_id: str) -> None:
        self._request("DELETE", f"/interface/wireguard/peers/{self._rid(peer_id)}")

    def create_queue(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/queue/tree", payload)

    def patch_queue(self, qid: str, payload: Dict[str, Any]) -> None:
        self._request("PATCH", f"/queue/tree/{self._rid(qid)}", payload)

    def delete_queue(self, qid: str) -> None:
        self._request("DELETE", f"/queue/tree/{self._rid(qid)}")

    def create_mangle(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/ip/firewall/mangle", payload)

    def patch_mangle(self, rid: str, payload: Dict[str, Any]) -> None:
        self._request("PATCH", f"/ip/firewall/mangle/{self._rid(rid)}", payload)

    def delete_mangle(self, rid: str) -> None:
        self._request("DELETE", f"/ip/firewall/mangle/{self._rid(rid)}")

    def create_filter(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/ip/firewall/filter", payload)

    def patch_filter(self, rid: str, payload: Dict[str, Any]) -> None:
        self._request("PATCH", f"/ip/firewall/filter/{self._rid(rid)}", payload)

    def delete_filter(self, rid: str) -> None:
        self._request("DELETE", f"/ip/firewall/filter/{self._rid(rid)}")

    def create_scheduler(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/system/scheduler", payload)

    def patch_scheduler(self, rid: str, payload: Dict[str, Any]) -> None:
        self._request("PATCH", f"/system/scheduler/{self._rid(rid)}", payload)

    def delete_scheduler(self, rid: str) -> None:
        self._request("DELETE", f"/system/scheduler/{self._rid(rid)}")


class StateStore:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.environ.get("WG_TUI_STATE_FILE", STATE_FILE)
        self.data: Dict[str, Any] = {"peers": {}}
        self.load()

    def load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
            if "peers" not in self.data:
                self.data = {"peers": {}}
        except Exception:
            self.data = {"peers": {}}

    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def peer(self, pid: str) -> Dict[str, Any]:
        peers = self.data.setdefault("peers", {})
        return peers.setdefault(pid, {})


class App:
    def __init__(self, stdscr: Any):
        ef = env_file_path()
        load_dotenv(ef)
        self.profiles = parse_router_profiles(ef)
        self.profile_name = ""
        self.host = ""
        self.user = ""
        self.password = ""
        self.use_https = False
        self.timeout_sec = 30.0
        self.cfg_dns = CFG_DNS
        self.cfg_endpoint_host = CFG_ENDPOINT_HOST

        self.stdscr = stdscr
        self.client: Optional[RouterOSClient] = None
        self.state = StateStore()

        self.selected = 0
        self.top = 0
        self.view_mode = "dashboard"
        self.peers: List[PeerView] = []
        self.router_resource: Dict[str, Any] = {}
        self.interfaces: List[Dict[str, Any]] = []
        self.last_sample: Dict[str, Tuple[int, int, float]] = {}
        self.iface_last_sample: Dict[str, Tuple[int, int, float]] = {}
        self.iface_speed: Dict[str, Tuple[float, float]] = {}
        self.iface_baseline: Dict[str, Tuple[int, int]] = {}
        self.dash_window_seconds = 3600
        self.dash_window_started_at = now_ts()
        self.clients_disabled_only = False
        self.last_poll_latency_ms = 0.0
        self.last_poll_ok_ts = 0
        self.history_cpu: deque[float] = deque(maxlen=120)
        self.history_bw: deque[float] = deque(maxlen=120)
        self.diagnostics: List[Dict[str, str]] = []
        self.diagnostics_last_run = 0
        self.last_refresh_at = 0.0
        self.status = "Ready"
        self.error = ""
        self.filter_query = ""
        self.sort_key = "comment"
        self.sort_desc = False
        self.visible_peers: List[PeerView] = []
        self.colors_ready = False
        self.remote_synced = False
        self.c_title = curses.A_BOLD
        self.c_header = curses.A_BOLD
        self.c_selected = curses.A_REVERSE
        self.c_disabled = curses.A_DIM
        self.c_disabled_selected = curses.A_REVERSE
        self.c_normal = curses.A_NORMAL
        self.c_status = curses.A_DIM
        self.c_error = curses.A_BOLD
        self.c_hint = curses.A_DIM

    def run(self) -> None:
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        self.stdscr.timeout(200)
        self.init_colors()
        self.bootstrap_router_config()

        self.refresh_data(force=True)

        while True:
            now = time.time()
            if now - self.last_refresh_at >= DEFAULT_POLL_SECONDS:
                self.refresh_data(force=False)

            h, _ = self.stdscr.getmaxyx()
            table_rows = max(1, h - 9)
            self.visible_peers = self.build_visible_peers()
            self.normalize_selection(table_rows)
            if self.view_mode == "dashboard":
                self.draw_dashboard()
            elif self.view_mode == "diagnostics":
                self.draw_diagnostics()
            else:
                self.draw_main()
            ch = self.stdscr.getch()
            if ch == -1:
                continue
            if ch in (ord("?"),):
                self.show_help(self.view_mode)
                continue
            if ch in (ord("q"), 27):
                break
            if self.view_mode == "dashboard":
                if ch in (ord("l"), ord("c"), ord("\n"), 10, 13):
                    self.view_mode = "clients"
                elif ch in (ord("g"),):
                    self.view_mode = "diagnostics"
                    self.run_connection_diagnostics()
                elif ch in (ord("p"),):
                    order = [0, 3600, 86400, 7 * 86400]
                    try:
                        idx = order.index(self.dash_window_seconds)
                    except ValueError:
                        idx = 0
                    self.dash_window_seconds = order[(idx + 1) % len(order)]
                    self.reset_dashboard_window(now)
                    self.status = f"Dashboard traffic window: {self.dashboard_window_h()}"
                elif ch in (ord("w"),):
                    self.reset_dashboard_window(now)
                    self.status = "Dashboard window reset"
                elif ch in (ord("i"),):
                    ifaces = [str(i.get("name", "")) for i in self.interfaces if str(i.get("name", ""))]
                    idx = self.choose_from_dialog("Open Clients For Interface", ifaces)
                    if idx is not None:
                        self.filter_query = ifaces[idx]
                        self.clients_disabled_only = False
                        self.view_mode = "clients"
                        self.selected = 0
                        self.top = 0
                        self.status = f"Client list filtered by interface: {ifaces[idx]}"
                elif ch in (ord("u"),):
                    self.clients_disabled_only = True
                    self.view_mode = "clients"
                    self.selected = 0
                    self.top = 0
                    self.status = "Client list: disabled-only"
                elif ch in (ord("j"),):
                    try:
                        path = self.export_dashboard_snapshot(csv_mode=False)
                        self.status = f"Dashboard exported: {path}"
                    except Exception as e:
                        self.error = f"Export failed: {e}"
                elif ch in (ord("v"),):
                    try:
                        path = self.export_dashboard_snapshot(csv_mode=True)
                        self.status = f"Dashboard exported: {path}"
                    except Exception as e:
                        self.error = f"Export failed: {e}"
                elif ch in (ord("r"),):
                    self.refresh_data(force=True)
                continue
            if self.view_mode == "diagnostics":
                if ch in (ord("b"), ord("h")):
                    self.view_mode = "dashboard"
                elif ch in (ord("r"),):
                    self.run_connection_diagnostics()
                continue
            if ch in (curses.KEY_DOWN, ord("j")):
                if self.visible_peers:
                    self.selected = min(self.selected + 1, len(self.visible_peers) - 1)
                    self.normalize_selection(table_rows)
            elif ch in (curses.KEY_UP, ord("k")):
                if self.visible_peers:
                    self.selected = max(self.selected - 1, 0)
                    self.normalize_selection(table_rows)
            elif ch in (ord("r"),):
                self.refresh_data(force=True)
            elif ch in (ord("o"),):
                order = ["comment", "ip", "interface", "down_used", "up_used", "down_speed", "up_speed", "state"]
                idx = order.index(self.sort_key) if self.sort_key in order else 0
                self.sort_key = order[(idx + 1) % len(order)]
                self.status = f"Sort by {self.sort_key} ({'desc' if self.sort_desc else 'asc'})"
            elif ch in (ord("O"),):
                self.sort_desc = not self.sort_desc
                self.status = f"Sort direction {'desc' if self.sort_desc else 'asc'}"
            elif ch in (ord("/"), ord("f")):
                s = self.prompt("Search/filter (comment/ip/interface/id), empty=clear: ", self.filter_query)
                if s is not None:
                    self.filter_query = s.strip()
                    self.selected = 0
                    self.top = 0
                    self.status = f"Filter: {self.filter_query or 'none'}"
            elif ch in (ord("u"),):
                self.clients_disabled_only = not self.clients_disabled_only
                self.selected = 0
                self.top = 0
                self.status = f"Disabled-only filter: {'on' if self.clients_disabled_only else 'off'}"
            elif ch in (ord("e"),):
                if self.visible_peers:
                    self.main_enable_disable(self.visible_peers[self.selected], enabled=True)
            elif ch in (ord("d"),):
                if self.visible_peers:
                    self.main_enable_disable(self.visible_peers[self.selected], enabled=False)
            elif ch in (ord("x"),):
                if self.visible_peers:
                    self.main_delete_peer(self.visible_peers[self.selected])
            elif ch in (ord("a"),):
                self.main_add_peer()
            elif ch in (ord("b"), ord("h")):
                self.view_mode = "dashboard"
            elif ch in (ord("\n"), curses.KEY_ENTER, 10, 13):
                if self.visible_peers:
                    self.user_menu(self.visible_peers[self.selected])
                    self.refresh_data(force=True)

    def show_help(self, context: str) -> None:
        # Centralized key-map help so UI hints stay consistent with behavior.
        sections = [
            "WireGuard Users TUI Help",
            "",
            "Global:",
            "  ?            Show this help",
            "  q / Esc      Quit app",
            "  r            Refresh now",
            "",
            "Dashboard:",
            "  l / Enter    Open client list",
            "  g            Open connection diagnostics",
            "  p            Cycle interface traffic window (off/1h/1d/1w)",
            "  w            Reset dashboard window baseline now",
            "  i            Open client list filtered by interface",
            "  u            Open client list with disabled-only filter",
            "  j            Export dashboard snapshot JSON",
            "  v            Export dashboard snapshot CSV",
            "",
            "Client List:",
            "  j/k, arrows  Move selection",
            "  o            Cycle sort column",
            "  O            Toggle sort direction",
            "  / or f       Search/filter clients",
            "  u            Toggle disabled-only filter",
            "  a            Add client (wizard)",
            "  e / d        Enable / disable selected client",
            "  x            Delete selected client (with confirm)",
            "  Enter        Open selected client details",
            "  b            Back to dashboard",
            "",
            "Client Details:",
            "  z            Reset usage baseline (since-now)",
            "  t            Set traffic policy (quota/period/mode)",
            "  s            Set normal speed limits",
            "  e / d        Enable / disable peer",
            "  v            Realtime speed view",
            "  x            Clear limits and policies",
            "  b            Back to client list",
            "",
            "Add Client Wizard:",
            "  - Pick interface",
            "  - Suggested free IP is prefilled (Enter accepts it)",
            "  - Client keypair generated automatically",
            "  - Config viewer: c=copy, s=save, q=close",
            "",
            "Persistence and Automation:",
            "  - Local state file stores baselines/limits",
            "  - Router schedulers enforce quota/period even when TUI is closed",
            "",
            f"Current screen: {context}",
        ]
        top = 0
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self.put(0, 0, "[ Help ]".ljust(w), self.c_title)
            self.put(1, 0, ("-" * max(1, w))[:w], self.c_hint)
            rows = max(1, h - 4)
            shown = sections[top : top + rows]
            for i, ln in enumerate(shown):
                attr = self.c_header if ln.endswith(":") else self.c_normal
                self.put(2 + i, 0, self._fit(ln, w), attr)
            self.put(h - 2, 0, ("-" * max(1, w))[:w], self.c_hint)
            self.put(h - 1, 0, "j/k or arrows scroll | ? help | q/esc/enter close".ljust(w), self.c_header)
            self.stdscr.refresh()
            ch = self.stdscr.getch()
            if ch in (ord("q"), 27, 10, 13, curses.KEY_ENTER):
                return
            if ch in (ord("j"), curses.KEY_DOWN):
                top = min(max(0, len(sections) - rows), top + 1)
            elif ch in (ord("k"), curses.KEY_UP):
                top = max(0, top - 1)

    def bootstrap_router_config(self) -> None:
        # Multi-router profile mode from .env:
        # profile={user=...,password=...,router_ip=...,endpoint_ip=...,dns_servers=...}
        if self.profiles:
            names = sorted(self.profiles.keys())
            rows = []
            for n in names:
                p = self.profiles[n]
                rows.append(
                    f"{n} | {p.get('router_ip','?')} | user:{p.get('user','?')} | endpoint:{p.get('endpoint_ip', CFG_ENDPOINT_HOST)}"
                )
            idx = self.choose_from_dialog("Select Router Profile", rows)
            if idx is None:
                raise RuntimeError("No router selected")
            selected = names[idx]
            p = self.profiles[selected]
            host = p.get("router_ip", "").strip()
            user = p.get("user", "").strip()
            password = p.get("password", "").strip().strip('"').strip("'")
            if not host or not user or not password:
                raise RuntimeError(f"Profile '{selected}' missing router_ip/user/password")
            self.profile_name = selected
            self.host = host
            self.user = user
            self.password = password
            self.use_https = str(p.get("use_https", "false")).lower() == "true"
            self.timeout_sec = float(p.get("timeout_sec", "30") or "30")
            self.cfg_dns = p.get("dns_servers", CFG_DNS).strip() or CFG_DNS
            self.cfg_endpoint_host = p.get("endpoint_ip", CFG_ENDPOINT_HOST).strip() or CFG_ENDPOINT_HOST
            self.client = RouterOSClient(self.host, self.user, self.password, use_https=self.use_https, timeout_sec=self.timeout_sec)
            self.status = f"Connected profile: {self.profile_name} ({self.host})"
            return

        # Backward-compatible single-router mode
        host = os.environ.get("ROUTER_IP", "").strip()
        user = os.environ.get("ROUTER_USER", "").strip()
        password = os.environ.get("ROUTER_PASS", "").strip().strip('"').strip("'")
        use_https = os.environ.get("ROUTER_USE_HTTPS", "false").lower() == "true"
        timeout_sec = float(os.environ.get("ROUTER_TIMEOUT_SEC", "30") or "30")
        if not host or not user or not password:
            raise RuntimeError("Missing router config. Use profiles in .env or ROUTER_IP/ROUTER_USER/ROUTER_PASS")
        self.profile_name = "default"
        self.host = host
        self.user = user
        self.password = password
        self.use_https = use_https
        self.timeout_sec = timeout_sec
        self.cfg_dns = os.environ.get("DNS_SERVERS", CFG_DNS).strip() or CFG_DNS
        self.cfg_endpoint_host = os.environ.get("ENDPOINT_IP", CFG_ENDPOINT_HOST).strip() or CFG_ENDPOINT_HOST
        self.client = RouterOSClient(self.host, self.user, self.password, use_https=self.use_https, timeout_sec=self.timeout_sec)

    def init_colors(self) -> None:
        if not curses.has_colors():
            return
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)    # title
        curses.init_pair(2, curses.COLOR_YELLOW, -1)  # header
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_CYAN)  # selected row
        curses.init_pair(4, curses.COLOR_GREEN, -1)   # status
        curses.init_pair(5, curses.COLOR_RED, -1)     # error
        curses.init_pair(6, curses.COLOR_CYAN, -1)    # hint
        curses.init_pair(7, curses.COLOR_RED, -1)     # disabled
        curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_RED) # disabled selected

        self.c_title = curses.color_pair(1) | curses.A_BOLD
        self.c_header = curses.color_pair(2) | curses.A_BOLD
        self.c_selected = curses.color_pair(3) | curses.A_BOLD
        self.c_disabled = curses.color_pair(7) | curses.A_BOLD
        self.c_disabled_selected = curses.color_pair(8) | curses.A_BOLD
        self.c_normal = curses.A_NORMAL
        self.c_status = curses.color_pair(4) | curses.A_BOLD
        self.c_error = curses.color_pair(5) | curses.A_BOLD
        self.c_hint = curses.color_pair(6) | curses.A_DIM
        self.colors_ready = True

    def put(self, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = self.stdscr.getmaxyx()
        if h <= 0 or w <= 0:
            return
        if y < 0 or y >= h or x >= w:
            return
        x = max(0, x)
        avail = w - x
        if avail <= 0:
            return
        s = text if isinstance(text, str) else str(text)
        if len(s) > avail:
            s = s[:avail]
        try:
            self.stdscr.addnstr(y, x, s, avail, attr)
        except curses.error:
            pass

    @staticmethod
    def _fit(text: str, width: int) -> str:
        s = str(text or "")
        if width <= 0:
            return ""
        if len(s) <= width:
            return s.ljust(width)
        if width <= 1:
            return s[:width]
        return (s[: width - 1] + "…")

    def build_visible_peers(self) -> List[PeerView]:
        q = self.filter_query.strip().lower()
        out: List[PeerView] = []
        for p in self.peers:
            if self.clients_disabled_only and not p.disabled:
                continue
            if q:
                blob = f"{p.comment} {p.ip} {p.interface} {p.peer_id}".lower()
                if q not in blob:
                    continue
            out.append(p)

        def sort_value(p: PeerView) -> Any:
            st = self.state.peer(p.peer_id)
            if self.sort_key == "ip":
                try:
                    return tuple(int(x) for x in p.ip.split("."))
                except Exception:
                    return (999, 999, 999, 999)
            if self.sort_key == "interface":
                return p.interface
            if self.sort_key == "down_used":
                return max(0, p.tx - int(st.get("baseline_tx", p.tx)))
            if self.sort_key == "up_used":
                return max(0, p.rx - int(st.get("baseline_rx", p.rx)))
            if self.sort_key == "down_speed":
                return p.down_speed_bps
            if self.sort_key == "up_speed":
                return p.up_speed_bps
            if self.sort_key == "state":
                return 1 if p.disabled else 0
            return (p.comment or "").lower()

        out.sort(key=sort_value, reverse=self.sort_desc)
        return out

    def normalize_selection(self, rows_visible: int) -> None:
        n = len(self.visible_peers)
        if n <= 0:
            self.selected = 0
            self.top = 0
            return
        self.selected = max(0, min(self.selected, n - 1))
        self.top = max(0, min(self.top, max(0, n - 1)))
        if self.selected < self.top:
            self.top = self.selected
        elif self.selected >= self.top + rows_visible:
            self.top = self.selected - rows_visible + 1

    def update_interface_rates(self, now: float) -> None:
        # Compute per-interface live bps from successive byte samples.
        for row in self.interfaces:
            name = str(row.get("name", ""))
            if not name:
                continue
            rx = int(row.get("rx-byte", 0) or 0)
            tx = int(row.get("tx-byte", 0) or 0)
            if name not in self.iface_baseline:
                self.iface_baseline[name] = (rx, tx)
            prev = self.iface_last_sample.get(name)
            if prev:
                prx, ptx, pts = prev
                dt = max(0.001, now - pts)
                rx_bps = max(0.0, (rx - prx) * 8.0 / dt)
                tx_bps = max(0.0, (tx - ptx) * 8.0 / dt)
                self.iface_speed[name] = (rx_bps, tx_bps)
            else:
                self.iface_speed[name] = (0.0, 0.0)
            self.iface_last_sample[name] = (rx, tx, now)

    def reset_dashboard_window(self, now: Optional[float] = None) -> None:
        # Reset per-interface traffic-window baselines used in dashboard counters.
        if now is None:
            now = time.time()
        self.dash_window_started_at = int(now)
        for row in self.interfaces:
            name = str(row.get("name", ""))
            if not name:
                continue
            self.iface_baseline[name] = (int(row.get("rx-byte", 0) or 0), int(row.get("tx-byte", 0) or 0))

    def dashboard_window_h(self) -> str:
        if self.dash_window_seconds <= 0:
            return "since app start"
        return self.period_h(self.dash_window_seconds)

    @staticmethod
    def bar(pct: float, width: int = 20) -> str:
        pct = max(0.0, min(100.0, pct))
        fill = int((pct / 100.0) * width)
        return "[" + ("#" * fill) + ("-" * (width - fill)) + f"] {pct:5.1f}%"

    @staticmethod
    def sparkline(values: List[float], width: int = 28) -> str:
        if width <= 0:
            return ""
        if not values:
            return "." * width
        chars = " .:-=+*#%@"
        if len(values) > width:
            step = len(values) / width
            sampled = []
            for i in range(width):
                idx = int(i * step)
                sampled.append(values[min(len(values) - 1, idx)])
            values = sampled
        else:
            values = ([values[0]] * (width - len(values))) + values
        vmax = max(values) if max(values) > 0 else 1.0
        out = []
        for v in values:
            pos = int((v / vmax) * (len(chars) - 1))
            out.append(chars[max(0, min(len(chars) - 1, pos))])
        return "".join(out)

    def total_bandwidth(self) -> Tuple[float, float]:
        rx = 0.0
        tx = 0.0
        for r, t in self.iface_speed.values():
            rx += r
            tx += t
        return rx, tx

    def sync_remote_policies_once(self) -> None:
        if self.client is None:
            return
        for p in self.peers:
            st = self.state.peer(p.peer_id)
            lim_d = int(st.get("traffic_limit_down_bytes", 0) or 0)
            lim_u = int(st.get("traffic_limit_up_bytes", 0) or 0)
            if lim_d <= 0 and lim_u <= 0:
                continue
            try:
                self.install_remote_policy(p, st)
            except Exception as e:
                self.error = f"Remote sync failed for {p.comment or p.ip}: {e}"

    def dashboard_alerts(self) -> List[str]:
        # Lightweight health checks for at-a-glance operator visibility.
        alerts: List[str] = []
        rr = self.router_resource or {}
        cpu = float(rr.get("cpu-load", 0) or 0)
        tm = int(rr.get("total-memory", 0) or 0)
        fm = int(rr.get("free-memory", 0) or 0)
        mem_used_pct = 0.0 if tm <= 0 else (100.0 * (tm - fm) / tm)
        th = int(rr.get("total-hdd-space", 0) or 0)
        fh = int(rr.get("free-hdd-space", 0) or 0)
        disk_used_pct = 0.0 if th <= 0 else (100.0 * (th - fh) / th)
        if cpu >= 85:
            alerts.append(f"High CPU: {cpu:.1f}%")
        if mem_used_pct >= 85:
            alerts.append(f"High memory usage: {mem_used_pct:.1f}%")
        if disk_used_pct >= 90:
            alerts.append(f"Low disk free: {bytes_h(fh)} left")
        for i in self.interfaces:
            if str(i.get("type", "")) == "wg" and str(i.get("running", "false")) != "true":
                alerts.append(f"WireGuard interface down: {i.get('name','?')}")
        stale = []
        for p in self.peers:
            if p.disabled:
                continue
            hs = parse_ros_duration_to_seconds(p.last_handshake)
            if hs is not None and hs > 600:
                stale.append(p.comment or p.ip)
        if stale:
            alerts.append(f"Stale handshake peers (>10m): {len(stale)}")
        return alerts

    @staticmethod
    def tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    def rest_probe(self, host: str, user: str, password: str, scheme: str, timeout_sec: float) -> Tuple[str, str]:
        import base64

        url = f"{scheme}://{host}/rest/system/resource"
        headers = {
            "Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii"),
            "Accept": "application/json",
        }
        req = request.Request(url, method="GET", headers=headers)
        try:
            if scheme == "https":
                resp = request.urlopen(req, timeout=timeout_sec, context=ssl._create_unverified_context())
            else:
                resp = request.urlopen(req, timeout=timeout_sec)
            with resp:
                _ = resp.read(128)
            return ("ok", "REST reachable")
        except error.HTTPError as e:
            if e.code in (401, 403):
                return ("auth", f"HTTP {e.code}")
            if e.code == 404:
                return ("rest-404", "REST path not available")
            return ("error", f"HTTP {e.code}")
        except Exception as e:
            msg = str(e).lower()
            if "refused" in msg or "timed out" in msg or "no route" in msg:
                return ("unreachable", str(e))
            return ("error", str(e))

    def classify_profile(self, name: str, cfg: Dict[str, str]) -> Dict[str, str]:
        host = cfg.get("router_ip", "").strip()
        user = cfg.get("user", "").strip()
        password = cfg.get("password", "").strip().strip('"').strip("'")
        use_https = str(cfg.get("use_https", "false")).lower() == "true"
        timeout_sec = float(cfg.get("timeout_sec", "5") or "5")
        if not host or not user or not password:
            return {"profile": name, "router_ip": host or "-", "status": "error", "detail": "missing router_ip/user/password", "ports": "-"}

        p80 = self.tcp_open(host, 80)
        p443 = self.tcp_open(host, 443)
        p8729 = self.tcp_open(host, 8729)
        ports = f"80:{'open' if p80 else 'closed'} 443:{'open' if p443 else 'closed'} 8729:{'open' if p8729 else 'closed'}"

        schemes = ["https", "http"] if use_https else ["http", "https"]
        first_status, first_detail = self.rest_probe(host, user, password, schemes[0], timeout_sec)
        if first_status == "ok":
            return {"profile": name, "router_ip": host, "status": "ok", "detail": f"{schemes[0]} ok", "ports": ports}

        second_status, second_detail = self.rest_probe(host, user, password, schemes[1], timeout_sec)
        if second_status == "ok":
            return {"profile": name, "router_ip": host, "status": "ok", "detail": f"{schemes[1]} ok (preferred {schemes[0]} failed: {first_status})", "ports": ports}

        # Classification precedence
        for st, dt in ((first_status, first_detail), (second_status, second_detail)):
            if st == "auth":
                return {"profile": name, "router_ip": host, "status": "auth", "detail": dt, "ports": ports}
        for st, dt in ((first_status, first_detail), (second_status, second_detail)):
            if st == "rest-404":
                return {"profile": name, "router_ip": host, "status": "rest-404", "detail": dt, "ports": ports}
        for st, dt in ((first_status, first_detail), (second_status, second_detail)):
            if st == "unreachable":
                return {"profile": name, "router_ip": host, "status": "unreachable", "detail": dt, "ports": ports}
        if not p80 and not p443:
            return {"profile": name, "router_ip": host, "status": "unreachable", "detail": "REST ports closed (80/443)", "ports": ports}
        return {"profile": name, "router_ip": host, "status": "error", "detail": f"{first_status}/{second_status}", "ports": ports}

    def run_connection_diagnostics(self) -> None:
        rows: List[Dict[str, str]] = []
        profiles = self.profiles.copy()
        if not profiles:
            profiles = {
                "default": {
                    "router_ip": self.host,
                    "user": self.user,
                    "password": self.password,
                    "use_https": "true" if self.use_https else "false",
                    "timeout_sec": str(self.timeout_sec),
                }
            }
        for name, cfg in profiles.items():
            try:
                rows.append(self.classify_profile(name, cfg))
            except Exception as e:
                rows.append({"profile": name, "router_ip": cfg.get("router_ip", "-"), "status": "error", "detail": str(e), "ports": "-"})
        self.diagnostics = rows
        self.diagnostics_last_run = now_ts()
        self.status = f"Diagnostics finished for {len(rows)} profile(s)"

    def draw_diagnostics(self) -> None:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        self.put(0, 0, " Connection Diagnostics ".ljust(w), self.c_title)
        self.put(1, 0, ("-" * max(1, w))[:w], self.c_hint)
        ran = "never" if not self.diagnostics_last_run else f"{self.age_h(max(0, now_ts()-self.diagnostics_last_run))} ago"
        self.put(2, 0, f"Last run: {ran} | Profiles: {len(self.diagnostics)}", self.c_header)
        self.put(3, 0, "+" + "-" * max(1, w - 2) + "+", self.c_hint)
        self.put(4, 0, self._fit("| Profile            | Router IP        | Status       | Ports                         | Detail", w), self.c_header)
        self.put(5, 0, "+" + "-" * max(1, w - 2) + "+", self.c_hint)
        rows = max(1, h - 10)
        for i, d in enumerate(self.diagnostics[:rows]):
            line = f"| {self._fit(d.get('profile','-'),18)} | {self._fit(d.get('router_ip','-'),16)} | {self._fit(d.get('status','-'),12)} | {self._fit(d.get('ports','-'),29)} | {d.get('detail','-')}"
            attr = self.c_status if d.get("status") == "ok" else (self.c_error if d.get("status") in ("auth", "rest-404", "unreachable", "error") else self.c_normal)
            self.put(6 + i, 0, self._fit(line, w), attr)
        self.put(6 + min(len(self.diagnostics), rows), 0, "+" + "-" * max(1, w - 2) + "+", self.c_hint)
        actions = "Keys: r run diagnostics | b dashboard | ? help | q quit"
        msg = self.error if self.error else self.status
        self.put(h - 3, 0, actions[:w].ljust(w), self.c_header)
        self.put(h - 2, 0, ("-" * max(1, w))[:w], self.c_hint)
        self.put(h - 1, 0, msg[:w].ljust(w), self.c_error if self.error else self.c_status)
        self.stdscr.refresh()

    def top_users_by_speed(self, n: int = 5) -> List[Tuple[str, float]]:
        rows: List[Tuple[str, float]] = []
        for p in self.peers:
            total = p.up_speed_bps + p.down_speed_bps
            rows.append((p.comment or p.ip, total))
        rows.sort(key=lambda x: x[1], reverse=True)
        return rows[:n]

    def top_users_by_window_usage(self, n: int = 5) -> List[Tuple[str, int]]:
        rows: List[Tuple[str, int]] = []
        for p in self.peers:
            st = self.state.peer(p.peer_id)
            used = max(0, p.rx - int(st.get("baseline_rx", p.rx))) + max(0, p.tx - int(st.get("baseline_tx", p.tx)))
            rows.append((p.comment or p.ip, used))
        rows.sort(key=lambda x: x[1], reverse=True)
        return rows[:n]

    def wg_interface_health(self) -> List[str]:
        out: List[str] = []
        wg_ifaces = [i for i in self.interfaces if str(i.get("type", "")) == "wg"]
        for i in wg_ifaces:
            name = str(i.get("name", ""))
            peers = [p for p in self.peers if p.interface == name]
            active = 0
            for p in peers:
                hs = parse_ros_duration_to_seconds(p.last_handshake)
                if hs is not None and hs <= 180:
                    active += 1
            rx_bps, tx_bps = self.iface_speed.get(name, (0.0, 0.0))
            out.append(
                f"{name}: peers={len(peers)} active<=3m={active} bw={bps_h(rx_bps+tx_bps)} running={i.get('running','?')}"
            )
        return out

    def export_dashboard_snapshot(self, csv_mode: bool = False) -> str:
        # Export current dashboard state for reporting/auditing.
        ts = time.strftime("%Y%m%d-%H%M%S")
        if csv_mode:
            path = f"dashboard-{self.profile_name}-{ts}.csv"
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["interface", "rx_bps", "tx_bps", "combined_bps", "window_usage_bytes"])
                for row in self.interfaces:
                    name = str(row.get("name", ""))
                    rx_bps, tx_bps = self.iface_speed.get(name, (0.0, 0.0))
                    rx = int(row.get("rx-byte", 0) or 0)
                    tx = int(row.get("tx-byte", 0) or 0)
                    brx, btx = self.iface_baseline.get(name, (rx, tx))
                    used = max(0, rx - brx) + max(0, tx - btx)
                    w.writerow([name, int(rx_bps), int(tx_bps), int(rx_bps + tx_bps), used])
            return path
        path = f"dashboard-{self.profile_name}-{ts}.json"
        rr = self.router_resource or {}
        rx, tx = self.total_bandwidth()
        payload = {
            "profile": self.profile_name,
            "router": self.host,
            "mode": "REST",
            "poll_latency_ms": self.last_poll_latency_ms,
            "poll_time": self.last_poll_ok_ts,
            "resource": rr,
            "total_bandwidth_bps": {"rx": rx, "tx": tx, "combined": rx + tx},
            "alerts": self.dashboard_alerts(),
            "wg_health": self.wg_interface_health(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return path

    def refresh_data(self, force: bool) -> None:
        try:
            t0 = time.time()
            if self.client is None:
                raise RuntimeError("Router client is not initialized")
            self.router_resource = self.client._request("GET", "/system/resource") or {}
            self.interfaces = self.client._request("GET", "/interface") or []
            peers = self.client.list_peers()
            now = time.time()
            for p in peers:
                st = self.state.peer(p.peer_id)
                if "baseline_rx" not in st:
                    st["baseline_rx"] = p.rx
                    st["baseline_tx"] = p.tx
                    st["baseline_at"] = now_ts()

                prev = self.last_sample.get(p.peer_id)
                if prev:
                    prx, ptx, pts = prev
                    dt = max(0.001, now - pts)
                    p.up_speed_bps = max(0.0, (p.rx - prx) * 8.0 / dt)
                    p.down_speed_bps = max(0.0, (p.tx - ptx) * 8.0 / dt)
                self.last_sample[p.peer_id] = (p.rx, p.tx, now)

            if self.dash_window_seconds > 0 and (now_ts() - self.dash_window_started_at >= self.dash_window_seconds):
                self.reset_dashboard_window(now)
            self.update_interface_rates(now)

            self.peers = peers
            if not self.remote_synced:
                self.sync_remote_policies_once()
                self.remote_synced = True
            self.enforce_traffic_limits()
            total_rx_bps = 0.0
            total_tx_bps = 0.0
            for rx_bps, tx_bps in self.iface_speed.values():
                total_rx_bps += rx_bps
                total_tx_bps += tx_bps
            self.history_cpu.append(float(self.router_resource.get("cpu-load", 0) or 0))
            self.history_bw.append(total_rx_bps + total_tx_bps)
            self.last_poll_latency_ms = (time.time() - t0) * 1000.0
            self.last_poll_ok_ts = now_ts()
            self.state.save()
            if force:
                self.status = f"Refreshed {time.strftime('%H:%M:%S')}"
            self.error = ""
        except Exception as e:
            msg = str(e)
            if "Connection refused" in msg and "/rest/" in msg:
                msg = (
                    msg
                    + " | Hint: RouterOS REST needs /ip service www or www-ssl enabled and reachable from this host."
                )
            self.error = msg
            self.status = "Refresh failed"
        finally:
            self.last_refresh_at = time.time()

    def enforce_traffic_limits(self) -> None:
        for p in self.peers:
            st = self.state.peer(p.peer_id)
            self.maybe_rollover_window(p, st)
            up_used = max(0, p.rx - int(st.get("baseline_rx", p.rx)))
            down_used = max(0, p.tx - int(st.get("baseline_tx", p.tx)))
            up_lim = int(st.get("traffic_limit_up_bytes", 0) or 0)
            down_lim = int(st.get("traffic_limit_down_bytes", 0) or 0)
            exceeded = (up_lim > 0 and up_used >= up_lim) or (down_lim > 0 and down_used >= down_lim)
            mode = str(st.get("overlimit_mode", "disable") or "disable")
            over_down = int(st.get("overlimit_speed_down_bps", 0) or 0)
            over_up = int(st.get("overlimit_speed_up_bps", 0) or 0)
            over_active = bool(st.get("overlimit_active", False))
            if exceeded:
                if mode == "throttle" and (over_down > 0 or over_up > 0) and not over_active:
                    try:
                        self.apply_speed_rules(p, down_bps=over_down, up_bps=over_up)
                        st["overlimit_active"] = True
                        self.status = f"Over-limit throttle active for {p.comment or p.ip}"
                    except Exception as e:
                        self.error = str(e)
                elif mode == "throttle" and over_down <= 0 and over_up <= 0 and not p.disabled:
                    try:
                        self.client.set_peer_disabled(p.peer_id, True)
                        st["disabled_by_policy"] = True
                        self.status = f"Disabled {p.comment or p.ip}: throttle mode without throttle speed"
                    except Exception as e:
                        self.error = str(e)
                elif mode == "trusted_only" and not over_active:
                    try:
                        self.apply_trusted_only_rule(p, enabled=True)
                        st["overlimit_active"] = True
                        self.status = f"Trusted-only mode active for {p.comment or p.ip}"
                    except Exception as e:
                        self.error = str(e)
                elif mode == "disable" and not p.disabled:
                    try:
                        self.client.set_peer_disabled(p.peer_id, True)
                        st["disabled_by_policy"] = True
                        self.status = f"Disabled {p.comment or p.ip}: traffic limit exceeded"
                    except Exception as e:
                        self.error = str(e)
            else:
                if over_active:
                    try:
                        if mode == "trusted_only":
                            self.apply_trusted_only_rule(p, enabled=False)
                        else:
                            normal_down = int(st.get("speed_limit_down_bps", 0) or 0)
                            normal_up = int(st.get("speed_limit_up_bps", 0) or 0)
                            self.apply_speed_rules(p, down_bps=normal_down, up_bps=normal_up)
                        st["overlimit_active"] = False
                        self.status = f"Normal speed rules restored for {p.comment or p.ip}"
                    except Exception as e:
                        self.error = str(e)

    def maybe_rollover_window(self, p: PeerView, st: Dict[str, Any]) -> None:
        period_seconds = int(st.get("traffic_period_seconds", 0) or 0)
        if period_seconds <= 0:
            return
        started = int(st.get("baseline_at", now_ts()) or now_ts())
        if now_ts() - started < period_seconds:
            return
        st["baseline_rx"] = p.rx
        st["baseline_tx"] = p.tx
        st["baseline_at"] = now_ts()
        if bool(st.get("overlimit_active", False)):
            try:
                mode = str(st.get("overlimit_mode", "disable") or "disable")
                if mode == "trusted_only":
                    self.apply_trusted_only_rule(p, enabled=False)
                else:
                    normal_down = int(st.get("speed_limit_down_bps", 0) or 0)
                    normal_up = int(st.get("speed_limit_up_bps", 0) or 0)
                    self.apply_speed_rules(p, down_bps=normal_down, up_bps=normal_up)
                st["overlimit_active"] = False
            except Exception as e:
                self.error = str(e)
        if bool(st.get("disabled_by_policy", False)) and p.disabled:
            try:
                self.client.set_peer_disabled(p.peer_id, False)
                st["disabled_by_policy"] = False
            except Exception as e:
                self.error = str(e)
        self.status = f"Traffic window reset for {p.comment or p.ip}"

    def scroll_into_view(self) -> None:
        h, _ = self.stdscr.getmaxyx()
        rows = max(5, h - 6)
        if self.selected < self.top:
            self.top = self.selected
        elif self.selected >= self.top + rows:
            self.top = self.selected - rows + 1

    def draw_main(self) -> None:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        title = " WireGuard Users TUI "
        self.put(0, 0, title.ljust(w), self.c_title)
        self.put(1, 0, ("-" * max(1, w))[:w], self.c_hint)
        meta = (
            f"Router: {self.profile_name}@{self.host} | "
            f"Sort: {self.sort_key} ({'desc' if self.sort_desc else 'asc'}) | "
            f"Filter: {self.filter_query or 'none'} | DisabledOnly: {'on' if self.clients_disabled_only else 'off'} | Clients: {len(self.visible_peers)}"
        )
        self.put(2, 0, meta[:w].ljust(w), self.c_hint)

        user_w = max(12, min(36, w - 124))
        cols = [
            ("No", 4),
            ("Iface", 10),
            ("IP", 15),
            ("User", user_w),
            ("Down", 11),
            ("Up", 11),
            ("DSpd", 12),
            ("USpd", 12),
            ("DLim", 11),
            ("ULim", 11),
            ("St", 8),
        ]
        # + plus for borders and 2 spaces around each cell value
        row_fmt_width = 1 + sum(cw + 3 for _, cw in cols)
        if row_fmt_width > w:
            shrink = row_fmt_width - w
            cols[3] = ("User", max(8, cols[3][1] - shrink))
            row_fmt_width = 1 + sum(cw + 3 for _, cw in cols)

        def border() -> str:
            return "+" + "+".join("-" * (cw + 2) for _, cw in cols) + "+"

        def format_row(values: List[str]) -> str:
            parts = []
            for i, (_, cw) in enumerate(cols):
                parts.append(" " + self._fit(values[i], cw) + " ")
            return "|" + "|".join(parts) + "|"

        self.put(3, 0, border(), self.c_hint)
        self.put(4, 0, format_row([x for x, _ in cols]), self.c_header)
        self.put(5, 0, border(), self.c_hint)

        max_rows = max(1, h - 10)
        shown = self.visible_peers[self.top : self.top + max_rows]
        for i, p in enumerate(shown):
            row_idx = self.top + i
            st = self.state.peer(p.peer_id)
            d_used = max(0, p.tx - int(st.get("baseline_tx", p.tx)))
            u_used = max(0, p.rx - int(st.get("baseline_rx", p.rx)))
            d_lim = int(st.get("traffic_limit_down_bytes", 0) or 0)
            u_lim = int(st.get("traffic_limit_up_bytes", 0) or 0)
            line = format_row([
                str(row_idx + 1),
                p.interface,
                p.ip,
                p.comment or "-",
                bytes_h(d_used),
                bytes_h(u_used),
                bps_h(p.down_speed_bps),
                bps_h(p.up_speed_bps),
                bytes_h(d_lim) if d_lim > 0 else "not set",
                bytes_h(u_lim) if u_lim > 0 else "not set",
                "disabled" if p.disabled else "enabled",
            ])
            if row_idx == self.selected and p.disabled:
                attr = self.c_disabled_selected
            elif row_idx == self.selected:
                attr = self.c_selected
            elif p.disabled:
                attr = self.c_disabled
            else:
                attr = self.c_normal
            self.put(6 + i, 0, line[:w], attr)
        self.put(6 + len(shown), 0, border(), self.c_hint)

        msg = self.error if self.error else self.status
        sel = self.visible_peers[self.selected] if self.visible_peers else None
        full = f"Selected: {sel.comment or '-'} | IP: {sel.ip} | Peer: {sel.peer_id}" if sel else "Selected: none"
        actions = "Keys: Enter actions | j/k move | o sort | O reverse | / filter | u disabled-only | a add | e enable | d disable | x delete | b dashboard | ? help | r refresh | q quit"
        self.put(h - 3, 0, actions[:w].ljust(w), self.c_header)
        self.put(h - 2, 0, full[:w].ljust(w), self.c_hint)
        self.put(h - 1, 0, msg[:w].ljust(w), self.c_error if self.error else self.c_status)
        self.stdscr.refresh()

    def draw_dashboard(self) -> None:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        rr = self.router_resource or {}
        cpu = float(rr.get("cpu-load", 0) or 0)
        tm = int(rr.get("total-memory", 0) or 0)
        fm = int(rr.get("free-memory", 0) or 0)
        mem_used_pct = 0.0 if tm <= 0 else (100.0 * (tm - fm) / tm)
        th = int(rr.get("total-hdd-space", 0) or 0)
        fh = int(rr.get("free-hdd-space", 0) or 0)
        disk_used_pct = 0.0 if th <= 0 else (100.0 * (th - fh) / th)

        self.put(0, 0, " Router Dashboard ".ljust(w), self.c_title)
        self.put(1, 0, ("-" * max(1, w))[:w], self.c_hint)
        poll_ago = self.age_h(max(0, now_ts() - self.last_poll_ok_ts)) if self.last_poll_ok_ts else "n/a"
        self.put(2, 0, f"Router: {self.profile_name}@{self.host}  Mode: REST  Poll: {self.last_poll_latency_ms:.0f}ms ({poll_ago} ago)", self.c_header)
        self.put(3, 0, f"Version: {rr.get('version','?')}  Uptime: {rr.get('uptime','?')}", self.c_normal)
        self.put(4, 0, f"Platform: {rr.get('platform','?')}  Board: {rr.get('board-name','?')}  CPU: {rr.get('cpu','?')} x{rr.get('cpu-count','?')} @ {rr.get('cpu-frequency','?')}MHz", self.c_normal)

        self.put(5, 0, f"CPU     {self.bar(cpu, 28)}", self.c_header)
        self.put(6, 0, f"Memory  {self.bar(mem_used_pct, 28)}  Used: {bytes_h(max(0, tm-fm))} / {bytes_h(tm)}", self.c_header)
        self.put(7, 0, f"Disk    {self.bar(disk_used_pct, 28)}  Used: {bytes_h(max(0, th-fh))} / {bytes_h(th)}", self.c_header)
        self.put(8, 0, f"CPU trend  {self.sparkline(list(self.history_cpu), 34)}", self.c_hint)
        self.put(9, 0, f"BW trend   {self.sparkline(list(self.history_bw), 34)}", self.c_hint)

        iface_rows: List[Tuple[str, float, float, int]] = []
        total_rx_bps, total_tx_bps = self.total_bandwidth()
        for row in self.interfaces:
            name = str(row.get("name", ""))
            if not name:
                continue
            rx_bps, tx_bps = self.iface_speed.get(name, (0.0, 0.0))
            rx = int(row.get("rx-byte", 0) or 0)
            tx = int(row.get("tx-byte", 0) or 0)
            brx, btx = self.iface_baseline.get(name, (rx, tx))
            used = max(0, rx - brx) + max(0, tx - btx)
            iface_rows.append((name, rx_bps, tx_bps, used))
        iface_rows.sort(key=lambda x: (x[1] + x[2]), reverse=True)

        alerts = self.dashboard_alerts()
        alert_text = "Alerts: " + ("none" if not alerts else " | ".join(alerts[:2]))
        self.put(10, 0, alert_text[:w], self.c_error if alerts else self.c_status)
        self.put(11, 0, f"Total bandwidth: RX {bps_h(total_rx_bps)} | TX {bps_h(total_tx_bps)} | Combined {bps_h(total_rx_bps + total_tx_bps)}", self.c_header)
        self.put(12, 0, f"Interface traffic window: {self.dashboard_window_h()} (press p to cycle, w to reset)", self.c_hint)
        self.put(13, 0, "+" + "-" * max(1, w - 2) + "+", self.c_hint)
        self.put(14, 0, self._fit("| Interface                 | RX Speed      | TX Speed      | Traffic In Window |", w), self.c_header)
        self.put(15, 0, "+" + "-" * max(1, w - 2) + "+", self.c_hint)

        max_rows = max(1, h - 24)
        for i, (name, rx_bps, tx_bps, used) in enumerate(iface_rows[:max_rows]):
            line = f"| {self._fit(name,25)} | {self._fit(bps_h(rx_bps),12)} | {self._fit(bps_h(tx_bps),12)} | {self._fit(bytes_h(used),17)} |"
            self.put(16 + i, 0, self._fit(line, w), self.c_normal)
        y_after_table = 16 + min(len(iface_rows), max_rows)
        self.put(y_after_table, 0, "+" + "-" * max(1, w - 2) + "+", self.c_hint)

        top_speed = self.top_users_by_speed(3)
        top_usage = self.top_users_by_window_usage(3)
        wg_health = self.wg_interface_health()[:3]
        self.put(y_after_table + 1, 0, ("Top speed: " + " | ".join([f"{n}={bps_h(v)}" for n, v in top_speed]))[:w], self.c_header)
        self.put(y_after_table + 2, 0, ("Top usage: " + " | ".join([f"{n}={bytes_h(v)}" for n, v in top_usage]))[:w], self.c_header)
        self.put(y_after_table + 3, 0, ("WG health: " + (" | ".join(wg_health) if wg_health else "none"))[:w], self.c_hint)

        msg = self.error if self.error else self.status
        actions = "Keys: l clients | g diagnostics | i clients-by-iface | u disabled clients | p cycle window | w reset window | j export json | v export csv | ? help | r refresh | q quit"
        self.put(h - 3, 0, actions[:w].ljust(w), self.c_header)
        self.put(h - 2, 0, ("-" * max(1, w))[:w], self.c_hint)
        self.put(h - 1, 0, msg[:w].ljust(w), self.c_error if self.error else self.c_status)
        self.stdscr.refresh()

    def prompt(self, label: str, initial: str = "") -> Optional[str]:
        h, w = self.stdscr.getmaxyx()
        curses.echo()
        curses.curs_set(1)
        try:
            self.stdscr.nodelay(False)
            self.stdscr.timeout(-1)
            if h <= 0 or w <= 1:
                return None
            self.stdscr.move(h - 1, 0)
            self.stdscr.clrtoeol()
            prompt = f"{label}"
            self.put(h - 1, 0, prompt, self.c_header)
            if initial:
                self.put(h - 1, len(prompt), initial, self.c_normal)
            self.stdscr.refresh()
            max_len = max(1, w - len(prompt) - 1)
            if len(prompt) >= w:
                return None
            s = self.stdscr.getstr(h - 1, len(prompt), max_len)
            if s is None:
                return None
            return s.decode("utf-8").strip()
        except Exception:
            return None
        finally:
            curses.noecho()
            curses.curs_set(0)
            self.stdscr.nodelay(True)
            self.stdscr.timeout(200)

    def confirm(self, label: str) -> bool:
        ans = self.prompt(f"{label} [y/N]: ")
        if ans is None:
            return False
        return ans.strip().lower() in ("y", "yes")

    def _draw_box(self, title: str, lines: List[str], footer: str = "") -> Tuple[int, int, int, int]:
        h, w = self.stdscr.getmaxyx()
        bw = max(60, min(w - 4, 110))
        bh = max(8, min(h - 4, len(lines) + 5))
        y = max(1, (h - bh) // 2)
        x = max(1, (w - bw) // 2)
        top = "+" + "-" * (bw - 2) + "+"
        self.put(y, x, top, self.c_header)
        for i in range(1, bh - 1):
            self.put(y + i, x, "|" + " " * (bw - 2) + "|", self.c_header if i in (1, bh - 2) else self.c_hint)
        self.put(y + bh - 1, x, top, self.c_header)
        self.put(y, x + 2, f"[ {title} ]", self.c_title)
        for i, ln in enumerate(lines[: max(0, bh - 4)]):
            self.put(y + 2 + i, x + 2, ln[: bw - 4], self.c_normal)
        if footer:
            self.put(y + bh - 2, x + 2, footer[: bw - 4], self.c_hint)
        return y, x, bh, bw

    def choose_from_dialog(self, title: str, items: List[str]) -> Optional[int]:
        if not items:
            return None
        idx = 0
        top = 0
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self.put(0, 0, f"[ {title} ]".ljust(w), self.c_title)
            self.put(1, 0, ("-" * max(1, w))[:w], self.c_hint)
            self.put(h - 2, 0, ("-" * max(1, w))[:w], self.c_hint)
            self.put(h - 1, 0, "Enter=Select  j/k or arrows=Move  ? help  q/Esc=Cancel".ljust(w), self.c_header)
            rows = max(1, h - 4)
            if idx < top:
                top = idx
            elif idx >= top + rows:
                top = idx - rows + 1
            shown = items[top : top + rows]
            for i, text in enumerate(shown):
                attr = self.c_selected if (top + i) == idx else self.c_normal
                self.put(2 + i, 0, self._fit(text, w), attr)
            self.stdscr.refresh()
            ch = self.stdscr.getch()
            if ch in (ord("q"), 27):
                return None
            if ch in (ord("?"),):
                self.show_help("selection-dialog")
                continue
            if ch in (curses.KEY_UP, ord("k")):
                idx = max(0, idx - 1)
            elif ch in (curses.KEY_DOWN, ord("j")):
                idx = min(len(items) - 1, idx + 1)
            elif ch in (10, 13, curses.KEY_ENTER):
                return idx

    def prompt_in_dialog(self, title: str, label: str, initial: str = "") -> Optional[str]:
        h, w = self.stdscr.getmaxyx()
        bw = max(60, min(w - 4, 110))
        bh = 8
        y = max(1, (h - bh) // 2)
        x = max(1, (w - bw) // 2)
        curses.echo()
        curses.curs_set(1)
        try:
            self.stdscr.nodelay(False)
            self.stdscr.timeout(-1)
            self.draw_main()
            self._draw_box(title, [label], "Enter=OK  Esc=Cancel  (? help)")
            px = x + 2
            py = y + 4
            self.put(py, px, "> " + initial, self.c_header)
            self.stdscr.move(py, px + 2 + len(initial))
            self.stdscr.refresh()
            max_len = max(1, bw - 6)
            s = self.stdscr.getstr(py, px + 2, max_len)
            if s is None:
                return None
            out = s.decode("utf-8").strip()
            # Empty Enter accepts the suggested default value.
            if out == "":
                return initial.strip()
            return out
        except Exception:
            return None
        finally:
            curses.noecho()
            curses.curs_set(0)
            self.stdscr.nodelay(True)
            self.stdscr.timeout(200)

    def show_config_dialog(self, title: str, content: str, default_filename: str = "wg-client.conf") -> None:
        # Full-screen plain-text viewer keeps manual selection/copy clean.
        lines = content.splitlines()
        top = 0
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self.put(0, 0, f"[ {title} ]".ljust(w), self.c_title)
            self.put(1, 0, ("-" * max(1, w))[:w], self.c_hint)
            self.put(h - 2, 0, ("-" * max(1, w))[:w], self.c_hint)
            self.put(h - 1, 0, "j/k or arrows scroll | c copy | s save | ? help | q close".ljust(w), self.c_header)
            rows = max(1, h - 4)
            shown = lines[top : top + rows]
            for i, ln in enumerate(shown):
                self.put(2 + i, 0, self._fit(ln, w), self.c_normal)
            self.stdscr.refresh()
            ch = self.stdscr.getch()
            if ch in (ord("q"), 27, ord("\n"), 10, 13):
                return
            if ch in (ord("?"),):
                self.show_help("config-view")
                continue
            if ch in (ord("j"), curses.KEY_DOWN):
                top = min(max(0, len(lines) - rows), top + 1)
            elif ch in (ord("k"), curses.KEY_UP):
                top = max(0, top - 1)
            elif ch == ord("c"):
                try:
                    self.copy_to_clipboard(content)
                    self.status = "Configuration copied to clipboard"
                except Exception as e:
                    self.error = str(e)
            elif ch == ord("s"):
                path = self.prompt_in_dialog("Save Config", "File path:", default_filename)
                if path:
                    try:
                        with open(path, "w", encoding="utf-8") as f:
                            f.write(content + "\n")
                        self.status = f"Saved to {path}"
                        self.error = ""
                    except Exception as e:
                        self.error = f"Save failed: {e}"

    def generate_client_keypair(self) -> Tuple[str, str]:
        try:
            priv = subprocess.check_output(["wg", "genkey"], text=True, timeout=5).strip()
            pub = subprocess.check_output(["wg", "pubkey"], input=priv + "\n", text=True, timeout=5).strip()
            if not priv or not pub:
                raise RuntimeError("empty key output")
            return priv, pub
        except FileNotFoundError as e:
            raise RuntimeError("`wg` command not found; install wireguard-tools") from e
        except Exception as e:
            raise RuntimeError(f"key generation failed: {e}") from e

    def copy_to_clipboard(self, text: str) -> None:
        cmds = [
            ["pbcopy"],
            ["wl-copy"],
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
        ]
        for cmd in cmds:
            try:
                subprocess.run(cmd, input=text, text=True, check=True, timeout=5)
                return
            except Exception:
                continue
        raise RuntimeError("No clipboard tool found (tried pbcopy/wl-copy/xclip/xsel)")

    def main_enable_disable(self, p: PeerView, enabled: bool) -> None:
        try:
            self.client.set_peer_disabled(p.peer_id, not enabled)
            self.status = f"{'Enabled' if enabled else 'Disabled'} {p.comment or p.ip}"
            self.error = ""
            self.refresh_data(force=True)
        except Exception as e:
            self.error = str(e)

    def main_delete_peer(self, p: PeerView) -> None:
        label = f"Delete peer '{p.comment or p.ip}' ({p.ip})?"
        if not self.confirm(label):
            self.status = "Delete cancelled"
            return
        try:
            self.client.delete_peer(p.peer_id)
            self.status = f"Deleted peer {p.comment or p.ip}"
            self.error = ""
            self.refresh_data(force=True)
        except Exception as e:
            self.error = f"Delete failed: {e}"

    def main_add_peer(self) -> None:
        try:
            ifaces = self.client.list_wireguard_interfaces()
            if not ifaces:
                self.error = "No wireguard interfaces found"
                return
            labels = [f"{i.get('name','?')}  (listen:{i.get('listen-port','?')})" for i in ifaces]
            sel = self.choose_from_dialog("Select WireGuard Interface", labels)
            if sel is None:
                self.status = "Add cancelled"
                return
            iface = ifaces[sel]
            iface_name = str(iface.get("name", "wireguard"))
            listen_port = str(iface.get("listen-port", "13231"))
            server_pub = str(iface.get("public-key", "")).strip()

            ip_rows = self.client.list_ip_addresses()
            peers = self.client.list_peers()
            local_cidr = ""
            iface_ip = None
            for r in ip_rows:
                if str(r.get("interface", "")) == iface_name:
                    local_cidr = str(r.get("address", ""))
                    try:
                        iface_ip = ipaddress.ip_interface(local_cidr).ip
                    except Exception:
                        iface_ip = None
                    break
            if not local_cidr:
                self.error = f"No IP address found on interface {iface_name}"
                return
            network = ipaddress.ip_interface(local_cidr).network
            used = set()
            for p in peers:
                if p.interface != iface_name:
                    continue
                try:
                    used.add(ipaddress.ip_address(p.ip))
                except Exception:
                    pass
            if iface_ip:
                used.add(iface_ip)
            used.add(ipaddress.ip_address("100.100.100.100"))
            used.add(ipaddress.ip_address("100.100.100.101"))

            suggest = None
            for host in network.hosts():
                if host in used:
                    continue
                suggest = host
                break
            if suggest is None:
                self.error = f"No free IP found in {network}"
                return

            ip_in = self.prompt_in_dialog("Add Client", f"Client IP in {network}:", str(suggest))
            if ip_in is None:
                self.status = "Add cancelled"
                return
            ip_obj = ipaddress.ip_address(ip_in.strip())
            if ip_obj not in network:
                self.error = f"IP {ip_obj} is not in {network}"
                return
            if ip_obj in used:
                self.error = f"IP {ip_obj} is already used"
                return

            comment = self.prompt_in_dialog("Add Client", "Client comment:", "")
            if comment is None:
                self.status = "Add cancelled"
                return

            priv, pub = self.generate_client_keypair()
            payload = {
                "interface": iface_name,
                "allowed-address": f"{ip_obj}/32",
                "public-key": pub,
                "disabled": "false",
            }
            if comment.strip():
                payload["comment"] = comment.strip()
            self.client.create_peer(payload)
            self.status = f"Peer added: {comment.strip() or ip_obj}"
            self.error = ""
            self.refresh_data(force=True)

            conf = [
                "[Interface]",
                f"PrivateKey = {priv}",
                f"Address = {ip_obj}/32",
                f"DNS = {self.cfg_dns}",
                "",
                "[Peer]",
                f"PublicKey = {server_pub}",
                f"AllowedIPs = {CFG_ALLOWED_IPS}",
                f"Endpoint = {self.cfg_endpoint_host}:{listen_port}",
                f"PersistentKeepalive = {CFG_KEEPALIVE}",
            ]
            safe_name = slug(comment.strip() or str(ip_obj), max_len=32).replace("-", "_")
            self.show_config_dialog("Client Configuration", "\n".join(conf), default_filename=f"{safe_name}.conf")
        except Exception as e:
            self.error = f"Add failed: {e}"

    def user_menu(self, p: PeerView) -> None:
        while True:
            self.refresh_data(force=False)
            current = next((x for x in self.peers if x.peer_id == p.peer_id), p)
            self.draw_user(current)
            ch = self.stdscr.getch()
            if ch == -1:
                continue
            if ch in (ord("?"),):
                self.show_help("client-details")
                continue
            if ch in (ord("q"), 27, ord("b")):
                break
            if ch == ord("x"):
                self.clear_limits(current)
            elif ch == ord("t"):
                self.set_traffic_policy(current)
            elif ch == ord("s"):
                self.set_speed_limits(current)
            elif ch == ord("e"):
                self.set_enable(current, True)
            elif ch == ord("d"):
                self.set_enable(current, False)
            elif ch == ord("z"):
                self.reset_usage(current)
            elif ch == ord("v"):
                self.realtime_view(current)

    def draw_user(self, p: PeerView) -> None:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        st = self.state.peer(p.peer_id)
        base_rx = int(st.get("baseline_rx", p.rx))
        base_tx = int(st.get("baseline_tx", p.tx))
        up_used = max(0, p.rx - base_rx)
        down_used = max(0, p.tx - base_tx)
        mode = str(st.get("overlimit_mode", "disable"))
        state_attr = self.c_disabled if p.disabled else self.c_status

        def section(y: int, title: str, rows: List[Tuple[str, str]], accent: bool = False) -> int:
            if y >= h - 5:
                return y
            inner_w = max(20, w - 4)
            top = f"+- {title} " + "-" * max(1, inner_w - len(title) - 3) + "+"
            self.put(y, 1, top[: w - 2], self.c_header)
            yy = y + 1
            for k, v in rows:
                if yy >= h - 5:
                    break
                label = self._fit(k, 22)
                val_w = max(1, inner_w - 25)
                val = self._fit(v, val_w)
                self.put(yy, 1, f"| {label} : {val} |", self.c_normal)
                if accent:
                    self.put(yy, 26, val[:val_w], self.c_header)
                yy += 1
            if yy < h - 5:
                self.put(yy, 1, "+" + "-" * max(1, inner_w) + "+", self.c_hint)
                yy += 1
            return yy

        self.put(0, 0, f" User Details ".ljust(w), self.c_title)
        self.put(1, 0, ("-" * max(1, w))[:w], self.c_hint)
        self.put(2, 0, f"Name: {p.comment or '(no comment)'}", self.c_header)
        self.put(2, max(0, w - 28), f"State: {'disabled' if p.disabled else 'enabled'}", state_attr)

        y = 4
        y = section(
            y,
            "Identity",
            [
                ("Peer ID", p.peer_id),
                ("Interface", p.interface),
                ("Client IP", p.ip),
            ],
        )
        y = section(
            y,
            "Usage",
            [
                ("Download since now", bytes_h(down_used)),
                ("Upload since now", bytes_h(up_used)),
                ("Total download", bytes_h(p.tx)),
                ("Total upload", bytes_h(p.rx)),
                ("Baseline age", self.age_h(now_ts() - int(st.get("baseline_at", now_ts()) or now_ts()))),
                ("Realtime down", bps_h(p.down_speed_bps)),
                ("Realtime up", bps_h(p.up_speed_bps)),
            ],
        )
        y = section(
            y,
            "Policy",
            [
                ("Traffic limit down", bytes_h(int(st.get("traffic_limit_down_bytes", 0))) if int(st.get("traffic_limit_down_bytes", 0) or 0) > 0 else "not set"),
                ("Traffic limit up", bytes_h(int(st.get("traffic_limit_up_bytes", 0))) if int(st.get("traffic_limit_up_bytes", 0) or 0) > 0 else "not set"),
                ("Traffic period", self.period_h(int(st.get("traffic_period_seconds", 0) or 0))),
                ("Over-limit mode", mode),
                ("Over-limit down", bps_h(float(st.get("overlimit_speed_down_bps", 0))) if float(st.get("overlimit_speed_down_bps", 0) or 0) > 0 else "not set"),
                ("Over-limit up", bps_h(float(st.get("overlimit_speed_up_bps", 0))) if float(st.get("overlimit_speed_up_bps", 0) or 0) > 0 else "not set"),
                ("Over-limit active", "yes" if bool(st.get("overlimit_active", False)) else "no"),
                ("Speed limit down", bps_h(float(st.get("speed_limit_down_bps", 0))) if float(st.get("speed_limit_down_bps", 0) or 0) > 0 else "not set"),
                ("Speed limit up", bps_h(float(st.get("speed_limit_up_bps", 0))) if float(st.get("speed_limit_up_bps", 0) or 0) > 0 else "not set"),
            ],
            accent=True,
        )

        msg = self.error if self.error else self.status
        actions = "Keys: z reset | t traffic policy | s speed | e enable | d disable | v realtime | x clear | b back | ? help"
        self.put(h - 3, 0, actions[:w].ljust(w), self.c_header)
        self.put(h - 2, 0, ("-" * max(1, w))[:w], self.c_hint)
        self.put(h - 1, 0, msg[:w].ljust(w), self.c_error if self.error else self.c_status)
        self.stdscr.refresh()

    def reset_usage(self, p: PeerView) -> None:
        st = self.state.peer(p.peer_id)
        st["baseline_rx"] = p.rx
        st["baseline_tx"] = p.tx
        st["baseline_at"] = now_ts()
        try:
            self.install_remote_policy(p, st)
        except Exception as e:
            self.error = f"Remote policy sync failed: {e}"
        self.state.save()
        self.status = f"Usage baseline reset for {p.comment or p.ip}"

    def set_traffic_policy(self, p: PeerView) -> None:
        sdown = self.prompt("Download limit GB (0 = not set): ")
        if sdown is None:
            return
        sup = self.prompt("Upload limit GB (0 = not set): ")
        if sup is None:
            return
        speriod = self.prompt("Period: day/hour/week or 2h/1d/3600s or 0: ")
        if speriod is None:
            return
        smode = self.prompt("On limit: disable/throttle/trusted_only (default disable): ")
        if smode is None:
            return
        sover_down = self.prompt("Over-limit down speed Mbps (0 = disable/throttle off): ")
        if sover_down is None:
            return
        sover_up = self.prompt("Over-limit up speed Mbps (0 = disable/throttle off): ")
        if sover_up is None:
            return
        try:
            d_gb = float(sdown or "0")
            u_gb = float(sup or "0")
            od_mbps = float(sover_down or "0")
            ou_mbps = float(sover_up or "0")
            if d_gb < 0 or u_gb < 0:
                raise ValueError("must be >= 0")
            if od_mbps < 0 or ou_mbps < 0:
                raise ValueError("over-limit speed must be >= 0")
            mode = (smode or "disable").strip().lower()
            if mode in ("trusted", "trusted-only", "trustedonly"):
                mode = "trusted_only"
            if mode not in ("disable", "throttle", "trusted_only"):
                raise ValueError("mode must be disable, throttle, or trusted_only")
            period_s = parse_period_input(speriod)
            if period_s < 0:
                raise ValueError("period must be >= 0")
            st = self.state.peer(p.peer_id)
            st["traffic_limit_down_bytes"] = gb_to_bytes(d_gb) if d_gb > 0 else 0
            st["traffic_limit_up_bytes"] = gb_to_bytes(u_gb) if u_gb > 0 else 0
            st["traffic_period_seconds"] = period_s
            st["overlimit_mode"] = mode
            st["overlimit_speed_down_bps"] = mbps_to_bps(od_mbps) if od_mbps > 0 else 0
            st["overlimit_speed_up_bps"] = mbps_to_bps(ou_mbps) if ou_mbps > 0 else 0
            st["overlimit_active"] = False
            st["disabled_by_policy"] = False
            self.apply_trusted_only_rule(p, enabled=False)
            self.reset_usage(p)
            self.install_remote_policy(p, st)
            self.state.save()
            self.status = f"Traffic policy updated for {p.comment or p.ip}"
            self.error = ""
        except Exception as e:
            self.error = f"Invalid input: {e}"

    def set_speed_limits(self, p: PeerView) -> None:
        sdown = self.prompt("Download speed Mbps (0 = not set): ")
        if sdown is None:
            return
        sup = self.prompt("Upload speed Mbps (0 = not set): ")
        if sup is None:
            return
        try:
            d_mbps = float(sdown or "0")
            u_mbps = float(sup or "0")
            if d_mbps < 0 or u_mbps < 0:
                raise ValueError("must be >= 0")
            st = self.state.peer(p.peer_id)
            down_bps = mbps_to_bps(d_mbps) if d_mbps > 0 else 0
            up_bps = mbps_to_bps(u_mbps) if u_mbps > 0 else 0
            self.apply_speed_rules(p, down_bps=down_bps, up_bps=up_bps)
            st["speed_limit_down_bps"] = down_bps
            st["speed_limit_up_bps"] = up_bps
            self.install_remote_policy(p, st)
            self.state.save()
            self.status = f"Speed limits applied for {p.comment or p.ip}"
            self.error = ""
        except Exception as e:
            self.error = f"Failed to set speed limits: {e}"

    def clear_limits(self, p: PeerView) -> None:
        st = self.state.peer(p.peer_id)
        st["traffic_limit_down_bytes"] = 0
        st["traffic_limit_up_bytes"] = 0
        st["traffic_period_seconds"] = 0
        st["overlimit_mode"] = "disable"
        st["overlimit_speed_down_bps"] = 0
        st["overlimit_speed_up_bps"] = 0
        st["overlimit_active"] = False
        st["disabled_by_policy"] = False
        st["speed_limit_down_bps"] = 0
        st["speed_limit_up_bps"] = 0
        try:
            self.uninstall_remote_policy(p)
            self.apply_trusted_only_rule(p, enabled=False)
            self.apply_speed_rules(p, down_bps=0, up_bps=0)
        except Exception as e:
            self.error = f"Cleared local limits, but router cleanup failed: {e}"
        self.state.save()
        self.status = f"All limits cleared for {p.comment or p.ip}"

    def scheduler_names(self, p: PeerView) -> Tuple[str, str]:
        sid = safe_id(p.peer_id)
        return (f"wg-tui-check-{sid}", f"wg-tui-reset-{sid}")

    def interval_expr(self, seconds: int) -> str:
        if seconds <= 0:
            return "0s"
        return f"{seconds}s"

    def get_scheduler_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        if self.client is None:
            return None
        for s in self.client.list_scheduler():
            if str(s.get("name", "")) == name:
                return s
        return None

    def install_remote_policy(self, p: PeerView, st: Dict[str, Any]) -> None:
        if self.client is None:
            return
        lim_down = int(st.get("traffic_limit_down_bytes", 0) or 0)
        lim_up = int(st.get("traffic_limit_up_bytes", 0) or 0)
        period = int(st.get("traffic_period_seconds", 0) or 0)
        if lim_down <= 0 and lim_up <= 0:
            self.uninstall_remote_policy(p)
            return

        check_name, reset_name = self.scheduler_names(p)
        # Scheduler comment stores compact mutable state for router-side enforcement.
        # brx/btx: baseline counters, ov: over-limit mode active, db: disabled-by-policy.
        state_comment = f"brx={int(st.get('baseline_rx', p.rx))};btx={int(st.get('baseline_tx', p.tx))};ov=0;db=0;"
        check_script = self.build_policy_check_script(p, st, check_name, reset_name)
        check_payload = {
            "name": check_name,
            "interval": "1m",
            "comment": state_comment,
            "on-event": check_script,
            "disabled": "false",
        }
        existing_check = self.get_scheduler_by_name(check_name)
        if existing_check:
            self.client.patch_scheduler(str(existing_check.get(".id")), check_payload)
        else:
            self.client.create_scheduler(check_payload)

        if period > 0:
            reset_script = self.build_policy_reset_script(p, st, check_name)
            reset_payload = {
                "name": reset_name,
                "interval": self.interval_expr(period),
                "on-event": reset_script,
                "disabled": "false",
            }
            existing_reset = self.get_scheduler_by_name(reset_name)
            if existing_reset:
                self.client.patch_scheduler(str(existing_reset.get(".id")), reset_payload)
            else:
                self.client.create_scheduler(reset_payload)
        else:
            existing_reset = self.get_scheduler_by_name(reset_name)
            if existing_reset:
                self.client.delete_scheduler(str(existing_reset.get(".id")))

    def uninstall_remote_policy(self, p: PeerView) -> None:
        if self.client is None:
            return
        check_name, reset_name = self.scheduler_names(p)
        for name in (check_name, reset_name):
            found = self.get_scheduler_by_name(name)
            if found:
                self.client.delete_scheduler(str(found.get(".id")))

    def build_policy_check_script(self, p: PeerView, st: Dict[str, Any], check_name: str, reset_name: str) -> str:
        # Router-side minute loop:
        # - read peer counters
        # - compare with baseline
        # - apply over-limit mode (disable/trusted_only/throttle)
        # - restore normal state when no longer over limit.
        # State is persisted in scheduler comment to avoid external storage.
        sid = slug((p.comment or p.ip), max_len=18)
        uniq = safe_id(p.peer_id)
        mark_up = f"wg-{sid}-{uniq}-up"
        mark_down = f"wg-{sid}-{uniq}-down"
        mcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-tui mangle up"
        mcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-tui mangle down"
        qcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-tui queue up"
        qcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-tui queue down"
        qname_up = f"{sid}-{uniq}-up"
        qname_down = f"{sid}-{uniq}-down"
        trusted_comment = f"{p.comment or p.ip} | {p.peer_id} | wg-tui trusted-only"
        mode = str(st.get("overlimit_mode", "disable") or "disable")
        lim_down = int(st.get("traffic_limit_down_bytes", 0) or 0)
        lim_up = int(st.get("traffic_limit_up_bytes", 0) or 0)
        over_down = int(st.get("overlimit_speed_down_bps", 0) or 0)
        over_up = int(st.get("overlimit_speed_up_bps", 0) or 0)
        norm_down = int(st.get("speed_limit_down_bps", 0) or 0)
        norm_up = int(st.get("speed_limit_up_bps", 0) or 0)

        return (
            f":local pid {ros_q(p.peer_id)};"
            f":local pip {ros_q(p.ip)};"
            f":local mode {ros_q(mode)};"
            f":local limD {lim_down};:local limU {lim_up};"
            f":local ovD {over_down};:local ovU {over_up};"
            f":local nD {norm_down};:local nU {norm_up};"
            f":local checkName {ros_q(check_name)};:local resetName {ros_q(reset_name)};"
            f":local markUp {ros_q(mark_up)};:local markDown {ros_q(mark_down)};"
            f":local mcu {ros_q(mcomment_up)};:local mcd {ros_q(mcomment_down)};"
            f":local qcu {ros_q(qcomment_up)};:local qcd {ros_q(qcomment_down)};"
            f":local qnu {ros_q(qname_up)};:local qnd {ros_q(qname_down)};"
            f":local tComment {ros_q(trusted_comment)};"
            ":local pf [/interface wireguard peers find where .id=$pid];"
            ":if ([:len $pf]=0) do={"
            "/system scheduler remove [find where name=$checkName];"
            "/system scheduler remove [find where name=$resetName];"
            ":error \"peer-missing\";};"
            ":local rx [:tonum [/interface wireguard peers get $pf rx]];"
            ":local tx [:tonum [/interface wireguard peers get $pf tx]];"
            ":local sf [/system scheduler find where name=$checkName];"
            ":local c [/system scheduler get $sf comment];"
            ":local p1 [:find $c \"brx=\"];:local p2 [:find $c \";btx=\"];"
            ":local p3 [:find $c \";ov=\"];:local p4 [:find $c \";db=\"];"
            ":if (($p1=nil) or ($p2=nil) or ($p3=nil) or ($p4=nil)) do={:set c (\"brx=\".$rx.\";btx=\".$tx.\";ov=0;db=0;\");/system scheduler set $sf comment=$c;};"
            ":set p1 [:find $c \"brx=\"];:set p2 [:find $c \";btx=\"];:set p3 [:find $c \";ov=\"];:set p4 [:find $c \";db=\"];"
            ":local brx [:tonum [:pick $c ($p1+4) $p2]];"
            ":local btx [:tonum [:pick $c ($p2+5) $p3]];"
            ":local ov [:tonum [:pick $c ($p3+4) $p4]];"
            ":local db [:tonum [:pick $c ($p4+4) ([:len $c]-1)]];"
            ":local uu ($rx-$brx);:local dd ($tx-$btx);"
            ":if ($uu<0) do={:set uu 0;};:if ($dd<0) do={:set dd 0;};"
            ":local ex false;"
            ":if (($limU>0) and ($uu>=$limU)) do={:set ex true;};"
            ":if (($limD>0) and ($dd>=$limD)) do={:set ex true;};"
            ":if (!$ex) do={"
            " :if ($ov=1) do={"
            "   :if ($mode=\"trusted_only\") do={/ip firewall filter remove [find where comment=$tComment];} else={"
            "     :local mu [/ip firewall mangle find where comment=$mcu];:local md [/ip firewall mangle find where comment=$mcd];"
            "     :local qu [/queue tree find where comment=$qcu];:local qd [/queue tree find where comment=$qcd];"
            "     :if ($nU<=0) do={:if ([:len $mu]>0) do={/ip firewall mangle remove $mu;};:if ([:len $qu]>0) do={/queue tree remove $qu;};} else={"
            "       :if ([:len $mu]=0) do={/ip firewall mangle add chain=forward action=mark-packet src-address=$pip new-packet-mark=$markUp passthrough=no comment=$mcu;}"
            "       else={/ip firewall mangle set $mu chain=forward action=mark-packet src-address=$pip new-packet-mark=$markUp passthrough=no comment=$mcu;};"
            "       :if ([:len $qu]=0) do={/queue tree add name=$qnu parent=global packet-mark=$markUp max-limit=$nU comment=$qcu;}"
            "       else={/queue tree set $qu name=$qnu parent=global packet-mark=$markUp max-limit=$nU comment=$qcu;};};"
            "     :if ($nD<=0) do={:if ([:len $md]>0) do={/ip firewall mangle remove $md;};:if ([:len $qd]>0) do={/queue tree remove $qd;};} else={"
            "       :if ([:len $md]=0) do={/ip firewall mangle add chain=forward action=mark-packet dst-address=$pip new-packet-mark=$markDown passthrough=no comment=$mcd;}"
            "       else={/ip firewall mangle set $md chain=forward action=mark-packet dst-address=$pip new-packet-mark=$markDown passthrough=no comment=$mcd;};"
            "       :if ([:len $qd]=0) do={/queue tree add name=$qnd parent=global packet-mark=$markDown max-limit=$nD comment=$qcd;}"
            "       else={/queue tree set $qd name=$qnd parent=global packet-mark=$markDown max-limit=$nD comment=$qcd;};};"
            "   };"
            "   :set ov 0;};"
            " :if (($db=1) and ([/interface wireguard peers get $pf disabled]=true)) do={/interface wireguard peers set $pf disabled=no;:set db 0;};"
            " /system scheduler set $sf comment=(\"brx=\".$brx.\";btx=\".$btx.\";ov=\".$ov.\";db=\".$db.\";\");"
            " :error \"ok\";};"
            ":if ($mode=\"disable\") do={:if ([/interface wireguard peers get $pf disabled]=false) do={/interface wireguard peers set $pf disabled=yes;:set db 1;};};"
            ":if ($mode=\"trusted_only\") do={"
            " :if ($ov=0) do={"
            "   /ip firewall filter remove [find where comment=$tComment];"
            "   /ip firewall filter add chain=forward action=drop src-address=$pip dst-address-list=!trusted_list place-before=0 comment=$tComment;"
            "   :set ov 1;};};"
            ":if ($mode=\"throttle\") do={"
            " :if ($ov=0) do={"
            "   :local mu [/ip firewall mangle find where comment=$mcu];:local md [/ip firewall mangle find where comment=$mcd];"
            "   :local qu [/queue tree find where comment=$qcu];:local qd [/queue tree find where comment=$qcd];"
            "   :if ($ovU<=0) do={:if ([:len $mu]>0) do={/ip firewall mangle remove $mu;};:if ([:len $qu]>0) do={/queue tree remove $qu;};} else={"
            "     :if ([:len $mu]=0) do={/ip firewall mangle add chain=forward action=mark-packet src-address=$pip new-packet-mark=$markUp passthrough=no comment=$mcu;}"
            "     else={/ip firewall mangle set $mu chain=forward action=mark-packet src-address=$pip new-packet-mark=$markUp passthrough=no comment=$mcu;};"
            "     :if ([:len $qu]=0) do={/queue tree add name=$qnu parent=global packet-mark=$markUp max-limit=$ovU comment=$qcu;}"
            "     else={/queue tree set $qu name=$qnu parent=global packet-mark=$markUp max-limit=$ovU comment=$qcu;};};"
            "   :if ($ovD<=0) do={:if ([:len $md]>0) do={/ip firewall mangle remove $md;};:if ([:len $qd]>0) do={/queue tree remove $qd;};} else={"
            "     :if ([:len $md]=0) do={/ip firewall mangle add chain=forward action=mark-packet dst-address=$pip new-packet-mark=$markDown passthrough=no comment=$mcd;}"
            "     else={/ip firewall mangle set $md chain=forward action=mark-packet dst-address=$pip new-packet-mark=$markDown passthrough=no comment=$mcd;};"
            "     :if ([:len $qd]=0) do={/queue tree add name=$qnd parent=global packet-mark=$markDown max-limit=$ovD comment=$qcd;}"
            "     else={/queue tree set $qd name=$qnd parent=global packet-mark=$markDown max-limit=$ovD comment=$qcd;};};"
            "   :set ov 1;};};"
            "/system scheduler set $sf comment=(\"brx=\".$brx.\";btx=\".$btx.\";ov=\".$ov.\";db=\".$db.\";\");"
        )

    def build_policy_reset_script(self, p: PeerView, st: Dict[str, Any], check_name: str) -> str:
        # Period reset loop:
        # - baseline := current counters
        # - clear over-limit artifacts
        # - re-enable peer if policy disabled it
        mode = str(st.get("overlimit_mode", "disable") or "disable")
        trusted_comment = f"{p.comment or p.ip} | {p.peer_id} | wg-tui trusted-only"
        return (
            f":local pid {ros_q(p.peer_id)};:local checkName {ros_q(check_name)};"
            f":local mode {ros_q(mode)};:local tComment {ros_q(trusted_comment)};"
            ":local pf [/interface wireguard peers find where .id=$pid];"
            ":if ([:len $pf]=0) do={:error \"peer-missing\";};"
            ":local rx [:tonum [/interface wireguard peers get $pf rx]];"
            ":local tx [:tonum [/interface wireguard peers get $pf tx]];"
            ":local sf [/system scheduler find where name=$checkName];"
            ":if ([:len $sf]=0) do={:error \"check-missing\";};"
            ":local c [/system scheduler get $sf comment];"
            ":local p4 [:find $c \";db=\"];"
            ":local db 0;"
            ":if ($p4!=nil) do={:set db [:tonum [:pick $c ($p4+4) ([:len $c]-1)]];};"
            ":if (($db=1) and ([/interface wireguard peers get $pf disabled]=true)) do={/interface wireguard peers set $pf disabled=no;};"
            ":if ($mode=\"trusted_only\") do={/ip firewall filter remove [find where comment=$tComment];};"
            "/system scheduler set $sf comment=(\"brx=\".$rx.\";btx=\".$tx.\";ov=0;db=0;\");"
        )

    def period_h(self, seconds: int) -> str:
        if seconds <= 0:
            return "not set"
        if seconds % 86400 == 0:
            d = seconds // 86400
            return f"{d} day" if d == 1 else f"{d} days"
        if seconds % 3600 == 0:
            h = seconds // 3600
            return f"{h} hour" if h == 1 else f"{h} hours"
        return f"{seconds}s"

    def age_h(self, seconds: int) -> str:
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m"
        if seconds < 86400:
            return f"{seconds // 3600}h"
        return f"{seconds // 86400}d"

    def set_enable(self, p: PeerView, enabled: bool) -> None:
        try:
            self.client.set_peer_disabled(p.peer_id, not enabled)
            self.status = f"{'Enabled' if enabled else 'Disabled'} {p.comment or p.ip}"
            self.error = ""
        except Exception as e:
            self.error = str(e)

    def realtime_view(self, p: PeerView) -> None:
        while True:
            self.refresh_data(force=False)
            cur = next((x for x in self.peers if x.peer_id == p.peer_id), p)
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            lines = [
                f"Realtime usage for: {cur.comment or cur.ip}",
                f"Download speed: {bps_h(cur.down_speed_bps)}",
                f"Upload speed:   {bps_h(cur.up_speed_bps)}",
                f"Total rx: {bytes_h(cur.rx)}    Total tx: {bytes_h(cur.tx)}",
                "",
                "Press q/b/ESC to return",
            ]
            self.put(0, 0, " Realtime View ".ljust(w), self.c_title)
            self.put(1, 0, ("-" * max(1, w))[:w], self.c_hint)
            for i, line in enumerate(lines[: h - 4]):
                self.put(2 + i, 0, line[:w], self.c_normal)
            self.put(h - 2, 0, ("-" * max(1, w))[:w], self.c_hint)
            self.put(h - 1, 0, "Live polling every ~2s".ljust(w), self.c_status)
            self.stdscr.refresh()
            ch = self.stdscr.getch()
            if ch in (ord("?"),):
                self.show_help("realtime")
                continue
            if ch in (ord("q"), ord("b"), 27):
                return

    def apply_trusted_only_rule(self, p: PeerView, enabled: bool) -> None:
        rules = self.client.list_filter()
        marker = f"| {p.peer_id} | wg-tui trusted-only"
        legacy = f"{MARKER_PREFIX}:{p.peer_id}:trusted-only"

        found = None
        for r in rules:
            c = str(r.get("comment", ""))
            if marker in c or c == legacy:
                found = r
                break

        if not enabled:
            if found:
                self.client.delete_filter(str(found.get(".id")))
            return

        display = p.comment or p.ip
        payload = {
            "chain": "forward",
            "action": "drop",
            "src-address": p.ip,
            "dst-address-list": "!trusted_list",
            # Put policy rule at top so it takes effect before broad accepts.
            "place-before": "0",
            "comment": f"{display} | {p.peer_id} | wg-tui trusted-only",
            "disabled": "false",
        }
        if found:
            # Recreate to guarantee top position in rule order.
            self.client.delete_filter(str(found.get(".id")))
            self.client.create_filter(payload)
        else:
            self.client.create_filter(payload)

    def apply_speed_rules(self, p: PeerView, down_bps: int, up_bps: int) -> None:
        sid = slug((p.comment or p.ip), max_len=18)
        uniq = safe_id(p.peer_id)
        mark_up = f"wg-{sid}-{uniq}-up"
        mark_down = f"wg-{sid}-{uniq}-down"
        mcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-tui mangle up"
        mcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-tui mangle down"
        qcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-tui queue up"
        qcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-tui queue down"
        qname_up = f"{sid}-{uniq}-up"
        qname_down = f"{sid}-{uniq}-down"

        mangle = self.client.list_mangle()
        queues = self.client.list_queue_tree()

        legacy_mcomment_up = f"{MARKER_PREFIX}:{p.peer_id}:mangle:up"
        legacy_mcomment_down = f"{MARKER_PREFIX}:{p.peer_id}:mangle:down"
        legacy_qcomment_up = f"{MARKER_PREFIX}:{p.peer_id}:queue:up"
        legacy_qcomment_down = f"{MARKER_PREFIX}:{p.peer_id}:queue:down"

        def by_comment(rows: List[Dict[str, Any]], comment: str, legacy: str) -> Optional[Dict[str, Any]]:
            for r in rows:
                c = str(r.get("comment", ""))
                if c == comment or c == legacy:
                    return r
            return None

        mup = by_comment(mangle, mcomment_up, legacy_mcomment_up)
        mdown = by_comment(mangle, mcomment_down, legacy_mcomment_down)
        qup = by_comment(queues, qcomment_up, legacy_qcomment_up)
        qdown = by_comment(queues, qcomment_down, legacy_qcomment_down)

        if up_bps <= 0:
            if mup:
                self.client.delete_mangle(str(mup.get(".id")))
            if qup:
                self.client.delete_queue(str(qup.get(".id")))
        else:
            mpayload = {
                "chain": "forward",
                "action": "mark-packet",
                "src-address": p.ip,
                "new-packet-mark": mark_up,
                "passthrough": "false",
                "comment": mcomment_up,
                "disabled": "false",
            }
            if mup:
                self.client.patch_mangle(str(mup.get(".id")), mpayload)
            else:
                self.client.create_mangle(mpayload)

            qpayload = {
                "name": qname_up,
                "parent": "global",
                "packet-mark": mark_up,
                "max-limit": str(up_bps),
                "comment": qcomment_up,
                "disabled": "false",
            }
            if qup:
                self.client.patch_queue(str(qup.get(".id")), qpayload)
            else:
                self.client.create_queue(qpayload)

        if down_bps <= 0:
            if mdown:
                self.client.delete_mangle(str(mdown.get(".id")))
            if qdown:
                self.client.delete_queue(str(qdown.get(".id")))
        else:
            mpayload = {
                "chain": "forward",
                "action": "mark-packet",
                "dst-address": p.ip,
                "new-packet-mark": mark_down,
                "passthrough": "false",
                "comment": mcomment_down,
                "disabled": "false",
            }
            if mdown:
                self.client.patch_mangle(str(mdown.get(".id")), mpayload)
            else:
                self.client.create_mangle(mpayload)

            qpayload = {
                "name": qname_down,
                "parent": "global",
                "packet-mark": mark_down,
                "max-limit": str(down_bps),
                "comment": qcomment_down,
                "disabled": "false",
            }
            if qdown:
                self.client.patch_queue(str(qdown.get(".id")), qpayload)
            else:
                self.client.create_queue(qpayload)


def main(stdscr: Any) -> None:
    app = App(stdscr)
    app.run()


def run_tui() -> int:
    try:
        curses.wrapper(main)
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(run_tui())
