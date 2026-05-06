#!/usr/bin/env python3
import csv
import json
import os
import socket
import ssl
import subprocess
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple
from urllib import error, request

from .config import (
    CFG_ALLOWED_IPS,
    CFG_DNS,
    CFG_ENDPOINT_HOST,
    CFG_EXEMPT_DST_LIST,
    CFG_KEEPALIVE,
    MARKER_PREFIX,
    env_file_path,
    get_default_profile_name,
    load_dotenv,
    parse_router_profiles,
)
from .models import PeerView
from .routeros import ApiSslClient, RouterOSClient
from .state import StateStore
from .utils import (
    bps_h,
    bytes_h,
    now_ts,
    parse_ros_duration_to_seconds,
    pdf_escape_text,
    ros_q,
    safe_id,
    slug,
)


class App:
    def __init__(self, _legacy_screen: Any = None) -> None:
        self.env_path = env_file_path()
        load_dotenv(self.env_path)
        self.profiles = parse_router_profiles(self.env_path)
        self.profile_name = ""
        self.host = ""
        self.user = ""
        self.password = ""
        self.use_https = False
        self.timeout_sec = 30.0
        self.cfg_dns = CFG_DNS
        self.cfg_endpoint_host = CFG_ENDPOINT_HOST
        self.cfg_exempt_dst_list = os.environ.get("EXEMPT_TRAFFIC_DST_LIST", CFG_EXEMPT_DST_LIST).strip() or CFG_EXEMPT_DST_LIST

        self.client: Optional[RouterOSClient] = None
        self.state = StateStore()

        self.peers: List[PeerView] = []
        self.router_resource: Dict[str, Any] = {}
        self.interfaces: List[Dict[str, Any]] = []
        self.last_sample: Dict[str, Tuple[int, int, float]] = {}
        self.peer_exempt_counters: Dict[str, Tuple[int, int]] = {}
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
        self.remote_synced = False



    def bootstrap_router_config(self) -> None:
        # Multi-router profile mode from .env:
        # profile={user=...,password=...,router_ip=...,endpoint_ip=...,dns_servers=...}
        if self.profiles:
            preferred = get_default_profile_name(self.env_path)
            selected = preferred if preferred in self.profiles else sorted(self.profiles.keys())[0]
            self.connect_profile(selected, self.profiles[selected])
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
        self.cfg_exempt_dst_list = (
            os.environ.get("EXEMPT_TRAFFIC_DST_LIST", CFG_EXEMPT_DST_LIST).strip() or CFG_EXEMPT_DST_LIST
        )
        self.client = RouterOSClient(self.host, self.user, self.password, use_https=self.use_https, timeout_sec=self.timeout_sec)


    def connect_profile(self, name: str, p: Dict[str, str]) -> None:
        host = p.get("router_ip", "").strip()
        user = p.get("user", "").strip()
        password = p.get("password", "").strip().strip('"').strip("'")
        if not host or not user or not password:
            raise RuntimeError(f"Profile '{name}' missing router_ip/user/password")
        self.profile_name = name
        self.host = host
        self.user = user
        self.password = password
        self.use_https = str(p.get("use_https", "false")).lower() == "true"
        self.timeout_sec = float(p.get("timeout_sec", "30") or "30")
        transport = str(p.get("transport", "rest")).strip().lower()
        self.cfg_dns = p.get("dns_servers", CFG_DNS).strip() or CFG_DNS
        self.cfg_endpoint_host = p.get("endpoint_ip", CFG_ENDPOINT_HOST).strip() or CFG_ENDPOINT_HOST
        self.cfg_exempt_dst_list = p.get("exempt_traffic_dst_list", self.cfg_exempt_dst_list).strip() or self.cfg_exempt_dst_list
        if transport in ("api_ssl", "api-ssl"):
            self.client = ApiSslClient(self.host, self.user, self.password, timeout_sec=self.timeout_sec, port=8729, use_ssl=True)
            self.status = f"Connected profile: {self.profile_name} ({self.host}) via api-ssl"
        elif transport in ("api",):
            self.client = ApiSslClient(self.host, self.user, self.password, timeout_sec=self.timeout_sec, port=8728, use_ssl=False)
            self.status = f"Connected profile: {self.profile_name} ({self.host}) via api"
        else:
            self.client = RouterOSClient(self.host, self.user, self.password, use_https=self.use_https, timeout_sec=self.timeout_sec)
            self.status = f"Connected profile: {self.profile_name} ({self.host}) via rest"

    def reset_runtime_caches(self) -> None:
        self.peers = []
        self.router_resource = {}
        self.interfaces = []
        self.visible_peers = []
        self.last_sample = {}
        self.peer_exempt_counters = {}
        self.iface_last_sample = {}
        self.iface_speed = {}
        self.iface_baseline = {}
        self.dash_window_started_at = now_ts()
        self.history_cpu.clear()
        self.history_bw.clear()
        self.last_poll_latency_ms = 0.0
        self.last_poll_ok_ts = 0
        self.remote_synced = False
        self.error = ""




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
                down_used, _ = self.peer_used_bytes(p, st)
                return down_used
            if self.sort_key == "up_used":
                _, up_used = self.peer_used_bytes(p, st)
                return up_used
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
                self.install_remote_policy(p, st, preserve_existing_state=True)
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
        transport = str(cfg.get("transport", "rest")).strip().lower()
        if not host or not user or not password:
            return {"profile": name, "router_ip": host or "-", "status": "error", "detail": "missing router_ip/user/password", "ports": "-"}

        p80 = self.tcp_open(host, 80)
        p443 = self.tcp_open(host, 443)
        p8729 = self.tcp_open(host, 8729)
        ports = f"80:{'open' if p80 else 'closed'} 443:{'open' if p443 else 'closed'} 8729:{'open' if p8729 else 'closed'}"

        if transport in ("api_ssl", "api-ssl", "api"):
            try:
                if transport in ("api_ssl", "api-ssl"):
                    c = ApiSslClient(host, user, password, timeout_sec=timeout_sec, port=8729, use_ssl=True)
                else:
                    c = ApiSslClient(host, user, password, timeout_sec=timeout_sec, port=8728, use_ssl=False)
                _ = c.list_system_resource()
                mode_txt = "api-ssl" if transport in ("api_ssl", "api-ssl") else "api"
                return {"profile": name, "router_ip": host, "status": "ok", "detail": f"{mode_txt} ok", "ports": ports}
            except Exception as e:
                msg = str(e).lower()
                if "invalid user name or password" in msg or "not logged in" in msg:
                    return {"profile": name, "router_ip": host, "status": "auth", "detail": str(e), "ports": ports}
                if transport in ("api_ssl", "api-ssl"):
                    if not p8729:
                        return {"profile": name, "router_ip": host, "status": "unreachable", "detail": "api-ssl port closed (8729)", "ports": ports}
                else:
                    if not self.tcp_open(host, 8728):
                        return {"profile": name, "router_ip": host, "status": "unreachable", "detail": "api port closed (8728)", "ports": ports}
                return {"profile": name, "router_ip": host, "status": "error", "detail": str(e), "ports": ports}

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
        if self.profile_name:
            current = dict(profiles.get(self.profile_name, {}))
            current.update(
                {
                    "router_ip": self.host,
                    "user": self.user,
                    "password": self.password,
                    "use_https": "true" if self.use_https else "false",
                    "timeout_sec": str(self.timeout_sec),
                }
            )
            profiles[self.profile_name] = current
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

    def build_users_export_rows(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for p in self.peers:
            st = self.state.peer(p.peer_id)
            down_used, up_used = self.peer_used_bytes(p, st)
            row = {
                "peer_id": p.peer_id,
                "name": p.comment or "",
                "interface": p.interface,
                "ip": p.ip,
                "state": "disabled" if p.disabled else "enabled",
                "last_handshake": p.last_handshake,
                "total_download_bytes": p.tx,
                "total_upload_bytes": p.rx,
                "download_since_baseline_bytes": down_used,
                "upload_since_baseline_bytes": up_used,
                "realtime_down_bps": int(p.down_speed_bps),
                "realtime_up_bps": int(p.up_speed_bps),
                "baseline_at": int(st.get("baseline_at", 0) or 0),
                "baseline_age_seconds": max(0, now_ts() - int(st.get("baseline_at", now_ts()) or now_ts())),
                "traffic_limit_down_bytes": int(st.get("traffic_limit_down_bytes", 0) or 0),
                "traffic_limit_up_bytes": int(st.get("traffic_limit_up_bytes", 0) or 0),
                "traffic_period_seconds": int(st.get("traffic_period_seconds", 0) or 0),
                "overlimit_mode": str(st.get("overlimit_mode", "disable") or "disable"),
                "overlimit_speed_down_bps": int(st.get("overlimit_speed_down_bps", 0) or 0),
                "overlimit_speed_up_bps": int(st.get("overlimit_speed_up_bps", 0) or 0),
                "overlimit_active": bool(st.get("overlimit_active", False)),
                "speed_limit_down_bps": int(st.get("speed_limit_down_bps", 0) or 0),
                "speed_limit_up_bps": int(st.get("speed_limit_up_bps", 0) or 0),
                "exempt_destination_list": self.cfg_exempt_dst_list,
            }
            rows.append(row)
        rows.sort(key=lambda r: (str(r.get("interface", "")), str(r.get("name", "")).lower(), str(r.get("ip", ""))))
        return rows

    def export_users_snapshot_json(self) -> str:
        ts = time.strftime("%Y%m%d-%H%M%S")
        path = f"users-snapshot-{self.profile_name}-{ts}.json"
        rows = self.build_users_export_rows()
        payload = {
            "generated_at_epoch": now_ts(),
            "generated_at_local": time.strftime("%Y-%m-%d %H:%M:%S"),
            "router_profile": self.profile_name,
            "router_ip": self.host,
            "users_count": len(rows),
            "poll_latency_ms": self.last_poll_latency_ms,
            "exempt_destination_list": self.cfg_exempt_dst_list,
            "users": rows,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return path

    def write_simple_pdf(self, path: str, pages_lines: List[List[str]]) -> None:
        # Minimal text-only PDF generator without external dependencies.
        page_chunks = pages_lines if pages_lines else [["No data"]]
        objects: List[Tuple[int, bytes]] = []
        font_id = 3
        next_id = 4
        page_ids: List[int] = []
        content_ids: List[int] = []
        for _ in page_chunks:
            page_ids.append(next_id)
            content_ids.append(next_id + 1)
            next_id += 2

        objects.append((1, b"<< /Type /Catalog /Pages 2 0 R >>"))
        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        objects.append((2, f"<< /Type /Pages /Kids [ {kids} ] /Count {len(page_ids)} >>".encode("ascii")))
        objects.append((font_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))

        for i, lines in enumerate(page_chunks):
            page_id = page_ids[i]
            content_id = content_ids[i]
            body: List[str] = ["BT", "/F1 10 Tf", "50 800 Td"]
            for idx, ln in enumerate(lines):
                text = pdf_escape_text(ln[:140])
                if idx == 0:
                    body.append(f"({text}) Tj")
                else:
                    body.append("0 -14 Td")
                    body.append(f"({text}) Tj")
            body.append("ET")
            stream = "\n".join(body).encode("latin-1", "replace")
            page_obj = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
            ).encode("ascii")
            content_obj = b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"
            objects.append((page_id, page_obj))
            objects.append((content_id, content_obj))

        objects.sort(key=lambda x: x[0])
        out = bytearray()
        out += b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        offsets: Dict[int, int] = {}
        for oid, body in objects:
            offsets[oid] = len(out)
            out += f"{oid} 0 obj\n".encode("ascii")
            out += body
            out += b"\nendobj\n"

        xref_pos = len(out)
        max_obj = max(offsets.keys()) if offsets else 0
        out += f"xref\n0 {max_obj + 1}\n".encode("ascii")
        out += b"0000000000 65535 f \n"
        for i in range(1, max_obj + 1):
            off = offsets.get(i, 0)
            out += f"{off:010d} 00000 n \n".encode("ascii")
        out += f"trailer\n<< /Size {max_obj + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")

        with open(path, "wb") as f:
            f.write(out)

    def export_users_snapshot_pdf(self) -> str:
        ts = time.strftime("%Y%m%d-%H%M%S")
        path = f"users-snapshot-{self.profile_name}-{ts}.pdf"
        rows = self.build_users_export_rows()
        lines: List[str] = [
            "WireGuard Users Snapshot",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Router: {self.profile_name}@{self.host}",
            f"Users: {len(rows)}",
            f"Exempt destination list: {self.cfg_exempt_dst_list}",
            "-" * 120,
        ]
        for idx, r in enumerate(rows, start=1):
            lines.extend(
                [
                    f"{idx}. {r.get('name') or '-'} | {r.get('ip')} | {r.get('interface')} | {r.get('state')}",
                    f"   Total D/U: {bytes_h(int(r.get('total_download_bytes',0)))} / {bytes_h(int(r.get('total_upload_bytes',0)))}",
                    f"   Used D/U:  {bytes_h(int(r.get('download_since_baseline_bytes',0)))} / {bytes_h(int(r.get('upload_since_baseline_bytes',0)))}",
                    f"   Speed D/U: {bps_h(float(r.get('realtime_down_bps',0)))} / {bps_h(float(r.get('realtime_up_bps',0)))}",
                    f"   Limit D/U: {bytes_h(int(r.get('traffic_limit_down_bytes',0)))} / {bytes_h(int(r.get('traffic_limit_up_bytes',0)))} | period: {self.period_h(int(r.get('traffic_period_seconds',0)))}",
                    f"   Over-limit: mode={r.get('overlimit_mode')} active={'yes' if r.get('overlimit_active') else 'no'} speed D/U {bps_h(float(r.get('overlimit_speed_down_bps',0)))} / {bps_h(float(r.get('overlimit_speed_up_bps',0)))}",
                    f"   Speed cap D/U: {bps_h(float(r.get('speed_limit_down_bps',0)))} / {bps_h(float(r.get('speed_limit_up_bps',0)))}",
                    f"   Peer ID: {r.get('peer_id')} | Last HS: {r.get('last_handshake') or '-'} | Baseline age: {self.age_h(int(r.get('baseline_age_seconds',0)))}",
                    "-" * 120,
                ]
            )

        max_lines_per_page = 50
        pages_lines: List[List[str]] = []
        for i in range(0, len(lines), max_lines_per_page):
            pages_lines.append(lines[i : i + max_lines_per_page])
        self.write_simple_pdf(path, pages_lines)
        return path

    @staticmethod
    def _row_bytes(row: Dict[str, Any]) -> int:
        for k in ("bytes", "byte", "bytes-total"):
            if k in row:
                try:
                    return int(row.get(k, 0) or 0)
                except Exception:
                    return 0
        return 0

    def exempt_rule_comments(self, p: PeerView) -> Tuple[str, str]:
        base = p.comment or p.ip
        return (
            f"{base} | {p.peer_id} | wg-web exempt up",
            f"{base} | {p.peer_id} | wg-web exempt down",
        )

    def get_peer_exempt_counters(self, p: PeerView, mangle_rows: Optional[List[Dict[str, Any]]] = None) -> Tuple[int, int]:
        if mangle_rows is None:
            mangle_rows = self.client.list_mangle() if self.client else []
        up_comment, down_comment = self.exempt_rule_comments(p)
        up_bytes = 0
        down_bytes = 0
        for r in mangle_rows or []:
            c = str(r.get("comment", ""))
            if c == up_comment:
                up_bytes = self._row_bytes(r)
            elif c == down_comment:
                down_bytes = self._row_bytes(r)
        return up_bytes, down_bytes

    def ensure_exempt_counter_rules(self, p: PeerView) -> None:
        if self.client is None:
            return
        mangle = self.client.list_mangle() or []
        up_comment, down_comment = self.exempt_rule_comments(p)

        up_found = None
        down_found = None
        for r in mangle:
            c = str(r.get("comment", ""))
            if c == up_comment:
                up_found = r
            elif c == down_comment:
                down_found = r

        up_payload = {
            "chain": "forward",
            "action": "passthrough",
            "src-address": p.ip,
            "dst-address-list": self.cfg_exempt_dst_list,
            "comment": up_comment,
            "disabled": "false",
        }
        down_payload = {
            "chain": "forward",
            "action": "passthrough",
            "dst-address": p.ip,
            "src-address-list": self.cfg_exempt_dst_list,
            "comment": down_comment,
            "disabled": "false",
        }
        if up_found:
            self.client.patch_mangle(str(up_found.get(".id")), up_payload)
        else:
            self.client.create_mangle(up_payload)
        if down_found:
            self.client.patch_mangle(str(down_found.get(".id")), down_payload)
        else:
            self.client.create_mangle(down_payload)

    def peer_used_bytes(self, p: PeerView, st: Dict[str, Any]) -> Tuple[int, int]:
        # Accounted usage = peer counters minus exempt destination traffic counters.
        base_rx_raw = st.get("baseline_rx")
        base_tx_raw = st.get("baseline_tx")
        base_rx = int(p.rx if base_rx_raw is None else base_rx_raw)
        base_tx = int(p.tx if base_tx_raw is None else base_tx_raw)
        raw_up = max(0, p.rx - base_rx)
        raw_down = max(0, p.tx - base_tx)
        cur_ex_up, cur_ex_down = self.peer_exempt_counters.get(p.peer_id, (0, 0))
        base_ex_up = int(st.get("baseline_exempt_up", 0) or 0)
        base_ex_down = int(st.get("baseline_exempt_down", 0) or 0)
        ex_up = max(0, cur_ex_up - base_ex_up)
        ex_down = max(0, cur_ex_down - base_ex_down)
        up_used = max(0, raw_up - ex_up)
        down_used = max(0, raw_down - ex_down)
        return down_used, up_used

    def refresh_data(self, force: bool) -> None:
        try:
            t0 = time.time()
            if self.client is None:
                raise RuntimeError("Router client is not initialized")
            self.router_resource = self.client.list_system_resource() or {}
            self.interfaces = self.client.list_interfaces() or []
            peers = self.client.list_peers()
            mangle_rows = self.client.list_mangle() or []
            self.peer_exempt_counters = {}
            now = time.time()
            for p in peers:
                st = self.state.peer(p.peer_id)
                ex_up, ex_down = self.get_peer_exempt_counters(p, mangle_rows)
                self.peer_exempt_counters[p.peer_id] = (ex_up, ex_down)
                if "baseline_rx" not in st:
                    st["baseline_rx"] = p.rx
                    st["baseline_tx"] = p.tx
                    st["baseline_at"] = now_ts()
                if "baseline_exempt_up" not in st:
                    st["baseline_exempt_up"] = ex_up
                if "baseline_exempt_down" not in st:
                    st["baseline_exempt_down"] = ex_down

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
            down_used, up_used = self.peer_used_bytes(p, st)
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
        ex_up, ex_down = self.peer_exempt_counters.get(p.peer_id, (0, 0))
        st["baseline_exempt_up"] = ex_up
        st["baseline_exempt_down"] = ex_down
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









    def config_dir_path(self) -> str:
        return "client-configs"

    def default_config_path(self, filename: str) -> str:
        base = (filename or "").strip()
        if not base:
            base = "wg-client.conf"
        if os.path.dirname(base):
            return base
        return os.path.join(self.config_dir_path(), base)

    def normalize_config_save_path(self, path: str) -> str:
        p = (path or "").strip()
        if not p:
            return self.default_config_path("wg-client.conf")
        if os.path.dirname(p):
            return p
        return os.path.join(self.config_dir_path(), p)


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







    def reset_usage(self, p: PeerView) -> None:
        st = self.state.peer(p.peer_id)
        mode = str(st.get("overlimit_mode", "disable") or "disable")
        normal_down = int(st.get("speed_limit_down_bps", 0) or 0)
        normal_up = int(st.get("speed_limit_up_bps", 0) or 0)
        if bool(st.get("overlimit_active", False)):
            try:
                if mode == "trusted_only":
                    self.apply_trusted_only_rule(p, enabled=False)
                else:
                    self.apply_speed_rules(p, down_bps=normal_down, up_bps=normal_up)
            except Exception as e:
                self.error = f"Failed to restore normal limits during reset: {e}"
        if bool(st.get("disabled_by_policy", False)) and p.disabled:
            try:
                self.client.set_peer_disabled(p.peer_id, False)
            except Exception as e:
                self.error = f"Failed to re-enable peer during reset: {e}"
        st["overlimit_active"] = False
        st["disabled_by_policy"] = False
        st["baseline_rx"] = p.rx
        st["baseline_tx"] = p.tx
        try:
            self.ensure_exempt_counter_rules(p)
            ex_up, ex_down = self.get_peer_exempt_counters(p)
        except Exception:
            ex_up, ex_down = self.peer_exempt_counters.get(p.peer_id, (0, 0))
        st["baseline_exempt_up"] = ex_up
        st["baseline_exempt_down"] = ex_down
        st["baseline_at"] = now_ts()
        try:
            self.install_remote_policy(p, st)
        except Exception as e:
            self.error = f"Remote policy sync failed: {e}"
        self.state.save()
        self.status = f"Usage baseline reset for {p.comment or p.ip}"



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
        return (f"wg-web-check-{sid}", f"wg-web-reset-{sid}")

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

    @staticmethod
    def _parse_scheduler_state_comment(comment: str) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for part in str(comment or "").split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip()
            if key not in {"brx", "btx", "bexu", "bexd", "ov", "db"}:
                continue
            try:
                out[key] = int(value.strip() or "0")
            except ValueError:
                continue
        return out

    def install_remote_policy(self, p: PeerView, st: Dict[str, Any], preserve_existing_state: bool = False) -> None:
        if self.client is None:
            return
        lim_down = int(st.get("traffic_limit_down_bytes", 0) or 0)
        lim_up = int(st.get("traffic_limit_up_bytes", 0) or 0)
        period = int(st.get("traffic_period_seconds", 0) or 0)
        if lim_down <= 0 and lim_up <= 0:
            self.uninstall_remote_policy(p)
            return

        self.ensure_exempt_counter_rules(p)
        ex_up, ex_down = self.get_peer_exempt_counters(p)
        if "baseline_exempt_up" not in st:
            st["baseline_exempt_up"] = ex_up
        if "baseline_exempt_down" not in st:
            st["baseline_exempt_down"] = ex_down

        check_name, reset_name = self.scheduler_names(p)
        existing_check = self.get_scheduler_by_name(check_name)
        existing_comment = str((existing_check or {}).get("comment", "") or "")
        if preserve_existing_state and existing_comment:
            existing_state = self._parse_scheduler_state_comment(existing_comment)
            if "brx" in existing_state:
                st["baseline_rx"] = existing_state["brx"]
            if "btx" in existing_state:
                st["baseline_tx"] = existing_state["btx"]
            if "bexu" in existing_state:
                st["baseline_exempt_up"] = existing_state["bexu"]
            if "bexd" in existing_state:
                st["baseline_exempt_down"] = existing_state["bexd"]

        # Scheduler comment stores compact mutable state for router-side enforcement.
        # brx/btx: total baselines, bexu/bexd: exempt traffic baselines,
        # ov: over-limit mode active, db: disabled-by-policy.
        state_comment = (
            f"brx={int(st.get('baseline_rx', p.rx))};"
            f"btx={int(st.get('baseline_tx', p.tx))};"
            f"bexu={int(st.get('baseline_exempt_up', ex_up))};"
            f"bexd={int(st.get('baseline_exempt_down', ex_down))};"
            "ov=0;db=0;"
        )
        if preserve_existing_state and existing_comment:
            state_comment = existing_comment
        check_script = self.build_policy_check_script(p, st, check_name, reset_name)
        check_payload = {
            "name": check_name,
            "interval": "1m",
            "comment": state_comment,
            "on-event": check_script,
            "disabled": "false",
        }
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
        self.remove_exempt_counter_rules(p)

    def remove_exempt_counter_rules(self, p: PeerView) -> None:
        if self.client is None:
            return
        mangle = self.client.list_mangle() or []
        up_comment, down_comment = self.exempt_rule_comments(p)
        for r in mangle:
            c = str(r.get("comment", ""))
            if c == up_comment or c == down_comment or self._wg_web_row_matches_peer(p, r):
                self.client.delete_mangle(str(r.get(".id")))

    def _wg_web_row_matches_peer(self, p: PeerView, row: Dict[str, Any]) -> bool:
        text = " ".join(
            str(row.get(k, "") or "")
            for k in ("name", "comment", "on-event")
        )
        marker = f"| {p.peer_id} | wg-web"
        legacy = f"{MARKER_PREFIX}:{p.peer_id}:"
        return marker in text or legacy in text

    def cleanup_peer_router_artifacts(self, p: PeerView) -> None:
        if self.client is None:
            raise RuntimeError("Router client is not initialized")

        errors: List[str] = []

        def run(label: str, fn) -> None:
            try:
                fn()
            except Exception as e:
                errors.append(f"{label}: {e}")

        run("policy schedulers/exempt counters", lambda: self.uninstall_remote_policy(p))
        run("trusted-only filter", lambda: self.apply_trusted_only_rule(p, enabled=False))
        run("speed queues", lambda: self.apply_speed_rules(p, down_bps=0, up_bps=0))

        check_name, reset_name = self.scheduler_names(p)

        def remove_leftover_schedulers() -> None:
            for row in self.client.list_scheduler() or []:
                name = str(row.get("name", "") or "")
                if name in (check_name, reset_name) or self._wg_web_row_matches_peer(p, row):
                    self.client.delete_scheduler(str(row.get(".id")))

        def remove_leftover_mangle() -> None:
            for row in self.client.list_mangle() or []:
                if self._wg_web_row_matches_peer(p, row):
                    self.client.delete_mangle(str(row.get(".id")))

        def remove_leftover_filter() -> None:
            for row in self.client.list_filter() or []:
                if self._wg_web_row_matches_peer(p, row):
                    self.client.delete_filter(str(row.get(".id")))

        def remove_leftover_queues() -> None:
            for row in self.client.list_queue_tree() or []:
                if self._wg_web_row_matches_peer(p, row):
                    self.client.delete_queue(str(row.get(".id")))

        run("leftover schedulers", remove_leftover_schedulers)
        run("leftover mangle rules", remove_leftover_mangle)
        run("leftover filter rules", remove_leftover_filter)
        run("leftover queues", remove_leftover_queues)

        if errors:
            raise RuntimeError("; ".join(errors))

    def delete_peer_and_cleanup(self, p: PeerView) -> None:
        if self.client is None:
            raise RuntimeError("Router client is not initialized")
        self.cleanup_peer_router_artifacts(p)
        self.client.delete_peer(p.peer_id)
        self.state.delete_peer(p.peer_id)
        self.state.save()

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
        mcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-web mangle up"
        mcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-web mangle down"
        qcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-web queue up"
        qcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-web queue down"
        ex_comment_up, ex_comment_down = self.exempt_rule_comments(p)
        qname_up = f"{sid}-{uniq}-up"
        qname_down = f"{sid}-{uniq}-down"
        trusted_comment = f"{p.comment or p.ip} | {p.peer_id} | wg-web trusted-only"
        exempt_list = self.cfg_exempt_dst_list
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
            f":local ecu {ros_q(ex_comment_up)};:local ecd {ros_q(ex_comment_down)};"
            f":local qnu {ros_q(qname_up)};:local qnd {ros_q(qname_down)};"
            f":local exList {ros_q(exempt_list)};"
            f":local tComment {ros_q(trusted_comment)};"
            ":local pf [/interface wireguard peers find where .id=$pid];"
            ":if ([:len $pf]=0) do={"
            "/system scheduler remove [find where name=$checkName];"
            "/system scheduler remove [find where name=$resetName];"
            ":error \"peer-missing\";};"
            ":local rx [:tonum [/interface wireguard peers get $pf rx]];"
            ":local tx [:tonum [/interface wireguard peers get $pf tx]];"
            ":local exuRule [/ip firewall mangle find where comment=$ecu];"
            ":if ([:len $exuRule]=0) do={/ip firewall mangle add chain=forward action=passthrough src-address=$pip dst-address-list=$exList comment=$ecu;:set exuRule [/ip firewall mangle find where comment=$ecu];};"
            ":local exdRule [/ip firewall mangle find where comment=$ecd];"
            ":if ([:len $exdRule]=0) do={/ip firewall mangle add chain=forward action=passthrough dst-address=$pip src-address-list=$exList comment=$ecd;:set exdRule [/ip firewall mangle find where comment=$ecd];};"
            ":local exu [:tonum [/ip firewall mangle get $exuRule bytes]];"
            ":local exd [:tonum [/ip firewall mangle get $exdRule bytes]];"
            ":local sf [/system scheduler find where name=$checkName];"
            ":local c [/system scheduler get $sf comment];"
            ":local p1 [:find $c \"brx=\"];:local p2 [:find $c \";btx=\"];"
            ":local p3 [:find $c \";bexu=\"];:local p4 [:find $c \";bexd=\"];"
            ":local p5 [:find $c \";ov=\"];:local p6 [:find $c \";db=\"];"
            ":if (($p1=nil) or ($p2=nil) or ($p3=nil) or ($p4=nil) or ($p5=nil) or ($p6=nil)) do={:set c (\"brx=\".$rx.\";btx=\".$tx.\";bexu=\".$exu.\";bexd=\".$exd.\";ov=0;db=0;\");/system scheduler set $sf comment=$c;};"
            ":set p1 [:find $c \"brx=\"];:set p2 [:find $c \";btx=\"];:set p3 [:find $c \";bexu=\"];:set p4 [:find $c \";bexd=\"];:set p5 [:find $c \";ov=\"];:set p6 [:find $c \";db=\"];"
            ":local brx [:tonum [:pick $c ($p1+4) $p2]];"
            ":local btx [:tonum [:pick $c ($p2+5) $p3]];"
            ":local bexu [:tonum [:pick $c ($p3+6) $p4]];"
            ":local bexd [:tonum [:pick $c ($p4+6) $p5]];"
            ":local ov [:tonum [:pick $c ($p5+4) $p6]];"
            ":local db [:tonum [:pick $c ($p6+4) ([:len $c]-1)]];"
            ":local uu (($rx-$brx)-($exu-$bexu));:local dd (($tx-$btx)-($exd-$bexd));"
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
            " /system scheduler set $sf comment=(\"brx=\".$brx.\";btx=\".$btx.\";bexu=\".$bexu.\";bexd=\".$bexd.\";ov=\".$ov.\";db=\".$db.\";\");"
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
            "/system scheduler set $sf comment=(\"brx=\".$brx.\";btx=\".$btx.\";bexu=\".$bexu.\";bexd=\".$bexd.\";ov=\".$ov.\";db=\".$db.\";\");"
        )

    def build_policy_reset_script(self, p: PeerView, st: Dict[str, Any], check_name: str) -> str:
        # Period reset loop:
        # - baseline := current counters
        # - restore normal queue/filter state
        # - re-enable peer if policy disabled it
        mode = str(st.get("overlimit_mode", "disable") or "disable")
        sid = slug((p.comment or p.ip), max_len=18)
        uniq = safe_id(p.peer_id)
        mark_up = f"wg-{sid}-{uniq}-up"
        mark_down = f"wg-{sid}-{uniq}-down"
        mcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-web mangle up"
        mcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-web mangle down"
        qcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-web queue up"
        qcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-web queue down"
        qname_up = f"{sid}-{uniq}-up"
        qname_down = f"{sid}-{uniq}-down"
        trusted_comment = f"{p.comment or p.ip} | {p.peer_id} | wg-web trusted-only"
        ex_comment_up, ex_comment_down = self.exempt_rule_comments(p)
        norm_down = int(st.get("speed_limit_down_bps", 0) or 0)
        norm_up = int(st.get("speed_limit_up_bps", 0) or 0)
        return (
            f":local pid {ros_q(p.peer_id)};:local checkName {ros_q(check_name)};"
            f":local mode {ros_q(mode)};:local tComment {ros_q(trusted_comment)};"
            f":local pip {ros_q(p.ip)};:local nD {norm_down};:local nU {norm_up};"
            f":local markUp {ros_q(mark_up)};:local markDown {ros_q(mark_down)};"
            f":local mcu {ros_q(mcomment_up)};:local mcd {ros_q(mcomment_down)};"
            f":local qcu {ros_q(qcomment_up)};:local qcd {ros_q(qcomment_down)};"
            f":local qnu {ros_q(qname_up)};:local qnd {ros_q(qname_down)};"
            f":local exList {ros_q(self.cfg_exempt_dst_list)};"
            f":local ecu {ros_q(ex_comment_up)};:local ecd {ros_q(ex_comment_down)};"
            ":local pf [/interface wireguard peers find where .id=$pid];"
            ":if ([:len $pf]=0) do={:error \"peer-missing\";};"
            ":local rx [:tonum [/interface wireguard peers get $pf rx]];"
            ":local tx [:tonum [/interface wireguard peers get $pf tx]];"
            ":local exuRule [/ip firewall mangle find where comment=$ecu];"
            ":if ([:len $exuRule]=0) do={/ip firewall mangle add chain=forward action=passthrough src-address=$pip dst-address-list=$exList comment=$ecu;:set exuRule [/ip firewall mangle find where comment=$ecu];};"
            ":local exdRule [/ip firewall mangle find where comment=$ecd];"
            ":if ([:len $exdRule]=0) do={/ip firewall mangle add chain=forward action=passthrough dst-address=$pip src-address-list=$exList comment=$ecd;:set exdRule [/ip firewall mangle find where comment=$ecd];};"
            ":local exu [:tonum [/ip firewall mangle get $exuRule bytes]];"
            ":local exd [:tonum [/ip firewall mangle get $exdRule bytes]];"
            ":local sf [/system scheduler find where name=$checkName];"
            ":if ([:len $sf]=0) do={:error \"check-missing\";};"
            ":local c [/system scheduler get $sf comment];"
            ":local p4 [:find $c \";db=\"];"
            ":local db 0;"
            ":if ($p4!=nil) do={:set db [:tonum [:pick $c ($p4+4) ([:len $c]-1)]];};"
            ":if (($db=1) and ([/interface wireguard peers get $pf disabled]=true)) do={/interface wireguard peers set $pf disabled=no;};"
            ":if ($mode=\"trusted_only\") do={/ip firewall filter remove [find where comment=$tComment];} else={"
            "  :local mu [/ip firewall mangle find where comment=$mcu];:local md [/ip firewall mangle find where comment=$mcd];"
            "  :local qu [/queue tree find where comment=$qcu];:local qd [/queue tree find where comment=$qcd];"
            "  :if ($nU<=0) do={:if ([:len $mu]>0) do={/ip firewall mangle remove $mu;};:if ([:len $qu]>0) do={/queue tree remove $qu;};} else={"
            "    :if ([:len $mu]=0) do={/ip firewall mangle add chain=forward action=mark-packet src-address=$pip new-packet-mark=$markUp passthrough=no comment=$mcu;}"
            "    else={/ip firewall mangle set $mu chain=forward action=mark-packet src-address=$pip new-packet-mark=$markUp passthrough=no comment=$mcu;};"
            "    :if ([:len $qu]=0) do={/queue tree add name=$qnu parent=global packet-mark=$markUp max-limit=$nU comment=$qcu;}"
            "    else={/queue tree set $qu name=$qnu parent=global packet-mark=$markUp max-limit=$nU comment=$qcu;};};"
            "  :if ($nD<=0) do={:if ([:len $md]>0) do={/ip firewall mangle remove $md;};:if ([:len $qd]>0) do={/queue tree remove $qd;};} else={"
            "    :if ([:len $md]=0) do={/ip firewall mangle add chain=forward action=mark-packet dst-address=$pip new-packet-mark=$markDown passthrough=no comment=$mcd;}"
            "    else={/ip firewall mangle set $md chain=forward action=mark-packet dst-address=$pip new-packet-mark=$markDown passthrough=no comment=$mcd;};"
            "    :if ([:len $qd]=0) do={/queue tree add name=$qnd parent=global packet-mark=$markDown max-limit=$nD comment=$qcd;}"
            "    else={/queue tree set $qd name=$qnd parent=global packet-mark=$markDown max-limit=$nD comment=$qcd;};};"
            "};"
            "/system scheduler set $sf comment=(\"brx=\".$rx.\";btx=\".$tx.\";bexu=\".$exu.\";bexd=\".$exd.\";ov=0;db=0;\");"
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

    def revoke_client(self, p: PeerView) -> None:
        if not self.confirm(f"Revoke key for '{p.comment or p.ip}' and generate new config?"):
            self.status = "Revoke cancelled"
            return
        try:
            priv, pub = self.generate_client_keypair()
            self.client.update_peer_public_key(p.peer_id, pub)
            self.refresh_data(force=True)

            server_pub = ""
            listen_port = "13231"
            ifaces = self.client.list_wireguard_interfaces()
            for iface in ifaces:
                if str(iface.get("name", "")) == p.interface:
                    server_pub = str(iface.get("public-key", "")).strip()
                    listen_port = str(iface.get("listen-port", "13231"))
                    break
            if not server_pub:
                server_pub = "REPLACE_WITH_SERVER_PUBLIC_KEY"

            conf = [
                "[Interface]",
                f"PrivateKey = {priv}",
                f"Address = {p.ip}/32",
                f"DNS = {self.cfg_dns}",
                "",
                "[Peer]",
                f"PublicKey = {server_pub}",
                f"AllowedIPs = {CFG_ALLOWED_IPS}",
                f"Endpoint = {self.cfg_endpoint_host}:{listen_port}",
                f"PersistentKeepalive = {CFG_KEEPALIVE}",
            ]
            safe_name = slug((p.comment or p.ip) + "-revoked", max_len=40)
            self.show_config_dialog("Revoked Client - New Configuration", "\n".join(conf), default_filename=f"{safe_name}.conf")
            self.status = f"Client revoked: {p.comment or p.ip}"
            self.error = ""
        except Exception as e:
            self.error = f"Revoke failed: {e}"


    def apply_trusted_only_rule(self, p: PeerView, enabled: bool) -> None:
        rules = self.client.list_filter()
        marker = f"| {p.peer_id} | wg-web trusted-only"
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
            "comment": f"{display} | {p.peer_id} | wg-web trusted-only",
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
        mcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-web mangle up"
        mcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-web mangle down"
        qcomment_up = f"{p.comment or p.ip} | {p.peer_id} | wg-web queue up"
        qcomment_down = f"{p.comment or p.ip} | {p.peer_id} | wg-web queue down"
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

        def queue_by_comment_or_name(
            rows: List[Dict[str, Any]],
            comment: str,
            legacy: str,
            name: str,
        ) -> Optional[Dict[str, Any]]:
            found = by_comment(rows, comment, legacy)
            if found:
                return found
            for r in rows:
                if str(r.get("name", "")) == name:
                    return r
            return None

        def upsert_queue(existing: Optional[Dict[str, Any]], payload: Dict[str, Any]) -> None:
            if existing:
                self.client.patch_queue(str(existing.get(".id")), payload)
                return
            try:
                self.client.create_queue(payload)
            except RuntimeError as e:
                if "already have such name" not in str(e).lower():
                    raise
                name = str(payload.get("name", ""))
                refreshed = self.client.list_queue_tree()
                duplicate = next((r for r in refreshed if str(r.get("name", "")) == name), None)
                if not duplicate:
                    raise
                self.client.patch_queue(str(duplicate.get(".id")), payload)

        mup = by_comment(mangle, mcomment_up, legacy_mcomment_up)
        mdown = by_comment(mangle, mcomment_down, legacy_mcomment_down)
        qup = queue_by_comment_or_name(queues, qcomment_up, legacy_qcomment_up, qname_up)
        qdown = queue_by_comment_or_name(queues, qcomment_down, legacy_qcomment_down, qname_down)

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
                upsert_queue(qup, qpayload)
            else:
                upsert_queue(None, qpayload)

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
                upsert_queue(qdown, qpayload)
            else:
                upsert_queue(None, qpayload)
