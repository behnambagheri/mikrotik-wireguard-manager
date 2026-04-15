#!/usr/bin/env python3
import ipaddress
import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .app import (
    App,
    CFG_ALLOWED_IPS,
    CFG_KEEPALIVE,
    RouterOSClient,
    bps_h,
    bytes_h,
    gb_to_bytes,
    mbps_to_bps,
    parse_period_input,
    slug,
)


class _DummyScreen:
    def getmaxyx(self) -> Tuple[int, int]:
        return (40, 120)

    def nodelay(self, *_args: Any, **_kwargs: Any) -> None:
        return

    def timeout(self, *_args: Any, **_kwargs: Any) -> None:
        return


@dataclass
class AddClientRequest:
    interface: str
    ip: str
    comment: str = ""
    speed_down_mbps: Optional[float] = None
    speed_up_mbps: Optional[float] = None
    limit_down_gb: Optional[float] = None
    limit_up_gb: Optional[float] = None
    period: Optional[str] = None
    overlimit_mode: Optional[str] = None
    overlimit_down_mbps: Optional[float] = None
    overlimit_up_mbps: Optional[float] = None


class WebManager:
    def __init__(self) -> None:
        # Re-entrant lock is required because some high-level operations
        # call other methods that also acquire the manager lock.
        self._lock = threading.RLock()
        self.engine = App(_DummyScreen())
        self._bootstrap_non_interactive()
        self.engine.refresh_data(force=True)

    def _bootstrap_non_interactive(self) -> None:
        # Web mode must never invoke curses dialogs.
        if self.engine.profiles:
            preferred = os.environ.get("WG_WEB_DEFAULT_PROFILE", "").strip()
            if preferred and preferred in self.engine.profiles:
                name = preferred
            else:
                name = sorted(self.engine.profiles.keys())[0]
            self.engine.connect_profile(name, self.engine.profiles[name])
            return

        host = self.engine.host or os.environ.get("ROUTER_IP", "").strip()
        user = self.engine.user or os.environ.get("ROUTER_USER", "").strip()
        password = os.environ.get("ROUTER_PASS", "").strip().strip('"').strip("'")
        if not host or not user or not password:
            raise RuntimeError(
                "Missing router config for web mode. Configure .env profiles or ROUTER_IP/ROUTER_USER/ROUTER_PASS."
            )
        use_https = os.environ.get("ROUTER_USE_HTTPS", "false").lower() == "true"
        timeout_sec = float(os.environ.get("ROUTER_TIMEOUT_SEC", "30") or "30")
        self.engine.profile_name = "default"
        self.engine.host = host
        self.engine.user = user
        self.engine.password = password
        self.engine.use_https = use_https
        self.engine.timeout_sec = timeout_sec
        self.engine.cfg_dns = os.environ.get("DNS_SERVERS", self.engine.cfg_dns).strip() or self.engine.cfg_dns
        self.engine.cfg_endpoint_host = os.environ.get("ENDPOINT_IP", self.engine.cfg_endpoint_host).strip() or self.engine.cfg_endpoint_host
        self.engine.client = RouterOSClient(host, user, password, use_https=use_https, timeout_sec=timeout_sec)

    def current_profile(self) -> str:
        return self.engine.profile_name

    def list_profiles(self) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        for name in sorted(self.engine.profiles.keys()):
            p = self.engine.profiles[name]
            rows.append(
                {
                    "name": name,
                    "router_ip": p.get("router_ip", ""),
                    "transport": p.get("transport", "rest"),
                    "endpoint_ip": p.get("endpoint_ip", ""),
                }
            )
        return rows

    def select_profile(self, name: str) -> None:
        with self._lock:
            if name not in self.engine.profiles:
                raise RuntimeError(f"Profile not found: {name}")
            self.engine.connect_profile(name, self.engine.profiles[name])
            self.engine.reset_runtime_caches()
            self.engine.refresh_data(force=True)

    def refresh(self) -> None:
        with self._lock:
            self.engine.refresh_data(force=True)

    def _peer_by_id(self, peer_id: str):
        for p in self.engine.peers:
            if p.peer_id == peer_id:
                return p
        raise RuntimeError(f"Peer not found: {peer_id}")

    def router_overview(self) -> Dict[str, Any]:
        with self._lock:
            rr = self.engine.router_resource or {}
            rx, tx = self.engine.total_bandwidth()
            # Fallback for environments where interface byte counters are not
            # exposed/reliable: derive approximate totals from peer live speeds.
            if (rx + tx) <= 0 and self.engine.peers:
                rx = sum(max(0.0, float(p.up_speed_bps or 0.0)) for p in self.engine.peers)
                tx = sum(max(0.0, float(p.down_speed_bps or 0.0)) for p in self.engine.peers)
            return {
                "profile": self.engine.profile_name,
                "router": self.engine.host,
                "resource": rr,
                "bandwidth_bps": {"rx": int(rx), "tx": int(tx), "total": int(rx + tx)},
                "alerts": self.engine.dashboard_alerts(),
                "wg_health": self.engine.wg_interface_health(),
                "poll_latency_ms": self.engine.last_poll_latency_ms,
                "status": self.engine.status,
                "error": self.engine.error,
            }

    def interface_stats(self) -> List[Dict[str, Any]]:
        with self._lock:
            out: List[Dict[str, Any]] = []
            for row in self.engine.interfaces:
                name = str(row.get("name", ""))
                if not name:
                    continue
                rx_bps, tx_bps = self.engine.iface_speed.get(name, (0.0, 0.0))
                rx = int(row.get("rx-byte", 0) or 0)
                tx = int(row.get("tx-byte", 0) or 0)
                brx, btx = self.engine.iface_baseline.get(name, (rx, tx))
                used = max(0, rx - brx) + max(0, tx - btx)
                out.append(
                    {
                        "name": name,
                        "type": str(row.get("type", "")),
                        "running": str(row.get("running", "")),
                        "rx_bps": int(rx_bps),
                        "tx_bps": int(tx_bps),
                        "combined_bps": int(rx_bps + tx_bps),
                        "window_usage_bytes": used,
                        "window_usage_h": bytes_h(used),
                        "rx_h": bps_h(rx_bps),
                        "tx_h": bps_h(tx_bps),
                    }
                )
            out.sort(key=lambda x: int(x.get("combined_bps", 0)), reverse=True)
            return out

    def list_wireguard_interfaces(self) -> List[Dict[str, Any]]:
        with self._lock:
            self.engine.refresh_data(force=False)
            if self.engine.client is None:
                raise RuntimeError("Router client is not initialized")
            ifaces = self.engine.client.list_wireguard_interfaces() or []
            out = []
            for i in ifaces:
                out.append(
                    {
                        "name": str(i.get("name", "")),
                        "listen_port": str(i.get("listen-port", "")),
                        "public_key": str(i.get("public-key", "")),
                    }
                )
            return out

    def suggest_ip(self, interface: str) -> str:
        with self._lock:
            if self.engine.client is None:
                raise RuntimeError("Router client is not initialized")
            ip_rows = self.engine.client.list_ip_addresses()
            peers = self.engine.client.list_peers()
            local_cidr = ""
            iface_ip = None
            for r in ip_rows:
                if str(r.get("interface", "")) == interface:
                    local_cidr = str(r.get("address", ""))
                    try:
                        iface_ip = ipaddress.ip_interface(local_cidr).ip
                    except Exception:
                        iface_ip = None
                    break
            if not local_cidr:
                raise RuntimeError(f"No IP address found on interface {interface}")
            network = ipaddress.ip_interface(local_cidr).network
            used = set()
            for p in peers:
                if p.interface != interface:
                    continue
                try:
                    used.add(ipaddress.ip_address(p.ip))
                except Exception:
                    pass
            if iface_ip:
                used.add(iface_ip)
            used.add(ipaddress.ip_address("100.100.100.100"))
            used.add(ipaddress.ip_address("100.100.100.101"))

            for host in network.hosts():
                if host in used:
                    continue
                return str(host)
            raise RuntimeError(f"No free IP found in {network}")

    def build_clients_payload(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for p in self.engine.peers:
            st = self.engine.state.peer(p.peer_id)
            down_used, up_used = self.engine.peer_used_bytes(p, st)
            out.append(
                {
                    "peer_id": p.peer_id,
                    "name": p.comment,
                    "interface": p.interface,
                    "ip": p.ip,
                    "state": "disabled" if p.disabled else "enabled",
                    "download_since_now_bytes": down_used,
                    "upload_since_now_bytes": up_used,
                    "download_since_now": bytes_h(down_used),
                    "upload_since_now": bytes_h(up_used),
                    "total_download_bytes": p.tx,
                    "total_upload_bytes": p.rx,
                    "total_download": bytes_h(p.tx),
                    "total_upload": bytes_h(p.rx),
                    "down_speed_bps": p.down_speed_bps,
                    "up_speed_bps": p.up_speed_bps,
                    "down_speed": bps_h(p.down_speed_bps),
                    "up_speed": bps_h(p.up_speed_bps),
                    "traffic_limit_down_bytes": int(st.get("traffic_limit_down_bytes", 0) or 0),
                    "traffic_limit_up_bytes": int(st.get("traffic_limit_up_bytes", 0) or 0),
                    "traffic_period_seconds": int(st.get("traffic_period_seconds", 0) or 0),
                    "overlimit_mode": str(st.get("overlimit_mode", "disable") or "disable"),
                    "overlimit_speed_down_bps": int(st.get("overlimit_speed_down_bps", 0) or 0),
                    "overlimit_speed_up_bps": int(st.get("overlimit_speed_up_bps", 0) or 0),
                    "overlimit_active": bool(st.get("overlimit_active", False)),
                    "speed_limit_down_bps": int(st.get("speed_limit_down_bps", 0) or 0),
                    "speed_limit_up_bps": int(st.get("speed_limit_up_bps", 0) or 0),
                    "last_handshake": p.last_handshake,
                }
            )
        return out

    def list_clients(self) -> List[Dict[str, Any]]:
        with self._lock:
            self.engine.refresh_data(force=False)
            return self.build_clients_payload()

    def get_client(self, peer_id: str) -> Dict[str, Any]:
        with self._lock:
            self.engine.refresh_data(force=False)
            for row in self.build_clients_payload():
                if row["peer_id"] == peer_id:
                    return row
            raise RuntimeError(f"Peer not found: {peer_id}")

    def set_enabled(self, peer_id: str, enabled: bool) -> None:
        with self._lock:
            p = self._peer_by_id(peer_id)
            self.engine.set_enable(p, enabled)
            self.engine.state.save()

    def batch_set_enabled(self, peer_ids: List[str], enabled: bool) -> Dict[str, Any]:
        with self._lock:
            req = [str(x or "").strip() for x in peer_ids if str(x or "").strip()]
            if not req:
                raise RuntimeError("No peer ids provided")
            existing = {p.peer_id for p in self.engine.peers}
            updated: List[str] = []
            skipped: List[str] = []
            for pid in req:
                if pid not in existing:
                    skipped.append(pid)
                    continue
                p = self._peer_by_id(pid)
                self.engine.set_enable(p, enabled)
                updated.append(pid)
            self.engine.state.save()
            self.engine.refresh_data(force=True)
            return {"updated": updated, "skipped": skipped, "requested": len(req), "enabled": enabled}

    def delete_client(self, peer_id: str) -> None:
        with self._lock:
            p = self._peer_by_id(peer_id)
            if self.engine.client is None:
                raise RuntimeError("Router client is not initialized")
            self.engine.client.delete_peer(p.peer_id)
            self.engine.state.save()
            self.engine.refresh_data(force=True)

    def batch_delete_clients(self, peer_ids: List[str]) -> Dict[str, Any]:
        with self._lock:
            if self.engine.client is None:
                raise RuntimeError("Router client is not initialized")
            req = [str(x or "").strip() for x in peer_ids if str(x or "").strip()]
            if not req:
                raise RuntimeError("No peer ids provided")
            existing = {p.peer_id for p in self.engine.peers}
            deleted: List[str] = []
            skipped: List[str] = []
            for pid in req:
                if pid not in existing:
                    skipped.append(pid)
                    continue
                self.engine.client.delete_peer(pid)
                deleted.append(pid)
            self.engine.state.save()
            self.engine.refresh_data(force=True)
            return {"deleted": deleted, "skipped": skipped, "requested": len(req)}

    def reset_usage(self, peer_id: str) -> None:
        with self._lock:
            p = self._peer_by_id(peer_id)
            self.engine.reset_usage(p)
            self.engine.state.save()

    def batch_reset_usage(self, peer_ids: List[str]) -> Dict[str, Any]:
        with self._lock:
            req = [str(x or "").strip() for x in peer_ids if str(x or "").strip()]
            if not req:
                raise RuntimeError("No peer ids provided")
            existing = {p.peer_id: p for p in self.engine.peers}
            updated: List[str] = []
            skipped: List[str] = []
            for pid in req:
                p = existing.get(pid)
                if p is None:
                    skipped.append(pid)
                    continue
                self.engine.reset_usage(p)
                updated.append(pid)
            self.engine.state.save()
            self.engine.refresh_data(force=True)
            return {"updated": updated, "skipped": skipped, "requested": len(req)}

    def clear_limits(self, peer_id: str) -> None:
        with self._lock:
            p = self._peer_by_id(peer_id)
            self.engine.clear_limits(p)
            self.engine.state.save()

    def batch_clear_limits(self, peer_ids: List[str]) -> Dict[str, Any]:
        with self._lock:
            req = [str(x or "").strip() for x in peer_ids if str(x or "").strip()]
            if not req:
                raise RuntimeError("No peer ids provided")
            existing = {p.peer_id: p for p in self.engine.peers}
            updated: List[str] = []
            skipped: List[str] = []
            for pid in req:
                p = existing.get(pid)
                if p is None:
                    skipped.append(pid)
                    continue
                self.engine.clear_limits(p)
                updated.append(pid)
            self.engine.state.save()
            self.engine.refresh_data(force=True)
            return {"updated": updated, "skipped": skipped, "requested": len(req)}

    def set_speed_limits(self, peer_id: str, down_mbps: float, up_mbps: float) -> None:
        with self._lock:
            p = self._peer_by_id(peer_id)
            st = self.engine.state.peer(p.peer_id)
            down_bps = mbps_to_bps(down_mbps) if down_mbps > 0 else 0
            up_bps = mbps_to_bps(up_mbps) if up_mbps > 0 else 0
            self.engine.apply_speed_rules(p, down_bps=down_bps, up_bps=up_bps)
            st["speed_limit_down_bps"] = down_bps
            st["speed_limit_up_bps"] = up_bps
            self.engine.install_remote_policy(p, st)
            self.engine.state.save()
            self.engine.refresh_data(force=True)

    def batch_set_speed_limits(self, peer_ids: List[str], down_mbps: float, up_mbps: float) -> Dict[str, Any]:
        with self._lock:
            req = [str(x or "").strip() for x in peer_ids if str(x or "").strip()]
            if not req:
                raise RuntimeError("No peer ids provided")
            existing = {p.peer_id: p for p in self.engine.peers}
            updated: List[str] = []
            skipped: List[str] = []
            down_bps = mbps_to_bps(down_mbps) if down_mbps > 0 else 0
            up_bps = mbps_to_bps(up_mbps) if up_mbps > 0 else 0
            for pid in req:
                p = existing.get(pid)
                if p is None:
                    skipped.append(pid)
                    continue
                st = self.engine.state.peer(p.peer_id)
                self.engine.apply_speed_rules(p, down_bps=down_bps, up_bps=up_bps)
                st["speed_limit_down_bps"] = down_bps
                st["speed_limit_up_bps"] = up_bps
                self.engine.install_remote_policy(p, st)
                updated.append(pid)
            self.engine.state.save()
            self.engine.refresh_data(force=True)
            return {"updated": updated, "skipped": skipped, "requested": len(req)}

    def set_traffic_policy(
        self,
        peer_id: str,
        down_gb: float,
        up_gb: float,
        period: str,
        mode: str,
        over_down_mbps: float,
        over_up_mbps: float,
    ) -> None:
        with self._lock:
            p = self._peer_by_id(peer_id)
            st = self.engine.state.peer(p.peer_id)
            period_s = parse_period_input(period) if period.strip() else 0
            mode_value = (mode or "disable").strip().lower()
            if mode_value in ("trusted", "trusted-only", "trustedonly"):
                mode_value = "trusted_only"
            if mode_value not in ("disable", "throttle", "trusted_only"):
                raise ValueError("mode must be disable, throttle, or trusted_only")
            st["traffic_limit_down_bytes"] = gb_to_bytes(down_gb) if down_gb > 0 else 0
            st["traffic_limit_up_bytes"] = gb_to_bytes(up_gb) if up_gb > 0 else 0
            st["traffic_period_seconds"] = period_s
            st["overlimit_mode"] = mode_value
            st["overlimit_speed_down_bps"] = mbps_to_bps(over_down_mbps) if over_down_mbps > 0 else 0
            st["overlimit_speed_up_bps"] = mbps_to_bps(over_up_mbps) if over_up_mbps > 0 else 0
            st["overlimit_active"] = False
            st["disabled_by_policy"] = False
            self.engine.apply_trusted_only_rule(p, enabled=False)
            self.engine.reset_usage(p)
            self.engine.install_remote_policy(p, st)
            self.engine.state.save()
            self.engine.refresh_data(force=True)

    def batch_set_traffic_policy(
        self,
        peer_ids: List[str],
        down_gb: float,
        up_gb: float,
        period: str,
        mode: str,
        over_down_mbps: float,
        over_up_mbps: float,
    ) -> Dict[str, Any]:
        with self._lock:
            req = [str(x or "").strip() for x in peer_ids if str(x or "").strip()]
            if not req:
                raise RuntimeError("No peer ids provided")
            existing = {p.peer_id: p for p in self.engine.peers}
            period_s = parse_period_input(period) if period.strip() else 0
            mode_value = (mode or "disable").strip().lower()
            if mode_value in ("trusted", "trusted-only", "trustedonly"):
                mode_value = "trusted_only"
            if mode_value not in ("disable", "throttle", "trusted_only"):
                raise ValueError("mode must be disable, throttle, or trusted_only")

            updated: List[str] = []
            skipped: List[str] = []
            for pid in req:
                p = existing.get(pid)
                if p is None:
                    skipped.append(pid)
                    continue
                st = self.engine.state.peer(p.peer_id)
                st["traffic_limit_down_bytes"] = gb_to_bytes(down_gb) if down_gb > 0 else 0
                st["traffic_limit_up_bytes"] = gb_to_bytes(up_gb) if up_gb > 0 else 0
                st["traffic_period_seconds"] = period_s
                st["overlimit_mode"] = mode_value
                st["overlimit_speed_down_bps"] = mbps_to_bps(over_down_mbps) if over_down_mbps > 0 else 0
                st["overlimit_speed_up_bps"] = mbps_to_bps(over_up_mbps) if over_up_mbps > 0 else 0
                st["overlimit_active"] = False
                st["disabled_by_policy"] = False
                self.engine.apply_trusted_only_rule(p, enabled=False)
                self.engine.reset_usage(p)
                self.engine.install_remote_policy(p, st)
                updated.append(pid)
            self.engine.state.save()
            self.engine.refresh_data(force=True)
            return {"updated": updated, "skipped": skipped, "requested": len(req)}

    def revoke_client(self, peer_id: str) -> Dict[str, str]:
        with self._lock:
            p = self._peer_by_id(peer_id)
            priv, pub = self.engine.generate_client_keypair()
            if self.engine.client is None:
                raise RuntimeError("Router client is not initialized")
            self.engine.client.update_peer_public_key(p.peer_id, pub)
            self.engine.refresh_data(force=True)

            server_pub = ""
            listen_port = "13231"
            ifaces = self.engine.client.list_wireguard_interfaces()
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
                f"DNS = {self.engine.cfg_dns}",
                "",
                "[Peer]",
                f"PublicKey = {server_pub}",
                f"AllowedIPs = {CFG_ALLOWED_IPS}",
                f"Endpoint = {self.engine.cfg_endpoint_host}:{listen_port}",
                f"PersistentKeepalive = {CFG_KEEPALIVE}",
            ]
            filename = f"{slug((p.comment or p.ip) + '-revoked', max_len=40)}.conf"
            return {"config": "\n".join(conf), "filename": filename}

    def add_client(self, req: AddClientRequest) -> Dict[str, str]:
        with self._lock:
            if self.engine.client is None:
                raise RuntimeError("Router client is not initialized")
            ifaces = self.engine.client.list_wireguard_interfaces()
            iface = None
            for i in ifaces:
                if str(i.get("name", "")) == req.interface:
                    iface = i
                    break
            if iface is None:
                raise RuntimeError(f"Interface not found: {req.interface}")

            iface_name = str(iface.get("name", "wireguard"))
            listen_port = str(iface.get("listen-port", "13231"))
            server_pub = str(iface.get("public-key", "")).strip()

            ip_rows = self.engine.client.list_ip_addresses()
            peers = self.engine.client.list_peers()
            local_cidr = ""
            for r in ip_rows:
                if str(r.get("interface", "")) == iface_name:
                    local_cidr = str(r.get("address", ""))
                    break
            if not local_cidr:
                raise RuntimeError(f"No IP address found on interface {iface_name}")
            network = ipaddress.ip_interface(local_cidr).network
            ip_obj = ipaddress.ip_address(req.ip)
            if ip_obj not in network:
                raise RuntimeError(f"IP {ip_obj} is not in {network}")
            for p in peers:
                if p.interface == iface_name and p.ip == str(ip_obj):
                    raise RuntimeError(f"IP {ip_obj} is already used")

            priv, pub = self.engine.generate_client_keypair()
            payload = {
                "interface": iface_name,
                "allowed-address": f"{ip_obj}/32",
                "public-key": pub,
                "disabled": "false",
            }
            if req.comment.strip():
                payload["comment"] = req.comment.strip()
            self.engine.client.create_peer(payload)
            self.engine.refresh_data(force=True)

            created = next((x for x in self.engine.peers if x.interface == iface_name and x.ip == str(ip_obj)), None)
            if created is None:
                raise RuntimeError("Peer created but not found in refreshed list")

            if req.speed_down_mbps is not None or req.speed_up_mbps is not None:
                self.set_speed_limits(
                    created.peer_id,
                    float(req.speed_down_mbps or 0),
                    float(req.speed_up_mbps or 0),
                )

            has_policy = any(
                x is not None
                for x in (
                    req.limit_down_gb,
                    req.limit_up_gb,
                    req.period,
                    req.overlimit_mode,
                    req.overlimit_down_mbps,
                    req.overlimit_up_mbps,
                )
            )
            if has_policy:
                self.set_traffic_policy(
                    created.peer_id,
                    float(req.limit_down_gb or 0),
                    float(req.limit_up_gb or 0),
                    req.period or "0",
                    req.overlimit_mode or "disable",
                    float(req.overlimit_down_mbps or 0),
                    float(req.overlimit_up_mbps or 0),
                )

            conf = [
                "[Interface]",
                f"PrivateKey = {priv}",
                f"Address = {ip_obj}/32",
                f"DNS = {self.engine.cfg_dns}",
                "",
                "[Peer]",
                f"PublicKey = {server_pub}",
                f"AllowedIPs = {CFG_ALLOWED_IPS}",
                f"Endpoint = {self.engine.cfg_endpoint_host}:{listen_port}",
                f"PersistentKeepalive = {CFG_KEEPALIVE}",
            ]
            filename = f"{slug(req.comment.strip() or str(ip_obj), max_len=32)}.conf"
            return {"config": "\n".join(conf), "filename": filename, "peer_id": created.peer_id}

    def export_users_json(self) -> str:
        with self._lock:
            self.engine.refresh_data(force=False)
            return self.engine.export_users_snapshot_json()

    def export_users_pdf(self) -> str:
        with self._lock:
            self.engine.refresh_data(force=False)
            return self.engine.export_users_snapshot_pdf()

    def export_dashboard_json(self) -> str:
        with self._lock:
            self.engine.refresh_data(force=False)
            return self.engine.export_dashboard_snapshot(csv_mode=False)

    def export_dashboard_csv(self) -> str:
        with self._lock:
            self.engine.refresh_data(force=False)
            return self.engine.export_dashboard_snapshot(csv_mode=True)

    def diagnostics(self) -> List[Dict[str, str]]:
        with self._lock:
            self.engine.run_connection_diagnostics()
            return self.engine.diagnostics


def load_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
