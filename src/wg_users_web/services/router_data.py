#!/usr/bin/env python3
from .common import *


class RouterDataMixin:
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

    def build_wireguard_interfaces_payload(self) -> List[Dict[str, Any]]:
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

    def list_wireguard_interfaces(self) -> List[Dict[str, Any]]:
        with self._lock:
            self.engine.refresh_data(force=False)
            return self.build_wireguard_interfaces_payload()

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

    def interface_ip_pool_info(self, interface: str) -> Dict[str, Any]:
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
                        iface_ip = str(ipaddress.ip_interface(local_cidr).ip)
                    except Exception:
                        iface_ip = None
                    break
            if not local_cidr:
                raise RuntimeError(f"No IP address found on interface {interface}")
            network = ipaddress.ip_interface(local_cidr).network
            used_ips: List[str] = []
            for p in peers:
                if p.interface != interface:
                    continue
                try:
                    used_ips.append(str(ipaddress.ip_address(p.ip)))
                except Exception:
                    continue
            return {
                "interface": interface,
                "cidr": str(network),
                "interface_ip": iface_ip,
                "used_ips": sorted(set(used_ips)),
            }

    def build_clients_payload(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        now = int(time.time())
        try:
            groups_by_peer = self._peer_group_map()
        except Exception:
            groups_by_peer = {}
        for p in self.engine.peers:
            st = self.engine.state.peer(p.peer_id)
            peer_groups = groups_by_peer.get(p.peer_id, [])
            speed_groups = [g for g in peer_groups if g.get("has_speed_limit")]
            policy_groups = [g for g in peer_groups if g.get("has_policy")]
            individual_speed = int(st.get("speed_limit_down_bps", 0) or 0) > 0 or int(st.get("speed_limit_up_bps", 0) or 0) > 0
            individual_policy = int(st.get("traffic_limit_down_bytes", 0) or 0) > 0 or int(st.get("traffic_limit_up_bytes", 0) or 0) > 0
            individual_limits = self._peer_has_individual_limits(st)
            conflict_notes: List[str] = []
            if speed_groups and individual_speed:
                conflict_notes.append("group speed overrides individual speed")
            if policy_groups and individual_policy:
                conflict_notes.append("group policy can override individual policy")
            down_used, up_used = self.engine.peer_used_bytes(p, st)
            period_seconds = int(st.get("traffic_period_seconds", 0) or 0)
            baseline_at = int(st.get("baseline_at", 0) or 0)
            baseline_age_seconds = max(0, now - baseline_at) if baseline_at > 0 else 0
            traffic_reset_elapsed_seconds = min(period_seconds, baseline_age_seconds) if period_seconds > 0 else 0
            traffic_reset_remaining_seconds = max(0, period_seconds - baseline_age_seconds) if period_seconds > 0 else 0
            traffic_reset_progress_pct = ((traffic_reset_elapsed_seconds / period_seconds) * 100.0) if period_seconds > 0 else 0.0
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
                    "traffic_period_seconds": period_seconds,
                    "baseline_at": baseline_at,
                    "baseline_age_seconds": baseline_age_seconds,
                    "traffic_reset_elapsed_seconds": traffic_reset_elapsed_seconds,
                    "traffic_reset_remaining_seconds": traffic_reset_remaining_seconds,
                    "traffic_reset_progress_pct": traffic_reset_progress_pct,
                    "overlimit_mode": str(st.get("overlimit_mode", "disable") or "disable"),
                    "overlimit_speed_down_bps": int(st.get("overlimit_speed_down_bps", 0) or 0),
                    "overlimit_speed_up_bps": int(st.get("overlimit_speed_up_bps", 0) or 0),
                    "overlimit_active": bool(st.get("overlimit_active", False)),
                    "speed_limit_down_bps": int(st.get("speed_limit_down_bps", 0) or 0),
                    "speed_limit_up_bps": int(st.get("speed_limit_up_bps", 0) or 0),
                    "groups": peer_groups,
                    "group_names": ", ".join(g["name"] for g in peer_groups),
                    "has_individual_limits": individual_limits,
                    "effective_speed_scope": "group" if speed_groups else ("individual" if individual_speed else "none"),
                    "effective_speed_group_names": ", ".join(g["name"] for g in speed_groups),
                    "effective_policy_scope": "group" if policy_groups else ("individual" if individual_policy else "none"),
                    "effective_policy_group_names": ", ".join(g["name"] for g in policy_groups),
                    "limit_conflicts": conflict_notes,
                    "limit_conflict_count": len(conflict_notes),
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

    def build_dashboard_snapshot(self, status: str = "ok") -> Dict[str, Any]:
        return {
            "status": status,
            "profile": self.current_profile(),
            "overview": self.router_overview(),
            "interfaces": self.interface_stats(),
            "wireguard_interfaces": self.build_wireguard_interfaces_payload(),
            "groups": self.build_groups_payload(),
            "clients": self.build_clients_payload(),
        }

    def dashboard_snapshot(self, force_refresh: bool = False) -> Dict[str, Any]:
        with self._operation("dashboard snapshot", refresh=force_refresh):
            with self._busy_lock("dashboard snapshot"):
                if force_refresh:
                    self.engine.refresh_data(force=True)
                return self.build_dashboard_snapshot()
