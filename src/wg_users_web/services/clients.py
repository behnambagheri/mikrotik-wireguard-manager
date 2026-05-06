#!/usr/bin/env python3
from .common import *


class ClientManagerMixin:
    def set_enabled(self, peer_id: str, enabled: bool) -> None:
        with self._operation("client set enabled", peer_id=peer_id, enabled=enabled):
            with self._lock:
                p = self._peer_by_id(peer_id)
                self.engine.set_enable(p, enabled)
                self.engine.state.save()

    def batch_set_enabled(self, peer_ids: List[str], enabled: bool) -> Dict[str, Any]:
        with self._operation("batch set enabled", count=len(peer_ids), enabled=enabled):
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
        with self._operation("client delete", peer_id=peer_id):
            with self._lock:
                p = self._peer_by_id(peer_id)
                if self.engine.client is None:
                    raise RuntimeError("Router client is not initialized")
                self.engine.delete_peer_and_cleanup(p)
                self._remove_peer_from_profile_groups(p.peer_id)
                self._sync_all_group_address_lists()
                self._sync_all_group_speed_rules()
                self.engine.refresh_data(force=True)

    def batch_delete_clients(self, peer_ids: List[str]) -> Dict[str, Any]:
        with self._operation("batch client delete", count=len(peer_ids)):
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
                    p = self._peer_by_id(pid)
                    self.engine.delete_peer_and_cleanup(p)
                    self._remove_peer_from_profile_groups(pid)
                    deleted.append(pid)
                self._sync_all_group_address_lists()
                self._sync_all_group_speed_rules()
                self.engine.refresh_data(force=True)
                return {"deleted": deleted, "skipped": skipped, "requested": len(req)}

    def reset_usage(self, peer_id: str) -> None:
        with self._operation("client reset usage", peer_id=peer_id):
            with self._lock:
                p = self._peer_by_id(peer_id)
                self.engine.reset_usage(p)
                self.engine.state.save()

    def batch_reset_usage(self, peer_ids: List[str]) -> Dict[str, Any]:
        with self._operation("batch reset usage", count=len(peer_ids)):
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
        with self._operation("client clear limits", peer_id=peer_id):
            with self._lock:
                p = self._peer_by_id(peer_id)
                self.engine.clear_limits(p)
                self.engine.state.save()

    def batch_clear_limits(self, peer_ids: List[str]) -> Dict[str, Any]:
        with self._operation("batch clear limits", count=len(peer_ids)):
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
        with self._operation("client set speed", peer_id=peer_id, down_mbps=down_mbps, up_mbps=up_mbps):
            with self._lock:
                p = self._peer_by_id(peer_id)
                self._reject_individual_limit_change_for_group_member(p.peer_id)
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
        with self._operation("batch set speed", count=len(peer_ids), down_mbps=down_mbps, up_mbps=up_mbps):
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
                    if self._peer_existing_group_ids(p.peer_id):
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
        with self._operation(
            "client set policy",
            peer_id=peer_id,
            down_gb=down_gb,
            up_gb=up_gb,
            period=period,
            mode=mode,
            over_down_mbps=over_down_mbps,
            over_up_mbps=over_up_mbps,
        ):
            with self._lock:
                p = self._peer_by_id(peer_id)
                self._reject_individual_limit_change_for_group_member(p.peer_id)
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
        with self._operation(
            "batch set policy",
            count=len(peer_ids),
            down_gb=down_gb,
            up_gb=up_gb,
            period=period,
            mode=mode,
            over_down_mbps=over_down_mbps,
            over_up_mbps=over_up_mbps,
        ):
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
                    if self._peer_existing_group_ids(p.peer_id):
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
        with self._operation("client revoke", peer_id=peer_id):
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
        with self._operation("client add", interface=req.interface, ip=req.ip, comment=req.comment.strip()):
            with self._lock:
                if self.engine.client is None:
                    raise RuntimeError("Router client is not initialized")
                if req.comment and not re.fullmatch(r"[A-Za-z0-9 -]{1,32}", req.comment.strip()):
                    raise RuntimeError("Comment must be English letters/digits/space/- and max 32 chars")
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
                    raise RuntimeError(f"No IP address found on interface {iface_name}")
                network = ipaddress.ip_interface(local_cidr).network
                ip_obj = ipaddress.ip_address(req.ip)
                if ip_obj not in network:
                    raise RuntimeError(f"IP {ip_obj} is not in {network}")
                if iface_ip is not None and ip_obj == iface_ip:
                    raise RuntimeError(f"IP {ip_obj} is interface IP and cannot be assigned to peer")
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
