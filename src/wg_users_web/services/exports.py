#!/usr/bin/env python3
import json

from .common import *


class ExportManagerMixin:
    # Panel settings are user-facing preferences and live in the same JSON state file
    # as router-side client/group baselines.
    def panel_settings(self) -> Dict[str, Any]:
        with self._lock:
            settings = self.engine.state.data.setdefault("panel_settings", {})
            return dict(settings) if isinstance(settings, dict) else {}

    def save_panel_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            current = self.engine.state.data.setdefault("panel_settings", {})
            if not isinstance(current, dict):
                current = {}
            current.update(settings or {})
            self.engine.state.data["panel_settings"] = current
            self.engine.state.save()
            return dict(current)

    def export_users_json(self) -> str:
        with self._operation("export users json"):
            with self._lock:
                self.engine.refresh_data(force=False)
                ts = time.strftime("%Y%m%d-%H%M%S")
                path = f"users-snapshot-{self.engine.profile_name}-{ts}.json"
                users = self.list_clients()
                groups = self.list_groups()
                payload = {
                    "generated_at_epoch": int(time.time()),
                    "generated_at_local": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "router_profile": self.engine.profile_name,
                    "router_ip": self.engine.host,
                    "users_count": len(users),
                    "groups_count": len(groups),
                    "poll_latency_ms": self.engine.last_poll_latency_ms,
                    "exempt_destination_list": self.engine.cfg_exempt_dst_list,
                    "groups": groups,
                    "users": users,
                }
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                return path

    def export_users_pdf(self) -> str:
        with self._operation("export users pdf"):
            with self._lock:
                self.engine.refresh_data(force=False)
                ts = time.strftime("%Y%m%d-%H%M%S")
                path = f"users-snapshot-{self.engine.profile_name}-{ts}.pdf"
                users = self.list_clients()
                groups = self.list_groups()
                lines: List[str] = [
                    "WireGuard Users and Groups Snapshot",
                    f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                    f"Router: {self.engine.profile_name}@{self.engine.host}",
                    f"Users: {len(users)} | Groups: {len(groups)}",
                    f"Exempt destination list: {self.engine.cfg_exempt_dst_list}",
                    "-" * 120,
                    "Groups",
                ]
                if not groups:
                    lines.append("No groups configured.")
                for g in groups:
                    members = ", ".join(str(m.get("name") or m.get("ip") or m.get("peer_id")) for m in g.get("members", []))
                    lines.extend(
                        [
                            f"- {g.get('name')} ({g.get('member_count', 0)} members)",
                            f"  Members: {members or '-'}",
                            f"  Speed D/U: {bps_h(float(g.get('speed_limit_down_bps', 0)))} / {bps_h(float(g.get('speed_limit_up_bps', 0)))}",
                            f"  Quota D/U: {bytes_h(int(g.get('traffic_limit_down_bytes', 0) or 0))} / {bytes_h(int(g.get('traffic_limit_up_bytes', 0) or 0))}",
                            f"  Mode: {g.get('overlimit_mode')} | Period: {g.get('traffic_period_seconds', 0)}s",
                        ]
                    )
                lines.extend(["-" * 120, "Users"])
                for idx, u in enumerate(users, start=1):
                    lines.extend(
                        [
                            f"{idx}. {u.get('name') or '-'} | {u.get('ip')} | {u.get('interface')} | {u.get('state')}",
                            f"   Groups: {u.get('group_names') or '-'} | Effective: speed={u.get('effective_speed_scope')} policy={u.get('effective_policy_scope')}",
                            f"   Total D/U: {u.get('total_download')} / {u.get('total_upload')} | Current D/U: {u.get('down_speed')} / {u.get('up_speed')}",
                            f"   Used D/U: {u.get('download_since_now')} / {u.get('upload_since_now')} | Last HS: {u.get('last_handshake') or '-'}",
                            "-" * 120,
                        ]
                    )
                max_lines_per_page = 50
                pages = [lines[i : i + max_lines_per_page] for i in range(0, len(lines), max_lines_per_page)]
                self.engine.write_simple_pdf(path, pages)
                return path

    def export_dashboard_json(self) -> str:
        with self._operation("export dashboard json"):
            with self._lock:
                self.engine.refresh_data(force=False)
                return self.engine.export_dashboard_snapshot(csv_mode=False)

    def export_dashboard_csv(self) -> str:
        with self._operation("export dashboard csv"):
            with self._lock:
                self.engine.refresh_data(force=False)
                return self.engine.export_dashboard_snapshot(csv_mode=True)

    def diagnostics(self) -> List[Dict[str, str]]:
        with self._operation("diagnostics run"):
            with self._lock:
                self.engine.run_connection_diagnostics()
                return self.engine.diagnostics
