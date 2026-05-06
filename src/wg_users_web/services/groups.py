#!/usr/bin/env python3
from .common import *


class GroupManagerMixin:
    def _profile_state_key(self) -> str:
        profile = getattr(self.engine, "profile_name", "")
        if isinstance(profile, str) and profile.strip():
            return profile.strip()
        host = getattr(self.engine, "host", "")
        if isinstance(host, str) and host.strip():
            return host.strip()
        return "default"

    def _profile_state(self) -> Dict[str, Any]:
        profiles = self.engine.state.data.setdefault("profiles", {})
        key = self._profile_state_key()
        scoped = profiles.setdefault(key, {})
        groups = scoped.setdefault("groups", {})

        # One-time safety migration for state files created before groups were
        # profile-scoped. Move legacy global groups into the currently active
        # profile so they cannot leak into later router/profile selections.
        legacy = self.engine.state.data.get("groups", {})
        if legacy and not groups:
            groups.update(legacy)
            self.engine.state.data["groups"] = {}
        return scoped

    def _groups(self) -> Dict[str, Any]:
        return self._profile_state().setdefault("groups", {})

    def _remove_peer_from_profile_groups(self, peer_id: str) -> None:
        for group in self._groups().values():
            peer_ids = group.get("peer_ids", [])
            if isinstance(peer_ids, list):
                group["peer_ids"] = [pid for pid in peer_ids if pid != peer_id]

    @staticmethod
    def _validate_group_name(name: str) -> str:
        n = str(name or "").strip()
        if not n:
            raise RuntimeError("Group name is required")
        if len(n) > 64:
            raise RuntimeError("Group name must be 64 characters or less")
        if not re.fullmatch(r"[A-Za-z0-9 _.-]+", n):
            raise RuntimeError("Group name must use English letters, digits, space, _, -, or .")
        return n

    @staticmethod
    def _clean_peer_ids(peer_ids: List[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for raw in peer_ids or []:
            pid = str(raw or "").strip()
            if not pid or pid in seen:
                continue
            out.append(pid)
            seen.add(pid)
        return out

    def _group_member_names(self) -> Dict[str, List[Dict[str, str]]]:
        groups = self._groups()
        peer_map = {p.peer_id: p for p in self.engine.peers}
        out: Dict[str, List[Dict[str, str]]] = {}
        for gid, group in groups.items():
            members: List[Dict[str, str]] = []
            for pid in self._clean_peer_ids(group.get("peer_ids", [])):
                p = peer_map.get(pid)
                members.append(
                    {
                        "peer_id": pid,
                        "name": p.comment if p else "",
                        "ip": p.ip if p else "",
                        "interface": p.interface if p else "",
                        "missing": "false" if p else "true",
                    }
                )
            out[str(gid)] = members
        return out

    def _peer_group_map(self) -> Dict[str, List[Dict[str, str]]]:
        out: Dict[str, List[Dict[str, Any]]] = {}
        groups = self._groups()
        for gid, group in groups.items():
            name = str(group.get("name", gid) or gid)
            for pid in self._clean_peer_ids(group.get("peer_ids", [])):
                speed_down = int(group.get("speed_limit_down_bps", 0) or 0)
                speed_up = int(group.get("speed_limit_up_bps", 0) or 0)
                quota_down = int(group.get("traffic_limit_down_bytes", 0) or 0)
                quota_up = int(group.get("traffic_limit_up_bytes", 0) or 0)
                out.setdefault(pid, []).append(
                    {
                        "id": str(gid),
                        "name": name,
                        "address_list": self.group_address_list_name(str(gid)),
                        "has_speed_limit": speed_down > 0 or speed_up > 0,
                        "has_policy": quota_down > 0 or quota_up > 0,
                        "speed_limit_down_bps": speed_down,
                        "speed_limit_up_bps": speed_up,
                        "traffic_limit_down_bytes": quota_down,
                        "traffic_limit_up_bytes": quota_up,
                        "overlimit_mode": str(group.get("overlimit_mode", "disable") or "disable"),
                    }
                )
        return out

    @staticmethod
    def _peer_has_individual_limits(st: Dict[str, Any]) -> bool:
        return (
            int(st.get("speed_limit_down_bps", 0) or 0) > 0
            or int(st.get("speed_limit_up_bps", 0) or 0) > 0
            or int(st.get("traffic_limit_down_bytes", 0) or 0) > 0
            or int(st.get("traffic_limit_up_bytes", 0) or 0) > 0
            or int(st.get("traffic_period_seconds", 0) or 0) > 0
            or str(st.get("overlimit_mode", "disable") or "disable") != "disable"
            or int(st.get("overlimit_speed_down_bps", 0) or 0) > 0
            or int(st.get("overlimit_speed_up_bps", 0) or 0) > 0
            or bool(st.get("overlimit_active", False))
        )

    def _peer_existing_group_ids(self, peer_id: str, except_group_id: Optional[str] = None) -> List[str]:
        matches: List[str] = []
        for gid, group in self._groups().items():
            if except_group_id is not None and str(gid) == str(except_group_id):
                continue
            if peer_id in self._clean_peer_ids(group.get("peer_ids", [])):
                matches.append(str(gid))
        return matches

    def _validate_new_group_members(self, group_id: str, peer_ids: List[str], current_ids: Optional[List[str]] = None) -> List[str]:
        existing = {p.peer_id for p in self.engine.peers}
        current = set(self._clean_peer_ids(current_ids or []))
        accepted: List[str] = []
        errors: List[str] = []
        for pid in self._clean_peer_ids(peer_ids):
            if pid not in existing:
                continue
            if pid in current:
                accepted.append(pid)
                continue
            other_groups = self._peer_existing_group_ids(pid, except_group_id=group_id)
            if other_groups:
                errors.append(f"{pid}: already belongs to another group")
                continue
            if self._peer_has_individual_limits(self.engine.state.peer(pid)):
                errors.append(f"{pid}: has individual limits")
                continue
            accepted.append(pid)
        if errors:
            raise RuntimeError("Cannot add group members: " + "; ".join(errors))
        return accepted

    def _reject_individual_limit_change_for_group_member(self, peer_id: str) -> None:
        group_ids = self._peer_existing_group_ids(peer_id)
        if group_ids:
            raise RuntimeError(f"Cannot set individual limits for {peer_id}: already belongs to a group")

    def _next_group_id(self, name: str) -> str:
        base = slug(name, max_len=32)
        groups = self._groups()
        if base not in groups:
            return base
        idx = 2
        while f"{base}-{idx}" in groups:
            idx += 1
        return f"{base}-{idx}"

    @staticmethod
    def group_address_list_name(group_id: str) -> str:
        return f"wg-web-group-{slug(group_id, max_len=36)}"

    @staticmethod
    def group_address_comment(group_id: str, peer_id: str) -> str:
        return f"{group_id} | {peer_id} | wg-web group member"

    @staticmethod
    def group_rule_names(group_id: str) -> Dict[str, str]:
        sid = slug(group_id, max_len=36)
        return {
            "mark_up": f"wg-g-{sid}-up",
            "mark_down": f"wg-g-{sid}-down",
            "mcomment_up": f"{group_id} | wg-web group mangle up",
            "mcomment_down": f"{group_id} | wg-web group mangle down",
            "qcomment_up": f"{group_id} | wg-web group queue up",
            "qcomment_down": f"{group_id} | wg-web group queue down",
            "qname_up": f"group-{sid}-up",
            "qname_down": f"group-{sid}-down",
            "counter_up": f"{group_id} | wg-web group counter up",
            "counter_down": f"{group_id} | wg-web group counter down",
            "filter_policy": f"{group_id} | wg-web group policy filter",
            "check_scheduler": f"wg-web-group-check-{sid}",
            "reset_scheduler": f"wg-web-group-reset-{sid}",
        }

    @staticmethod
    def _row_by_comment(rows: List[Dict[str, Any]], comment: str) -> Optional[Dict[str, Any]]:
        for row in rows:
            if str(row.get("comment", "")) == comment:
                return row
        return None

    @staticmethod
    def _row_by_comment_or_name(rows: List[Dict[str, Any]], comment: str, name: str) -> Optional[Dict[str, Any]]:
        for row in rows:
            if str(row.get("comment", "")) == comment or str(row.get("name", "")) == name:
                return row
        return None

    def _create_mangle_prefer_top(self, payload: Dict[str, Any]) -> None:
        try:
            self.engine.client.create_mangle(payload)
        except Exception:
            fallback = dict(payload)
            fallback.pop("place-before", None)
            self.engine.client.create_mangle(fallback)

    def _create_filter_prefer_top(self, payload: Dict[str, Any]) -> None:
        try:
            self.engine.client.create_filter(payload)
        except Exception:
            fallback = dict(payload)
            fallback.pop("place-before", None)
            self.engine.client.create_filter(fallback)

    @staticmethod
    def _interval_expr(seconds: int) -> str:
        return f"{max(0, int(seconds))}s"

    def _sync_group_address_list(self, group_id: str) -> None:
        client = self.engine.client
        if client is None:
            raise RuntimeError("Router client is not initialized")
        list_name = self.group_address_list_name(group_id)
        groups = self._groups()
        group = groups.get(group_id)
        if group is None:
            self._delete_group_address_list(group_id)
            return

        peer_map = {p.peer_id: p for p in self.engine.peers}
        desired: Dict[str, Any] = {}
        for pid in self._clean_peer_ids(group.get("peer_ids", [])):
            p = peer_map.get(pid)
            if p is not None and p.ip:
                desired[pid] = p

        rows = client.list_address_list() or []
        list_rows = [r for r in rows if str(r.get("list", "")) == list_name]
        owned = [r for r in list_rows if str(r.get("comment", "")).endswith("| wg-web group member")]
        seen: set[str] = set()
        for row in owned:
            comment = str(row.get("comment", ""))
            pid = ""
            parts = [x.strip() for x in comment.split("|")]
            if len(parts) >= 3:
                pid = parts[1]
            p = desired.get(pid)
            rid = str(row.get(".id", ""))
            if p is None:
                if rid:
                    client.delete_address_list(rid)
                continue
            payload = {
                "list": list_name,
                "address": p.ip,
                "comment": self.group_address_comment(group_id, pid),
                "disabled": "false",
            }
            if str(row.get("address", "")) != p.ip or str(row.get("disabled", "false")).lower() == "true":
                client.patch_address_list(rid, payload)
            seen.add(pid)

        for pid, p in desired.items():
            if pid in seen:
                continue
            payload = {
                "list": list_name,
                "address": p.ip,
                "comment": self.group_address_comment(group_id, pid),
                "disabled": "false",
            }
            existing_same_address = next((r for r in list_rows if str(r.get("address", "")) == p.ip), None)
            if existing_same_address is not None:
                rid = str(existing_same_address.get(".id", ""))
                if rid:
                    client.patch_address_list(rid, payload)
                    seen.add(pid)
                    continue
            try:
                client.create_address_list(payload)
            except RuntimeError as e:
                if "already have such entry" not in str(e).lower():
                    raise
                refreshed = client.list_address_list() or []
                duplicate = next(
                    (
                        r for r in refreshed
                        if str(r.get("list", "")) == list_name and str(r.get("address", "")) == p.ip
                    ),
                    None,
                )
                rid = str((duplicate or {}).get(".id", ""))
                if not rid:
                    raise
                client.patch_address_list(rid, payload)

    def _delete_group_address_list(self, group_id: str) -> None:
        client = self.engine.client
        if client is None:
            raise RuntimeError("Router client is not initialized")
        list_name = self.group_address_list_name(group_id)
        for row in client.list_address_list() or []:
            if str(row.get("list", "")) != list_name:
                continue
            if str(row.get("comment", "")).endswith("| wg-web group member"):
                client.delete_address_list(str(row.get(".id", "")))

    def _sync_all_group_address_lists(self) -> None:
        for gid in list(self._groups().keys()):
            self._sync_group_address_list(str(gid))

    def _sync_group_speed_rules(self, group_id: str) -> None:
        client = self.engine.client
        if client is None:
            raise RuntimeError("Router client is not initialized")
        groups = self._groups()
        group = groups.get(group_id)
        if group is None:
            self._delete_group_speed_rules(group_id)
            return

        self._sync_group_address_list(group_id)
        list_name = self.group_address_list_name(group_id)
        names = self.group_rule_names(group_id)
        down_bps = int(group.get("speed_limit_down_bps", 0) or 0)
        up_bps = int(group.get("speed_limit_up_bps", 0) or 0)
        mangle = client.list_mangle() or []
        queues = client.list_queue_tree() or []
        mup = self._row_by_comment(mangle, names["mcomment_up"])
        mdown = self._row_by_comment(mangle, names["mcomment_down"])
        qup = self._row_by_comment_or_name(queues, names["qcomment_up"], names["qname_up"])
        qdown = self._row_by_comment_or_name(queues, names["qcomment_down"], names["qname_down"])

        if up_bps <= 0:
            if mup:
                client.delete_mangle(str(mup.get(".id")))
            if qup:
                client.delete_queue(str(qup.get(".id")))
        else:
            mpayload = {
                "chain": "forward",
                "action": "mark-packet",
                "src-address-list": list_name,
                "new-packet-mark": names["mark_up"],
                "passthrough": "false",
                "place-before": "0",
                "comment": names["mcomment_up"],
                "disabled": "false",
            }
            if mup:
                client.delete_mangle(str(mup.get(".id")))
            self._create_mangle_prefer_top(mpayload)

            qpayload = {
                "name": names["qname_up"],
                "parent": "global",
                "packet-mark": names["mark_up"],
                "max-limit": str(up_bps),
                "comment": names["qcomment_up"],
                "disabled": "false",
            }
            if qup:
                client.patch_queue(str(qup.get(".id")), qpayload)
            else:
                client.create_queue(qpayload)

        if down_bps <= 0:
            if mdown:
                client.delete_mangle(str(mdown.get(".id")))
            if qdown:
                client.delete_queue(str(qdown.get(".id")))
        else:
            mpayload = {
                "chain": "forward",
                "action": "mark-packet",
                "dst-address-list": list_name,
                "new-packet-mark": names["mark_down"],
                "passthrough": "false",
                "place-before": "0",
                "comment": names["mcomment_down"],
                "disabled": "false",
            }
            if mdown:
                client.delete_mangle(str(mdown.get(".id")))
            self._create_mangle_prefer_top(mpayload)

            qpayload = {
                "name": names["qname_down"],
                "parent": "global",
                "packet-mark": names["mark_down"],
                "max-limit": str(down_bps),
                "comment": names["qcomment_down"],
                "disabled": "false",
            }
            if qdown:
                client.patch_queue(str(qdown.get(".id")), qpayload)
            else:
                client.create_queue(qpayload)

    def _delete_group_speed_rules(self, group_id: str) -> None:
        client = self.engine.client
        if client is None:
            raise RuntimeError("Router client is not initialized")
        names = self.group_rule_names(group_id)
        for row in client.list_mangle() or []:
            if str(row.get("comment", "")) in (names["mcomment_up"], names["mcomment_down"]):
                client.delete_mangle(str(row.get(".id", "")))
        for row in client.list_queue_tree() or []:
            if str(row.get("comment", "")) in (names["qcomment_up"], names["qcomment_down"]):
                client.delete_queue(str(row.get(".id", "")))

    def _sync_all_group_speed_rules(self) -> None:
        for gid in list(self._groups().keys()):
            self._sync_group_speed_rules(str(gid))

    def _get_scheduler_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        client = self.engine.client
        if client is None:
            return None
        for row in client.list_scheduler() or []:
            if str(row.get("name", "")) == name:
                return row
        return None

    def _ensure_group_counter_rules(self, group_id: str) -> Tuple[int, int]:
        client = self.engine.client
        if client is None:
            raise RuntimeError("Router client is not initialized")
        names = self.group_rule_names(group_id)
        list_name = self.group_address_list_name(group_id)
        rows = client.list_mangle() or []
        up = self._row_by_comment(rows, names["counter_up"])
        down = self._row_by_comment(rows, names["counter_down"])
        if up is None:
            self._create_mangle_prefer_top(
                {
                    "chain": "forward",
                    "action": "passthrough",
                    "src-address-list": list_name,
                    "place-before": "0",
                    "comment": names["counter_up"],
                    "disabled": "false",
                }
            )
        if down is None:
            self._create_mangle_prefer_top(
                {
                    "chain": "forward",
                    "action": "passthrough",
                    "dst-address-list": list_name,
                    "place-before": "0",
                    "comment": names["counter_down"],
                    "disabled": "false",
                }
            )
        rows = client.list_mangle() or []
        up = self._row_by_comment(rows, names["counter_up"])
        down = self._row_by_comment(rows, names["counter_down"])
        return (int((up or {}).get("bytes", 0) or 0), int((down or {}).get("bytes", 0) or 0))

    def _delete_group_policy_rules(self, group_id: str) -> None:
        client = self.engine.client
        if client is None:
            raise RuntimeError("Router client is not initialized")
        names = self.group_rule_names(group_id)
        for row in client.list_scheduler() or []:
            if str(row.get("name", "")) in (names["check_scheduler"], names["reset_scheduler"]):
                client.delete_scheduler(str(row.get(".id", "")))
        for row in client.list_filter() or []:
            if str(row.get("comment", "")) == names["filter_policy"]:
                client.delete_filter(str(row.get(".id", "")))
        for row in client.list_mangle() or []:
            if str(row.get("comment", "")) in (names["counter_up"], names["counter_down"]):
                client.delete_mangle(str(row.get(".id", "")))

    @staticmethod
    def _parse_group_policy_comment(comment: str) -> Dict[str, int]:
        out = {"bu": 0, "bd": 0, "ov": 0}
        for key in out.keys():
            m = re.search(rf"(?:^|;){key}=(-?\d+)", str(comment or ""))
            if m:
                out[key] = int(m.group(1))
        return out

    @staticmethod
    def _seconds_until_router_time(next_run: str, period_seconds: int) -> int:
        m = re.search(r"(\d{1,2}):(\d{2}):(\d{2})", str(next_run or ""))
        if not m or period_seconds <= 0:
            return 0
        hour, minute, second = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        target = hour * 3600 + minute * 60 + second
        now = time.localtime()
        current = now.tm_hour * 3600 + now.tm_min * 60 + now.tm_sec
        remaining = target - current
        if remaining < 0:
            remaining += 24 * 3600
        return max(0, min(period_seconds, remaining))

    def _group_policy_usage_window(self, group_id: str) -> Dict[str, Any]:
        client = self.engine.client
        if client is None:
            return {}
        group = self._groups().get(group_id, {})
        names = self.group_rule_names(group_id)
        try:
            mangle_rows = client.list_mangle() or []
            sched_rows = client.list_scheduler() or []
        except Exception:
            return {}
        up_counter = self._row_by_comment(mangle_rows, names["counter_up"]) or {}
        down_counter = self._row_by_comment(mangle_rows, names["counter_down"]) or {}
        check_sched = next((row for row in sched_rows if str(row.get("name", "")) == names["check_scheduler"]), {})
        reset_sched = next((row for row in sched_rows if str(row.get("name", "")) == names["reset_scheduler"]), {})
        parsed = self._parse_group_policy_comment(str(check_sched.get("comment", "")))
        up_now = int(up_counter.get("bytes", 0) or 0)
        down_now = int(down_counter.get("bytes", 0) or 0)
        period = int(group.get("traffic_period_seconds", 0) or 0)
        baseline_at = int(group.get("policy_baseline_at", 0) or 0)
        if period > 0 and baseline_at > 0:
            remaining = max(0, period - max(0, int(time.time()) - baseline_at))
        else:
            remaining = self._seconds_until_router_time(str(reset_sched.get("next-run", "")), period)
        return {
            "upload_since_now_bytes": max(0, up_now - int(parsed.get("bu", 0) or 0)),
            "download_since_now_bytes": max(0, down_now - int(parsed.get("bd", 0) or 0)),
            "overlimit_active": int(parsed.get("ov", 0) or 0) == 1,
            "traffic_reset_remaining_seconds": remaining,
            "traffic_reset_elapsed_seconds": max(0, period - remaining) if period > 0 else 0,
        }

    def _build_group_policy_apply_speed_script(self, group_id: str, down_bps: int, up_bps: int) -> str:
        names = self.group_rule_names(group_id)
        list_name = self.group_address_list_name(group_id)
        return (
            f":local listName {ros_q(list_name)};"
            f":local markUp {ros_q(names['mark_up'])};:local markDown {ros_q(names['mark_down'])};"
            f":local mcu {ros_q(names['mcomment_up'])};:local mcd {ros_q(names['mcomment_down'])};"
            f":local qcu {ros_q(names['qcomment_up'])};:local qcd {ros_q(names['qcomment_down'])};"
            f":local qnu {ros_q(names['qname_up'])};:local qnd {ros_q(names['qname_down'])};"
            f":local nD {int(down_bps)};:local nU {int(up_bps)};"
            ":local mu [/ip firewall mangle find where comment=$mcu];:local md [/ip firewall mangle find where comment=$mcd];"
            ":local qu [/queue tree find where comment=$qcu];:local qd [/queue tree find where comment=$qcd];"
            ":if ($nU<=0) do={:if ([:len $mu]>0) do={/ip firewall mangle remove $mu;};:if ([:len $qu]>0) do={/queue tree remove $qu;};} else={"
            " :if ([:len $mu]>0) do={/ip firewall mangle remove $mu;};"
            " /ip firewall mangle add chain=forward action=mark-packet src-address-list=$listName new-packet-mark=$markUp passthrough=no place-before=0 comment=$mcu;"
            " :if ([:len $qu]=0) do={/queue tree add name=$qnu parent=global packet-mark=$markUp max-limit=$nU comment=$qcu;} else={/queue tree set $qu name=$qnu parent=global packet-mark=$markUp max-limit=$nU comment=$qcu;};};"
            ":if ($nD<=0) do={:if ([:len $md]>0) do={/ip firewall mangle remove $md;};:if ([:len $qd]>0) do={/queue tree remove $qd;};} else={"
            " :if ([:len $md]>0) do={/ip firewall mangle remove $md;};"
            " /ip firewall mangle add chain=forward action=mark-packet dst-address-list=$listName new-packet-mark=$markDown passthrough=no place-before=0 comment=$mcd;"
            " :if ([:len $qd]=0) do={/queue tree add name=$qnd parent=global packet-mark=$markDown max-limit=$nD comment=$qcd;} else={/queue tree set $qd name=$qnd parent=global packet-mark=$markDown max-limit=$nD comment=$qcd;};};"
        )

    def _build_group_policy_check_script(self, group_id: str, group: Dict[str, Any]) -> str:
        names = self.group_rule_names(group_id)
        list_name = self.group_address_list_name(group_id)
        mode = str(group.get("overlimit_mode", "disable") or "disable")
        lim_down = int(group.get("traffic_limit_down_bytes", 0) or 0)
        lim_up = int(group.get("traffic_limit_up_bytes", 0) or 0)
        over_down = int(group.get("overlimit_speed_down_bps", 0) or 0)
        over_up = int(group.get("overlimit_speed_up_bps", 0) or 0)
        normal_down = int(group.get("speed_limit_down_bps", 0) or 0)
        normal_up = int(group.get("speed_limit_up_bps", 0) or 0)
        normal_speed_script = self._build_group_policy_apply_speed_script(group_id, normal_down, normal_up)
        over_speed_script = self._build_group_policy_apply_speed_script(group_id, over_down, over_up)
        return (
            f":local checkName {ros_q(names['check_scheduler'])};:local resetName {ros_q(names['reset_scheduler'])};"
            f":local listName {ros_q(list_name)};:local mode {ros_q(mode)};"
            f":local limD {lim_down};:local limU {lim_up};"
            f":local cu {ros_q(names['counter_up'])};:local cd {ros_q(names['counter_down'])};"
            f":local fComment {ros_q(names['filter_policy'])};"
            ":local ru [/ip firewall mangle find where comment=$cu];"
            ":if ([:len $ru]=0) do={/ip firewall mangle add chain=forward action=passthrough src-address-list=$listName place-before=0 comment=$cu;:set ru [/ip firewall mangle find where comment=$cu];};"
            ":local rd [/ip firewall mangle find where comment=$cd];"
            ":if ([:len $rd]=0) do={/ip firewall mangle add chain=forward action=passthrough dst-address-list=$listName place-before=0 comment=$cd;:set rd [/ip firewall mangle find where comment=$cd];};"
            ":local u [:tonum [/ip firewall mangle get $ru bytes]];:local d [:tonum [/ip firewall mangle get $rd bytes]];"
            ":local sf [/system scheduler find where name=$checkName];:local c [/system scheduler get $sf comment];"
            ":local p1 [:find $c \"bu=\"];:local p2 [:find $c \";bd=\"];:local p3 [:find $c \";ov=\"];"
            ":if (($p1=nil) or ($p2=nil) or ($p3=nil)) do={:set c (\"bu=\".$u.\";bd=\".$d.\";ov=0;\");/system scheduler set $sf comment=$c;};"
            ":set p1 [:find $c \"bu=\"];:set p2 [:find $c \";bd=\"];:set p3 [:find $c \";ov=\"];"
            ":local bu [:tonum [:pick $c ($p1+3) $p2]];:local bd [:tonum [:pick $c ($p2+4) $p3]];:local ov [:tonum [:pick $c ($p3+4) ([:len $c]-1)]];"
            ":local uu ($u-$bu);:local dd ($d-$bd);:if ($uu<0) do={:set uu 0;};:if ($dd<0) do={:set dd 0;};"
            ":local ex false;:if (($limU>0) and ($uu>=$limU)) do={:set ex true;};:if (($limD>0) and ($dd>=$limD)) do={:set ex true;};"
            ":if (!$ex) do={:if ($ov=1) do={/ip firewall filter remove [find where comment=$fComment];"
            f"{normal_speed_script}"
            ":set ov 0;};/system scheduler set $sf comment=(\"bu=\".$bu.\";bd=\".$bd.\";ov=\".$ov.\";\");:error \"ok\";};"
            ":if ($ov=0) do={"
            ":if ($mode=\"disable\") do={/ip firewall filter remove [find where comment=$fComment];/ip firewall filter add chain=forward action=drop src-address-list=$listName place-before=0 comment=$fComment;};"
            ":if ($mode=\"trusted_only\") do={/ip firewall filter remove [find where comment=$fComment];/ip firewall filter add chain=forward action=drop src-address-list=$listName dst-address-list=!trusted_list place-before=0 comment=$fComment;};"
            f":if ($mode=\"throttle\") do={{/ip firewall filter remove [find where comment=$fComment];{over_speed_script}}};"
            ":set ov 1;};"
            "/system scheduler set $sf comment=(\"bu=\".$bu.\";bd=\".$bd.\";ov=\".$ov.\";\");"
        )

    def _build_group_policy_reset_script(self, group_id: str, group: Dict[str, Any]) -> str:
        names = self.group_rule_names(group_id)
        normal_down = int(group.get("speed_limit_down_bps", 0) or 0)
        normal_up = int(group.get("speed_limit_up_bps", 0) or 0)
        normal_speed_script = self._build_group_policy_apply_speed_script(group_id, normal_down, normal_up)
        return (
            f":local checkName {ros_q(names['check_scheduler'])};"
            f":local cu {ros_q(names['counter_up'])};:local cd {ros_q(names['counter_down'])};"
            f":local fComment {ros_q(names['filter_policy'])};"
            ":local ru [/ip firewall mangle find where comment=$cu];:local rd [/ip firewall mangle find where comment=$cd];"
            ":if ([:len $ru]=0) do={:error \"counter-up-missing\";};:if ([:len $rd]=0) do={:error \"counter-down-missing\";};"
            ":local u [:tonum [/ip firewall mangle get $ru bytes]];:local d [:tonum [/ip firewall mangle get $rd bytes]];"
            "/ip firewall filter remove [find where comment=$fComment];"
            f"{normal_speed_script}"
            ":local sf [/system scheduler find where name=$checkName];:if ([:len $sf]=0) do={:error \"check-missing\";};"
            "/system scheduler set $sf comment=(\"bu=\".$u.\";bd=\".$d.\";ov=0;\");"
        )

    def _reset_group_usage_window(self, group_id: str) -> None:
        client = self.engine.client
        if client is None:
            raise RuntimeError("Router client is not initialized")
        names = self.group_rule_names(group_id)
        self._ensure_group_counter_rules(group_id)
        rows = client.list_mangle() or []
        up = self._row_by_comment(rows, names["counter_up"]) or {}
        down = self._row_by_comment(rows, names["counter_down"]) or {}
        up_bytes = int(up.get("bytes", 0) or 0)
        down_bytes = int(down.get("bytes", 0) or 0)
        for row in client.list_scheduler() or []:
            if str(row.get("name", "")) == names["check_scheduler"]:
                client.patch_scheduler(str(row.get(".id", "")), {"comment": f"bu={up_bytes};bd={down_bytes};ov=0;"})
                break
        group = self._groups().get(group_id)
        if group is not None:
            group["policy_baseline_at"] = int(time.time())

    def _reset_local_peer_usage_baseline(self, peer_id: str) -> None:
        peer = next((p for p in self.engine.peers if p.peer_id == peer_id), None)
        if peer is None:
            return
        st = self.engine.state.peer(peer.peer_id)
        st["baseline_rx"] = peer.rx
        st["baseline_tx"] = peer.tx
        ex_up, ex_down = getattr(self.engine, "peer_exempt_counters", {}).get(peer.peer_id, (0, 0))
        st["baseline_exempt_up"] = int(ex_up or 0)
        st["baseline_exempt_down"] = int(ex_down or 0)
        st["baseline_at"] = int(time.time())
        st["overlimit_active"] = False
        st["disabled_by_policy"] = False

    def _install_group_remote_policy(self, group_id: str) -> None:
        client = self.engine.client
        if client is None:
            raise RuntimeError("Router client is not initialized")
        group = self._groups().get(group_id)
        if group is None:
            raise RuntimeError(f"Group not found: {group_id}")
        lim_down = int(group.get("traffic_limit_down_bytes", 0) or 0)
        lim_up = int(group.get("traffic_limit_up_bytes", 0) or 0)
        if lim_down <= 0 and lim_up <= 0:
            self._delete_group_policy_rules(group_id)
            return
        self._sync_group_address_list(group_id)
        self._sync_group_speed_rules(group_id)
        up_bytes, down_bytes = self._ensure_group_counter_rules(group_id)
        group["policy_baseline_at"] = int(time.time())
        names = self.group_rule_names(group_id)
        check_payload = {
            "name": names["check_scheduler"],
            "interval": "1m",
            "comment": f"bu={up_bytes};bd={down_bytes};ov=0;",
            "on-event": self._build_group_policy_check_script(group_id, group),
            "disabled": "false",
        }
        existing_check = self._get_scheduler_by_name(names["check_scheduler"])
        if existing_check:
            client.patch_scheduler(str(existing_check.get(".id")), check_payload)
        else:
            client.create_scheduler(check_payload)

        period = int(group.get("traffic_period_seconds", 0) or 0)
        existing_reset = self._get_scheduler_by_name(names["reset_scheduler"])
        if period > 0:
            reset_payload = {
                "name": names["reset_scheduler"],
                "interval": self._interval_expr(period),
                "on-event": self._build_group_policy_reset_script(group_id, group),
                "disabled": "false",
            }
            if existing_reset:
                client.patch_scheduler(str(existing_reset.get(".id")), reset_payload)
            else:
                client.create_scheduler(reset_payload)
        elif existing_reset:
            client.delete_scheduler(str(existing_reset.get(".id")))

    def list_groups(self) -> List[Dict[str, Any]]:
        with self._lock:
            self.engine.refresh_data(force=False)
            groups = self._groups()
            members_by_group = self._group_member_names()
            rows: List[Dict[str, Any]] = []
            for gid in sorted(groups.keys(), key=lambda x: str(groups[x].get("name", x)).lower()):
                group = groups[gid]
                members = members_by_group.get(gid, [])
                usage_window: Dict[str, Any] = {}
                if int(group.get("traffic_limit_down_bytes", 0) or 0) > 0 or int(group.get("traffic_limit_up_bytes", 0) or 0) > 0:
                    usage_window = self._group_policy_usage_window(gid)
                rows.append(
                    {
                        "id": gid,
                        "name": str(group.get("name", gid) or gid),
                        "peer_ids": [m["peer_id"] for m in members],
                        "members": members,
                        "member_count": len(members),
                        "address_list": self.group_address_list_name(gid),
                        "speed_limit_down_bps": int(group.get("speed_limit_down_bps", 0) or 0),
                        "speed_limit_up_bps": int(group.get("speed_limit_up_bps", 0) or 0),
                        "speed_limit_down": bps_h(int(group.get("speed_limit_down_bps", 0) or 0)),
                        "speed_limit_up": bps_h(int(group.get("speed_limit_up_bps", 0) or 0)),
                        "traffic_limit_down_bytes": int(group.get("traffic_limit_down_bytes", 0) or 0),
                        "traffic_limit_up_bytes": int(group.get("traffic_limit_up_bytes", 0) or 0),
                        "traffic_period_seconds": int(group.get("traffic_period_seconds", 0) or 0),
                        "overlimit_mode": str(group.get("overlimit_mode", "disable") or "disable"),
                        "overlimit_speed_down_bps": int(group.get("overlimit_speed_down_bps", 0) or 0),
                        "overlimit_speed_up_bps": int(group.get("overlimit_speed_up_bps", 0) or 0),
                        "download_since_now_bytes": int(usage_window.get("download_since_now_bytes", 0) or 0),
                        "upload_since_now_bytes": int(usage_window.get("upload_since_now_bytes", 0) or 0),
                        "overlimit_active": bool(usage_window.get("overlimit_active", False)),
                        "traffic_reset_elapsed_seconds": int(usage_window.get("traffic_reset_elapsed_seconds", 0) or 0),
                        "traffic_reset_remaining_seconds": int(usage_window.get("traffic_reset_remaining_seconds", 0) or 0),
                        "created_at": int(group.get("created_at", 0) or 0),
                        "updated_at": int(group.get("updated_at", 0) or 0),
                    }
                )
            return rows

    def create_group(self, name: str, peer_ids: List[str]) -> Dict[str, Any]:
        with self._operation("group create", name=name, count=len(peer_ids)):
            with self._lock:
                clean_name = self._validate_group_name(name)
                now = int(time.time())
                gid = self._next_group_id(clean_name)
                members = self._validate_new_group_members(gid, peer_ids, current_ids=[])
                self._groups()[gid] = {
                    "name": clean_name,
                    "peer_ids": members,
                    "created_at": now,
                    "updated_at": now,
                    "speed_limit_down_bps": 0,
                    "speed_limit_up_bps": 0,
                    "traffic_limit_down_bytes": 0,
                    "traffic_limit_up_bytes": 0,
                    "traffic_period_seconds": 0,
                    "overlimit_mode": "disable",
                    "overlimit_speed_down_bps": 0,
                    "overlimit_speed_up_bps": 0,
                }
                self._sync_group_address_list(gid)
                self.engine.state.save()
                return {
                    "id": gid,
                    "name": clean_name,
                    "peer_ids": members,
                    "member_count": len(members),
                    "address_list": self.group_address_list_name(gid),
                    "speed_limit_down_bps": 0,
                    "speed_limit_up_bps": 0,
                    "traffic_limit_down_bytes": 0,
                    "traffic_limit_up_bytes": 0,
                }

    def update_group(
        self,
        group_id: str,
        name: Optional[str] = None,
        peer_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        with self._operation("group update", group_id=group_id):
            with self._lock:
                gid = str(group_id or "").strip()
                groups = self._groups()
                if gid not in groups:
                    raise RuntimeError(f"Group not found: {gid}")
                group = groups[gid]
                if name is not None:
                    group["name"] = self._validate_group_name(name)
                if peer_ids is not None:
                    current = self._clean_peer_ids(group.get("peer_ids", []))
                    group["peer_ids"] = self._validate_new_group_members(gid, peer_ids, current_ids=current)
                group["updated_at"] = int(time.time())
                self._sync_group_address_list(gid)
                self._sync_group_speed_rules(gid)
                self._install_group_remote_policy(gid)
                self.engine.state.save()
                return {
                    "id": gid,
                    "name": str(group.get("name", gid) or gid),
                    "peer_ids": self._clean_peer_ids(group.get("peer_ids", [])),
                    "member_count": len(self._clean_peer_ids(group.get("peer_ids", []))),
                    "address_list": self.group_address_list_name(gid),
                    "speed_limit_down_bps": int(group.get("speed_limit_down_bps", 0) or 0),
                    "speed_limit_up_bps": int(group.get("speed_limit_up_bps", 0) or 0),
                }

    def delete_group(self, group_id: str) -> None:
        with self._operation("group delete", group_id=group_id):
            with self._lock:
                gid = str(group_id or "").strip()
                groups = self._groups()
                if gid not in groups:
                    raise RuntimeError(f"Group not found: {gid}")
                member_ids = self._clean_peer_ids(groups[gid].get("peer_ids", []))
                peers_by_id = {p.peer_id: p for p in self.engine.peers}
                for pid in member_ids:
                    p = peers_by_id.get(pid)
                    if p is not None:
                        self.engine.clear_limits(p)
                self._delete_group_policy_rules(gid)
                self._delete_group_speed_rules(gid)
                self._delete_group_address_list(gid)
                groups.pop(gid, None)
                self.engine.state.save()

    def add_group_members(self, group_id: str, peer_ids: List[str]) -> Dict[str, Any]:
        with self._operation("group members add", group_id=group_id, count=len(peer_ids)):
            with self._lock:
                gid = str(group_id or "").strip()
                groups = self._groups()
                if gid not in groups:
                    raise RuntimeError(f"Group not found: {gid}")
                current = self._clean_peer_ids(groups[gid].get("peer_ids", []))
                current_set = set(current)
                added: List[str] = []
                input_ids = self._clean_peer_ids(peer_ids)
                existing = {p.peer_id for p in self.engine.peers}
                skipped = [pid for pid in input_ids if pid not in existing]
                requested = self._validate_new_group_members(gid, input_ids, current_ids=current)
                for pid in requested:
                    if pid not in current_set:
                        current.append(pid)
                        current_set.add(pid)
                        added.append(pid)
                groups[gid]["peer_ids"] = current
                groups[gid]["updated_at"] = int(time.time())
                self._sync_group_address_list(gid)
                self._sync_group_speed_rules(gid)
                self._install_group_remote_policy(gid)
                self.engine.state.save()
                return {
                    "added": added,
                    "skipped": skipped,
                    "member_count": len(current),
                    "address_list": self.group_address_list_name(gid),
                }

    def remove_group_members(self, group_id: str, peer_ids: List[str]) -> Dict[str, Any]:
        with self._operation("group members remove", group_id=group_id, count=len(peer_ids)):
            with self._lock:
                gid = str(group_id or "").strip()
                groups = self._groups()
                if gid not in groups:
                    raise RuntimeError(f"Group not found: {gid}")
                remove = set(self._clean_peer_ids(peer_ids))
                before = self._clean_peer_ids(groups[gid].get("peer_ids", []))
                after = [pid for pid in before if pid not in remove]
                groups[gid]["peer_ids"] = after
                groups[gid]["updated_at"] = int(time.time())
                self._sync_group_address_list(gid)
                self._sync_group_speed_rules(gid)
                self._install_group_remote_policy(gid)
                self.engine.state.save()
                return {
                    "removed": [pid for pid in before if pid in remove],
                    "member_count": len(after),
                    "address_list": self.group_address_list_name(gid),
                }

    def set_group_speed_limits(self, group_id: str, down_mbps: float, up_mbps: float) -> Dict[str, Any]:
        with self._operation("group set speed", group_id=group_id, down_mbps=down_mbps, up_mbps=up_mbps):
            with self._lock:
                gid = str(group_id or "").strip()
                groups = self._groups()
                if gid not in groups:
                    raise RuntimeError(f"Group not found: {gid}")
                group = groups[gid]
                if not self._clean_peer_ids(group.get("peer_ids", [])):
                    raise RuntimeError("Add at least one member before applying group limits")
                down_bps = mbps_to_bps(down_mbps) if down_mbps > 0 else 0
                up_bps = mbps_to_bps(up_mbps) if up_mbps > 0 else 0
                group["speed_limit_down_bps"] = down_bps
                group["speed_limit_up_bps"] = up_bps
                group["updated_at"] = int(time.time())
                self._sync_group_speed_rules(gid)
                self._install_group_remote_policy(gid)
                self.engine.state.save()
                return {
                    "id": gid,
                    "name": str(group.get("name", gid) or gid),
                    "speed_limit_down_bps": down_bps,
                    "speed_limit_up_bps": up_bps,
                    "speed_limit_down": bps_h(down_bps),
                    "speed_limit_up": bps_h(up_bps),
                    "address_list": self.group_address_list_name(gid),
                }

    def reset_group_usage(self, group_id: str) -> Dict[str, Any]:
        with self._operation("group reset usage", group_id=group_id):
            with self._lock:
                gid = str(group_id or "").strip()
                groups = self._groups()
                if gid not in groups:
                    raise RuntimeError(f"Group not found: {gid}")
                self._reset_group_usage_window(gid)
                for pid in self._clean_peer_ids(groups[gid].get("peer_ids", [])):
                    self._reset_local_peer_usage_baseline(pid)
                self.engine.state.save()
                return {"id": gid, "status": "ok"}

    def clear_group_limits(self, group_id: str) -> Dict[str, Any]:
        with self._operation("group clear limits", group_id=group_id):
            with self._lock:
                gid = str(group_id or "").strip()
                groups = self._groups()
                if gid not in groups:
                    raise RuntimeError(f"Group not found: {gid}")
                group = groups[gid]
                group["speed_limit_down_bps"] = 0
                group["speed_limit_up_bps"] = 0
                group["traffic_limit_down_bytes"] = 0
                group["traffic_limit_up_bytes"] = 0
                group["traffic_period_seconds"] = 0
                group["overlimit_mode"] = "disable"
                group["overlimit_speed_down_bps"] = 0
                group["overlimit_speed_up_bps"] = 0
                group["updated_at"] = int(time.time())
                self._delete_group_policy_rules(gid)
                self._delete_group_speed_rules(gid)
                self._sync_group_address_list(gid)
                self.engine.state.save()
                return {"id": gid, "status": "ok"}

    def set_group_traffic_policy(
        self,
        group_id: str,
        down_gb: float,
        up_gb: float,
        period: str,
        mode: str,
        over_down_mbps: float,
        over_up_mbps: float,
    ) -> Dict[str, Any]:
        with self._operation(
            "group set policy",
            group_id=group_id,
            down_gb=down_gb,
            up_gb=up_gb,
            period=period,
            mode=mode,
            over_down_mbps=over_down_mbps,
            over_up_mbps=over_up_mbps,
        ):
            with self._lock:
                gid = str(group_id or "").strip()
                groups = self._groups()
                if gid not in groups:
                    raise RuntimeError(f"Group not found: {gid}")
                mode_value = (mode or "disable").strip().lower()
                if mode_value in ("trusted", "trusted-only", "trustedonly"):
                    mode_value = "trusted_only"
                if mode_value not in ("disable", "throttle", "trusted_only"):
                    raise ValueError("mode must be disable, throttle, or trusted_only")
                group = groups[gid]
                if not self._clean_peer_ids(group.get("peer_ids", [])):
                    raise RuntimeError("Add at least one member before applying group policy")
                group["traffic_limit_down_bytes"] = gb_to_bytes(down_gb) if down_gb > 0 else 0
                group["traffic_limit_up_bytes"] = gb_to_bytes(up_gb) if up_gb > 0 else 0
                group["traffic_period_seconds"] = parse_period_input(period) if str(period or "").strip() else 0
                group["overlimit_mode"] = mode_value
                group["overlimit_speed_down_bps"] = mbps_to_bps(over_down_mbps) if over_down_mbps > 0 else 0
                group["overlimit_speed_up_bps"] = mbps_to_bps(over_up_mbps) if over_up_mbps > 0 else 0
                group["updated_at"] = int(time.time())
                self._install_group_remote_policy(gid)
                self.engine.state.save()
                return {
                    "id": gid,
                    "name": str(group.get("name", gid) or gid),
                    "traffic_limit_down_bytes": int(group.get("traffic_limit_down_bytes", 0) or 0),
                    "traffic_limit_up_bytes": int(group.get("traffic_limit_up_bytes", 0) or 0),
                    "traffic_period_seconds": int(group.get("traffic_period_seconds", 0) or 0),
                    "overlimit_mode": mode_value,
                    "overlimit_speed_down_bps": int(group.get("overlimit_speed_down_bps", 0) or 0),
                    "overlimit_speed_up_bps": int(group.get("overlimit_speed_up_bps", 0) or 0),
                    "address_list": self.group_address_list_name(gid),
                }
