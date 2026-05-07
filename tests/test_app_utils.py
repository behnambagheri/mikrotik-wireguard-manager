import os
import tempfile
import threading
import unittest
from unittest import mock

from wg_users_web import app
from wg_users_web import web_api


class DummyStdScr:
    def getmaxyx(self):
        return (40, 120)


class TestAppUtils(unittest.TestCase):
    def test_parse_router_profiles_preserves_comma_values(self):
        content = """
# comment
novin={user=bea,password=1234,router_ip=172.16.40.1,endpoint_ip=77.74.202.60,dns_servers=100.100.100.100,100.100.100.101,transport=rest}
empty={}
invalid=just-text
"""
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            profiles = app.parse_router_profiles(path)
        finally:
            os.unlink(path)

        self.assertIn("novin", profiles)
        self.assertEqual(profiles["novin"]["user"], "bea")
        self.assertEqual(profiles["novin"]["router_ip"], "172.16.40.1")
        self.assertEqual(profiles["novin"]["dns_servers"], "100.100.100.100,100.100.100.101")
        self.assertNotIn("empty", profiles)
        self.assertNotIn("invalid", profiles)

    def test_default_profile_name_reads_env_file(self):
        content = """
Router1={user=u,password=p,router_ip=1.1.1.1}
DEFAULT_ROUTER_PROFILE=Router1
"""
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            self.assertEqual(app.get_default_profile_name(path), "Router1")
        finally:
            os.unlink(path)

    def test_web_manager_set_default_profile_updates_env(self):
        content = """
Router1={user=u,password=p,router_ip=1.1.1.1}
Router2={user=u,password=p,router_ip=2.2.2.2}
WG_WEB_DEFAULT_PROFILE=Router1
"""
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.profile_name = "Router1"
            wm.engine.profiles = app.parse_router_profiles(path)
            with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": path}, clear=False):
                out = wm.set_default_profile("Router2")
                self.assertEqual(out, {"default": "Router2"})
                self.assertEqual(app.get_default_profile_name(path), "Router2")
                with open(path, "r", encoding="utf-8") as f2:
                    saved = f2.read()
                self.assertIn("DEFAULT_ROUTER_PROFILE=Router2", saved)
                self.assertNotIn("WG_WEB_DEFAULT_PROFILE=Router1", saved)
        finally:
            os.unlink(path)

    def test_parse_period_input(self):
        self.assertEqual(app.parse_period_input("1h"), 3600)
        self.assertEqual(app.parse_period_input("2d"), 172800)
        self.assertEqual(app.parse_period_input("none"), 0)
        self.assertEqual(app.parse_period_input("2"), 7200)

    def test_parse_ros_duration_to_seconds(self):
        self.assertEqual(app.parse_ros_duration_to_seconds("1w2d3h4m5s"), 788645)
        self.assertEqual(app.parse_ros_duration_to_seconds("10m"), 600)
        self.assertIsNone(app.parse_ros_duration_to_seconds(""))
        self.assertIsNone(app.parse_ros_duration_to_seconds("5"))
        self.assertIsNone(app.parse_ros_duration_to_seconds("3x"))

    def test_slug_safe_id_and_first_ip(self):
        self.assertEqual(app.safe_id("*A-B_1"), "ab1")
        self.assertEqual(app.slug("  Behnam Bagheri - Phone  "), "behnam-bagheri-phone")
        self.assertEqual(app.first_ip("100.100.100.12/32, 10.0.0.1/32"), "100.100.100.12")

    def test_api_ssl_length_encode_decode_round_trip(self):
        values = [0, 127, 128, 1024, 16383, 16384, 200000, 2000000]
        for n in values:
            encoded = app.ApiSslClient._encode_len(n)
            idx = {"i": 0}

            def read1():
                b = encoded[idx["i"] : idx["i"] + 1]
                idx["i"] += 1
                return b

            decoded = app.ApiSslClient._decode_len(read1)
            self.assertEqual(decoded, n)

    def test_state_store_save_and_load(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            st = app.StateStore(path)
            st.peer("*1")["baseline_rx"] = 123
            st.save()

            loaded = app.StateStore(path)
            self.assertEqual(loaded.peer("*1")["baseline_rx"], 123)

            loaded.delete_peer("*1")
            loaded.save()
            reloaded = app.StateStore(path)
            self.assertNotIn("*1", reloaded.data.get("peers", {}))

    def test_state_store_delete_peer_removes_group_membership(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            st = app.StateStore(path)
            st.peer("*1")["baseline_rx"] = 1
            st.groups()["marketing"] = {"name": "Marketing", "peer_ids": ["*1", "*2"]}
            st.delete_peer("*1")
            st.save()

            loaded = app.StateStore(path)
            self.assertEqual(loaded.groups()["marketing"]["peer_ids"], ["*2"])

    def test_web_manager_group_create_syncs_router_address_list(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False),
                app.PeerView("*2", "wireguard", "100.100.100.3", "Bob", 0, 0, False),
            ]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = []

            out = wm.create_group("Marketing", ["*1", "*2", "*missing"])

            self.assertEqual(out["id"], "marketing")
            self.assertEqual(out["peer_ids"], ["*1", "*2"])
            self.assertEqual(out["address_list"], "wg-web-group-marketing")
            calls = wm.engine.client.create_address_list.call_args_list
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0].args[0]["list"], "wg-web-group-marketing")
            self.assertEqual(calls[0].args[0]["address"], "100.100.100.2")
            self.assertEqual(calls[1].args[0]["address"], "100.100.100.3")

    def test_web_manager_group_address_list_reuses_existing_same_address(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False),
            ]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = [
                {
                    ".id": "*a1",
                    "list": "wg-web-group-marketing",
                    "address": "100.100.100.2",
                    "comment": "stale manual entry",
                    "disabled": "false",
                }
            ]

            wm.create_group("Marketing", ["*1"])

            wm.engine.client.create_address_list.assert_not_called()
            wm.engine.client.patch_address_list.assert_called_once()
            rid, payload = wm.engine.client.patch_address_list.call_args.args
            self.assertEqual(rid, "*a1")
            self.assertEqual(payload["comment"], "marketing | *1 | wg-web group member")

    def test_web_manager_list_groups_reports_router_reset_window_usage(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False),
            ]
            wm.engine.client = mock.Mock()
            wm._groups()["marketing"] = {
                "name": "Marketing",
                "peer_ids": ["*1"],
                "traffic_limit_down_bytes": 1000,
                "traffic_limit_up_bytes": 1000,
                "traffic_period_seconds": 600,
            }
            wm.engine.client.list_mangle.return_value = [
                {"comment": "marketing | wg-web group counter up", "bytes": "900"},
                {"comment": "marketing | wg-web group counter down", "bytes": "2000"},
            ]
            wm.engine.client.list_scheduler.return_value = [
                {"name": "wg-web-group-check-marketing", "comment": "bu=200;bd=500;ov=1;"},
            ]

            row = wm.list_groups()[0]

            self.assertEqual(row["upload_since_now_bytes"], 700)
            self.assertEqual(row["download_since_now_bytes"], 1500)
            self.assertTrue(row["overlimit_active"])
            self.assertIn("traffic_reset_elapsed_seconds", row)
            self.assertIn("traffic_reset_remaining_seconds", row)

    def test_web_manager_list_groups_reuses_policy_router_rows(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.profile_name = "Novin"
            wm.engine.host = "10.0.0.1"
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView(f"*{idx}", "wireguard", f"100.100.100.{idx}", f"User {idx}", 0, 0, False)
                for idx in range(1, 11)
            ]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_mangle.return_value = []
            wm.engine.client.list_scheduler.return_value = []

            for idx, peer in enumerate(wm.engine.peers, start=1):
                wm._groups()[f"group-{idx}"] = {
                    "name": f"Group {idx}",
                    "peer_ids": [peer.peer_id],
                    "traffic_limit_down_bytes": 1024,
                    "traffic_limit_up_bytes": 0,
                    "traffic_period_seconds": 600,
                }

            rows = wm.list_groups()

            self.assertEqual(len(rows), 10)
            wm.engine.client.list_mangle.assert_called_once()
            wm.engine.client.list_scheduler.assert_called_once()

    def test_dashboard_snapshot_refreshes_once_and_reuses_group_policy_rows(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.profile_name = "Novin"
            wm.engine.host = "10.0.0.1"
            wm.engine.state = app.StateStore(path)
            wm.engine.router_resource = {}
            wm.engine.interfaces = []
            wm.engine.iface_speed = {}
            wm.engine.iface_baseline = {}
            wm.engine.peer_exempt_counters = {}
            wm.engine.last_poll_latency_ms = 0
            wm.engine.status = ""
            wm.engine.error = ""
            wm.engine.total_bandwidth.return_value = (0, 0)
            wm.engine.dashboard_alerts.return_value = []
            wm.engine.wg_interface_health.return_value = []
            wm.engine.peer_used_bytes.return_value = (0, 0)
            wm.engine.peers = [
                app.PeerView(f"*{idx}", "wireguard", f"100.100.100.{idx}", f"User {idx}", 0, 0, False)
                for idx in range(1, 6)
            ]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_wireguard_interfaces.return_value = [{"name": "wireguard", "listen-port": "13231"}]
            wm.engine.client.list_mangle.return_value = []
            wm.engine.client.list_scheduler.return_value = []
            for idx, peer in enumerate(wm.engine.peers, start=1):
                wm._groups()[f"group-{idx}"] = {
                    "name": f"Group {idx}",
                    "peer_ids": [peer.peer_id],
                    "traffic_limit_down_bytes": 1024,
                    "traffic_limit_up_bytes": 0,
                    "traffic_period_seconds": 600,
                }

            snapshot = wm.dashboard_snapshot(force_refresh=True)

            wm.engine.refresh_data.assert_called_once_with(force=True)
            wm.engine.client.list_wireguard_interfaces.assert_called_once()
            wm.engine.client.list_mangle.assert_called_once()
            wm.engine.client.list_scheduler.assert_called_once()
            self.assertEqual(snapshot["status"], "ok")
            self.assertEqual(len(snapshot["groups"]), 5)
            self.assertEqual(len(snapshot["clients"]), 5)

    def test_web_manager_group_membership_rejects_other_group_members(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False),
            ]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = []
            wm.engine.client.list_mangle.return_value = []
            wm.engine.client.list_queue_tree.return_value = []
            wm.engine.client.list_scheduler.return_value = []
            wm.engine.client.list_filter.return_value = []

            wm.create_group("Marketing", ["*1"])
            wm.create_group("Sales", [])

            with self.assertRaisesRegex(RuntimeError, "already belongs to another group"):
                wm.add_group_members("sales", ["*1"])

            groups = {g["id"]: g for g in wm.list_groups()}
            self.assertEqual(groups["marketing"]["peer_ids"], ["*1"])
            self.assertEqual(groups["sales"]["peer_ids"], [])

    def test_web_manager_group_membership_rejects_individual_limits(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False),
            ]
            wm.engine.state.peer("*1")["speed_limit_down_bps"] = 10_000_000
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = []

            with self.assertRaisesRegex(RuntimeError, "has individual limits"):
                wm.create_group("Marketing", ["*1"])

            wm.create_group("Sales", [])
            with self.assertRaisesRegex(RuntimeError, "has individual limits"):
                wm.add_group_members("sales", ["*1"])

            self.assertEqual(wm.list_groups()[0]["peer_ids"], [])

    def test_web_manager_rejects_individual_limits_for_group_member(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            peer = app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False)
            wm.engine.peers = [peer]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = []

            wm.create_group("Marketing", ["*1"])

            with self.assertRaisesRegex(RuntimeError, "already belongs to a group"):
                wm.set_speed_limits("*1", 10, 5)
            with self.assertRaisesRegex(RuntimeError, "already belongs to a group"):
                wm.set_traffic_policy("*1", 1, 1, "1d", "throttle", 1, 1)

            wm.engine.apply_speed_rules.assert_not_called()
            wm.engine.install_remote_policy.assert_not_called()

    def test_web_manager_delete_group_keeps_members_and_clears_member_limits(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            peer = app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False)
            wm.engine.peers = [peer]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = []
            wm.engine.client.list_mangle.return_value = []
            wm.engine.client.list_queue_tree.return_value = []
            wm.engine.client.list_scheduler.return_value = []
            wm.engine.client.list_filter.return_value = []
            wm.create_group("Marketing", ["*1"])
            st = wm.engine.state.peer("*1")
            st["speed_limit_down_bps"] = 10_000_000
            st["traffic_limit_down_bytes"] = 1024

            def clear_limits(p):
                member_state = wm.engine.state.peer(p.peer_id)
                member_state["speed_limit_down_bps"] = 0
                member_state["traffic_limit_down_bytes"] = 0

            wm.engine.clear_limits.side_effect = clear_limits

            wm.delete_group("marketing")

            self.assertEqual(wm.engine.peers, [peer])
            self.assertEqual(wm.list_groups(), [])
            self.assertEqual(wm.engine.state.peer("*1")["speed_limit_down_bps"], 0)
            self.assertEqual(wm.engine.state.peer("*1")["traffic_limit_down_bytes"], 0)
            wm.engine.clear_limits.assert_called_once_with(peer)

    def test_web_manager_groups_are_scoped_by_profile(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.profile_name = "Router1"
            wm.engine.host = "10.0.0.1"
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False),
            ]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = []

            wm.create_group("Marketing", ["*1"])
            self.assertEqual([g["name"] for g in wm.list_groups()], ["Marketing"])

            wm.engine.profile_name = "Router2"
            wm.engine.host = "10.0.0.2"
            self.assertEqual(wm.list_groups(), [])

            wm.engine.profile_name = "Router1"
            wm.engine.host = "10.0.0.1"
            self.assertEqual([g["name"] for g in wm.list_groups()], ["Marketing"])

    def test_web_manager_legacy_groups_migrate_to_current_profile_only(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.profile_name = "Router1"
            wm.engine.host = "10.0.0.1"
            wm.engine.state = app.StateStore(path)
            wm.engine.state.data["groups"] = {
                "legacy": {"name": "Legacy", "peer_ids": []}
            }
            wm.engine.peers = []
            wm.engine.client = mock.Mock()

            self.assertEqual([g["name"] for g in wm.list_groups()], ["Legacy"])
            self.assertEqual(wm.engine.state.data.get("groups"), {})

            wm.engine.profile_name = "Router2"
            wm.engine.host = "10.0.0.2"
            self.assertEqual(wm.list_groups(), [])

    def test_web_manager_group_speed_syncs_router_mangle_and_queues(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False),
            ]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = []
            wm.engine.client.list_mangle.return_value = []
            wm.engine.client.list_queue_tree.return_value = []
            wm.engine.client.list_scheduler.return_value = []
            wm.engine.client.list_filter.return_value = []
            wm.create_group("Marketing", ["*1"])

            out = wm.set_group_speed_limits("marketing", 10, 5)

            self.assertEqual(out["speed_limit_down_bps"], 10_000_000)
            self.assertEqual(out["speed_limit_up_bps"], 5_000_000)
            mangle_payloads = [c.args[0] for c in wm.engine.client.create_mangle.call_args_list]
            self.assertEqual(len(mangle_payloads), 2)
            self.assertEqual(mangle_payloads[0]["src-address-list"], "wg-web-group-marketing")
            self.assertEqual(mangle_payloads[0]["new-packet-mark"], "wg-g-marketing-up")
            self.assertEqual(mangle_payloads[0]["place-before"], "0")
            self.assertEqual(mangle_payloads[1]["dst-address-list"], "wg-web-group-marketing")
            self.assertEqual(mangle_payloads[1]["new-packet-mark"], "wg-g-marketing-down")
            queue_payloads = [c.args[0] for c in wm.engine.client.create_queue.call_args_list]
            self.assertEqual(len(queue_payloads), 2)
            self.assertEqual(queue_payloads[0]["packet-mark"], "wg-g-marketing-up")
            self.assertEqual(queue_payloads[0]["max-limit"], "5000000")
            self.assertEqual(queue_payloads[1]["packet-mark"], "wg-g-marketing-down")
            self.assertEqual(queue_payloads[1]["max-limit"], "10000000")

    def test_web_manager_group_policy_installs_router_schedulers(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False),
            ]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = []
            wm.engine.client.list_mangle.side_effect = [
                [],
                [],
                [
                    {".id": "*c1", "comment": "marketing | wg-web group counter up", "bytes": "100"},
                    {".id": "*c2", "comment": "marketing | wg-web group counter down", "bytes": "200"},
                ],
            ]
            wm.engine.client.list_queue_tree.return_value = []
            wm.engine.client.list_scheduler.return_value = []
            wm.engine.client.list_filter.return_value = []
            wm.create_group("Marketing", ["*1"])

            out = wm.set_group_traffic_policy("marketing", 1, 2, "1d", "throttle", 1, 0.5)

            self.assertEqual(out["traffic_limit_down_bytes"], 1024 * 1024 * 1024)
            self.assertEqual(out["traffic_limit_up_bytes"], 2 * 1024 * 1024 * 1024)
            self.assertEqual(out["traffic_period_seconds"], 86400)
            self.assertEqual(out["overlimit_mode"], "throttle")
            scheduler_payloads = [c.args[0] for c in wm.engine.client.create_scheduler.call_args_list]
            self.assertEqual(len(scheduler_payloads), 2)
            self.assertEqual(scheduler_payloads[0]["name"], "wg-web-group-check-marketing")
            self.assertIn("bu=100;bd=200;ov=0;", scheduler_payloads[0]["comment"])
            self.assertIn("wg-web group counter up", scheduler_payloads[0]["on-event"])
            self.assertIn(':local mode "throttle"', scheduler_payloads[0]["on-event"])
            self.assertEqual(scheduler_payloads[1]["name"], "wg-web-group-reset-marketing")
            self.assertEqual(scheduler_payloads[1]["interval"], "86400s")

    def test_web_manager_group_reset_usage_updates_router_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 111, 222, False),
            ]
            wm.engine.peer_exempt_counters = {"*1": (3, 4)}
            wm.engine.client = mock.Mock()
            wm._groups()["marketing"] = {"name": "Marketing", "peer_ids": ["*1"]}
            wm.engine.client.list_mangle.side_effect = [
                [
                    {".id": "*c1", "comment": "marketing | wg-web group counter up", "bytes": "1000"},
                    {".id": "*c2", "comment": "marketing | wg-web group counter down", "bytes": "2000"},
                ],
                [
                    {".id": "*c1", "comment": "marketing | wg-web group counter up", "bytes": "1000"},
                    {".id": "*c2", "comment": "marketing | wg-web group counter down", "bytes": "2000"},
                ],
                [
                    {".id": "*c1", "comment": "marketing | wg-web group counter up", "bytes": "1000"},
                    {".id": "*c2", "comment": "marketing | wg-web group counter down", "bytes": "2000"},
                ],
            ]
            wm.engine.client.list_scheduler.return_value = [
                {".id": "*s1", "name": "wg-web-group-check-marketing", "comment": "bu=1;bd=2;ov=1;"},
            ]

            wm.reset_group_usage("marketing")

            wm.engine.client.patch_scheduler.assert_called_once_with("*s1", {"comment": "bu=1000;bd=2000;ov=0;"})
            st = wm.engine.state.peer("*1")
            self.assertEqual(st["baseline_rx"], 111)
            self.assertEqual(st["baseline_tx"], 222)
            self.assertEqual(st["baseline_exempt_up"], 3)
            self.assertEqual(st["baseline_exempt_down"], 4)

    def test_web_manager_group_clear_limits_keeps_group_and_members(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            wm = web_api.WebManager.__new__(web_api.WebManager)
            wm._lock = threading.RLock()
            wm.engine = mock.Mock()
            wm.engine.state = app.StateStore(path)
            wm.engine.peers = [
                app.PeerView("*1", "wireguard", "100.100.100.2", "Alice", 0, 0, False),
            ]
            wm.engine.client = mock.Mock()
            wm.engine.client.list_address_list.return_value = []
            wm.engine.client.list_mangle.return_value = []
            wm.engine.client.list_queue_tree.return_value = []
            wm.engine.client.list_scheduler.return_value = []
            wm.engine.client.list_filter.return_value = []
            wm._groups()["marketing"] = {
                "name": "Marketing",
                "peer_ids": ["*1"],
                "speed_limit_down_bps": 10_000_000,
                "speed_limit_up_bps": 5_000_000,
                "traffic_limit_down_bytes": 1024,
                "traffic_limit_up_bytes": 2048,
                "traffic_period_seconds": 600,
                "overlimit_mode": "throttle",
                "overlimit_speed_down_bps": 1_000_000,
                "overlimit_speed_up_bps": 500_000,
            }

            wm.clear_group_limits("marketing")

            group = wm._groups()["marketing"]
            self.assertEqual(group["peer_ids"], ["*1"])
            self.assertEqual(group["speed_limit_down_bps"], 0)
            self.assertEqual(group["traffic_limit_down_bytes"], 0)
            self.assertEqual(group["traffic_period_seconds"], 0)
            self.assertEqual(group["overlimit_mode"], "disable")

    def test_web_manager_clients_payload_reports_group_limit_precedence(self):
        wm = web_api.WebManager.__new__(web_api.WebManager)
        wm.engine = mock.Mock()
        p = app.PeerView(peer_id="*1", interface="wireguard", ip="100.100.100.2", comment="Alice", rx=0, tx=0, disabled=False)
        wm.engine.peers = [p]
        wm.engine.state = app.StateStore(os.devnull)
        wm.engine.state.data = {
            "peers": {
                "*1": {
                    "speed_limit_down_bps": 20_000_000,
                    "traffic_limit_down_bytes": 5 * 1024 * 1024 * 1024,
                }
            },
            "groups": {
                "marketing": {
                    "name": "Marketing",
                    "peer_ids": ["*1"],
                    "speed_limit_down_bps": 10_000_000,
                    "traffic_limit_down_bytes": 1024 * 1024 * 1024,
                    "overlimit_mode": "throttle",
                }
            },
        }
        wm.engine.peer_used_bytes.return_value = (0, 0)

        rows = wm.build_clients_payload()

        self.assertEqual(rows[0]["effective_speed_scope"], "group")
        self.assertEqual(rows[0]["effective_speed_group_names"], "Marketing")
        self.assertEqual(rows[0]["effective_policy_scope"], "group")
        self.assertEqual(rows[0]["effective_policy_group_names"], "Marketing")
        self.assertEqual(rows[0]["limit_conflict_count"], 2)
        self.assertIn("group speed overrides individual speed", rows[0]["limit_conflicts"])

    def test_build_visible_peers_filter_and_sort(self):
        with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())

        a.peers = [
            app.PeerView(peer_id="*2", interface="wireguard", ip="100.100.100.11", comment="Beta", rx=200, tx=300, disabled=False),
            app.PeerView(peer_id="*1", interface="wireguard", ip="100.100.100.3", comment="Alpha", rx=100, tx=150, disabled=True),
        ]
        a.sort_key = "ip"
        a.sort_desc = False
        a.filter_query = ""
        a.clients_disabled_only = False

        all_rows = a.build_visible_peers()
        self.assertEqual([p.peer_id for p in all_rows], ["*1", "*2"])

        a.clients_disabled_only = True
        disabled_rows = a.build_visible_peers()
        self.assertEqual([p.peer_id for p in disabled_rows], ["*1"])

        a.clients_disabled_only = False
        a.filter_query = "beta"
        filtered_rows = a.build_visible_peers()
        self.assertEqual([p.peer_id for p in filtered_rows], ["*2"])

    def test_default_and_normalized_config_save_path(self):
        with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())
        self.assertEqual(a.default_config_path("alice.conf"), "client-configs/alice.conf")
        self.assertEqual(a.default_config_path("nested/alice.conf"), "nested/alice.conf")
        self.assertEqual(a.normalize_config_save_path("bob.conf"), "client-configs/bob.conf")
        self.assertEqual(a.normalize_config_save_path("nested/bob.conf"), "nested/bob.conf")

    def test_peer_used_bytes_subtracts_exempt_counters(self):
        with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())
        p = app.PeerView(peer_id="*7", interface="wireguard", ip="100.100.100.7", comment="User7", rx=1_000_000, tx=2_000_000, disabled=False)
        st = {
            "baseline_rx": 100_000,
            "baseline_tx": 200_000,
            "baseline_exempt_up": 10_000,
            "baseline_exempt_down": 20_000,
        }
        a.peer_exempt_counters[p.peer_id] = (110_000, 220_000)
        down_used, up_used = a.peer_used_bytes(p, st)
        self.assertEqual(up_used, 800_000)   # (1_000_000-100_000) - (110_000-10_000)
        self.assertEqual(down_used, 1_600_000)  # (2_000_000-200_000) - (220_000-20_000)

    def test_build_users_export_rows_contains_policy_and_usage(self):
        with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())
        p = app.PeerView(peer_id="*9", interface="wireguard", ip="100.100.100.9", comment="User9", rx=5000, tx=7000, disabled=False)
        a.peers = [p]
        a.peer_exempt_counters[p.peer_id] = (1000, 2000)
        st = a.state.peer(p.peer_id)
        st["baseline_rx"] = 100
        st["baseline_tx"] = 200
        st["baseline_exempt_up"] = 10
        st["baseline_exempt_down"] = 20
        st["traffic_limit_down_bytes"] = 1024
        st["traffic_limit_up_bytes"] = 2048
        st["overlimit_mode"] = "throttle"
        rows = a.build_users_export_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["peer_id"], "*9")
        self.assertEqual(rows[0]["traffic_limit_down_bytes"], 1024)
        self.assertEqual(rows[0]["traffic_limit_up_bytes"], 2048)
        self.assertEqual(rows[0]["overlimit_mode"], "throttle")

    def test_web_manager_build_clients_payload_contains_reset_window_metrics(self):
        wm = web_api.WebManager.__new__(web_api.WebManager)
        wm.engine = mock.Mock()
        p = app.PeerView(peer_id="*9", interface="wireguard", ip="100.100.100.9", comment="User9", rx=5000, tx=7000, disabled=False)
        wm.engine.peers = [p]
        st = {
            "baseline_at": 1_000,
            "traffic_period_seconds": 3_600,
            "traffic_limit_down_bytes": 1024,
            "traffic_limit_up_bytes": 2048,
            "overlimit_mode": "throttle",
            "overlimit_active": False,
            "speed_limit_down_bps": 10_000_000,
            "speed_limit_up_bps": 5_000_000,
        }
        wm.engine.state.peer.return_value = st
        wm.engine.peer_used_bytes.return_value = (120, 240)

        with mock.patch("wg_users_web.web_api.time.time", return_value=2_800):
            rows = wm.build_clients_payload()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["baseline_at"], 1000)
        self.assertEqual(rows[0]["baseline_age_seconds"], 1800)
        self.assertEqual(rows[0]["traffic_reset_elapsed_seconds"], 1800)
        self.assertEqual(rows[0]["traffic_reset_remaining_seconds"], 1800)
        self.assertEqual(rows[0]["traffic_reset_progress_pct"], 50.0)

    def test_web_manager_client_config_options_are_optional(self):
        wm = web_api.WebManager.__new__(web_api.WebManager)
        wm.engine = mock.Mock()
        wm.engine.cfg_dns = "100.100.100.100, 100.100.100.101"
        wm.engine.cfg_endpoint_host = "vpn.example.com"

        conf = wm._build_client_config(
            priv="client-private",
            address="100.100.100.9/32",
            server_pub="server-public",
            listen_port="13231",
            include_dns=False,
            include_persistent_keepalive=False,
            include_full_route=False,
        )

        self.assertIn("AllowedIPs = ", conf)
        self.assertNotIn("AllowedIPs = 0.0.0.0/0", conf)
        self.assertNotIn("DNS =", conf)
        self.assertNotIn("PersistentKeepalive =", conf)

    def test_diagnostics_skips_rest_probe_when_rest_ports_closed(self):
        with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())
        cfg = {
            "router_ip": "10.0.0.1",
            "user": "u",
            "password": "p",
            "transport": "rest",
            "timeout_sec": "30",
        }
        a.tcp_open = mock.Mock(return_value=False)
        a.rest_probe = mock.Mock()

        row = a.classify_profile("Novin", cfg)

        self.assertEqual(row["status"], "unreachable")
        self.assertEqual(row["detail"], "http port closed")
        a.rest_probe.assert_not_called()

    def test_sort_down_used_uses_adjusted_usage(self):
        with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())
        p1 = app.PeerView(peer_id="*1", interface="wireguard", ip="100.100.100.1", comment="A", rx=1000, tx=2000, disabled=False)
        p2 = app.PeerView(peer_id="*2", interface="wireguard", ip="100.100.100.2", comment="B", rx=1000, tx=1500, disabled=False)
        a.peers = [p1, p2]
        # p1 raw down is bigger, but exempt subtraction makes it zero.
        st1 = a.state.peer("*1")
        st1["baseline_tx"] = 0
        st1["baseline_rx"] = 0
        st1["baseline_exempt_down"] = 0
        st1["baseline_exempt_up"] = 0
        a.peer_exempt_counters["*1"] = (0, 2000)
        st2 = a.state.peer("*2")
        st2["baseline_tx"] = 0
        st2["baseline_rx"] = 0
        st2["baseline_exempt_down"] = 0
        st2["baseline_exempt_up"] = 0
        a.peer_exempt_counters["*2"] = (0, 0)
        a.sort_key = "down_used"
        a.sort_desc = True
        out = a.build_visible_peers()
        self.assertEqual([x.peer_id for x in out], ["*2", "*1"])

    def test_api_remove_with_fallback_uses_numbers_after_id_failure(self):
        c = app.ApiSslClient("1.1.1.1", "u", "p")
        calls = []

        def fake_cmd(path, attrs=None):
            calls.append((path, attrs))
            if attrs and ".id" in attrs:
                raise RuntimeError("bad command argument")
            return []

        c._cmd = fake_cmd  # type: ignore[assignment]
        c.delete_peer("*10")
        self.assertEqual(calls[0], ("/interface/wireguard/peers/remove", {".id": "*10"}))
        self.assertEqual(calls[1], ("/interface/wireguard/peers/remove", {"numbers": "*10"}))

    def test_api_remove_with_fallback_does_not_retry_missing_item(self):
        c = app.ApiSslClient("1.1.1.1", "u", "p")
        calls = []

        def fake_cmd(path, attrs=None):
            calls.append((path, attrs))
            raise RuntimeError("no such item")

        c._cmd = fake_cmd  # type: ignore[assignment]
        with self.assertRaises(RuntimeError):
            c.delete_peer("*10")
        self.assertEqual(len(calls), 1)

    def test_apply_speed_rules_patches_existing_queue_by_name(self):
        with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())
        a.client = mock.Mock()
        a.client.list_mangle.return_value = []
        a.client.list_queue_tree.return_value = [
            {".id": "*A", "name": "ali-yousefi-5f-up", "comment": ""},
            {".id": "*B", "name": "ali-yousefi-5f-down", "comment": ""},
        ]
        p = app.PeerView(
            peer_id="*5F",
            interface="wireguard",
            ip="100.100.100.68",
            comment="Ali Yousefi",
            rx=0,
            tx=0,
            disabled=False,
        )

        a.apply_speed_rules(p, down_bps=8_000_000, up_bps=2_000_000)

        a.client.create_queue.assert_not_called()
        patched = [(call.args[0], call.args[1]) for call in a.client.patch_queue.call_args_list]
        self.assertEqual([row[0] for row in patched], ["*A", "*B"])
        self.assertEqual(patched[0][1]["max-limit"], "2000000")
        self.assertEqual(patched[0][1]["comment"], "Ali Yousefi | *5F | wg-web queue up")
        self.assertEqual(patched[1][1]["max-limit"], "8000000")
        self.assertEqual(patched[1][1]["comment"], "Ali Yousefi | *5F | wg-web queue down")

    def test_reset_usage_restores_normal_speed_when_throttle_was_active(self):
        with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())
        p = app.PeerView(
            peer_id="*10",
            interface="wireguard",
            ip="100.100.100.10",
            comment="Maryam Esmaeili - Laptop",
            rx=1200,
            tx=2400,
            disabled=False,
        )
        st = a.state.peer(p.peer_id)
        st["overlimit_mode"] = "throttle"
        st["overlimit_active"] = True
        st["disabled_by_policy"] = False
        st["speed_limit_down_bps"] = 10_000_000
        st["speed_limit_up_bps"] = 10_000_000

        a.ensure_exempt_counter_rules = mock.Mock()
        a.get_peer_exempt_counters = mock.Mock(return_value=(55, 66))
        a.install_remote_policy = mock.Mock()
        a.apply_speed_rules = mock.Mock()

        a.reset_usage(p)

        a.apply_speed_rules.assert_called_once_with(p, down_bps=10_000_000, up_bps=10_000_000)
        self.assertFalse(st["overlimit_active"])
        self.assertFalse(st["disabled_by_policy"])
        self.assertEqual(st["baseline_rx"], 1200)
        self.assertEqual(st["baseline_tx"], 2400)
        self.assertEqual(st["baseline_exempt_up"], 55)
        self.assertEqual(st["baseline_exempt_down"], 66)

    def test_build_policy_reset_script_restores_normal_queue_limits(self):
        with mock.patch.dict(os.environ, {"WG_WEB_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())
        p = app.PeerView(
            peer_id="*11",
            interface="wireguard",
            ip="100.100.100.11",
            comment="Maryam Esmaeili - Laptop",
            rx=0,
            tx=0,
            disabled=False,
        )
        st = {
            "overlimit_mode": "throttle",
            "speed_limit_down_bps": 10_000_000,
            "speed_limit_up_bps": 10_000_000,
        }

        script = a.build_policy_reset_script(p, st, "wg-web-check-11")

        self.assertIn(':local nD 10000000;:local nU 10000000;', script)
        self.assertIn('/queue tree set $qu name=$qnu parent=global packet-mark=$markUp max-limit=$nU comment=$qcu;', script)
        self.assertIn('/queue tree set $qd name=$qnd parent=global packet-mark=$markDown max-limit=$nD comment=$qcd;', script)
        self.assertIn('/system scheduler set $sf comment=("brx=".$rx.";btx=".$tx.";bexu=".$exu.";bexd=".$exd.";ov=0;db=0;");', script)

    def test_web_manager_refresh_fails_fast_when_busy(self):
        wm = web_api.WebManager.__new__(web_api.WebManager)
        wm._lock = threading.RLock()
        wm.engine = mock.Mock()
        locked = threading.Event()
        release = threading.Event()

        def holder():
            wm._lock.acquire()
            locked.set()
            release.wait(timeout=2)
            wm._lock.release()

        t = threading.Thread(target=holder)
        t.start()
        self.assertTrue(locked.wait(timeout=1))
        try:
            with self.assertRaisesRegex(RuntimeError, "Manager busy during refresh; try again"):
                wm.refresh()
        finally:
            release.set()
            t.join(timeout=1)

    def test_web_manager_select_profile_fails_fast_when_busy(self):
        wm = web_api.WebManager.__new__(web_api.WebManager)
        wm._lock = threading.RLock()
        wm.engine = mock.Mock()
        wm.engine.profiles = {"Novin_max": {"router_ip": "1.1.1.1", "user": "u", "password": "p"}}
        locked = threading.Event()
        release = threading.Event()

        def holder():
            wm._lock.acquire()
            locked.set()
            release.wait(timeout=2)
            wm._lock.release()

        t = threading.Thread(target=holder)
        t.start()
        self.assertTrue(locked.wait(timeout=1))
        try:
            with self.assertRaisesRegex(RuntimeError, "Manager busy during profile switch; try again"):
                wm.select_profile("Novin_max")
        finally:
            release.set()
            t.join(timeout=1)

    def test_delete_peer_and_cleanup_removes_router_artifacts_and_state(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with mock.patch.dict(
                os.environ,
                {"WG_WEB_ENV_FILE": "/tmp/does-not-exist", "WG_WEB_STATE_FILE": state_path},
                clear=False,
            ):
                a = app.App(DummyStdScr())

            p = app.PeerView(
                peer_id="*ABC",
                interface="wireguard",
                ip="100.100.100.50",
                comment="Deleted User",
                rx=0,
                tx=0,
                disabled=False,
            )
            a.state.peer(p.peer_id)["traffic_limit_down_bytes"] = 123

            class FakeClient:
                def __init__(self):
                    self.deleted_peer = ""
                    self.deleted_schedulers = []
                    self.deleted_mangle = []
                    self.deleted_filter = []
                    self.deleted_queue = []

                def list_scheduler(self):
                    return [
                        {".id": "*s1", "name": "wg-web-check-abc", "on-event": ""},
                        {".id": "*s2", "name": "old-name", "on-event": "| *ABC | wg-web old script"},
                    ]

                def delete_scheduler(self, rid):
                    self.deleted_schedulers.append(rid)

                def list_mangle(self):
                    return [
                        {".id": "*m1", "comment": "Old User | *ABC | wg-web exempt up"},
                        {".id": "*m2", "comment": "Old User | *ABC | wg-web mangle down"},
                    ]

                def delete_mangle(self, rid):
                    self.deleted_mangle.append(rid)

                def list_filter(self):
                    return [{".id": "*f1", "comment": "Old User | *ABC | wg-web trusted-only"}]

                def delete_filter(self, rid):
                    self.deleted_filter.append(rid)

                def list_queue_tree(self):
                    return [{".id": "*q1", "comment": "Old User | *ABC | wg-web queue down"}]

                def delete_queue(self, rid):
                    self.deleted_queue.append(rid)

                def delete_peer(self, peer_id):
                    self.deleted_peer = peer_id

            fake = FakeClient()
            a.client = fake

            a.delete_peer_and_cleanup(p)

            self.assertEqual(fake.deleted_peer, "*ABC")
            self.assertIn("*s1", fake.deleted_schedulers)
            self.assertIn("*s2", fake.deleted_schedulers)
            self.assertIn("*m1", fake.deleted_mangle)
            self.assertIn("*m2", fake.deleted_mangle)
            self.assertIn("*f1", fake.deleted_filter)
            self.assertIn("*q1", fake.deleted_queue)
            self.assertNotIn("*ABC", a.state.data.get("peers", {}))


if __name__ == "__main__":
    unittest.main()
