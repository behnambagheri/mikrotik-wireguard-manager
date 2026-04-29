import os
import tempfile
import threading
import unittest
from unittest import mock

from wg_users_tui import app
from wg_users_tui import web_api


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
            with mock.patch.dict(os.environ, {"WG_TUI_ENV_FILE": path}, clear=False):
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

    def test_build_visible_peers_filter_and_sort(self):
        with mock.patch.dict(os.environ, {"WG_TUI_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
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
        with mock.patch.dict(os.environ, {"WG_TUI_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
            a = app.App(DummyStdScr())
        self.assertEqual(a.default_config_path("alice.conf"), "client-configs/alice.conf")
        self.assertEqual(a.default_config_path("nested/alice.conf"), "nested/alice.conf")
        self.assertEqual(a.normalize_config_save_path("bob.conf"), "client-configs/bob.conf")
        self.assertEqual(a.normalize_config_save_path("nested/bob.conf"), "nested/bob.conf")

    def test_peer_used_bytes_subtracts_exempt_counters(self):
        with mock.patch.dict(os.environ, {"WG_TUI_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
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
        with mock.patch.dict(os.environ, {"WG_TUI_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
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

        with mock.patch("wg_users_tui.web_api.time.time", return_value=2_800):
            rows = wm.build_clients_payload()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["baseline_at"], 1000)
        self.assertEqual(rows[0]["baseline_age_seconds"], 1800)
        self.assertEqual(rows[0]["traffic_reset_elapsed_seconds"], 1800)
        self.assertEqual(rows[0]["traffic_reset_remaining_seconds"], 1800)
        self.assertEqual(rows[0]["traffic_reset_progress_pct"], 50.0)

    def test_sort_down_used_uses_adjusted_usage(self):
        with mock.patch.dict(os.environ, {"WG_TUI_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
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

    def test_reset_usage_restores_normal_speed_when_throttle_was_active(self):
        with mock.patch.dict(os.environ, {"WG_TUI_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
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
        with mock.patch.dict(os.environ, {"WG_TUI_ENV_FILE": "/tmp/does-not-exist"}, clear=False):
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

        script = a.build_policy_reset_script(p, st, "wg-tui-check-11")

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


if __name__ == "__main__":
    unittest.main()
