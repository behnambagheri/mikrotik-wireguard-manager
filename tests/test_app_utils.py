import os
import tempfile
import unittest
from unittest import mock

from wg_users_tui import app


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


if __name__ == "__main__":
    unittest.main()
