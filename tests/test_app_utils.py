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


if __name__ == "__main__":
    unittest.main()
