import os
import sys
import types
import unittest
from unittest import mock

from wg_users_tui import web_cli


class TestWebCli(unittest.TestCase):
    def test_parser_defaults(self):
        p = web_cli.build_parser()
        args = p.parse_args([])
        self.assertEqual(args.host, "127.0.0.1")
        self.assertEqual(args.port, 8088)

    def test_main_sets_env_and_runs(self):
        fake = types.SimpleNamespace(run=mock.Mock())
        fake_config = types.SimpleNamespace(LOGGING_CONFIG={"version": 1, "formatters": {}, "handlers": {}, "loggers": {}})
        with mock.patch.dict(sys.modules, {"uvicorn": fake, "uvicorn.config": fake_config}):
            rc = web_cli.main(["--host", "0.0.0.0", "--port", "9090", "--env-file", "x.env", "--state-file", "x.json"])
        self.assertEqual(rc, 0)
        self.assertEqual(os.environ["WG_TUI_ENV_FILE"], "x.env")
        self.assertEqual(os.environ["WG_TUI_STATE_FILE"], "x.json")
        fake.run.assert_called_once()
        kwargs = fake.run.call_args.kwargs
        self.assertIn("log_config", kwargs)
        self.assertIn("wg_users_tui", kwargs["log_config"]["loggers"])
        self.assertEqual(kwargs["log_config"]["loggers"]["wg_users_tui"]["level"], "INFO")

    def test_profile_switch_endpoint_returns_selected_profile(self):
        try:
            from fastapi.testclient import TestClient
            from wg_users_tui import web
        except ModuleNotFoundError:
            self.skipTest("fastapi is not installed in this test environment")

        manager = mock.Mock()
        manager.current_profile.return_value = "Novin_max"

        with mock.patch("wg_users_tui.web.WebManager", return_value=manager):
            app = web.create_app()

        client = TestClient(app)
        resp = client.post("/api/profiles/select", json={"name": "Novin_max"})

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok", "current": "Novin_max"})
        manager.select_profile.assert_called_once_with("Novin_max")

    def test_default_profile_endpoint_updates_selected_default(self):
        try:
            from fastapi.testclient import TestClient
            from wg_users_tui import web
        except ModuleNotFoundError:
            self.skipTest("fastapi is not installed in this test environment")

        manager = mock.Mock()
        manager.set_default_profile.return_value = {"default": "Asiatech_LAP"}

        with mock.patch("wg_users_tui.web.WebManager", return_value=manager):
            app = web.create_app()

        client = TestClient(app)
        resp = client.post("/api/profiles/default", json={"name": "Asiatech_LAP"})

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok", "default": "Asiatech_LAP"})
        manager.set_default_profile.assert_called_once_with("Asiatech_LAP")


if __name__ == "__main__":
    unittest.main()
