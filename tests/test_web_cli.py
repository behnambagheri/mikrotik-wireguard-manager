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
        with mock.patch.dict(sys.modules, {"uvicorn": fake}):
            rc = web_cli.main(["--host", "0.0.0.0", "--port", "9090", "--env-file", "x.env", "--state-file", "x.json"])
        self.assertEqual(rc, 0)
        self.assertEqual(os.environ["WG_TUI_ENV_FILE"], "x.env")
        self.assertEqual(os.environ["WG_TUI_STATE_FILE"], "x.json")
        fake.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
