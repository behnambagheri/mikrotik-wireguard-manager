import os
import unittest
from unittest import mock

from wg_users_tui import cli


class TestCli(unittest.TestCase):
    def test_build_parser_defaults(self):
        parser = cli.build_parser()
        args = parser.parse_args([])
        self.assertEqual(args.env_file, os.environ.get("WG_TUI_ENV_FILE", ".env"))
        self.assertEqual(args.state_file, os.environ.get("WG_TUI_STATE_FILE", ".wg_tui_state.json"))

    @mock.patch("wg_users_tui.app.run_tui", return_value=7)
    def test_main_sets_env_and_calls_run_tui(self, run_tui_mock):
        rc = cli.main(["--env-file", "custom.env", "--state-file", "custom-state.json"])
        self.assertEqual(rc, 7)
        self.assertEqual(os.environ["WG_TUI_ENV_FILE"], "custom.env")
        self.assertEqual(os.environ["WG_TUI_STATE_FILE"], "custom-state.json")
        run_tui_mock.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
