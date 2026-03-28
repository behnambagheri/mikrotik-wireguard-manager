#!/usr/bin/env python3
import argparse
import os
import sys

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wg-tui",
        description="WireGuard RouterOS TUI: dashboard, client management, limits, and policy automation.",
    )
    p.add_argument(
        "--env-file",
        default=os.environ.get("WG_TUI_ENV_FILE", ".env"),
        help="Path to .env file (default: .env)",
    )
    p.add_argument(
        "--state-file",
        default=os.environ.get("WG_TUI_STATE_FILE", ".wg_tui_state.json"),
        help="Path to local state JSON (default: .wg_tui_state.json)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Pass runtime file paths through env vars so app module stays import-safe.
    os.environ["WG_TUI_ENV_FILE"] = args.env_file
    os.environ["WG_TUI_STATE_FILE"] = args.state_file
    from .app import run_tui

    return run_tui()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
