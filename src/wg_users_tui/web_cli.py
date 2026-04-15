#!/usr/bin/env python3
import argparse
import os
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wg-web",
        description="Run MikroTik WireGuard Manager Web UI/API",
    )
    p.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8088, help="Bind port (default: 8088)")
    p.add_argument(
        "--env-file",
        default=os.environ.get("WG_TUI_ENV_FILE", ".env"),
        help="Path to .env file (default: .env)",
    )
    p.add_argument(
        "--state-file",
        default=os.environ.get("WG_TUI_STATE_FILE", ".wg_tui_state.json"),
        help="Path to state JSON file (default: .wg_tui_state.json)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    os.environ["WG_TUI_ENV_FILE"] = args.env_file
    os.environ["WG_TUI_STATE_FILE"] = args.state_file

    try:
        import uvicorn
    except Exception as e:
        print(f"ERROR: uvicorn is required for web mode: {e}")
        return 1

    uvicorn.run("wg_users_tui.web:app", host=args.host, port=args.port, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
