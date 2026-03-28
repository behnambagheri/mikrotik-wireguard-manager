#!/usr/bin/env python3
import os
import sys


def _bootstrap_path() -> None:
    # Keep backward compatibility for running from repo root without install.
    root = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def main() -> int:
    _bootstrap_path()
    from wg_users_tui.cli import main as cli_main

    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
