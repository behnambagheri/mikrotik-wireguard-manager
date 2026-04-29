#!/usr/bin/env python3
import logging
import os
import sys


def _bootstrap_path() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def configure_logging() -> None:
    logger = logging.getLogger("wg_users_tui")
    logger.setLevel(os.environ.get("WG_LOG_LEVEL", "INFO").upper())
    logger.propagate = False

    for handler in logger.handlers:
        if getattr(handler, "_wg_main_handler", False):
            return

    handler = logging.StreamHandler()
    handler._wg_main_handler = True  # type: ignore[attr-defined]
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    logger.addHandler(handler)


_bootstrap_path()
configure_logging()

from wg_users_tui.web import app, create_app  # noqa: E402,F401


def main() -> int:
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8088, reload=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
