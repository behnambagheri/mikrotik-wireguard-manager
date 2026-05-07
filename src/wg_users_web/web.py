#!/usr/bin/env python3
from importlib import import_module

from .web_api import WebManager

_api_app = import_module("wg_users_web.api.app")
app = _api_app.app


def create_app():
    original = _api_app.WebManager
    _api_app.WebManager = WebManager
    try:
        return _api_app.create_app()
    finally:
        _api_app.WebManager = original

__all__ = ["WebManager", "app", "create_app"]
