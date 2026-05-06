#!/usr/bin/env python3
from .common import AddClientRequest, load_json_file
from .base import BaseManager
from .profiles import ProfileManagerMixin
from .groups import GroupManagerMixin
from .router_data import RouterDataMixin
from .clients import ClientManagerMixin
from .exports import ExportManagerMixin


class WebManager(
    ProfileManagerMixin,
    GroupManagerMixin,
    RouterDataMixin,
    ClientManagerMixin,
    ExportManagerMixin,
    BaseManager,
):
    pass


__all__ = ["AddClientRequest", "WebManager", "load_json_file"]
