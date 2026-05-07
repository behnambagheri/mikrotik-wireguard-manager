#!/usr/bin/env python3
import ipaddress
import json
import logging
import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..app import (
    App,
    CFG_ALLOWED_IPS,
    CFG_KEEPALIVE,
    RouterOSClient,
    bps_h,
    bytes_h,
    env_file_path,
    gb_to_bytes,
    get_default_profile_name,
    mbps_to_bps,
    parse_router_profiles,
    parse_period_input,
    ros_q,
    slug,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AddClientRequest",
    "Any",
    "App",
    "CFG_ALLOWED_IPS",
    "CFG_KEEPALIVE",
    "Dict",
    "List",
    "Optional",
    "RouterOSClient",
    "Tuple",
    "bps_h",
    "bytes_h",
    "contextmanager",
    "dataclass",
    "env_file_path",
    "gb_to_bytes",
    "get_default_profile_name",
    "ipaddress",
    "load_json_file",
    "logger",
    "mbps_to_bps",
    "os",
    "parse_period_input",
    "parse_router_profiles",
    "re",
    "ros_q",
    "slug",
    "threading",
    "time",
]


@dataclass
class AddClientRequest:
    interface: str
    ip: str
    comment: str = ""
    speed_down_mbps: Optional[float] = None
    speed_up_mbps: Optional[float] = None
    limit_down_gb: Optional[float] = None
    limit_up_gb: Optional[float] = None
    period: Optional[str] = None
    overlimit_mode: Optional[str] = None
    overlimit_down_mbps: Optional[float] = None
    overlimit_up_mbps: Optional[float] = None
    include_dns: bool = True
    include_persistent_keepalive: bool = True
    include_full_route: bool = True


def load_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
