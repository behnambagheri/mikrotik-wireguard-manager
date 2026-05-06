#!/usr/bin/env python3
import os
import re
from typing import Dict, Optional

STATE_FILE = os.environ.get("WG_WEB_STATE_FILE", ".wg_web_state.json")
DEFAULT_POLL_SECONDS = 2.0
MARKER_PREFIX = "wg-web"
CFG_DNS = "100.100.100.100, 100.100.100.101"
CFG_ALLOWED_IPS = "0.0.0.0/0"
CFG_ENDPOINT_HOST = "77.74.202.60"
CFG_KEEPALIVE = "25"
CFG_EXEMPT_DST_LIST = "quota_exempt"
DEFAULT_PROFILE_ENV_KEYS = ("DEFAULT_ROUTER_PROFILE", "WG_DEFAULT_PROFILE", "WG_WEB_DEFAULT_PROFILE")


def env_file_path() -> str:
    return os.environ.get("WG_WEB_ENV_FILE", ".env")


def load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


def get_default_profile_name(path: Optional[str] = None) -> str:
    env_path = path or env_file_path()
    file_values: Dict[str, str] = {}
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                key = k.strip()
                if key in DEFAULT_PROFILE_ENV_KEYS:
                    file_values[key] = v.strip().strip('"').strip("'")
    for key in DEFAULT_PROFILE_ENV_KEYS:
        value = file_values.get(key, "").strip()
        if value:
            return value
    for key in DEFAULT_PROFILE_ENV_KEYS:
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def parse_router_profiles(path: str = ".env") -> Dict[str, Dict[str, str]]:
    # Parse profile-style .env lines:
    # Name={ key=value, key=value, ... }
    # We split on commas that start a new key to preserve csv-like values.
    profiles: Dict[str, Dict[str, str]] = {}
    if not os.path.exists(path):
        return profiles
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, rest = line.split("=", 1)
            name = name.strip()
            rest = rest.strip()
            if not (rest.startswith("{") and rest.endswith("}")):
                continue
            inner = rest[1:-1].strip()
            if not inner:
                continue
            chunks = re.split(r",\s*(?=[a-zA-Z_][a-zA-Z0-9_]*\s*=)", inner)
            kv: Dict[str, str] = {}
            for c in chunks:
                if "=" not in c:
                    continue
                k, v = c.split("=", 1)
                k = k.strip().lower()
                v = v.strip().strip('"').strip("'")
                if k:
                    kv[k] = v
            if kv:
                profiles[name] = kv
    return profiles
