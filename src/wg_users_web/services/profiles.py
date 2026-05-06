#!/usr/bin/env python3
from .common import *


class ProfileManagerMixin:
    @staticmethod
    def _validate_profile_name(name: str) -> str:
        n = str(name or "").strip()
        if not n:
            raise RuntimeError("Profile name is required")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", n):
            raise RuntimeError("Profile name must be 1..64 chars: English letters, digits, _, -, .")
        return n

    @staticmethod
    def _clean_profile_patch(payload: Dict[str, Any]) -> Dict[str, str]:
        allowed = {
            "user",
            "password",
            "router_ip",
            "endpoint_ip",
            "dns_servers",
            "transport",
            "timeout_sec",
            "use_https",
            "exempt_traffic_dst_list",
        }
        out: Dict[str, str] = {}
        for k, v in payload.items():
            key = str(k or "").strip().lower()
            if key not in allowed:
                continue
            val = str(v or "").strip()
            if val == "":
                continue
            out[key] = val
        if "transport" in out:
            t = out["transport"].strip().lower()
            if t in ("api_ssl", "api-ssl"):
                out["transport"] = "api-ssl"
            elif t in ("api",):
                out["transport"] = "api"
            else:
                out["transport"] = "rest"
        if "use_https" in out:
            out["use_https"] = "true" if out["use_https"].lower() in ("1", "true", "yes", "on") else "false"
        return out

    @staticmethod
    def _profile_to_env_line(name: str, cfg: Dict[str, str]) -> str:
        order = [
            "user",
            "password",
            "router_ip",
            "endpoint_ip",
            "dns_servers",
            "transport",
            "timeout_sec",
            "use_https",
            "exempt_traffic_dst_list",
        ]
        chunks: List[str] = []
        for key in order:
            val = str(cfg.get(key, "")).strip()
            if val:
                chunks.append(f"{key}={val}")
        for key in sorted(cfg.keys()):
            if key in order:
                continue
            val = str(cfg.get(key, "")).strip()
            if val:
                chunks.append(f"{key}={val}")
        return f"{name}={{" + ",".join(chunks) + "}"

    def _profiles_env_path(self) -> str:
        return env_file_path()

    def _default_profile_name(self) -> str:
        return get_default_profile_name(self._profiles_env_path())

    def _save_default_profile_to_env(self, name: str) -> None:
        path = self._profiles_env_path()
        lines: List[str] = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()

        written = False
        keep: List[str] = []
        for raw in lines:
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _value = line.split("=", 1)
                if key.strip() in ("DEFAULT_ROUTER_PROFILE", "WG_DEFAULT_PROFILE", "WG_WEB_DEFAULT_PROFILE"):
                    if not written:
                        keep.append(f"DEFAULT_ROUTER_PROFILE={name}\n")
                        written = True
                    continue
            keep.append(raw)

        if not written:
            if keep and keep[-1].strip() != "":
                keep.append("\n")
            keep.append(f"DEFAULT_ROUTER_PROFILE={name}\n")

        with open(path, "w", encoding="utf-8") as f:
            f.writelines(keep)
        os.environ["DEFAULT_ROUTER_PROFILE"] = name

    def _save_profiles_to_env(self, profiles: Dict[str, Dict[str, str]]) -> None:
        path = self._profiles_env_path()
        lines: List[str] = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()

        keep: List[str] = []
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                keep.append(raw)
                continue
            _name, rest = line.split("=", 1)
            rest = rest.strip()
            if rest.startswith("{") and rest.endswith("}"):
                continue
            keep.append(raw)

        while keep and keep[-1].strip() == "":
            keep.pop()
        if keep:
            keep.append("\n")

        for name in sorted(profiles.keys()):
            keep.append(self._profile_to_env_line(name, profiles[name]) + "\n")

        with open(path, "w", encoding="utf-8") as f:
            f.writelines(keep)

    def _reload_profiles(self, prefer_name: Optional[str] = None) -> None:
        self.engine.profiles = parse_router_profiles(self._profiles_env_path())
        if not self.engine.profiles:
            raise RuntimeError("No profile found in .env after update")
        target = prefer_name if prefer_name in self.engine.profiles else None
        if not target:
            cur = self.engine.profile_name
            target = cur if cur in self.engine.profiles else sorted(self.engine.profiles.keys())[0]
        self.engine.connect_profile(target, self.engine.profiles[target])
        self.engine.reset_runtime_caches()
        self.engine.refresh_data(force=True)

    def list_profiles(self) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        default_name = self._default_profile_name()
        for name in sorted(self.engine.profiles.keys()):
            p = self.engine.profiles[name]
            active = name == self.engine.profile_name and self.engine.client is not None
            has_user = bool(p.get("user", "") or (active and self.engine.user))
            has_password = bool(p.get("password", "") or (active and self.engine.password))
            rows.append(
                {
                    "name": name,
                    "router_ip": p.get("router_ip", ""),
                    "transport": p.get("transport", "rest"),
                    "endpoint_ip": p.get("endpoint_ip", ""),
                    "has_user": "true" if has_user else "false",
                    "has_password": "true" if has_password else "false",
                    "session_authenticated": "true" if active else "false",
                    "is_default": "true" if name == default_name else "false",
                }
            )
        return rows

    def auth_status(self) -> Dict[str, Any]:
        current = self.engine.profile_name
        profile = self.engine.profiles.get(current, {}) if current else {}
        return {
            "connected": self.engine.client is not None,
            "current": current,
            "profile_count": len(self.engine.profiles),
            "needs_profile": len(self.engine.profiles) == 0 and self.engine.client is None,
            "needs_credentials": self.engine.client is None,
            "missing_user": not bool(self.engine.user or profile.get("user", "")),
            "missing_password": not bool(self.engine.password or profile.get("password", "")),
            "router_ip": self.engine.host or profile.get("router_ip", ""),
            "user": self.engine.user or profile.get("user", ""),
        }

    def default_profile(self) -> str:
        return self._default_profile_name()

    def set_default_profile(self, name: str) -> Dict[str, str]:
        with self._operation("profile default update", name=name):
            with self._lock:
                n = self._validate_profile_name(name)
                if n not in self.engine.profiles:
                    raise RuntimeError(f"Profile not found: {n}")
                self._save_default_profile_to_env(n)
                return {"default": n}

    def get_profile(self, name: str) -> Dict[str, str]:
        with self._lock:
            n = self._validate_profile_name(name)
            p = self.engine.profiles.get(n)
            if not p:
                raise RuntimeError(f"Profile not found: {n}")
            return {
                "name": n,
                "user": p.get("user", ""),
                "password": p.get("password", ""),
                "router_ip": p.get("router_ip", ""),
                "endpoint_ip": p.get("endpoint_ip", ""),
                "dns_servers": p.get("dns_servers", ""),
                "transport": p.get("transport", "rest"),
                "timeout_sec": p.get("timeout_sec", ""),
                "use_https": p.get("use_https", ""),
                "exempt_traffic_dst_list": p.get("exempt_traffic_dst_list", ""),
            }

    def create_profile(self, name: str, payload: Dict[str, Any]) -> None:
        with self._operation("profile create", name=name):
            with self._lock:
                n = self._validate_profile_name(name)
                if n in self.engine.profiles:
                    raise RuntimeError(f"Profile already exists: {n}")
                patch = self._clean_profile_patch(payload)
                if not patch.get("router_ip"):
                    raise RuntimeError("router_ip is required")
                profiles = {k: dict(v) for k, v in self.engine.profiles.items()}
                profiles[n] = patch
                self._save_profiles_to_env(profiles)
                self.engine.profiles = parse_router_profiles(self._profiles_env_path())
                prefer = self.engine.profile_name if self.engine.profile_name in self.engine.profiles else n
                if self.engine.profiles.get(prefer, {}).get("user") and self.engine.profiles.get(prefer, {}).get("password"):
                    self._reload_profiles(prefer_name=prefer)
                else:
                    self.engine.profile_name = prefer
                    self.engine.host = self.engine.profiles.get(prefer, {}).get("router_ip", "")
                    self.engine.client = None

    def update_profile(self, name: str, payload: Dict[str, Any], new_name: Optional[str] = None) -> Dict[str, str]:
        with self._operation("profile update", name=name, new_name=new_name):
            with self._lock:
                n = self._validate_profile_name(name)
                if n not in self.engine.profiles:
                    raise RuntimeError(f"Profile not found: {n}")
                final_name = self._validate_profile_name(new_name) if new_name else n
                if final_name != n and final_name in self.engine.profiles:
                    raise RuntimeError(f"Profile already exists: {final_name}")
                patch = self._clean_profile_patch(payload)
                profiles = {k: dict(v) for k, v in self.engine.profiles.items()}
                cur = dict(profiles.pop(n))
                cur.update(patch)
                if not cur.get("router_ip"):
                    raise RuntimeError("router_ip is required")
                profiles[final_name] = cur
                self._save_profiles_to_env(profiles)
                if self._default_profile_name() == n:
                    self._save_default_profile_to_env(final_name)
                current_before = self.engine.profile_name
                prefer = final_name if current_before == n else current_before
                if prefer not in profiles:
                    prefer = final_name
                self.engine.profiles = parse_router_profiles(self._profiles_env_path())
                if self.engine.profiles.get(prefer, {}).get("user") and self.engine.profiles.get(prefer, {}).get("password"):
                    self._reload_profiles(prefer_name=prefer)
                else:
                    self.engine.profile_name = prefer
                    self.engine.host = self.engine.profiles.get(prefer, {}).get("router_ip", "")
                    self.engine.user = self.engine.profiles.get(prefer, {}).get("user", "")
                    self.engine.password = ""
                    self.engine.client = None
                return {"name": final_name}

    def delete_profile(self, name: str) -> Dict[str, str]:
        with self._operation("profile delete", name=name):
            with self._lock:
                n = self._validate_profile_name(name)
                if n not in self.engine.profiles:
                    raise RuntimeError(f"Profile not found: {n}")
                if len(self.engine.profiles) <= 1:
                    raise RuntimeError("Cannot delete the last profile")
                profiles = {k: dict(v) for k, v in self.engine.profiles.items()}
                del profiles[n]
                current = self.engine.profile_name
                next_name = current if current in profiles else sorted(profiles.keys())[0]
                self._save_profiles_to_env(profiles)
                if self._default_profile_name() == n:
                    self._save_default_profile_to_env(next_name)
                self._reload_profiles(prefer_name=next_name)
                return {"current": self.engine.profile_name}

    def select_profile(self, name: str) -> None:
        with self._operation("profile switch", name=name):
            with self._busy_lock("profile switch"):
                if name not in self.engine.profiles:
                    raise RuntimeError(f"Profile not found: {name}")
                p = self.engine.profiles[name]
                if not p.get("router_ip") or not p.get("user") or not p.get("password"):
                    self.engine.profile_name = name
                    self.engine.host = p.get("router_ip", "")
                    self.engine.user = p.get("user", "")
                    self.engine.password = ""
                    self.engine.client = None
                    missing = []
                    if not p.get("router_ip"):
                        missing.append("router_ip")
                    if not p.get("user"):
                        missing.append("user")
                    if not p.get("password"):
                        missing.append("password")
                    raise RuntimeError(f"Profile needs credentials: {', '.join(missing)}")
                self.engine.connect_profile(name, self.engine.profiles[name])
                self.engine.reset_runtime_caches()
                self.engine.refresh_data(force=True)

    def connect_with_credentials(self, payload: Dict[str, Any]) -> Dict[str, str]:
        with self._operation("profile credential login", name=payload.get("name", "")):
            with self._busy_lock("profile credential login", timeout_sec=1.0):
                name = self._validate_profile_name(str(payload.get("name") or self.engine.profile_name or "default"))
                remember = bool(payload.get("remember", False))
                base = dict(self.engine.profiles.get(name, {}))
                patch = self._clean_profile_patch(payload)
                cfg = dict(base)
                cfg.update(patch)
                if not cfg.get("router_ip") or not cfg.get("user") or not cfg.get("password"):
                    raise RuntimeError("router_ip, user, and password are required to connect")

                saved_cfg = dict(cfg)
                if not remember:
                    saved_cfg.pop("user", None)
                    saved_cfg.pop("password", None)

                profiles = {k: dict(v) for k, v in self.engine.profiles.items()}
                profiles[name] = saved_cfg
                self._save_profiles_to_env(profiles)
                if not self._default_profile_name():
                    self._save_default_profile_to_env(name)
                self.engine.profiles = parse_router_profiles(self._profiles_env_path())

                self.engine.connect_profile(name, cfg)
                self.engine.reset_runtime_caches()
                self.engine.refresh_data(force=True)
                return {"status": "ok", "current": self.engine.profile_name, "remembered": "true" if remember else "false"}
