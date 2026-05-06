#!/usr/bin/env python3
from .common import *


class BaseManager:
    def __init__(self) -> None:
        # Re-entrant lock is required because some high-level operations
        # call other methods that also acquire the manager lock.
        self._lock = threading.RLock()
        self.engine = App()
        self._bootstrap_non_interactive()
        if self.engine.client is not None:
            self.engine.refresh_data(force=True)

    def _bootstrap_non_interactive(self) -> None:
        if self.engine.profiles:
            preferred = get_default_profile_name(self._profiles_env_path())
            if preferred and preferred in self.engine.profiles:
                name = preferred
            else:
                name = sorted(self.engine.profiles.keys())[0]
            profile = self.engine.profiles[name]
            if profile.get("router_ip") and profile.get("user") and profile.get("password"):
                self.engine.connect_profile(name, profile)
            else:
                self.engine.profile_name = name
                self.engine.host = profile.get("router_ip", "").strip()
                self.engine.user = profile.get("user", "").strip()
                self.engine.password = ""
                self.engine.status = f"Profile needs credentials: {name}"
            return

        host = self.engine.host or os.environ.get("ROUTER_IP", "").strip()
        user = self.engine.user or os.environ.get("ROUTER_USER", "").strip()
        password = os.environ.get("ROUTER_PASS", "").strip().strip('"').strip("'")
        if not host or not user or not password:
            self.engine.status = "Router profile setup required"
            return
        use_https = os.environ.get("ROUTER_USE_HTTPS", "false").lower() == "true"
        timeout_sec = float(os.environ.get("ROUTER_TIMEOUT_SEC", "30") or "30")
        self.engine.profile_name = "default"
        self.engine.host = host
        self.engine.user = user
        self.engine.password = password
        self.engine.use_https = use_https
        self.engine.timeout_sec = timeout_sec
        self.engine.cfg_dns = os.environ.get("DNS_SERVERS", self.engine.cfg_dns).strip() or self.engine.cfg_dns
        self.engine.cfg_endpoint_host = os.environ.get("ENDPOINT_IP", self.engine.cfg_endpoint_host).strip() or self.engine.cfg_endpoint_host
        self.engine.client = RouterOSClient(host, user, password, use_https=use_https, timeout_sec=timeout_sec)

    def current_profile(self) -> str:
        return self.engine.profile_name

    @staticmethod
    def _fmt_fields(**fields: Any) -> str:
        parts: List[str] = []
        for key, value in fields.items():
            if value is None or value == "":
                continue
            parts.append(f"{key}={value}")
        return " ".join(parts)

    @contextmanager
    def _operation(self, action: str, **fields: Any):
        profile = self.engine.profile_name or "unknown"
        start = time.monotonic()
        suffix = self._fmt_fields(profile=profile, **fields)
        msg = f"{action} started"
        if suffix:
            msg = f"{msg} | {suffix}"
        logger.info(msg)
        try:
            yield
        except Exception:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            fail = f"{action} failed"
            if suffix:
                fail = f"{fail} | {suffix}"
            logger.exception("%s duration_ms=%s", fail, elapsed_ms)
            raise
        elapsed_ms = int((time.monotonic() - start) * 1000)
        done = f"{action} finished"
        if suffix:
            done = f"{done} | {suffix}"
        logger.info("%s duration_ms=%s", done, elapsed_ms)

    @contextmanager
    def _busy_lock(self, action: str, timeout_sec: float = 0.25):
        acquired = self._lock.acquire(timeout=timeout_sec)
        if not acquired:
            raise RuntimeError(f"Manager busy during {action}; try again")
        try:
            yield
        finally:
            self._lock.release()

    def refresh(self) -> None:
        with self._operation("refresh"):
            with self._busy_lock("refresh"):
                self.engine.refresh_data(force=True)

    def _peer_by_id(self, peer_id: str):
        for p in self.engine.peers:
            if p.peer_id == peer_id:
                return p
        raise RuntimeError(f"Peer not found: {peer_id}")
