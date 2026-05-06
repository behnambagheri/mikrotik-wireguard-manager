#!/usr/bin/env python3
import json
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib import error, parse, request

from .models import PeerView
from .utils import first_ip, parse_bool


class RouterOSClient:
    def __init__(self, host: str, user: str, password: str, use_https: bool = False, timeout_sec: float = 30.0):
        self.host = host
        self.user = user
        self.password = password
        scheme = "https" if use_https else "http"
        self.base = f"{scheme}://{host}/rest"
        self.timeout_sec = timeout_sec
        creds = f"{user}:{password}".encode("utf-8")
        import base64

        self.auth_header = "Basic " + base64.b64encode(creds).decode("ascii")
        self.ssl_ctx = ssl._create_unverified_context()

    @staticmethod
    def _rid(raw: str) -> str:
        # RouterOS resource IDs contain "*" and must keep it in the path.
        return parse.quote(raw, safe="*")

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        # Thin REST wrapper with consistent auth + JSON behavior.
        if not path.startswith("/"):
            path = "/" + path
        url = self.base + path
        data = None
        headers = {
            "Authorization": self.auth_header,
            "Accept": "application/json",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(url, data=data, method=method, headers=headers)
        try:
            if self.base.startswith("https://"):
                resp = request.urlopen(req, timeout=self.timeout_sec, context=self.ssl_ctx)
            else:
                resp = request.urlopen(req, timeout=self.timeout_sec)
            with resp:
                raw = resp.read().decode("utf-8")
                if not raw:
                    return None
                return json.loads(raw)
        except error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8")
            except Exception:
                pass
            raise RuntimeError(f"HTTP {e.code} {method} {path}: {body}") from e
        except Exception as e:
            raise RuntimeError(f"Request failed {method} {path}: {e}") from e

    def list_peers(self) -> List[PeerView]:
        rows = self._request("GET", "/interface/wireguard/peers") or []
        peers: List[PeerView] = []
        for r in rows:
            peers.append(
                PeerView(
                    peer_id=str(r.get(".id", "")),
                    interface=str(r.get("interface", "")),
                    ip=first_ip(str(r.get("allowed-address", ""))),
                    comment=str(r.get("comment", "")),
                    rx=int(r.get("rx", 0) or 0),
                    tx=int(r.get("tx", 0) or 0),
                    disabled=parse_bool(r.get("disabled", False)),
                    last_handshake=str(r.get("last-handshake", "")),
                )
            )
        peers.sort(key=lambda p: (p.interface, p.comment.lower(), p.ip))
        return peers

    def list_system_resource(self) -> Dict[str, Any]:
        return self._request("GET", "/system/resource") or {}

    def list_interfaces(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/interface") or []

    def list_queue_tree(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/queue/tree") or []

    def list_mangle(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/ip/firewall/mangle") or []

    def list_filter(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/ip/firewall/filter") or []

    def list_address_list(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/ip/firewall/address-list") or []

    def list_wireguard_interfaces(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/interface/wireguard") or []

    def list_ip_addresses(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/ip/address") or []

    def list_scheduler(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/system/scheduler") or []

    def set_peer_disabled(self, peer_id: str, disabled: bool) -> None:
        pid = self._rid(peer_id)
        self._request("PATCH", f"/interface/wireguard/peers/{pid}", {"disabled": "true" if disabled else "false"})

    def update_peer_public_key(self, peer_id: str, public_key: str) -> None:
        pid = self._rid(peer_id)
        self._request("PATCH", f"/interface/wireguard/peers/{pid}", {"public-key": public_key})

    def create_peer(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/interface/wireguard/peers", payload)

    def delete_peer(self, peer_id: str) -> None:
        self._request("DELETE", f"/interface/wireguard/peers/{self._rid(peer_id)}")

    def create_queue(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/queue/tree", payload)

    def patch_queue(self, qid: str, payload: Dict[str, Any]) -> None:
        self._request("PATCH", f"/queue/tree/{self._rid(qid)}", payload)

    def delete_queue(self, qid: str) -> None:
        self._request("DELETE", f"/queue/tree/{self._rid(qid)}")

    def create_mangle(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/ip/firewall/mangle", payload)

    def patch_mangle(self, rid: str, payload: Dict[str, Any]) -> None:
        self._request("PATCH", f"/ip/firewall/mangle/{self._rid(rid)}", payload)

    def delete_mangle(self, rid: str) -> None:
        self._request("DELETE", f"/ip/firewall/mangle/{self._rid(rid)}")

    def create_filter(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/ip/firewall/filter", payload)

    def patch_filter(self, rid: str, payload: Dict[str, Any]) -> None:
        self._request("PATCH", f"/ip/firewall/filter/{self._rid(rid)}", payload)

    def delete_filter(self, rid: str) -> None:
        self._request("DELETE", f"/ip/firewall/filter/{self._rid(rid)}")

    def create_address_list(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/ip/firewall/address-list", payload)

    def patch_address_list(self, rid: str, payload: Dict[str, Any]) -> None:
        self._request("PATCH", f"/ip/firewall/address-list/{self._rid(rid)}", payload)

    def delete_address_list(self, rid: str) -> None:
        self._request("DELETE", f"/ip/firewall/address-list/{self._rid(rid)}")

    def create_scheduler(self, payload: Dict[str, Any]) -> None:
        self._request("PUT", "/system/scheduler", payload)

    def patch_scheduler(self, rid: str, payload: Dict[str, Any]) -> None:
        self._request("PATCH", f"/system/scheduler/{self._rid(rid)}", payload)

    def delete_scheduler(self, rid: str) -> None:
        self._request("DELETE", f"/system/scheduler/{self._rid(rid)}")


class ApiSslClient:
    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        timeout_sec: float = 30.0,
        port: int = 8729,
        use_ssl: bool = True,
    ):
        self.host = host
        self.user = user
        self.password = password
        self.timeout_sec = timeout_sec
        self.port = port
        self.use_ssl = use_ssl
        self.sock: Optional[socket.socket] = None
        self.ssl_sock: Optional[Any] = None

    @staticmethod
    def _encode_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        if n < 0x4000:
            n |= 0x8000
            return bytes([(n >> 8) & 0xFF, n & 0xFF])
        if n < 0x200000:
            n |= 0xC00000
            return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
        if n < 0x10000000:
            n |= 0xE0000000
            return bytes([(n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
        return bytes([0xF0, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])

    @staticmethod
    def _decode_len(read1) -> int:
        c = read1()[0]
        if (c & 0x80) == 0x00:
            return c
        if (c & 0xC0) == 0x80:
            c2 = read1()[0]
            return ((c & ~0xC0) << 8) + c2
        if (c & 0xE0) == 0xC0:
            c2 = read1()[0]
            c3 = read1()[0]
            return ((c & ~0xE0) << 16) + (c2 << 8) + c3
        if (c & 0xF0) == 0xE0:
            c2 = read1()[0]
            c3 = read1()[0]
            c4 = read1()[0]
            return ((c & ~0xF0) << 24) + (c2 << 16) + (c3 << 8) + c4
        if (c & 0xF8) == 0xF0:
            c2 = read1()[0]
            c3 = read1()[0]
            c4 = read1()[0]
            c5 = read1()[0]
            return (c2 << 24) + (c3 << 16) + (c4 << 8) + c5
        raise RuntimeError("Invalid API length header")

    def _connect(self) -> None:
        if self.ssl_sock is not None:
            return
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout_sec)
        if self.use_ssl:
            ctx = ssl._create_unverified_context()
            self.ssl_sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self.ssl_sock = raw
        self.ssl_sock.settimeout(self.timeout_sec)
        self.sock = raw
        self._login()

    def _close(self) -> None:
        try:
            if self.ssl_sock:
                self.ssl_sock.close()
        finally:
            self.ssl_sock = None
            self.sock = None

    def _read_exact(self, n: int) -> bytes:
        assert self.ssl_sock is not None
        out = b""
        while len(out) < n:
            chunk = self.ssl_sock.recv(n - len(out))
            if not chunk:
                raise RuntimeError("API connection closed")
            out += chunk
        return out

    def _write_sentence(self, words: List[str]) -> None:
        assert self.ssl_sock is not None
        buf = b""
        for w in words:
            wb = w.encode("utf-8")
            buf += self._encode_len(len(wb)) + wb
        buf += b"\x00"
        self.ssl_sock.sendall(buf)

    def _read_sentence(self) -> List[str]:
        def read1() -> bytes:
            return self._read_exact(1)

        words: List[str] = []
        while True:
            n = self._decode_len(read1)
            if n == 0:
                return words
            words.append(self._read_exact(n).decode("utf-8", errors="replace"))

    def _talk(self, words: List[str]) -> List[List[str]]:
        self._connect()
        assert self.ssl_sock is not None
        self._write_sentence(words)
        out: List[List[str]] = []
        while True:
            s = self._read_sentence()
            if not s:
                continue
            out.append(s)
            if s[0] in ("!done", "!trap", "!fatal"):
                break
        return out

    def _parse(self, replies: List[List[str]]) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        err = None
        for s in replies:
            kind = s[0]
            if kind == "!re":
                row: Dict[str, str] = {}
                for w in s[1:]:
                    if w.startswith("=") and "=" in w[1:]:
                        k, v = w[1:].split("=", 1)
                        row[k] = v
                rows.append(row)
            elif kind in ("!trap", "!fatal"):
                for w in s[1:]:
                    if w.startswith("=message="):
                        err = w[len("=message=") :]
                if err is None:
                    err = "API command failed"
        if err:
            raise RuntimeError(err)
        return rows

    def _cmd(self, path: str, attrs: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
        words = [path]
        if attrs:
            for k, v in attrs.items():
                words.append(f"={k}={v}")
        replies = self._talk(words)
        return self._parse(replies)

    def _remove_with_fallback(self, path: str, rid: str) -> None:
        # Some RouterOS API versions expect "numbers" on remove commands
        # while newer ones accept ".id". Try ".id" first, then fallback.
        try:
            self._cmd(path, {".id": rid})
            return
        except RuntimeError as e:
            msg = str(e).lower()
            if ("no such item" in msg) or ("invalid internal item number" in msg):
                raise
        self._cmd(path, {"numbers": rid})

    def _login(self) -> None:
        rows = self._talk(["/login", f"=name={self.user}", f"=password={self.password}"])
        # If login failed _parse would raise trap message.
        self._parse(rows)

    @staticmethod
    def _as_peer(rows: List[Dict[str, str]]) -> List[PeerView]:
        peers: List[PeerView] = []
        for r in rows:
            peers.append(
                PeerView(
                    peer_id=str(r.get(".id", "")),
                    interface=str(r.get("interface", "")),
                    ip=first_ip(str(r.get("allowed-address", ""))),
                    comment=str(r.get("comment", "")),
                    rx=int(r.get("rx", "0") or "0"),
                    tx=int(r.get("tx", "0") or "0"),
                    disabled=parse_bool(r.get("disabled", "false")),
                    last_handshake=str(r.get("last-handshake", "")),
                )
            )
        peers.sort(key=lambda p: (p.interface, p.comment.lower(), p.ip))
        return peers

    def list_peers(self) -> List[PeerView]:
        return self._as_peer(self._cmd("/interface/wireguard/peers/print"))

    def list_system_resource(self) -> Dict[str, Any]:
        rows = self._cmd("/system/resource/print")
        return rows[0] if rows else {}

    def list_interfaces(self) -> List[Dict[str, Any]]:
        return self._cmd("/interface/print")

    def list_queue_tree(self) -> List[Dict[str, Any]]:
        return self._cmd("/queue/tree/print")

    def list_mangle(self) -> List[Dict[str, Any]]:
        return self._cmd("/ip/firewall/mangle/print")

    def list_filter(self) -> List[Dict[str, Any]]:
        return self._cmd("/ip/firewall/filter/print")

    def list_address_list(self) -> List[Dict[str, Any]]:
        return self._cmd("/ip/firewall/address-list/print")

    def list_wireguard_interfaces(self) -> List[Dict[str, Any]]:
        return self._cmd("/interface/wireguard/print")

    def list_ip_addresses(self) -> List[Dict[str, Any]]:
        return self._cmd("/ip/address/print")

    def list_scheduler(self) -> List[Dict[str, Any]]:
        return self._cmd("/system/scheduler/print")

    def set_peer_disabled(self, peer_id: str, disabled: bool) -> None:
        self._cmd("/interface/wireguard/peers/set", {".id": peer_id, "disabled": "true" if disabled else "false"})

    def update_peer_public_key(self, peer_id: str, public_key: str) -> None:
        self._cmd("/interface/wireguard/peers/set", {".id": peer_id, "public-key": public_key})

    def create_peer(self, payload: Dict[str, Any]) -> None:
        self._cmd("/interface/wireguard/peers/add", payload)

    def delete_peer(self, peer_id: str) -> None:
        self._remove_with_fallback("/interface/wireguard/peers/remove", peer_id)

    def create_queue(self, payload: Dict[str, Any]) -> None:
        self._cmd("/queue/tree/add", payload)

    def patch_queue(self, qid: str, payload: Dict[str, Any]) -> None:
        p = dict(payload)
        p[".id"] = qid
        self._cmd("/queue/tree/set", p)

    def delete_queue(self, qid: str) -> None:
        self._remove_with_fallback("/queue/tree/remove", qid)

    def create_mangle(self, payload: Dict[str, Any]) -> None:
        self._cmd("/ip/firewall/mangle/add", payload)

    def patch_mangle(self, rid: str, payload: Dict[str, Any]) -> None:
        p = dict(payload)
        p[".id"] = rid
        self._cmd("/ip/firewall/mangle/set", p)

    def delete_mangle(self, rid: str) -> None:
        self._remove_with_fallback("/ip/firewall/mangle/remove", rid)

    def create_filter(self, payload: Dict[str, Any]) -> None:
        self._cmd("/ip/firewall/filter/add", payload)

    def patch_filter(self, rid: str, payload: Dict[str, Any]) -> None:
        p = dict(payload)
        p[".id"] = rid
        self._cmd("/ip/firewall/filter/set", p)

    def delete_filter(self, rid: str) -> None:
        self._remove_with_fallback("/ip/firewall/filter/remove", rid)

    def create_address_list(self, payload: Dict[str, Any]) -> None:
        self._cmd("/ip/firewall/address-list/add", payload)

    def patch_address_list(self, rid: str, payload: Dict[str, Any]) -> None:
        p = dict(payload)
        p[".id"] = rid
        self._cmd("/ip/firewall/address-list/set", p)

    def delete_address_list(self, rid: str) -> None:
        self._remove_with_fallback("/ip/firewall/address-list/remove", rid)

    def create_scheduler(self, payload: Dict[str, Any]) -> None:
        self._cmd("/system/scheduler/add", payload)

    def patch_scheduler(self, rid: str, payload: Dict[str, Any]) -> None:
        p = dict(payload)
        p[".id"] = rid
        self._cmd("/system/scheduler/set", p)

    def delete_scheduler(self, rid: str) -> None:
        self._remove_with_fallback("/system/scheduler/remove", rid)
