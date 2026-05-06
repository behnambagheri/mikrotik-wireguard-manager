#!/usr/bin/env python3
import json
import os
from typing import Any, Dict, Optional

from .config import STATE_FILE


class StateStore:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.environ.get("WG_WEB_STATE_FILE", STATE_FILE)
        self.data: Dict[str, Any] = {"peers": {}, "groups": {}}
        self.load()

    def load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
            if "peers" not in self.data:
                self.data["peers"] = {}
            if "groups" not in self.data:
                self.data["groups"] = {}
        except Exception:
            self.data = {"peers": {}, "groups": {}}

    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def peer(self, pid: str) -> Dict[str, Any]:
        peers = self.data.setdefault("peers", {})
        return peers.setdefault(pid, {})

    def delete_peer(self, pid: str) -> None:
        peers = self.data.setdefault("peers", {})
        peers.pop(pid, None)
        for group in self.groups().values():
            peer_ids = group.get("peer_ids", [])
            if isinstance(peer_ids, list):
                group["peer_ids"] = [x for x in peer_ids if x != pid]

    def groups(self) -> Dict[str, Any]:
        return self.data.setdefault("groups", {})

    def group(self, group_id: str) -> Dict[str, Any]:
        groups = self.groups()
        return groups.setdefault(group_id, {})

    def delete_group(self, group_id: str) -> None:
        self.groups().pop(group_id, None)
