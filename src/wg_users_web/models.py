#!/usr/bin/env python3
from dataclasses import dataclass


@dataclass
class PeerView:
    peer_id: str
    interface: str
    ip: str
    comment: str
    rx: int
    tx: int
    disabled: bool
    last_handshake: str = ""
    up_speed_bps: float = 0.0
    down_speed_bps: float = 0.0
