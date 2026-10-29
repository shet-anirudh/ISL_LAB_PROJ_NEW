"""Send an unsigned, dry-run STOP into the lab C2 relay.

Run on Kali only after the victim has connected to a relay-demo server:
    python3 -m tests.spoof_demo

No command handler in this phase performs an action.
"""

import json
import os
import socket
import struct

from config import ATTACKER_IP, C2_PORT


def recv_exact(sock, count):
    parts = bytearray()
    while len(parts) < count:
        data = sock.recv(count - len(parts))
        if not data:
            raise ConnectionError("C2 relay closed before responding")
        parts.extend(data)
    return bytes(parts)


def main():
    body = json.dumps({"cmd": "STOP", "data": {}, "nonce": os.urandom(16).hex()},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")
    frame = struct.pack("!I", len(body)) + body
    with socket.create_connection((ATTACKER_IP, C2_PORT), timeout=10) as connection:
        connection.settimeout(15)
        connection.sendall(frame)
        size = struct.unpack("!I", recv_exact(connection, 4))[0]
        if not (1 <= size <= 4096):
            raise ValueError("Invalid response size")
        response = json.loads(recv_exact(connection, size))
    if response.get("cmd") not in {"ACK", "REJECT"}:
        raise ValueError("Unexpected response")
    print(f"Unsigned STOP injection: {response['cmd']} {response.get('data', {})}")


if __name__ == "__main__":
    main()
