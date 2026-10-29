"""Victim-side one-command C2 client for the synthetic lab.

Run on victim after Kali server is listening: python3 -m victim.c2_client
Only records an accepted command; execution wiring comes later.
"""

import socket

from config import ATTACKER_IP, AUTH_MODE, C2_PORT
from shared.c2_protocol import COMMANDS, log_event, pack, unpack


def receive_once():
    with socket.create_connection((ATTACKER_IP, C2_PORT), timeout=10) as connection:
        connection.settimeout(180)
        try:
            message = unpack(connection, auth_mode=AUTH_MODE)
            command = message["cmd"]
            if command == "REJECT":
                log_event("untrusted_command_blocked", role="victim",
                          reason=message["data"].get("reason"))
                print(f"No command relayed: {message['data'].get('reason')}")
                return
            if command not in COMMANDS:
                raise ValueError("Expected a command")
        except (ValueError, UnicodeError) as exc:
            log_event("command_rejected", role="victim", reason=str(exc))
            connection.sendall(pack("REJECT", signed=AUTH_MODE, data={"reason": str(exc)}))
            print(f"REJECT: {exc}")
            return
        log_event("command_accepted", role="victim", cmd=command,
                  authenticated=message["authenticated"])
        connection.sendall(pack("ACK", signed=AUTH_MODE, data={"cmd": command, "executed": False}))
        print(f"ACK: {command} accepted (dry run; no action executed)")


if __name__ == "__main__":
    receive_once()