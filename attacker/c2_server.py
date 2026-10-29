"""Kali-side one-command C2 handshake for the synthetic lab.

Start on Kali before the victim client: python3 -m attacker.c2_server --cmd PING
The victim logs/acknowledges commands but does not execute attack actions yet.
"""

import argparse
import socket

from config import ATTACKER_IP, AUTH_MODE, C2_PORT, VICTIM_IP
from shared.c2_protocol import log_event, pack, unpack


def serve_once(command, unsigned=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((ATTACKER_IP, C2_PORT))
        server.listen(1)
        server.settimeout(300)
        print(f"C2 listening on {ATTACKER_IP}:{C2_PORT}; auth={AUTH_MODE}", flush=True)
        connection, peer = server.accept()
        with connection:
            connection.settimeout(60)
            if peer[0] != VICTIM_IP:
                raise ValueError(f"Unexpected C2 client: {peer[0]}")
            connection.sendall(pack(command, signed=not unsigned))
            log_event("command_sent", role="attacker", cmd=command,
                      signed=not unsigned, peer_ip=peer[0])
            answer = unpack(connection, auth_mode=AUTH_MODE)
            if answer["cmd"] not in {"ACK", "REJECT"}:
                raise ValueError("Unexpected victim response")
            log_event("response_received", role="attacker", cmd=answer["cmd"],
                      requested=command, data=answer["data"])
            print(f"Victim response: {answer['cmd']} {answer['data']}", flush=True)


def serve_relay_once():
    """Demo: first connection is the victim, second is an untrusted sender."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((ATTACKER_IP, C2_PORT))
        server.listen(2)
        server.settimeout(300)
        print(f"C2 relay listening on {ATTACKER_IP}:{C2_PORT}; auth={AUTH_MODE}", flush=True)
        victim, victim_peer = server.accept()
        with victim:
            victim.settimeout(180)
            if victim_peer[0] != VICTIM_IP:
                raise ValueError(f"Unexpected victim IP: {victim_peer[0]}")
            print("Victim connected; waiting for separate command sender", flush=True)
            injector, injector_peer = server.accept()
            with injector:
                injector.settimeout(180)
                try:
                    candidate = unpack(injector, auth_mode=AUTH_MODE)
                    if candidate["cmd"] != "STOP":
                        raise ValueError("Relay demo only permits STOP")
                except ValueError as exc:
                    log_event("spoof_rejected", role="attacker", reason=str(exc),
                              peer_ip=injector_peer[0])
                    injector.sendall(pack("REJECT", signed=AUTH_MODE,
                                          data={"reason": str(exc)}))
                    victim.sendall(pack("REJECT", signed=AUTH_MODE,
                                        data={"reason": "untrusted command blocked"}))
                    print(f"Injection rejected: {exc}", flush=True)
                    return
                log_event("spoof_accepted", role="attacker", cmd="STOP",
                          peer_ip=injector_peer[0], authenticated=AUTH_MODE)
                victim.sendall(pack("STOP", signed=AUTH_MODE))
                answer = unpack(victim, auth_mode=AUTH_MODE)
                if answer["cmd"] != "ACK":
                    raise ValueError("Victim did not acknowledge dry-run STOP")
                injector.sendall(pack("ACK", signed=AUTH_MODE,
                                      data={"cmd": "STOP", "executed": False}))
                print("Injection reached victim: dry-run STOP acknowledged", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cmd", choices=("PING", "STOP", "START_ENCRYPT", "START_EXFIL"), default="PING")
    parser.add_argument("--unsigned", action="store_true", help="Test unsigned-command rejection")
    parser.add_argument("--relay-demo", action="store_true", help="Accept a separate dry-run STOP sender")
    args = parser.parse_args()
    if args.relay_demo:
        serve_relay_once()
    else:
        serve_once(args.cmd, args.unsigned)


if __name__ == "__main__":
    main()
