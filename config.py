# config.py — single source of truth for all modules
from pathlib import Path

# ── Network ──────────────────────────────────────────
ATTACKER_IP     = "192.168.56.10"
VICTIM_IP       = "192.168.56.20"
C2_PORT         = 9001
TRANSFER_PORT   = 9002
BACKUP_PORT     = 9003

# ── Paths ─────────────────────────────────────────────
PROJECT_ROOT  = Path(__file__).resolve().parent
VICTIM_HOME   = Path("/home/vboxuser")

TEST_DATA_DIR   = str(VICTIM_HOME / "MILITARY_DATA")
HONEYPOT_DIR    = str(VICTIM_HOME / "MILITARY_DATA" / "A_COMMAND_ARCHIVE")
BACKUP_DIR      = str(VICTIM_HOME / "BACKUP")
LOG_DIR         = str(PROJECT_ROOT / "logs")
RESULTS_DIR     = str(PROJECT_ROOT / "results")

# ── File markers ──────────────────────────────────────
ENCRYPTED_EXT   = ".locked"
KEY_EXT         = ".key"
RANSOM_NOTE     = "README_DECRYPT.txt"

# ── Crypto ────────────────────────────────────────────
RSA_PUB_KEY_PATH = str(PROJECT_ROOT / "keys" / "public.pem")
RSA_PRIV_KEY_PATH = str(Path.home() / ".config" / "islab" / "private.pem")
BACKUP_CERT_PATH  = str(PROJECT_ROOT / "keys" / "backup.crt")
BACKUP_KEY_PATH   = str(PROJECT_ROOT / "keys" / "backup.key")
HMAC_SECRET       = b"change-this-before-demo-day"

# ── Feature flags ─────────────────────────────────────
AUTH_MODE         = True   # False = naive C2, True = HMAC-authenticated
NETWORK_ISOLATION = False  # Switch to True only for the final demo
