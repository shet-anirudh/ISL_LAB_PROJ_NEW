# config.py — single source of truth for all modules

# ── Network ──────────────────────────────────────────
ATTACKER_IP     = "192.168.56.10"
VICTIM_IP       = "192.168.56.20"
C2_PORT         = 9001
TRANSFER_PORT   = 9002
BACKUP_PORT     = 9003

# ── Paths ─────────────────────────────────────────────
TEST_DATA_DIR   = "/home/victim/MILITARY_DATA"
HONEYPOT_DIR    = "/home/victim/MILITARY_DATA/A_COMMAND_ARCHIVE"
BACKUP_DIR      = "/home/victim/BACKUP"
LOG_DIR         = "/home/victim/islab-project/logs"
RESULTS_DIR     = "/home/victim/islab-project/results"

# ── File markers ──────────────────────────────────────
ENCRYPTED_EXT   = ".locked"
KEY_EXT         = ".key"
RANSOM_NOTE     = "README_DECRYPT.txt"

# ── Crypto ────────────────────────────────────────────
RSA_PUB_KEY_PATH  = "/home/kali/islab-project/keys/public.pem"
RSA_PRIV_KEY_PATH = "/home/kali/islab-project/keys/private.pem"
BACKUP_CERT_PATH  = "/home/victim/islab-project/keys/backup.crt"
BACKUP_KEY_PATH   = "/home/victim/islab-project/keys/backup.key"
HMAC_SECRET       = b"change-this-before-demo-day"

# ── Feature flags ─────────────────────────────────────
AUTH_MODE         = True   # False = naive C2, True = HMAC-authenticated
NETWORK_ISOLATION = False  # Switch to True only for the final demo
