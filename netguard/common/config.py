"""Shared paths and constants for NetGuard."""
import os

APP_NAME = "netguard"

CONFIG_DIR = os.path.expanduser(f"~/.config/{APP_NAME}")
DATA_DIR = os.path.expanduser(f"~/.local/share/{APP_NAME}")
DB_PATH = os.path.join(DATA_DIR, "usage.db")
RULES_PATH = os.path.join(CONFIG_DIR, "rules.json")

CGROUP_ROOT = "/sys/fs/cgroup/netguard"
NFT_TABLE = "netguard"

HELPER_BIN = "/usr/local/libexec/netguard/netguard-helper"
POLKIT_ACTION_ID = "com.netguard.helper.run"

# Poll interval for the user-space collector (seconds). Keep this high enough
# to avoid CPU/battery overhead; nft counters don't need sub-second polling.
POLL_INTERVAL_SECONDS = 5

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
