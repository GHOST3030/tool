#!/usr/bin/env bash
# One-shot entry point: installs system + Python requirements (first run
# only), sets up autostart, then launches the NetGuard GUI.
#
# Usage: ./start.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$HOME/.local/share/netguard"
VENV_DIR="$DATA_DIR/venv"
MARKER="$DATA_DIR/.installed"

echo "==> NetGuard start.sh"

if [ ! -f "$MARKER" ]; then
    echo "==> First run detected, installing system requirements (requires sudo)"
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo apt-get install -y \
            nftables \
            python3 \
            python3-venv \
            python3-pip \
            policykit-1 \
            libnotify-bin
    else
        echo "WARNING: apt-get not found. Install these manually before continuing:"
        echo "  nftables, python3, python3-venv, python3-pip, policykit-1 (pkexec), libnotify-bin (notify-send)"
    fi

    echo "==> Running NetGuard installer (helper, polkit policy, venv, autostart)"
    bash "$REPO_ROOT/netguard/install/install.sh"

    mkdir -p "$DATA_DIR"
    touch "$MARKER"
else
    echo "==> Already installed, skipping setup (delete $MARKER to force a reinstall)"
fi

echo "==> Launching NetGuard"
exec "$VENV_DIR/bin/python" -m netguard.gui.main
