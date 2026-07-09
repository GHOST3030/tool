#!/usr/bin/env bash
# Installs NetGuard: helper binary, polkit policy, venv + package, autostart.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HELPER_DIR="/usr/local/libexec/netguard"
DATA_DIR="$HOME/.local/share/netguard"
VENV_DIR="$DATA_DIR/venv"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

echo "==> Installing privileged helper (requires sudo)"
sudo mkdir -p "$HELPER_DIR"
sudo cp "$REPO_ROOT/netguard/helper/netguard_helper.py" "$HELPER_DIR/netguard-helper"
sudo chmod 755 "$HELPER_DIR/netguard-helper"
sudo chown root:root "$HELPER_DIR/netguard-helper"

echo "==> Installing polkit policy (requires sudo)"
sudo cp "$REPO_ROOT/netguard/install/polkit/com.netguard.helper.policy" \
    /usr/share/polkit-1/actions/com.netguard.helper.policy

echo "==> Checking cgroup v2 is mounted"
if [ ! -d /sys/fs/cgroup/unified ] && ! mount | grep -q "cgroup2 on /sys/fs/cgroup"; then
    echo "WARNING: cgroup v2 unified hierarchy not detected. NetGuard requires it."
    echo "Zorin OS 16/17 (Ubuntu 20.04/22.04+ base) enables this by default; if not,"
    echo "add 'systemd.unified_cgroup_hierarchy=1' to your kernel boot parameters."
fi

echo "==> Creating Python virtual environment at $VENV_DIR"
mkdir -p "$DATA_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -e "$REPO_ROOT" -q

echo "==> Installing systemd --user services"
mkdir -p "$SYSTEMD_USER_DIR"
sed "s#%h/.local/share/netguard/venv#$VENV_DIR#" \
    "$REPO_ROOT/netguard/install/netguard-monitor.service" > "$SYSTEMD_USER_DIR/netguard-monitor.service"
sed "s#%h/.local/share/netguard/venv#$VENV_DIR#" \
    "$REPO_ROOT/netguard/install/netguard-tray.service" > "$SYSTEMD_USER_DIR/netguard-tray.service"

systemctl --user daemon-reload
systemctl --user enable --now netguard-monitor.service
systemctl --user enable --now netguard-tray.service

echo "==> Installing application menu launcher"
mkdir -p "$HOME/.local/share/applications"
sed "s#%h/.local/share/netguard/venv#$VENV_DIR#" \
    "$REPO_ROOT/netguard/install/netguard.desktop" > "$HOME/.local/share/applications/netguard.desktop"

echo "==> Enabling lingering so services start at boot without login (optional)"
sudo loginctl enable-linger "$USER" || true

cat <<'EOF'

NetGuard installed.

- The tray icon and background monitor now start automatically at login,
  and will start on this boot too.
- Run the full app with:  <venv>/bin/python -m netguard.gui.main
- The first time NetGuard needs to change a network rule, you'll get ONE
  polkit authentication prompt. After that, thanks to the installed policy,
  it will not prompt again for this helper.
- To uninstall: systemctl --user disable --now netguard-monitor netguard-tray
  and remove ~/.local/share/netguard, /usr/local/libexec/netguard,
  and /usr/share/polkit-1/actions/com.netguard.helper.policy
EOF
