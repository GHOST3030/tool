# NetGuard

Per-app network control for Zorin OS (and other GNOME-based Linux distros):
block internet access per application, cap bandwidth (MB/day or MB/session),
restrict apps to a time-of-day schedule, monitor usage over custom time
ranges, and see live totals from the taskbar tray icon.

## How it works

- Each controlled app is placed in its own **cgroup v2** group.
- **nftables** rules matched against that cgroup drop, rate-limit, or count
  that app's traffic — this is the standard, correct way to do per-app
  network control on Linux (there's no Windows-style built-in per-app
  firewall toggle).
- A small **privileged helper** (`netguard/helper/netguard_helper.py`)
  performs the actual root-level changes, invoked via `pkexec`. A **polkit
  policy** is installed so you authenticate once and it won't keep
  prompting for password on every change — while still avoiding a
  permanently-running root daemon.
- A user-level **monitor** (`netguard/monitor/collector.py`) polls usage
  counters, attaches new process IDs to the right cgroup, logs bandwidth
  to a local SQLite database, and enforces your caps/schedules
  automatically.
- A **PyQt6 GUI** (`netguard/gui/main.py`) lets you add apps (from running
  processes, installed `.desktop` entries — with proper Flatpak/Snap
  `Exec=` resolution — or a manual executable path), toggle blocking, set
  caps/schedules, and view historical usage charts (`pyqtgraph`).
- A **tray icon** (`netguard/gui/tray.py`) shows bandwidth totals (with a
  real download/upload split) for the last 3 hours, today, yesterday, this
  week, or a custom range.
- **Desktop notifications** fire when the monitor auto-blocks or
  auto-unblocks an app, so caps/schedules never silently kick in.
- Both the monitor and tray icon start automatically at login via
  `systemd --user` services.

## Install & run

```bash
git clone <this repo>
cd tool
./start.sh
```

`start.sh` installs system requirements (`nftables`, `python3-venv`,
`policykit-1`, `libnotify-bin`) via `apt`, runs the installer (helper,
polkit policy, Python venv, autostart services) on first run only, and then
launches the GUI. Run it again any time to just relaunch the GUI — it skips
setup once already installed (delete `~/.local/share/netguard/.installed`
to force it to reinstall/upgrade).

Requires cgroup v2 (default on Zorin OS 16/17) and an `apt`-based system.
If you're not on `apt`, install `nftables`, `python3-venv`, `policykit-1`,
and `libnotify-bin` manually, then run `netguard/install/install.sh` directly.

## Uninstall

```bash
systemctl --user disable --now netguard-monitor netguard-tray
rm -rf ~/.local/share/netguard ~/.config/systemd/user/netguard-*.service
sudo rm -rf /usr/local/libexec/netguard /usr/share/polkit-1/actions/com.netguard.helper.policy
```

## Status

This is an initial working implementation. Not yet tested on real hardware
in this environment — see "Suggested next steps" below before relying on
it for anything sensitive (e.g. parental controls).

## Suggested improvements (not yet done)

- **Per-app icons** in both the GUI table and tray menu for quicker
  visual scanning.
- **Config export/import** so cap/schedule setups can be backed up or
  shared across machines.
- **Real-world testing of Flatpak/Snap matching**: the matching logic
  scans `proc.cmdline()`/`proc.exe()` for the app ID/snap name, which
  should work but hasn't been verified against actual sandboxed apps on
  real hardware yet.
- **Per-app icons in the chart legend** and a per-app filter dropdown on
  the Usage tab chart (it currently charts the combined total, with the
  table below already broken out per app).
