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
  processes, installed `.desktop` entries, or a manual executable path),
  toggle blocking, and set caps/schedules.
- A **tray icon** (`netguard/gui/tray.py`) shows bandwidth totals for the
  last 3 hours, today, yesterday, this week, or a custom range.
- Both the monitor and tray icon start automatically at login via
  `systemd --user` services.

## Install

```bash
git clone <this repo>
cd tool
bash netguard/install/install.sh
```

Requires cgroup v2 (default on Zorin OS 16/17) and `nftables` installed.

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

## Suggested improvements

- **Real rx/tx split**: currently one shared nftables counter reports
  combined bytes; splitting input/output into separate named counters
  would give accurate upload vs download breakdowns.
- **`.desktop` file matching**: current desktop-entry matching just falls
  back to comparing process name; parsing the `Exec=` line properly would
  be more robust for apps with wrapper scripts (Flatpak, Electron, etc.).
- **Historical charts**: the Usage tab currently shows a table; adding
  `pyqtgraph` line/bar charts (hourly/daily trends) would make patterns
  easier to spot.
- **Per-app icons** in both the GUI table and tray menu for quicker
  visual scanning.
- **Notifications** (via `notify-send`/`libnotify`) when an app is
  auto-blocked for hitting its cap, so it's not a silent surprise.
- **Flatpak/Snap awareness**: sandboxed apps run under their own cgroup
  scopes already; worth testing matching against those namespaces
  specifically.
- **Config export/import** so cap/schedule setups can be backed up or
  shared across machines.
