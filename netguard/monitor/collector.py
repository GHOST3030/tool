#!/usr/bin/env python3
"""Background monitor/enforcer.

- Watches running processes, attaches matching PIDs to each app's cgroup.
- Polls nftables counters, converts cumulative counts to per-interval deltas,
  and logs them to the usage database.
- Enforces daily/session MB caps and time-of-day schedules by calling the
  helper to block/unblock as needed.

Meant to run as a systemd --user service, started at login (see install/).
"""
import logging
import subprocess
import time
from datetime import datetime

import psutil

from netguard.common import db, priv
from netguard.common.config import POLL_INTERVAL_SECONDS


def notify(summary, body):
    """Best-effort desktop notification. Silently does nothing if notify-send
    isn't available or there's no session bus (e.g. headless testing)."""
    try:
        subprocess.run(
            ["notify-send", "--app-name=NetGuard", "--icon=network-transmit-receive", summary, body],
            check=False, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s netguard-monitor: %(message)s")
log = logging.getLogger("netguard.monitor")


class Collector:
    def __init__(self):
        self._last_counter_bytes = {}   # app_name -> {"rx": last cumulative rx, "tx": last cumulative tx}
        self._session_start = {}        # app_id -> timestamp of first sample this "session"
        self._known_pids = {}           # app_name -> set of pids already attached
        self._auto_blocked = {}         # app_id -> bool, last known auto-enforcement state

    def bootstrap(self):
        priv.setup()
        for app in db.list_apps():
            priv.create(app["cgroup_name"])
            cap = db.get_cap(app["id"]) or {}
            if cap.get("blocked"):
                priv.block(app["cgroup_name"])
            elif cap.get("rate_kbps"):
                priv.limit(app["cgroup_name"], cap["rate_kbps"])
        log.info("bootstrap complete")

    def _matches(self, proc, app):
        try:
            kind, value = app["match_kind"], app["match_value"]
            if kind == "process_name":
                return proc.name() == value
            if kind == "path":
                return proc.exe() == value
            if kind == "flatpak":
                # Flatpak apps run under bwrap with the app ID somewhere in argv,
                # e.g. ".../flatpak-bwrap ... --app-id=org.mozilla.firefox ..."
                cmdline = " ".join(proc.cmdline())
                return value in cmdline
            if kind == "snap":
                # Snap apps run as /snap/<name>/current/... or via `snap run <name>`.
                exe = proc.exe() or ""
                cmdline = " ".join(proc.cmdline())
                return f"/snap/{value}/" in exe or value in cmdline
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        return False

    def attach_new_pids(self):
        apps = db.list_apps()
        if not apps:
            return
        procs = list(psutil.process_iter(["pid", "name", "exe"]))
        for app in apps:
            seen = self._known_pids.setdefault(app["cgroup_name"], set())
            for proc in procs:
                if proc.pid in seen:
                    continue
                if self._matches(proc, app):
                    try:
                        priv.add_pid(app["cgroup_name"], proc.pid)
                        seen.add(proc.pid)
                    except priv.HelperError as e:
                        log.warning("failed to attach pid %s to %s: %s", proc.pid, app["name"], e)

    def poll_counters_and_log(self):
        try:
            counts = priv.counters()
        except priv.HelperError as e:
            log.warning("counters read failed: %s", e)
            return
        for app in db.list_apps():
            cg = app["cgroup_name"]
            rx_now = counts.get(cg, {}).get("rx_bytes", 0)
            tx_now = counts.get(cg, {}).get("tx_bytes", 0)
            last = self._last_counter_bytes.get(cg, {"rx": rx_now, "tx": tx_now})
            rx_delta = max(0, rx_now - last["rx"])
            tx_delta = max(0, tx_now - last["tx"])
            self._last_counter_bytes[cg] = {"rx": rx_now, "tx": tx_now}
            if rx_delta > 0 or tx_delta > 0:
                db.record_sample(app["id"], rx_bytes=rx_delta, tx_bytes=tx_delta)

    def enforce_caps(self):
        now = datetime.now()
        for app in db.list_apps():
            cap = db.get_cap(app["id"])
            if not cap or not cap["enabled"]:
                continue
            cg = app["cgroup_name"]

            # Manual block always wins.
            if cap["blocked"]:
                continue

            in_window = True
            if cap["sched_start"] and cap["sched_end"]:
                start_t = datetime.strptime(cap["sched_start"], "%H:%M").time()
                end_t = datetime.strptime(cap["sched_end"], "%H:%M").time()
                now_t = now.time()
                in_window = start_t <= now_t <= end_t if start_t <= end_t else (now_t >= start_t or now_t <= end_t)

            over_cap = False
            if cap["cap_kind"] == "daily_mb" and cap["limit_mb"]:
                used = db.usage_for_app(app["id"], period="today")["total_bytes"]
                over_cap = used >= cap["limit_mb"] * 1024 * 1024
            elif cap["cap_kind"] == "session_mb" and cap["limit_mb"]:
                since = self._session_start.setdefault(app["id"], time.time())
                used = db.session_usage_bytes(app["id"], since)
                over_cap = used >= cap["limit_mb"] * 1024 * 1024

            should_block = (not in_window) or over_cap
            was_blocked = self._auto_blocked.get(app["id"], False)
            if should_block == was_blocked:
                continue  # no state change -- skip redundant nft/cgroup calls this tick

            try:
                if should_block:
                    priv.block(cg)
                    reason = "outside its allowed schedule" if not in_window else "hit its data cap"
                    db.log_event(app["id"], "auto_block",
                                 "schedule" if not in_window else "cap_exceeded")
                    notify("NetGuard: app blocked",
                           f"{app['name']} was blocked because it {reason}.")
                else:
                    notify("NetGuard: app unblocked", f"{app['name']} network access restored.")
                    priv.unblock(cg)
                    if cap["rate_kbps"]:
                        priv.limit(cg, cap["rate_kbps"])
                self._auto_blocked[app["id"]] = should_block
            except priv.HelperError as e:
                log.warning("enforcement failed for %s: %s", app["name"], e)

    def run_forever(self):
        db.init_db()
        self.bootstrap()
        while True:
            try:
                self.attach_new_pids()
                self.poll_counters_and_log()
                self.enforce_caps()
            except Exception:
                log.exception("collector loop iteration failed")
            time.sleep(POLL_INTERVAL_SECONDS)


def main():
    Collector().run_forever()


if __name__ == "__main__":
    main()
