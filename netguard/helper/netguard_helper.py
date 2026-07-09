#!/usr/bin/env python3
"""NetGuard privileged helper.

Runs as root (invoked via pkexec, authorized by the netguard polkit policy).
Manages one cgroup v2 per controlled app and uses nftables `socket cgroupv2`
matching to count, throttle, or fully drop that app's traffic -- without
needing a persistent root daemon. Each invocation does one job and exits.

Usage:
  netguard-helper setup
  netguard-helper create   <app>
  netguard-helper destroy  <app>
  netguard-helper add-pid  <app> <pid>
  netguard-helper block    <app>
  netguard-helper unblock  <app>
  netguard-helper limit    <app> <rate_kbps>
  netguard-helper unlimit  <app>
  netguard-helper counters              # JSON {app: {rx_bytes, tx_bytes}} for all apps, true rx/tx split
"""
import json
import os
import subprocess
import sys

CGROUP_ROOT = "/sys/fs/cgroup/netguard"
NFT_TABLE = "inet netguard"
CGROUP_LEVEL = None  # computed lazily from CGROUP_ROOT depth


def sh(*args, check=True, capture=False, input=None):
    return subprocess.run(args, check=check, capture_output=capture, text=True, input=input)


def cgroup_path(app):
    return os.path.join(CGROUP_ROOT, app)


def cgroup_rel(app):
    # Path as nft's "socket cgroupv2 level N" expects: relative to cgroup root,
    # e.g. "netguard/firefox"
    return f"netguard/{app}"


def cgroup_level(app):
    # Depth of the cgroup relative to the root hierarchy "/". netguard/<app> = level 2.
    return cgroup_rel(app).count("/") + 1


def ensure_cgroup_root():
    os.makedirs(CGROUP_ROOT, exist_ok=True)


def cmd_setup(_args):
    ensure_cgroup_root()
    # Base table + chains. Safe to re-run (nft add is idempotent for tables/chains).
    script = f"""
add table {NFT_TABLE}
add chain {NFT_TABLE} output {{ type filter hook output priority 0; policy accept; }}
add chain {NFT_TABLE} input {{ type filter hook input priority 0; policy accept; }}
"""
    sh("nft", "-f", "-", input=script, check=False)
    print("ok")


def counter_name(app, direction):
    # output chain = traffic leaving this machine = tx (upload)
    # input chain  = traffic arriving at this machine = rx (download)
    suffix = "tx" if direction == "output" else "rx"
    return f"cnt_{app}_{suffix}"


def cmd_create(args):
    app = args[0]
    ensure_cgroup_root()
    os.makedirs(cgroup_path(app), exist_ok=True)
    for direction in ("output", "input"):
        sh("nft", "add", "counter", *NFT_TABLE.split(), counter_name(app, direction), check=False)
    print("ok")


def cmd_destroy(args):
    app = args[0]
    for direction in ("output", "input"):
        _remove_matching_rules(app, direction)
        sh("nft", "delete", "counter", *NFT_TABLE.split(), counter_name(app, direction), check=False)
    path = cgroup_path(app)
    if os.path.isdir(path):
        try:
            os.rmdir(path)
        except OSError:
            pass  # still has processes attached; will clean up once they exit
    print("ok")


def cmd_add_pid(args):
    app, pid = args[0], args[1]
    path = os.path.join(cgroup_path(app), "cgroup.procs")
    if not os.path.isdir(cgroup_path(app)):
        cmd_create([app])
    with open(path, "w") as f:
        f.write(str(pid))
    print("ok")


def _handle_for_rules(direction, app):
    return sh(
        "nft", "-a", "list", "chain", *NFT_TABLE.split(), direction,
        capture=True, check=False,
    ).stdout


def _remove_matching_rules(app, direction):
    """Remove any existing rules tagged with this app's comment, so re-applying
    block/limit is idempotent instead of stacking duplicate rules."""
    listing = _handle_for_rules(direction, app)
    tag = f'"netguard:{app}"'
    for line in listing.splitlines():
        if tag in line and "handle" in line:
            handle = line.strip().split("handle")[-1].strip()
            sh("nft", "delete", "rule", *NFT_TABLE.split(), direction, "handle", handle, check=False)


def cmd_block(args):
    app = args[0]
    rel, level = cgroup_rel(app), cgroup_level(app)
    for direction in ("output", "input"):
        _remove_matching_rules(app, direction)
        sh(
            "nft", "add", "rule", *NFT_TABLE.split(), direction,
            "socket", "cgroupv2", "level", str(level), rel,
            "counter", "name", counter_name(app, direction),
            "drop",
            "comment", f"netguard:{app}",
        )
    print("ok")


def cmd_unblock(args):
    app = args[0]
    for direction in ("output", "input"):
        _remove_matching_rules(app, direction)
    print("ok")


def cmd_limit(args):
    app, rate_kbps = args[0], args[1]
    rel, level = cgroup_rel(app), cgroup_level(app)
    kbytes = max(1, int(float(rate_kbps) / 8))  # kbps -> KB/s for nft's `kbytes/second`
    for direction in ("output", "input"):
        _remove_matching_rules(app, direction)
        counter = counter_name(app, direction)
        # Accept up to the rate, drop the overflow -- two rules per direction.
        sh(
            "nft", "add", "rule", *NFT_TABLE.split(), direction,
            "socket", "cgroupv2", "level", str(level), rel,
            "limit", "rate", f"{kbytes}", "kbytes/second",
            "counter", "name", counter,
            "accept",
            "comment", f"netguard:{app}",
        )
        sh(
            "nft", "add", "rule", *NFT_TABLE.split(), direction,
            "socket", "cgroupv2", "level", str(level), rel,
            "counter", "name", counter,
            "drop",
            "comment", f"netguard:{app}",
        )
    print("ok")


def cmd_unlimit(args):
    cmd_unblock(args)  # same rule-removal logic; caller re-applies block/nothing as needed


def cmd_counters(_args):
    out = sh("nft", "-j", "list", "table", *NFT_TABLE.split(), capture=True, check=False).stdout
    result = {}
    try:
        data = json.loads(out) if out.strip() else {"nftables": []}
    except json.JSONDecodeError:
        data = {"nftables": []}
    for item in data.get("nftables", []):
        counter = item.get("counter")
        if not counter:
            continue
        name = counter.get("name", "")
        if not name.startswith("cnt_") or not (name.endswith("_rx") or name.endswith("_tx")):
            continue
        direction = name[-2:]        # "rx" or "tx"
        app = name[len("cnt_"):-3]   # strip "cnt_" prefix and "_rx"/"_tx" suffix
        entry = result.setdefault(app, {"rx_bytes": 0, "tx_bytes": 0})
        entry[f"{direction}_bytes"] += counter.get("bytes", 0)
    print(json.dumps(result))


COMMANDS = {
    "setup": cmd_setup,
    "create": cmd_create,
    "destroy": cmd_destroy,
    "add-pid": cmd_add_pid,
    "block": cmd_block,
    "unblock": cmd_unblock,
    "limit": cmd_limit,
    "unlimit": cmd_unlimit,
    "counters": cmd_counters,
}


def main():
    if os.geteuid() != 0:
        print("netguard-helper must run as root (via pkexec)", file=sys.stderr)
        sys.exit(1)
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    COMMANDS[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    main()
