"""Wrapper for invoking the privileged helper via pkexec.

With the netguard polkit policy installed, calls to the exact helper binary
path are allowed for the active session without a password prompt, so this
can be called frequently (e.g. every poll interval) without nagging the user.
"""
import json
import subprocess

from netguard.common.config import HELPER_BIN


class HelperError(RuntimeError):
    pass


def run(*args, timeout=10):
    try:
        proc = subprocess.run(
            ["pkexec", HELPER_BIN, *args],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise HelperError(f"helper timed out: {args}") from e
    if proc.returncode != 0:
        raise HelperError(f"helper failed ({args}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def setup():
    return run("setup")


def create(app):
    return run("create", app)


def destroy(app):
    return run("destroy", app)


def add_pid(app, pid):
    return run("add-pid", app, str(pid))


def block(app):
    return run("block", app)


def unblock(app):
    return run("unblock", app)


def limit(app, rate_kbps):
    return run("limit", app, str(rate_kbps))


def unlimit(app):
    return run("unlimit", app)


def counters():
    out = run("counters")
    try:
        return json.loads(out) if out else {}
    except json.JSONDecodeError:
        return {}
