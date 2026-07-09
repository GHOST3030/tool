"""Parse installed .desktop entries into something we can actually match
running processes against -- Flatpak/Snap/Electron apps don't run under
the name shown in the app menu, so a naive Exec= string isn't enough.
"""
import configparser
import glob
import os
import shlex

DESKTOP_DIRS = [
    "/usr/share/applications",
    "/usr/local/share/applications",
    os.path.expanduser("~/.local/share/applications"),
    "/var/lib/flatpak/exports/share/applications",
    os.path.expanduser("~/.local/share/flatpak/exports/share/applications"),
]

FIELD_CODES = {"%f", "%F", "%u", "%U", "%d", "%D", "%n", "%N", "%i", "%c", "%k", "%v", "%m"}


class DesktopApp:
    def __init__(self, name, desktop_id, exec_line, path):
        self.name = name
        self.desktop_id = desktop_id
        self.path = path
        self.kind, self.match_value = self._resolve(exec_line)

    def _resolve(self, exec_line):
        try:
            tokens = [t for t in shlex.split(exec_line) if t not in FIELD_CODES]
        except ValueError:
            tokens = exec_line.split()
        tokens = [t for t in tokens if t]
        if not tokens:
            return "process_name", self.name

        # Strip common env-var / wrapper prefixes: "env FOO=bar cmd", "sh -c 'cmd'"
        while tokens and ("=" in tokens[0] and tokens[0].split("=")[0].isupper()):
            tokens.pop(0)
        if tokens and tokens[0] == "env":
            tokens.pop(0)
            while tokens and "=" in tokens[0]:
                tokens.pop(0)

        if tokens and tokens[0] == "flatpak":
            # flatpak run [--options] org.some.AppId
            for t in tokens[1:]:
                if not t.startswith("-"):
                    return "flatpak", t
            return "process_name", self.name

        if tokens and tokens[0] == "snap":
            for t in tokens[1:]:
                if not t.startswith("-"):
                    return "snap", t
            return "process_name", self.name

        binary = os.path.basename(tokens[0])
        return "process_name", binary


def _parse_one(path):
    parser = configparser.RawConfigParser(strict=False)
    try:
        parser.read(path, encoding="utf-8")
    except (configparser.Error, OSError, UnicodeDecodeError):
        return None
    if "Desktop Entry" not in parser:
        return None
    section = parser["Desktop Entry"]
    if section.get("Type", "Application") != "Application":
        return None
    if section.getboolean("NoDisplay", fallback=False):
        return None
    if section.getboolean("Hidden", fallback=False):
        return None
    name = section.get("Name")
    exec_line = section.get("Exec")
    if not name or not exec_line:
        return None
    desktop_id = os.path.splitext(os.path.basename(path))[0]
    return DesktopApp(name, desktop_id, exec_line, path)


def list_desktop_apps():
    """Return a sorted, de-duplicated list of DesktopApp entries."""
    seen_ids = set()
    apps = []
    for base in DESKTOP_DIRS:
        for path in glob.glob(os.path.join(base, "*.desktop")):
            app = _parse_one(path)
            if app and app.desktop_id not in seen_ids:
                seen_ids.add(app.desktop_id)
                apps.append(app)
    apps.sort(key=lambda a: a.name.lower())
    return apps
