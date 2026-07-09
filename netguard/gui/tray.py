#!/usr/bin/env python3
"""NetGuard taskbar tray icon: shows total bandwidth for a chosen period.

Uses QSystemTrayIcon (works as an AppIndicator-style tray icon under
GNOME/Zorin via the standard tray protocol). Runs as a lightweight
long-lived process started at login; only wakes up once a minute to
refresh, so it stays effectively idle in between.
"""
import os
import sys
from datetime import datetime, timedelta

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QInputDialog

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from netguard.common import db  # noqa: E402

REFRESH_MS = 60_000

PERIODS = [
    ("Last 3 hours", "last_3h"),
    ("Today", "today"),
    ("Yesterday", "yesterday"),
    ("This week", "week"),
    ("Custom range...", "custom"),
]


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


class NetGuardTray(QSystemTrayIcon):
    def __init__(self, app):
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        icon = QIcon(icon_path) if os.path.exists(icon_path) else QIcon.fromTheme("network-transmit-receive")
        super().__init__(icon)
        self._app = app
        self._selected_period = "today"
        self._custom_range = None
        self.setToolTip("NetGuard")

        self.menu = QMenu()
        self.usage_action = QAction("Loading...")
        self.usage_action.setEnabled(False)
        self.menu.addAction(self.usage_action)
        self.menu.addSeparator()

        for label, period in PERIODS:
            action = QAction(label)
            action.triggered.connect(lambda _, p=period: self._select_period(p))
            self.menu.addAction(action)

        self.menu.addSeparator()
        open_action = QAction("Open NetGuard")
        open_action.triggered.connect(self._open_main_window)
        self.menu.addAction(open_action)

        quit_action = QAction("Quit")
        quit_action.triggered.connect(app.quit)
        self.menu.addAction(quit_action)

        self.setContextMenu(self.menu)
        self.activated.connect(self._on_activated)

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(REFRESH_MS)
        self.refresh()

    def _select_period(self, period):
        if period == "custom":
            self._prompt_custom_range()
        else:
            self._selected_period = period
        self.refresh()

    def _prompt_custom_range(self):
        days, ok = QInputDialog.getInt(
            None, "Custom range", "Show usage for the last N days:", 3, 1, 365
        )
        if ok:
            end = datetime.now()
            start = end - timedelta(days=days)
            self._custom_range = (start, end)
            self._selected_period = "custom"

    def refresh(self):
        try:
            db.init_db()
            if self._selected_period == "custom" and self._custom_range:
                total = db.usage_total("custom", *self._custom_range)
            else:
                total = db.usage_total(self._selected_period)
            label = next(l for l, p in PERIODS if p == self._selected_period)
            text = f"{label}: {human_bytes(total['total_bytes'])}"
            self.usage_action.setText(text)
            self.setToolTip(f"NetGuard - {text}")
        except Exception as e:
            self.usage_action.setText(f"Error: {e}")

    def _on_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.refresh()

    def _open_main_window(self):
        import subprocess
        subprocess.Popen([sys.executable, "-m", "netguard.gui.main"])


def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    tray = NetGuardTray(app)
    tray.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
