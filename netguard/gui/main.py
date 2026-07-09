#!/usr/bin/env python3
"""NetGuard main window: add/manage controlled apps, set caps, view usage."""
import os
import sys

import psutil
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel, QLineEdit, QComboBox,
    QDoubleSpinBox, QCheckBox, QFileDialog, QMessageBox, QHeaderView, QTimeEdit,
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from netguard.common import db, priv  # noqa: E402


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def slugify(name):
    return "".join(c if c.isalnum() else "_" for c in name).strip("_").lower() or "app"


class AppsTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        add_row = QHBoxLayout()
        self.proc_combo = QComboBox()
        self.proc_combo.setEditable(False)
        self.refresh_btn = QPushButton("Refresh running apps")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        self.browse_btn = QPushButton("Browse for executable...")
        self.browse_btn.clicked.connect(self.browse_executable)
        self.add_btn = QPushButton("Add to control list")
        self.add_btn.clicked.connect(self.add_selected)
        add_row.addWidget(self.proc_combo, 1)
        add_row.addWidget(self.refresh_btn)
        add_row.addWidget(self.browse_btn)
        add_row.addWidget(self.add_btn)
        layout.addLayout(add_row)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["App", "Blocked", "Cap type", "Limit (MB)", "Rate (kbps)", "Schedule", "Actions"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        self.refresh_processes()
        self.reload_table()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.reload_table)
        self._timer.start(5000)

    def refresh_processes(self):
        self.proc_combo.clear()
        seen = set()
        for p in psutil.process_iter(["name"]):
            try:
                name = p.info["name"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if name and name not in seen:
                seen.add(name)
                self.proc_combo.addItem(name)

    def browse_executable(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select executable", "/usr/bin")
        if path:
            self._add_app(os.path.basename(path), "path", path)

    def add_selected(self):
        name = self.proc_combo.currentText()
        if not name:
            return
        self._add_app(name, "process_name", name)

    def _add_app(self, name, match_kind, match_value):
        cgroup_name = slugify(name)
        app_id = db.add_app(name, match_kind, match_value, cgroup_name)
        try:
            priv.create(cgroup_name)
        except priv.HelperError as e:
            QMessageBox.warning(self, "NetGuard", f"Could not create control group:\n{e}")
        self.reload_table()

    def reload_table(self):
        apps = db.list_apps()
        self.table.setRowCount(len(apps))
        for row, app in enumerate(apps):
            cap = db.get_cap(app["id"]) or {}
            usage = db.usage_for_app(app["id"], period="today")

            self.table.setItem(row, 0, QTableWidgetItem(f"{app['name']}  ({human_bytes(usage['total_bytes'])} today)"))

            block_chk = QCheckBox()
            block_chk.setChecked(bool(cap.get("blocked")))
            block_chk.stateChanged.connect(lambda state, a=app, c=cap: self._toggle_block(a, c, state))
            self.table.setCellWidget(row, 1, block_chk)

            cap_combo = QComboBox()
            cap_combo.addItems(["none", "daily_mb", "session_mb"])
            cap_combo.setCurrentText(cap.get("cap_kind", "none"))
            self.table.setCellWidget(row, 2, cap_combo)

            limit_spin = QDoubleSpinBox()
            limit_spin.setRange(0, 1_000_000)
            limit_spin.setValue(cap.get("limit_mb") or 0)
            self.table.setCellWidget(row, 3, limit_spin)

            rate_spin = QDoubleSpinBox()
            rate_spin.setRange(0, 1_000_000)
            rate_spin.setValue(cap.get("rate_kbps") or 0)
            self.table.setCellWidget(row, 4, rate_spin)

            sched_widget = QWidget()
            sched_layout = QHBoxLayout(sched_widget)
            sched_layout.setContentsMargins(0, 0, 0, 0)
            start_edit = QTimeEdit()
            end_edit = QTimeEdit()
            if cap.get("sched_start"):
                start_edit.setTime(start_edit.time().fromString(cap["sched_start"], "HH:mm"))
            if cap.get("sched_end"):
                end_edit.setTime(end_edit.time().fromString(cap["sched_end"], "HH:mm"))
            sched_layout.addWidget(start_edit)
            sched_layout.addWidget(QLabel("-"))
            sched_layout.addWidget(end_edit)
            self.table.setCellWidget(row, 5, sched_widget)

            actions = QWidget()
            act_layout = QHBoxLayout(actions)
            act_layout.setContentsMargins(0, 0, 0, 0)
            save_btn = QPushButton("Save")
            save_btn.clicked.connect(
                lambda _, a=app, cc=cap_combo, ls=limit_spin, rs=rate_spin,
                se=start_edit, ee=end_edit: self._save_cap(a, cc, ls, rs, se, ee)
            )
            remove_btn = QPushButton("Remove")
            remove_btn.clicked.connect(lambda _, a=app: self._remove_app(a))
            act_layout.addWidget(save_btn)
            act_layout.addWidget(remove_btn)
            self.table.setCellWidget(row, 6, actions)

    def _toggle_block(self, app, cap, state):
        blocked = state == Qt.CheckState.Checked.value
        db.set_blocked(app["id"], blocked)
        try:
            if blocked:
                priv.block(app["cgroup_name"])
            else:
                priv.unblock(app["cgroup_name"])
        except priv.HelperError as e:
            QMessageBox.warning(self, "NetGuard", f"Could not apply block:\n{e}")
        db.log_event(app["id"], "manual_block" if blocked else "manual_unblock")

    def _save_cap(self, app, cap_combo, limit_spin, rate_spin, start_edit, end_edit):
        cap_kind = cap_combo.currentText()
        limit_mb = limit_spin.value() or None
        rate_kbps = rate_spin.value() or None
        sched_start = start_edit.time().toString("HH:mm")
        sched_end = end_edit.time().toString("HH:mm")
        # Treat "00:00-00:00" as "no schedule restriction".
        if sched_start == "00:00" and sched_end == "00:00":
            sched_start = sched_end = None
        db.set_cap(app["id"], cap_kind, limit_mb, rate_kbps, sched_start, sched_end, enabled=True)
        try:
            if rate_kbps:
                priv.limit(app["cgroup_name"], rate_kbps)
            else:
                priv.unlimit(app["cgroup_name"])
        except priv.HelperError as e:
            QMessageBox.warning(self, "NetGuard", f"Could not apply rate limit:\n{e}")
        QMessageBox.information(self, "NetGuard", f"Saved settings for {app['name']}")

    def _remove_app(self, app):
        try:
            priv.destroy(app["cgroup_name"])
        except priv.HelperError:
            pass
        db.remove_app(app["id"])
        self.reload_table()


class UsageTab(QWidget):
    PERIODS = [("Last 3 hours", "last_3h"), ("Today", "today"),
               ("Yesterday", "yesterday"), ("This week", "week")]

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.period_combo = QComboBox()
        self.period_combo.addItems([label for label, _ in self.PERIODS])
        self.period_combo.currentIndexChanged.connect(self.reload)
        top.addWidget(QLabel("Period:"))
        top.addWidget(self.period_combo)
        top.addStretch()
        self.total_label = QLabel()
        top.addWidget(self.total_label)
        layout.addLayout(top)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["App", "Usage"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        self.reload()
        timer = QTimer(self)
        timer.timeout.connect(self.reload)
        timer.start(10000)
        self._timer = timer

    def reload(self):
        period = self.PERIODS[self.period_combo.currentIndex()][1]
        rows = db.usage_by_app(period=period)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(r["name"]))
            self.table.setItem(i, 1, QTableWidgetItem(human_bytes(r["total_bytes"])))
        total = db.usage_total(period=period)
        self.total_label.setText(f"Total: {human_bytes(total['total_bytes'])}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetGuard")
        self.resize(900, 600)
        tabs = QTabWidget()
        tabs.addTab(AppsTab(), "Apps")
        tabs.addTab(UsageTab(), "Usage")
        self.setCentralWidget(tabs)


def main():
    db.init_db()
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
