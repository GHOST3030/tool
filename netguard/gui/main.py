#!/usr/bin/env python3
"""NetGuard main window: add/manage controlled apps, set caps, view usage."""
import os
import sys

import psutil
import pyqtgraph as pg
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel, QLineEdit, QComboBox,
    QDoubleSpinBox, QCheckBox, QFileDialog, QMessageBox, QHeaderView, QTimeEdit,
    QDialog, QFormLayout, QDialogButtonBox,
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from netguard.common import db, priv, desktopapps  # noqa: E402


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def slugify(name):
    return "".join(c if c.isalnum() else "_" for c in name).strip("_").lower() or "app"


class AppConfigDialog(QDialog):
    def __init__(self, parent, app_name, match_kind, match_value, existing_app=None, existing_cap=None):
        super().__init__(parent)
        self.setWindowTitle(f"Configure {app_name}")
        self.resize(400, 320)
        
        self.app_name = app_name
        self.match_kind = match_kind
        self.match_value = match_value
        self.existing_app = existing_app
        self.existing_cap = existing_cap
        
        layout = QVBoxLayout(self)
        form = QFormLayout()
        
        self.control_chk = QCheckBox("Enable Network Control / Monitoring")
        self.control_chk.setChecked(existing_app is not None)
        self.control_chk.stateChanged.connect(self._on_control_toggled)
        form.addRow(self.control_chk)
        
        self.block_chk = QCheckBox("Block Internet Access")
        form.addRow(self.block_chk)
        
        self.cap_combo = QComboBox()
        self.cap_combo.addItems(["none", "daily_mb", "session_mb"])
        self.cap_combo.currentIndexChanged.connect(self._on_cap_changed)
        form.addRow("Cap Type:", self.cap_combo)
        
        self.limit_spin = QDoubleSpinBox()
        self.limit_spin.setRange(0, 1_000_000)
        self.limit_spin.setDecimals(1)
        self.limit_spin.setSuffix(" MB")
        form.addRow("Limit:", self.limit_spin)
        
        self.rate_spin = QDoubleSpinBox()
        self.rate_spin.setRange(0, 1_000_000)
        self.rate_spin.setDecimals(1)
        self.rate_spin.setSuffix(" kbps")
        form.addRow("Rate Limit:", self.rate_spin)
        
        self.sched_start = QTimeEdit()
        self.sched_end = QTimeEdit()
        sched_layout = QHBoxLayout()
        sched_layout.addWidget(self.sched_start)
        sched_layout.addWidget(QLabel("-"))
        sched_layout.addWidget(self.sched_end)
        form.addRow("Allowed Schedule:", sched_layout)
        
        layout.addLayout(form)
        
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        
        if self.existing_cap:
            self.block_chk.setChecked(bool(self.existing_cap.get("blocked")))
            self.cap_combo.setCurrentText(self.existing_cap.get("cap_kind", "none"))
            self.limit_spin.setValue(self.existing_cap.get("limit_mb") or 0.0)
            self.rate_spin.setValue(self.existing_cap.get("rate_kbps") or 0.0)
            if self.existing_cap.get("sched_start"):
                self.sched_start.setTime(self.sched_start.time().fromString(self.existing_cap["sched_start"], "HH:mm"))
            if self.existing_cap.get("sched_end"):
                self.sched_end.setTime(self.sched_end.time().fromString(self.existing_cap["sched_end"], "HH:mm"))
                
        self._on_control_toggled()
        
    def _on_cap_changed(self):
        cap_kind = self.cap_combo.currentText()
        self.limit_spin.setEnabled(self.control_chk.isChecked() and cap_kind != "none")

    def _on_control_toggled(self):
        enabled = self.control_chk.isChecked()
        self.block_chk.setEnabled(enabled)
        self.cap_combo.setEnabled(enabled)
        self._on_cap_changed()
        self.rate_spin.setEnabled(enabled)
        self.sched_start.setEnabled(enabled)
        self.sched_end.setEnabled(enabled)

    def accept(self):
        cgroup_name = slugify(self.app_name)
        
        if self.control_chk.isChecked():
            app_id = db.add_app(self.app_name, self.match_kind, self.match_value, cgroup_name)
            
            blocked = self.block_chk.isChecked()
            cap_kind = self.cap_combo.currentText()
            limit_mb = self.limit_spin.value() or None
            rate_kbps = self.rate_spin.value() or None
            sched_start = self.sched_start.time().toString("HH:mm")
            sched_end = self.sched_end.time().toString("HH:mm")
            if sched_start == "00:00" and sched_end == "00:00":
                sched_start = sched_end = None
                
            db.set_cap(app_id, cap_kind, limit_mb, rate_kbps, sched_start, sched_end, enabled=True)
            db.set_blocked(app_id, blocked)
            
            try:
                priv.create(cgroup_name)
                if blocked:
                    priv.block(cgroup_name)
                else:
                    priv.unblock(cgroup_name)
                    if rate_kbps:
                        priv.limit(cgroup_name, rate_kbps)
                    else:
                        priv.unlimit(cgroup_name)
            except priv.HelperError as e:
                QMessageBox.warning(self, "NetGuard", f"Could not apply control configurations:\n{e}")
            db.log_event(app_id, "configured", f"blocked={blocked}, cap={cap_kind}, limit={limit_mb}, rate={rate_kbps}")
        else:
            if self.existing_app:
                app_id = self.existing_app["id"]
                try:
                    priv.destroy(cgroup_name)
                except priv.HelperError:
                    pass
                db.remove_app(app_id)
                
        super().accept()


class AppsTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        top_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search applications...")
        self.search_input.textChanged.connect(self.filter_table)
        
        self.refresh_btn = QPushButton("Refresh List")
        self.refresh_btn.clicked.connect(self.refresh_apps)
        
        self.browse_btn = QPushButton("Add Custom Executable...")
        self.browse_btn.clicked.connect(self.browse_executable)

        self.limit_all_btn = QPushButton("Limit All to 100MB Session")
        self.limit_all_btn.clicked.connect(self.limit_all_to_100mb)
        
        top_row.addWidget(QLabel("Search:"))
        top_row.addWidget(self.search_input, 1)
        top_row.addWidget(self.refresh_btn)
        top_row.addWidget(self.browse_btn)
        top_row.addWidget(self.limit_all_btn)
        layout.addLayout(top_row)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["App Name", "Controlled", "Status", "Today's Usage", "Actions"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.table)

        self._installed_apps = []
        self._displayed_apps = []
        self._current_rows = []
        
        self.refresh_apps()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.reload_usage_and_status)
        self._timer.start(3000)

    def refresh_apps(self):
        self._installed_apps = desktopapps.list_desktop_apps()
        self.reload_table()

    def limit_all_to_100mb(self):
        reply = QMessageBox.question(
            self,
            "Limit All Apps",
            "Are you sure you want to set a 100MB session cap for all installed applications?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.setCursor(Qt.CursorShape.WaitCursor)
            try:
                for app in self._installed_apps:
                    # Skip systemd to avoid blocking system management processes
                    if app.match_value == "systemd":
                        continue
                    cgroup_name = slugify(app.name)
                    app_id = db.add_app(app.name, app.kind, app.match_value, cgroup_name)
                    try:
                        priv.create(cgroup_name)
                        priv.unblock(cgroup_name)
                        priv.unlimit(cgroup_name)
                    except priv.HelperError:
                        pass
                    db.set_cap(app_id, cap_kind="session_mb", limit_mb=100.0, rate_kbps=None, sched_start=None, sched_end=None, enabled=True)
                    db.set_blocked(app_id, False)
            finally:
                self.restoreCursor()
            self.refresh_apps()

    def sort_apps(self):
        db_apps = db.list_apps()
        usage_map = {}
        for app in db_apps:
            usage = db.usage_for_app(app["id"], period="today")
            usage_map[app["match_value"]] = usage["total_bytes"]
            
        def sort_key(app):
            db_entry = app["db_entry"]
            if db_entry:
                usage = usage_map.get(app["match_value"], 0)
                return (0, -usage, app["name"].lower())
            else:
                return (1, 0, app["name"].lower())
                
        self._displayed_apps.sort(key=sort_key)

    def reload_table(self):
        db_apps = db.list_apps()
        db_app_map = {app["match_value"]: app for app in db_apps}
        
        displayed_apps = []
        seen_values = set()
        
        for app in self._installed_apps:
            displayed_apps.append({
                "name": app.name,
                "kind": app.kind,
                "match_value": app.match_value,
                "db_entry": db_app_map.get(app.match_value)
            })
            seen_values.add(app.match_value)
            
        for db_app in db_apps:
            if db_app["match_value"] not in seen_values:
                displayed_apps.append({
                    "name": db_app["name"],
                    "kind": db_app["match_kind"],
                    "match_value": db_app["match_value"],
                    "db_entry": db_app
                })
                
        self._displayed_apps = displayed_apps
        self.sort_apps()
        self.filter_table()

    def filter_table(self):
        query = self.search_input.text().lower()
        filtered = [app for app in self._displayed_apps if query in app["name"].lower()]
        
        self.table.setRowCount(len(filtered))
        self._current_rows = filtered
        
        for row, app in enumerate(filtered):
            self.table.setItem(row, 0, QTableWidgetItem(app["name"]))
            
            db_entry = app["db_entry"]
            controlled_str = "Yes" if db_entry else "No"
            self.table.setItem(row, 1, QTableWidgetItem(controlled_str))
            
            status_str = "Unrestricted"
            usage_str = "0 B"
            if db_entry:
                cap = db.get_cap(db_entry["id"]) or {}
                if cap.get("blocked"):
                    status_str = "Blocked"
                elif cap.get("cap_kind") == "daily_mb" and cap.get("limit_mb"):
                    status_str = f"Limit: {cap['limit_mb']} MB/day"
                elif cap.get("cap_kind") == "session_mb" and cap.get("limit_mb"):
                    status_str = f"Limit: {cap['limit_mb']} MB/session"
                elif cap.get("rate_kbps"):
                    status_str = f"Throttled: {cap['rate_kbps']} kbps"
                elif cap.get("sched_start") and cap.get("sched_end"):
                    status_str = f"Scheduled: {cap['sched_start']}-{cap['sched_end']}"
                
                usage = db.usage_for_app(db_entry["id"], period="today")
                usage_str = f"{human_bytes(usage['total_bytes'])} (↓{human_bytes(usage['rx_bytes'])} ↑{human_bytes(usage['tx_bytes'])})"
            
            self.table.setItem(row, 2, QTableWidgetItem(status_str))
            self.table.setItem(row, 3, QTableWidgetItem(usage_str))
            
            cfg_btn = QPushButton("Configure")
            cfg_btn.clicked.connect(lambda _, r=row: self._configure_row(r))
            self.table.setCellWidget(row, 4, cfg_btn)

    def reload_usage_and_status(self):
        self.reload_table()

    def _on_item_double_clicked(self, item):
        self._configure_row(item.row())

    def _configure_row(self, row):
        if row >= len(self._current_rows):
            return
        app = self._current_rows[row]
        db_entry = app["db_entry"]
        existing_cap = db.get_cap(db_entry["id"]) if db_entry else None
        
        dialog = AppConfigDialog(
            self,
            app_name=app["name"],
            match_kind=app["kind"],
            match_value=app["match_value"],
            existing_app=db_entry,
            existing_cap=existing_cap
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.refresh_apps()

    def browse_executable(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select executable", "/usr/bin")
        if path:
            name = os.path.basename(path)
            db_apps = db.list_apps()
            existing_app = next((a for a in db_apps if a["match_kind"] == "path" and a["match_value"] == path), None)
            existing_cap = db.get_cap(existing_app["id"]) if existing_app else None
            
            dialog = AppConfigDialog(
                self,
                app_name=name,
                match_kind="path",
                match_value=path,
                existing_app=existing_app,
                existing_cap=existing_cap
            )
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.refresh_apps()


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

        palette = self.palette()
        pg.setConfigOption("background", palette.color(palette.ColorRole.Window))
        pg.setConfigOption("foreground", palette.color(palette.ColorRole.WindowText))
        self.chart = pg.PlotWidget()
        self.chart.setLabel("left", "Bandwidth", units="B")
        self.chart.showGrid(x=True, y=True, alpha=0.3)
        self.chart.setMinimumHeight(220)
        layout.addWidget(self.chart)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["App", "Total", "Downloaded", "Uploaded"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        self.reload()
        timer = QTimer(self)
        timer.timeout.connect(self.reload)
        timer.start(3000)
        self._timer = timer

    def reload(self):
        period = self.PERIODS[self.period_combo.currentIndex()][1]
        rows = db.usage_by_app(period=period)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(r["name"]))
            self.table.setItem(i, 1, QTableWidgetItem(human_bytes(r["total_bytes"])))
            self.table.setItem(i, 2, QTableWidgetItem(human_bytes(r["rx_bytes"])))
            self.table.setItem(i, 3, QTableWidgetItem(human_bytes(r["tx_bytes"])))
        total = db.usage_total(period=period)
        self.total_label.setText(f"Total: {human_bytes(total['total_bytes'])}")
        self._reload_chart(period)

    def _reload_chart(self, period):
        series = db.usage_timeseries(period=period)
        self.chart.clear()
        if not series:
            return
        start_ts = series[0][0]
        xs = [(ts - start_ts) / 3600.0 for ts, _ in series]  # hours since range start
        ys = [total for _, total in series]
        bucket_hours = 24 if period == "week" else 1
        width = bucket_hours * 0.8
        bar = pg.BarGraphItem(x=xs, height=ys, width=width, brush=pg.mkColor(90, 140, 220))
        self.chart.addItem(bar)
        self.chart.setLabel("bottom", "Days ago" if period == "week" else "Hours ago")


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
