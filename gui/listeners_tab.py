# gui/listeners_tab.py
from PyQt5.QtWidgets import QWidget, QTableWidget, QTableWidgetItem, QPushButton, QComboBox, QLineEdit, QHBoxLayout, QVBoxLayout, QMessageBox
from PyQt5.QtCore import Qt

class ListenersTab(QWidget):
    def __init__(self, api):
        super().__init__()
        self.api = api

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID","Type","IP","Port","Status","Profile"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.type_combo = QComboBox(); self.type_combo.addItems(["tcp","http","https"])
        self.ip_edit = QLineEdit("0.0.0.0")
        self.port_edit = QLineEdit(); self.port_edit.setPlaceholderText("Port")
        self.profile_edit = QLineEdit(); self.profile_edit.setPlaceholderText("Profile path (optional)")

        self.btn_create = QPushButton("Create")
        self.btn_stop = QPushButton("Stop"); self.btn_stop.setEnabled(False)

        top = QHBoxLayout()
        top.addWidget(self.type_combo); top.addWidget(self.ip_edit); top.addWidget(self.port_edit); top.addWidget(self.profile_edit); top.addWidget(self.btn_create)
        top.addStretch(); top.addWidget(self.btn_stop)

        layout = QVBoxLayout(); layout.addLayout(top); layout.addWidget(self.table); self.setLayout(layout)

        self.btn_create.clicked.connect(self.create_listener)
        self.btn_stop.clicked.connect(self.stop_listener)
        self.table.itemSelectionChanged.connect(self._sel_changed)

        self.reload()

    def reload(self):
        try:
            rows = self.api.list_listeners()
        except Exception:
            rows = []
        self.table.setRowCount(0)
        for lst in rows:
            row = self.table.rowCount(); self.table.insertRow(row)
            vals = [lst["id"], lst["type"], lst["bind_ip"], str(lst["port"]), lst["status"], lst.get("profile") or ""]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(str(v))
                if c in (0,3): it.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, c, it)

    def _sel_changed(self):
        self.btn_stop.setEnabled(bool(self.table.selectionModel().selectedRows()))

    def create_listener(self):
        try:
            port = int(self.port_edit.text().strip())
        except Exception:
            QMessageBox.warning(self, "Port", "Enter a valid port number."); return
        t = self.type_combo.currentText(); ip = self.ip_edit.text().strip(); profile = self.profile_edit.text().strip() or None
        try:
            self.api.create_listener(t, ip, port, profile)
        except Exception as e:
            QMessageBox.critical(self, "Listener", str(e)); return
        self.reload()
        self.profile_edit.clear()

    def stop_listener(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows: return
        lid = self.table.item(rows[0].row(), 0).text()
        try:
            self.api.stop_listener(lid)
        except Exception as e:
            QMessageBox.critical(self, "Stop", str(e)); return
        self.reload()
