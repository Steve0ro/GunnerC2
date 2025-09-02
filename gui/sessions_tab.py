# gui/sessions_tab.py
from PyQt5.QtWidgets import QWidget, QTableWidget, QTableWidgetItem, QPushButton, QHBoxLayout, QVBoxLayout, QMessageBox
from PyQt5.QtCore import Qt, pyqtSignal

class SessionsTab(QWidget):
    session_double_clicked = pyqtSignal(str, str)

    def __init__(self, api):
        super().__init__()
        self.api = api

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["ID","Hostname","User","OS","Arch","Transport","LastSeen"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)

        self.btn_refresh = QPushButton("Refresh")
        self.btn_console = QPushButton("Open Console")
        self.btn_console.setEnabled(False)

        top = QHBoxLayout()
        top.addWidget(self.btn_refresh)
        top.addStretch()
        top.addWidget(self.btn_console)

        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(self.table)
        self.setLayout(layout)

        self.btn_refresh.clicked.connect(self.reload)
        self.btn_console.clicked.connect(self.open_console)
        self.table.itemSelectionChanged.connect(self._sel_changed)
        self.table.itemDoubleClicked.connect(self._dbl)

        self.reload()

    def reload(self):
        try:
            sessions = self.api.list_sessions()
        except Exception:
            sessions = []
        self.table.setRowCount(0)
        for s in sessions:
            row = self.table.rowCount(); self.table.insertRow(row)
            vals = [s["id"], s.get("hostname",""), s.get("user",""), s.get("os",""), s.get("arch",""), s.get("transport",""), str(s.get("last_checkin",""))]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(str(v)); 
                if c == 0: it.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, c, it)

    def _sel_changed(self):
        self.btn_console.setEnabled(bool(self.table.selectionModel().selectedRows()))

    def _dbl(self, item):
        r = item.row()
        sid = self.table.item(r, 0).text()
        host = self.table.item(r, 1).text()
        self.session_double_clicked.emit(sid, host)

    def open_console(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows: return
        r = rows[0].row()
        sid = self.table.item(r, 0).text()
        host = self.table.item(r, 1).text()
        self.session_double_clicked.emit(sid, host)
