# gui/file_browser.py
from PyQt5.QtWidgets import QDialog, QTableWidget, QTableWidgetItem, QPushButton, QLineEdit, QLabel, QHBoxLayout, QVBoxLayout, QFileDialog, QMessageBox
from PyQt5.QtCore import Qt

class FileBrowser(QDialog):
    def __init__(self, api, sid: str, start_path: str = "."):
        super().__init__()
        self.api = api; self.sid = sid; self.path = start_path
        self.setWindowTitle(f"Remote Files — {sid}")
        self.resize(720, 460)

        self.path_edit = QLineEdit(self.path); self.path_edit.setReadOnly(True)
        self.btn_up = QPushButton("Up")
        self.btn_refresh = QPushButton("Refresh")

        top = QHBoxLayout(); top.addWidget(QLabel("Path:")); top.addWidget(self.path_edit); top.addWidget(self.btn_up); top.addWidget(self.btn_refresh)

        self.table = QTableWidget(0, 2); self.table.setHorizontalHeaderLabels(["Name","Size"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.itemDoubleClicked.connect(self._dbl)

        self.btn_download = QPushButton("Download"); self.btn_upload = QPushButton("Upload")
        self.btn_download.setEnabled(False)
        self.table.itemSelectionChanged.connect(lambda: self.btn_download.setEnabled(bool(self.table.selectionModel().selectedRows())))

        bottom = QHBoxLayout(); bottom.addWidget(self.btn_upload); bottom.addWidget(self.btn_download); bottom.addStretch()

        layout = QVBoxLayout(); layout.addLayout(top); layout.addWidget(self.table); layout.addLayout(bottom); self.setLayout(layout)

        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_up.clicked.connect(self.up)
        self.btn_download.clicked.connect(self.download)
        self.btn_upload.clicked.connect(self.upload)

        self.refresh()

    def refresh(self):
        try:
            rows = self.api.list_dir(self.sid, self.path)
        except Exception as e:
            QMessageBox.critical(self, "List", str(e)); return
        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount(); self.table.insertRow(row)
            name = r["name"]; is_dir = r["is_dir"]; size = "" if is_dir else str(r.get("size") or "")
            it = QTableWidgetItem(name + ("/" if is_dir else "")); self.table.setItem(row, 0, it)
            it2 = QTableWidgetItem(size); it2.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter); self.table.setItem(row, 1, it2)

    def up(self):
        p = self.path.rstrip("/\\")
        if "\\" in p:
            idx = p.rfind("\\")
        else:
            idx = p.rfind("/")
        if idx <= 0:
            self.path = "/" if "/" in self.path else "C:\\"
        else:
            self.path = p[:idx]
        self.path_edit.setText(self.path); self.refresh()

    def _dbl(self, item):
        row = item.row()
        name = self.table.item(row,0).text()
        is_dir = name.endswith("/")
        base = name[:-1] if is_dir else name
        sep = "\\" if "\\" in self.path else "/"
        new_path = (self.path + ("" if self.path.endswith(sep) else sep) + base)
        if is_dir:
            self.path = new_path
            self.path_edit.setText(self.path)
            self.refresh()
        else:
            self.download()

    def download(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows: return
        name = self.table.item(rows[0].row(),0).text().rstrip("/")
        sep = "\\" if "\\" in self.path else "/"
        remote = self.path + ("" if self.path.endswith(sep) else sep) + name
        from PyQt5.QtWidgets import QFileDialog
        save_as, _ = QFileDialog.getSaveFileName(self, "Save As", name)
        if not save_as: return
        try:
            self.api.download_file(self.sid, remote, save_as)
        except Exception as e:
            QMessageBox.critical(self, "Download", str(e))

    def upload(self):
        from PyQt5.QtWidgets import QFileDialog
        local, _ = QFileDialog.getOpenFileName(self, "Upload File")
        if not local: return
        sep = "\\" if "\\" in self.path else "/"
        remote = self.path + ("" if self.path.endswith(sep) else sep) + local.split("/")[-1]
        try:
            self.api.upload_file(self.sid, local, remote)
        except Exception as e:
            QMessageBox.critical(self, "Upload", str(e))
        self.refresh()
