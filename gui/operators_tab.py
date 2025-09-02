# gui/operators_tab.py
from PyQt5.QtWidgets import QWidget, QTableWidget, QTableWidgetItem, QLabel, QLineEdit, QComboBox, QPushButton, QHBoxLayout, QVBoxLayout, QMessageBox
from PyQt5.QtCore import Qt

try:
    from .design_helpers.notruncate_field import make_column_not_truncated
except Exception:
    from design_helpers.notruncate_field import make_column_not_truncated

class OperatorsTab(QWidget):
    def __init__(self, api):
        super().__init__()
        self.api = api

        self.table = QTableWidget(0,3); self.table.setHorizontalHeaderLabels(["Username","Role","ID"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        make_column_not_truncated(self.table, column=2)
        self.table.setTextElideMode(Qt.ElideNone)

        self.user = QLineEdit(); self.passw = QLineEdit(); self.passw.setEchoMode(QLineEdit.Password)
        self.role = QComboBox(); self.role.addItems(["operator","admin"])

        self.btn_add = QPushButton("Add")
        self.btn_del = QPushButton("Remove"); self.btn_del.setEnabled(False)

        top = QHBoxLayout()
        top.addWidget(QLabel("Username:")); top.addWidget(self.user)
        top.addWidget(QLabel("Password:")); top.addWidget(self.passw)
        top.addWidget(QLabel("Role:")); top.addWidget(self.role)
        top.addWidget(self.btn_add); top.addStretch(); top.addWidget(self.btn_del)

        layout = QVBoxLayout(); layout.addLayout(top); layout.addWidget(self.table); self.setLayout(layout)

        self.btn_add.clicked.connect(self._add)
        self.btn_del.clicked.connect(self._del)
        self.table.itemSelectionChanged.connect(lambda: self.btn_del.setEnabled(bool(self.table.selectionModel().selectedRows())))

        self.reload()

    def reload(self):
        try:
            ops = self.api.get_operators()
        except Exception:
            ops = []
        self.table.setRowCount(0)
        for o in ops:
            r = self.table.rowCount(); self.table.insertRow(r)
            self.table.setItem(r,0,QTableWidgetItem(o["username"]))
            self.table.setItem(r,1,QTableWidgetItem(o["role"]))
            iditem = QTableWidgetItem(o["id"]); iditem.setTextAlignment(Qt.AlignCenter); self.table.setItem(r,2,iditem)

        self.table.resizeColumnToContents(2)

    def _add(self):
        u = self.user.text().strip(); p = self.passw.text().strip(); role = self.role.currentText()
        if not (u and p):
            QMessageBox.warning(self,"Add","Username and password are required."); return
        try:
            self.api.create_operator(u,p,role)
        except Exception as e:
            QMessageBox.critical(self,"Add",str(e)); return
        self.user.clear(); self.passw.clear(); self.reload()

    def _del(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows: return
        rid = rows[0].row()
        op_id = self.table.item(rid,2).text()
        try:
            self.api.delete_operator(op_id)
        except Exception as e:
            QMessageBox.critical(self,"Remove",str(e)); return
        self.reload()
