# gui/login_dialog.py
from PyQt5.QtWidgets import QDialog, QLabel, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout
from PyQt5.QtCore import Qt
from api_client import APIClient

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GunnerC2 — Login")
        self.api_client = None

        self.url_edit = QLineEdit("http://127.0.0.1:8000")
        self.user_edit = QLineEdit()
        self.pass_edit = QLineEdit(); self.pass_edit.setEchoMode(QLineEdit.Password)
        self.error = QLabel(""); self.error.setStyleSheet("color:#ff7676;")

        self.btn_login = QPushButton("Login")
        self.btn_cancel = QPushButton("Cancel")

        form = QVBoxLayout()
        row = QHBoxLayout(); row.addWidget(QLabel("Server URL:")); row.addWidget(self.url_edit); form.addLayout(row)
        row = QHBoxLayout(); row.addWidget(QLabel("Username:")); row.addWidget(self.user_edit); form.addLayout(row)
        row = QHBoxLayout(); row.addWidget(QLabel("Password:")); row.addWidget(self.pass_edit); form.addLayout(row)
        form.addWidget(self.error)
        row = QHBoxLayout(); row.addStretch(); row.addWidget(self.btn_login); row.addWidget(self.btn_cancel); form.addLayout(row)
        self.setLayout(form)

        self.btn_cancel.clicked.connect(self.reject)
        self.btn_login.clicked.connect(self._login)

    def _login(self):
        base = self.url_edit.text().strip()
        u = self.user_edit.text().strip()
        p = self.pass_edit.text()
        if not (base and u and p):
            self.error.setText("Fill all fields.")
            return
        try:
            api = APIClient(base)
            _ = api.login(u, p)
            self.api_client = api
            self.accept()
        except Exception as e:
            self.error.setText(str(e))
