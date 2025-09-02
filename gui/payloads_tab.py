# gui/payloads_tab.py
from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QComboBox, QPushButton, QHBoxLayout, QVBoxLayout, QTextEdit, QMessageBox

class PayloadsTab(QWidget):
    def __init__(self, api):
        super().__init__()
        self.api = api

        self.os_combo = QComboBox(); self.os_combo.addItems(["windows-ps1","linux-bash"])
        self.transport = QComboBox(); self.transport.addItems(["http","https","tcp"])
        self.host = QLineEdit(); self.host.setPlaceholderText("Connect host / IP")
        self.port = QLineEdit(); self.port.setPlaceholderText("Port")
        self.beacon = QLineEdit("5")

        self.btn_gen = QPushButton("Generate")
        self.out = QTextEdit(); self.out.setReadOnly(True)

        top = QHBoxLayout()
        top.addWidget(QLabel("Type:")); top.addWidget(self.os_combo)
        top.addWidget(QLabel("Transport:")); top.addWidget(self.transport)
        top.addWidget(QLabel("Host:")); top.addWidget(self.host)
        top.addWidget(QLabel("Port:")); top.addWidget(self.port)
        top.addWidget(QLabel("Beacon:")); top.addWidget(self.beacon)
        top.addWidget(self.btn_gen); top.addStretch()

        layout = QVBoxLayout(); layout.addLayout(top); layout.addWidget(self.out); self.setLayout(layout)
        self.btn_gen.clicked.connect(self.generate)

    def generate(self):
        typ = self.os_combo.currentText()
        t = self.transport.currentText().lower()
        host = self.host.text().strip()
        try: port = int(self.port.text().strip())
        except Exception: QMessageBox.warning(self,"Payload","Enter valid port"); return

        try:
            if typ == "windows-ps1":
                if t not in ("http","https"):
                    QMessageBox.warning(self,"Payload","Windows PS1 supports http/https"); return
                beacon = int(self.beacon.text().strip() or "5")
                text = self.api.gen_win_ps1(t, host, port, beacon)
            else:
                if t not in ("tcp","http"):
                    QMessageBox.warning(self,"Payload","Linux bash supports tcp/http"); return
                text = self.api.gen_linux_bash(t, host, port)
        except Exception as e:
            QMessageBox.critical(self,"Generate",str(e)); return
        self.out.setPlainText(text)
