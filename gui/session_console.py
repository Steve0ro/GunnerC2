# gui/session_console.py
from PyQt5.QtWidgets import QWidget, QPlainTextEdit, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout, QShortcut
from PyQt5.QtCore import QUrl, Qt, pyqtSignal
from PyQt5.QtGui import QKeySequence
from PyQt5.QtNetwork import QAbstractSocket
from PyQt5.QtWebSockets import QWebSocket

class SessionConsole(QWidget):
    files_requested = pyqtSignal(str, str)  # sid, hostname

    def __init__(self, api, sid: str, hostname: str):
        super().__init__()
        self.api = api; self.sid = sid
        self.sid = sid
        self.hostname = hostname

        self.out = QPlainTextEdit(); self.out.setReadOnly(True)
        self.inp = QLineEdit(); self.btn_send = QPushButton("Send")
        self.btn_files = QPushButton("Files")

        t = QHBoxLayout(); t.addWidget(self.btn_files); t.addStretch()
        layout = QVBoxLayout(); layout.addLayout(t); layout.addWidget(self.out)
        bottom = QHBoxLayout(); bottom.addWidget(self.inp); bottom.addWidget(self.btn_send)
        layout.addLayout(bottom); self.setLayout(layout)

        self.btn_send.clicked.connect(self._send)
        self.inp.returnPressed.connect(self._send)
        self.btn_files.clicked.connect(self._on_files_clicked)

        ws_url = self.api.base_url.replace("http", "ws", 1) + f"/ws/sessions/{sid}?token={self.api.token}"
        self.ws = QWebSocket()
        # --- Compat: Qt 5.12/5.14 use `error`; 5.15+ uses `errorOccurred`.
        def _on_ws_error(*args):
            # args may be (socketErrorEnum) or () depending on binding/version
            try:
                err_enum = args[0] if args else None
                # Attempt to stringify enum nicely if provided
                err_name = (
                    QAbstractSocket.SocketError(err_enum).name
                    if isinstance(err_enum, int) else str(err_enum)
                )
                self.out.appendPlainText(f"[websocket error] {err_name}")
            except Exception:
                self.out.appendPlainText("[websocket error]")

        # Hook whichever signal exists; don't reference the other unconditionally.
        connected_err_signal = False
        if hasattr(self.ws, "errorOccurred"):
            try:
                self.ws.errorOccurred.connect(_on_ws_error)
                connected_err_signal = True
            except Exception:
                pass
        if not connected_err_signal and hasattr(self.ws, "error"):
            try:
                self.ws.error.connect(_on_ws_error)  # PyQt5 < 5.15
                connected_err_signal = True
            except Exception:
                pass

        self.ws.textMessageReceived.connect(lambda m: self.out.appendPlainText(m))
        #self.ws.errorOccurred.connect(lambda _: self.out.appendPlainText("[websocket error]"))
        self.ws.open(QUrl(ws_url))

    def _send(self):
        cmd = self.inp.text().strip()
        if not cmd: return
        self.out.appendPlainText(f">>> {cmd}")
        self.ws.sendTextMessage(cmd)
        self.inp.clear()

    # Files now handled by Dashboard (opens a tab)
    def _on_files_clicked(self):
        self.files_requested.emit(self.sid, self.hostname)
