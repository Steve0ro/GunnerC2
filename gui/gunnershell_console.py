# gui/gunnershell_console.py
from PyQt5.QtWidgets import (
    QWidget, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout, QShortcut
)
from PyQt5.QtNetwork import QAbstractSocket
from PyQt5.QtWebSockets import QWebSocket
from PyQt5.QtCore import QUrl, Qt
from PyQt5.QtGui import QKeySequence, QFont, QFontDatabase, QTextOption, QTextCursor

# --- ANSI → HTML -------------------------------------------------------------
import re, html

_ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")

_FG_NORMAL = {
    30:"#000000", 31:"#cc0000", 32:"#00a000", 33:"#c7a41c",
    34:"#1f6feb", 35:"#a000a0", 36:"#008b8b", 37:"#e6e6e6",
}
_FG_BRIGHT = {
    30:"#7f7f7f", 31:"#ff4d4d", 32:"#00ff44", 33:"#ffd75f",
    34:"#66b0ff", 35:"#ff7ad9", 36:"#00e5ff", 37:"#ffffff",
}
_FG_EXPLICIT = {
    90:"#9e9e9e", 91:"#ff5c5c", 92:"#00ff66", 93:"#ffe66d",
    94:"#66b0ff", 95:"#ff7ad9", 96:"#66f0ff", 97:"#ffffff",
}
_BG = {
    40:"#000000", 41:"#330000", 42:"#002b00", 43:"#332b00",
    44:"#001a33", 45:"#2b0033", 46:"#003333", 47:"#2b2b2b",
    100:"#4d4d4d",101:"#662222",102:"#226622",103:"#666622",
    104:"#224d66",105:"#662266",106:"#226666",107:"#aaaaaa",
}

def _xterm256(n: int) -> str:
    table = [
        "#000000","#800000","#008000","#808000","#000080","#800080","#008080","#c0c0c0",
        "#808080","#ff0000","#00ff00","#ffff00","#0000ff","#ff00ff","#00ffff","#ffffff"
    ]
    if 0 <= n <= 15: return table[n]
    if 16 <= n <= 231:
        n -= 16
        r = (n // 36) % 6; g = (n // 6) % 6; b = n % 6
        def v(x): return 0 if x == 0 else 55 + x*40
        return f"#{v(r):02x}{v(g):02x}{v(b):02x}"
    if 232 <= n <= 255:
        v = 8 + (n - 232) * 10
        return f"#{v:02x}{v:02x}{v:02x}"
    return "#ffffff"

def _rgb(r,g,b):
    r = max(0, min(255, int(r))); g = max(0, min(255, int(g))); b = max(0, min(255, int(b)))
    return f"#{r:02x}{g:02x}{b:02x}"

def _style_from_state(state):
    parts = ["white-space: pre-wrap"]
    if state.get("fg"): parts.append(f"color:{state['fg']}")
    if state.get("bg"): parts.append(f"background:{state['bg']}")
    if state.get("bold"):
        parts.append("font-weight:700")
        parts.append("text-shadow: 0 0 6px currentColor")  # bright “glow”
    if state.get("underline"): parts.append("text-decoration: underline")
    return "; ".join(parts)

def ansi_to_html(s: str) -> str:
    s = s.replace("\x01","").replace("\x02","").replace("\r","")
    out, i, open_span = [], 0, False
    state = {"fg":None,"bg":None,"bold":False,"underline":False}

    for m in _ANSI_RE.finditer(s):
        if m.start() > i:
            out.append(html.escape(s[i:m.start()]).replace("\n","<br/>"))
        i = m.end()

        params = m.group(1)
        if params == "" or params == "0":
            if open_span: out.append("</span>"); open_span = False
            state = {"fg":None,"bg":None,"bold":False,"underline":False}
            continue

        toks = [int(p) for p in params.split(";") if p != ""]
        j = 0
        while j < len(toks):
            code = toks[j]

            # 24-bit truecolor: 38;2;r;g;b / 48;2;r;g;b
            if code == 38 and j+4 < len(toks) and toks[j+1] == 2:
                state["fg"] = _rgb(toks[j+2], toks[j+3], toks[j+4]); j += 5; continue
            if code == 48 and j+4 < len(toks) and toks[j+1] == 2:
                state["bg"] = _rgb(toks[j+2], toks[j+3], toks[j+4]); j += 5; continue

            # 256-color: 38;5;n / 48;5;n
            if code == 38 and j+2 < len(toks) and toks[j+1] == 5:
                state["fg"] = _xterm256(toks[j+2]); j += 3; continue
            if code == 48 and j+2 < len(toks) and toks[j+1] == 5:
                state["bg"] = _xterm256(toks[j+2]); j += 3; continue

            if code == 1: state["bold"] = True
            elif code == 22: state["bold"] = False
            elif code == 4:  state["underline"] = True
            elif code == 24: state["underline"] = False
            elif 30 <= code <= 37:
                state["fg"] = _FG_BRIGHT[code] if state["bold"] else _FG_NORMAL[code]
            elif 90 <= code <= 97:
                state["fg"] = _FG_EXPLICIT[code]
            elif code in _BG: state["bg"] = _BG[code]
            elif code == 39: state["fg"] = None
            elif code == 49: state["bg"] = None
            j += 1

        if open_span: out.append("</span>")
        out.append(f'<span style="{_style_from_state(state)}">'); open_span = True

    if i < len(s): out.append(html.escape(s[i:]).replace("\n","<br/>"))
    if open_span: out.append("</span>")
    return "".join(out)

# --- Widget ------------------------------------------------------------------

class GunnershellConsole(QWidget):
    def __init__(self, api, sid: str, hostname: str):
        super().__init__()
        self.api = api
        self.sid = sid

        # Rich text output (monospace)
        self.out = QTextEdit()
        self.out.setReadOnly(True)
        self.out.setLineWrapMode(QTextEdit.NoWrap)
        self.out.document().setMaximumBlockCount(2000)  # keep memory/lag in check
        self.out.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.out.setStyleSheet(
            "QTextEdit {"
            "  background:#0b0f14; color:#dce3ea;"
            "  font-size:12.5px;"
            "}"
        )

        # --- make ASCII art render correctly ---
        mono = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        try:
            mono.setStyleHint(QFont.Monospace)

        except AttributeError:
            mono.setStyleHint(QFont.TypeWriter)

        mono.setStyleStrategy(QFont.NoFontMerging)  # avoids ligatures/substitutions
        self.out.setFont(mono)
        self.out.setWordWrapMode(QTextOption.NoWrap)


        self.inp = QLineEdit()
        self.btn_send = QPushButton("Send")

        layout = QVBoxLayout(self)
        layout.addWidget(self.out)
        bottom = QHBoxLayout(); bottom.addWidget(self.inp); bottom.addWidget(self.btn_send)
        layout.addLayout(bottom)

        self.btn_send.clicked.connect(self._send)
        self.inp.returnPressed.connect(self._send)

        # --- Ctrl+L to clear screen ---
        self._sc_clear = QShortcut(QKeySequence("Ctrl+L"), self)
        self._sc_clear.setContext(Qt.WidgetWithChildrenShortcut)
        self._sc_clear.activated.connect(self._clear_screen)

        ws_url = self.api.base_url.replace("http", "ws", 1) + f"/ws/gunnershell/{sid}?token={self.api.token}"
        self.ws = QWebSocket()

        def _on_ws_error(*args):
            try:
                enum = args[0] if args else None
                name = (QAbstractSocket.SocketError(enum).name if isinstance(enum, int) else str(enum))
                self._append_html(f'<span style="color:#ff5555"><b>[websocket error]</b> {html.escape(name)}</span>')
            except Exception:
                self._append_html(f'<span style="color:#ff5555"><b>[websocket error]</b> {html.escape(self.ws.errorString())}</span>')
                self._append_html(f'<span style="color:#ff5555"><b>[websocket error]</b></span>')

        if hasattr(self.ws, "errorOccurred"):
            self.ws.errorOccurred.connect(_on_ws_error)
        elif hasattr(self.ws, "error"):
            self.ws.error.connect(_on_ws_error)

        self.ws.textMessageReceived.connect(self._on_msg)
        self.ws.open(QUrl(ws_url))

    # --- helpers -------------------------------------------------------------

    def _clear_screen(self):
        """Clear the console like a terminal Ctrl+L."""
        self.out.clear()
        # If you want to mimic CLI behavior and reprint the banner, uncomment:
        # self.ws.sendTextMessage("banner")

    def _append_html(self, html_str: str):
        cur = self.out.textCursor()
        cur.movePosition(QTextCursor.End)
        cur.insertHtml(html_str)
        cur.insertHtml("<br/>")
        self.out.setTextCursor(cur)
        self.out.ensureCursorVisible()

    # WebSocket text → colored output
    def _on_msg(self, msg: str):
        if msg == "\x00CLEAR\x00":
            self._clear_screen()
            return
        self._append_html(ansi_to_html(msg))

    def _send(self):
        text = self.inp.text().strip()
        if not text:
            return
        # echo in bright blue like a prompt
        self._append_html(f'<span style="color:#62a0ea;font-weight:600">&gt;&gt;&gt;</span> '
                          f'<span style="color:#cfcfcf">{html.escape(text)}</span>')
        self.ws.sendTextMessage(text)
        self.inp.clear()
