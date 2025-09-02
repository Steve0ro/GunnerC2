# gui/dashboard.py
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTabWidget, QSplitter
)

from session_graph import SessionGraph
from sessions_tab import SessionsTab
from listeners_tab import ListenersTab
from payloads_tab import PayloadsTab
from operators_tab import OperatorsTab
from session_console import SessionConsole
from gunnershell_console import GunnershellConsole

# ----------- Helpers ------------
def _strip_host_prefix(username: str, hostname: str) -> str:
    """Turn 'HOST\\user' into 'user' when HOST matches the hostname (case-insensitive)."""
    u = str(username or "")
    h = str(hostname or "")
    if u.lower().startswith(h.lower() + "\\"):
        return u[len(h) + 1 :]
    return u


class Dashboard(QWidget):
    """
    Main landing page:
      ┌───────────────────────────────────────────────┐
      │  Top Button Bar (Graph • Sessions • …)       │
      ├───────────────────────────────────────────────┤
      │  Graph (SessionGraph)                         │
      ├───────────────────────────────────────────────┤
      │  Bottom Tab Browser (QTabWidget, closable)    │
      └───────────────────────────────────────────────┘
    """
    def __init__(self, api, parent=None):
        super().__init__(parent)
        self.api = api

        # ---------- Top button bar ----------
        self.btn_graph = QPushButton("Graph")
        self.btn_sessions = QPushButton("Sessions")
        self.btn_listeners = QPushButton("Listeners")
        self.btn_payloads = QPushButton("Payloads")
        self.btn_operators = QPushButton("Operators")

        for b in (self.btn_graph, self.btn_sessions, self.btn_listeners, self.btn_payloads, self.btn_operators):
            b.setCursor(Qt.PointingHandCursor)
            b.setMinimumHeight(34)
            b.setStyleSheet(
                "QPushButton {"
                "  background:#2c313a; color:#e6e6e6; border:1px solid #3b404a;"
                "  border-radius:6px; padding:6px 12px; font-weight:600; }"
                "QPushButton:hover { border-color:#5a6270; }"
                "QPushButton:pressed { background:#23272e; }"
            )

        buttons = QHBoxLayout()
        buttons.setContentsMargins(8, 8, 8, 4)
        buttons.setSpacing(8)
        buttons.addWidget(self.btn_graph)
        buttons.addWidget(self.btn_sessions)
        buttons.addWidget(self.btn_listeners)
        buttons.addWidget(self.btn_payloads)
        buttons.addWidget(self.btn_operators)
        buttons.addStretch()

        # ---------- Graph (top) ----------
        self.graph = SessionGraph(self.api)
        self.graph.open_console_requested.connect(self._open_console_tab)
        self.graph.open_gunnershell_requested.connect(self._open_gunnershell_tab)
        self.graph.kill_session_requested.connect(self._kill_session)

        # ---------- Bottom tab browser ----------
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self._close_tab)

        # Use a vertical splitter so users can resize graph vs. tabs
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.graph)
        split.addWidget(self.tabs)
        split.setSizes([600, 260])  # initial proportions

        # ---------- Layout ----------
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addLayout(buttons)
        root.addWidget(split)

        # ---------- Button wiring ----------
        self.btn_graph.clicked.connect(self._focus_graph)
        self.btn_sessions.clicked.connect(self._open_sessions_tab)
        self.btn_listeners.clicked.connect(self._open_listeners_tab)
        self.btn_payloads.clicked.connect(self._open_payloads_tab)
        self.btn_operators.clicked.connect(self._open_operators_tab)

        # Lazy-singletons for the admin tabs
        self._tab_sessions = None
        self._tab_listeners = None
        self._tab_payloads = None
        self._tab_operators = None

        # Open Sessions by default in the bottom browser to mirror classic UX
        self._open_sessions_tab()

    # ---------- Helpers: open/focus singleton tabs ----------
    def _ensure_tab(self, attr_name: str, widget_factory, title: str):
        w = getattr(self, attr_name)
        if w is None:
            w = widget_factory()
            idx = self.tabs.addTab(w, title)
            self.tabs.setCurrentIndex(idx)
            setattr(self, attr_name, w)
        else:
            idx = self.tabs.indexOf(w)
            if idx >= 0:
                self.tabs.setCurrentIndex(idx)
        return w

    def _open_sessions_tab(self):
        def _make():
            t = SessionsTab(self.api)
            t.session_double_clicked.connect(self._open_console_tab)
            return t
        self._ensure_tab("_tab_sessions", _make, "Sessions")

    def _open_listeners_tab(self):
        self._ensure_tab("_tab_listeners", lambda: ListenersTab(self.api), "Listeners")

    def _open_payloads_tab(self):
        self._ensure_tab("_tab_payloads", lambda: PayloadsTab(self.api), "Payloads")

    def _open_operators_tab(self):
        self._ensure_tab("_tab_operators", lambda: OperatorsTab(self.api), "Operators")

    # ---------- Graph actions wiring ----------
    def _focus_graph(self):
        try:
            self.graph.view.centerOn(self.graph.c2)
            self.graph.view.raise_()
            # Give a gentle refresh
            self.graph.reload()
        except Exception:
            pass

    def _kill_session(self, sid: str, _hostname: str):
        try:
            self.api.kill_session(sid)
        except Exception as e:
            # Keep it simple; the Sessions tab can surface richer UX later
            print(f"[dashboard] kill_session failed: {e}")
        # Refresh both areas
        try:
            if self._tab_sessions:
                self._tab_sessions.reload()
        except Exception:
            pass
        try:
            self.graph.reload()
        except Exception:
            pass

    # ---------- Console tabs ----------
    def _open_console_tab(self, sid: str, hostname: str):
        # Build "username@hostname" title (strip HOST\ prefix if present)
        username = ""
        try:
            s = self.api.get_session(sid) or {}
            username = s.get("user") or s.get("username") or ""
        except Exception:
            # best-effort: leave empty, we’ll still open the console
            username = ""

        if username:
            username = _strip_host_prefix(username, hostname)
            title = f"{username}@{hostname}"
        else:
            # fallback if user not available
            title = hostname

        # Reuse if open
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == title:
                self.tabs.setCurrentIndex(i)
                return
        w = SessionConsole(self.api, sid, hostname)
        i = self.tabs.addTab(w, title)
        self.tabs.setCurrentIndex(i)

    def _open_gunnershell_tab(self, sid: str, hostname: str):
        # Title: GS — username@hostname (strip HOST\ prefix)
        username = ""
        try:
            s = self.api.get_session(sid) or {}
            username = s.get("user") or s.get("username") or ""
        except Exception:
            pass
        who = f"{_strip_host_prefix(username, hostname)}@{hostname}" if username else hostname
        title = f"GS — {who}"

        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == title:
                self.tabs.setCurrentIndex(i)
                return
        w = GunnershellConsole(self.api, sid, hostname)
        idx = self.tabs.addTab(w, title)
        self.tabs.setCurrentIndex(idx)
	
	# Closing Tabs

    def _close_tab(self, index: int):
        w = self.tabs.widget(index)
        # Clear singleton handle if one of the admin tabs is closed
        if w is self._tab_sessions:
            self._tab_sessions = None

        elif w is self._tab_listeners:
            self._tab_listeners = None

        elif w is self._tab_payloads:
            self._tab_payloads = None

        elif w is self._tab_operators:
            self._tab_operators = None

        self.tabs.removeTab(index)
