# gui/title_bar.py
from PyQt5.QtCore import Qt, QPoint, QEvent, QTimer, QSize
from PyQt5.QtGui import QCursor

from PyQt5.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QMenuBar, QMenu, QPushButton,
    QSizePolicy, QStyle, QApplication
)

# --- menu that closes itself shortly after the cursor leaves ---------------
class _CloseOnLeaveMenu(QMenu):
    def __init__(self, title="", parent=None, leave_delay_ms=80):
        super().__init__(title, parent)
        self._leave_timer = QTimer(self)
        self._leave_timer.setSingleShot(True)
        self._leave_timer.setInterval(leave_delay_ms)
        self._leave_timer.timeout.connect(self._maybe_close)
        self._menu_close_delay = leave_delay_ms

        # If we’re a submenu, stop the parent’s close timer when we show.
        p = self.parentWidget()
        if isinstance(p, _CloseOnLeaveMenu):
            self.aboutToShow.connect(p._leave_timer.stop)

    def enterEvent(self, e):
        # Pointer re-entered: cancel our close timer and our parent's (if any)
        self._leave_timer.stop()
        p = self.parentWidget()
        if isinstance(p, _CloseOnLeaveMenu):
            p._leave_timer.stop()
        super().enterEvent(e)

    def leaveEvent(self, e):
        # Start a delayed close; the timeout will verify pointer location first.
        self._leave_timer.start()
        super().leaveEvent(e)

    def event(self, ev):
        # If the app/window deactivates or we lose focus while a popup is up,
        # don't wait on Qt's long default — arm our 80ms close instead.
        if ev.type() in (QEvent.WindowDeactivate, QEvent.FocusOut):
            self._leave_timer.start()
        return super().event(ev)

    def _maybe_close(self):
        """
        Close unless the cursor is inside me or any visible submenu.
        Works even when the cursor is over non-Qt areas (OS title bar / desktop).
        """
        gpos = QCursor.pos()

        # inside me?
        if self.isVisible() and self.rect().contains(self.mapFromGlobal(gpos)):
            return

        # inside any visible submenu?
        for sm in self.findChildren(QMenu):
            if sm.isVisible() and sm.rect().contains(sm.mapFromGlobal(gpos)):
                return

        # cursor is nowhere in our popup tree -> close
        self.hide()

class _ClickOnlyMenuBar(QMenuBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(False)
        self._pressed = False

    # don’t activate actions on hover
    def mouseMoveEvent(self, e):
        if self._pressed:
            super().mouseMoveEvent(e)

    def enterEvent(self, e):
        # avoid hover selection
        self.setActiveAction(None)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            act = self.actionAt(e.pos())
            if act and act.menu():
                self._pressed = True
                self.setActiveAction(act)
                geo = self.actionGeometry(act)
                act.menu().popup(self.mapToGlobal(geo.bottomLeft()))
                e.accept()
                return
        super().mousePressEvent(e)

    def mouseReleaseEvent(self, e):
        self._pressed = False
        super().mouseReleaseEvent(e)

class TitleBar(QWidget):
    def __init__(self, owner_window, dashboard):
        super().__init__(owner_window)
        self._win = owner_window
        self._dash = dashboard
        self._drag_pos = None

        self.setFixedHeight(34)
        self.setAutoFillBackground(True)
        
        R = 14
        self.setStyleSheet(
            "QWidget { background:#2a2e36; }"
            "QMenuBar { background:transparent; color:#e8e8e8;"
            "            selection-background-color: transparent;"
            "            selection-color: #e8e8e8; }"
            "QMenuBar::item { padding:6px 10px; margin:0; background:transparent; }"
            "QMenuBar::item:selected { background:transparent; color:#e8e8e8; }"
            "QMenuBar::item:pressed  { background:transparent; color:#e8e8e8; }"
            "QMenuBar::item:on       { background:transparent; color:#e8e8e8; }"
            "QMenu { background:#23272e; color:#e8e8e8; }"
            "QMenu::item:selected { background:#374151; }"
            "QPushButton { border:none; background:transparent; }"
            "QPushButton:hover { background:rgba(255,255,255,0.08); }"

            f"#winClose {{ background:#e74c3c; border:1px solid rgba(255,255,255,0.20);"
            f"            border-radius:{R}px; }}"
            f"#winClose:hover  {{ background:#ff6b5a; border-color:rgba(255,255,255,0.35); }}"
            f"#winClose:pressed{{ background:#c0392b; }}"

            f"#winMax {{ background:#3498db; border:1px solid rgba(255,255,255,0.20);"
            f"          border-radius:{R}px; }}"
            f"#winMax:hover   {{ background:#5dade2; border-color:rgba(255,255,255,0.35); }}"
            f"#winMax:pressed {{ background:#2c81ba; }}"

            f"#winMin {{ background:#f1c40f; border:1px solid rgba(255,255,255,0.20);"
            f"          border-radius:{R}px; }}"
            f"#winMin:hover   {{ background:#f4d03f; border-color:rgba(255,255,255,0.35); }}"
            f"#winMin:pressed {{ background:#cda70d; }}"
        )

        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 0, 6, 0)
        lay.setSpacing(6)

        # Logo (also draggable)
        self.logo = QLabel()
        self.logo.setPixmap(QApplication.windowIcon().pixmap(18, 18))
        self.logo.setFixedSize(22, 22)
        self.logo.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.logo, 0, Qt.AlignVCenter)

        # Menubar
        self.menubar = _ClickOnlyMenuBar()
        self.menubar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.menubar.setNativeMenuBar(False)  # stay inside our title bar on macOS too
        lay.addWidget(self.menubar, 1)

        # --- Graph menu (renamed) ------------------------------------------
        CLOSE_DELAY_MS = 80
        self._menu_close_delay = CLOSE_DELAY_MS

        self.m_graph = _CloseOnLeaveMenu("Graph", self, leave_delay_ms=CLOSE_DELAY_MS)
        self.menubar.addMenu(self.m_graph)

        act_visit = self.m_graph.addAction("Visit C2")
        act_visit.triggered.connect(lambda: getattr(self._dash.graph, "visit_c2", lambda: None)())

        # Filter submenu
        self.m_filter = _CloseOnLeaveMenu("Filter", self.m_graph, leave_delay_ms=CLOSE_DELAY_MS)
        self.m_graph.addMenu(self.m_filter)

        self.act_os_win = self.m_filter.addAction("Windows agents"); self.act_os_win.setCheckable(True); self.act_os_win.setChecked(True)
        self.act_os_lin = self.m_filter.addAction("Linux agents");   self.act_os_lin.setCheckable(True); self.act_os_lin.setChecked(True)

        # Transports submenu
        self.m_trans = _CloseOnLeaveMenu("Transports", self.m_filter, leave_delay_ms=CLOSE_DELAY_MS)
        self.m_filter.addMenu(self.m_trans)
        self._proto_actions = {}
        for proto in ("tcp", "tls", "http", "https"):
            a = self.m_trans.addAction(proto)
            a.setCheckable(True); a.setChecked(True)
            a.toggled.connect(self._push_filters)
            self._proto_actions[proto] = a

        self.act_os_win.toggled.connect(self._push_filters)
        self.act_os_lin.toggled.connect(self._push_filters)

        # ---- WATCH TIMER: make menus close even when pointer leaves the app/window ----
        self._menu_watch = QTimer(self)
        self._menu_watch.setInterval(self._menu_close_delay)
        self._menu_watch.timeout.connect(self._menu_watch_tick)

        # Start/stop the watch when any of our menus show/hide
        for m in (self.m_graph, self.m_filter, self.m_trans):
            m.aboutToShow.connect(self._start_menu_watch)
            m.aboutToHide.connect(self._maybe_stop_menu_watch)

        # Window buttons
        self.btn_min   = QPushButton()
        self.btn_max   = QPushButton()
        self.btn_close = QPushButton()

        self.btn_min.setObjectName("winMin")
        self.btn_max.setObjectName("winMax")
        self.btn_close.setObjectName("winClose")

        self.btn_min.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMinButton))
        self.btn_max.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMaxButton))
        self.btn_close.setIcon(self.style().standardIcon(QStyle.SP_TitleBarCloseButton))

        BTN_SIZE = 28  # pick 26–32 to taste
        ICON_SIZE = 14

        for b in (self.btn_min, self.btn_max, self.btn_close):
            b.setFixedSize(BTN_SIZE, BTN_SIZE)       # square -> circle possible
            b.setIconSize(QSize(ICON_SIZE, ICON_SIZE))
            lay.addWidget(b, 0, Qt.AlignRight | Qt.AlignVCenter)

        self.btn_min.clicked.connect(self._win.showMinimized)
        self.btn_max.clicked.connect(self._toggle_max_restore)
        self.btn_close.clicked.connect(self._win.close)

        # Drag-from areas
        self.logo.installEventFilter(self)
        self.menubar.installEventFilter(self)
        self._win.installEventFilter(self)

        self._push_filters()  # initial filter sync

    def _open_graph_menus(self):
        # Track exactly the three menus we own; only return the visible ones.
        return [m for m in (self.m_graph, self.m_filter, self.m_trans) if m.isVisible()]

    def _pointer_in_any_menu(self):
        pos_g = QCursor.pos()
        for m in self._open_graph_menus():
            if m.isVisible():
                # Geometry-based hit test in global coords (robust even over other windows)
                if m.rect().contains(m.mapFromGlobal(pos_g)):
                    return True
        return False

    # ----- Watch Timers -----
    def _start_menu_watch(self):
        if not self._menu_watch.isActive():
            self._menu_watch.start()

    def _maybe_stop_menu_watch(self):
        if not self._open_graph_menus():
            self._menu_watch.stop()

    def _menu_watch_tick(self):
        # If the cursor isn't inside any of our popped menus, arm their 80ms close.
        if self._open_graph_menus() and not self._pointer_in_any_menu():
            for m in self._open_graph_menus():
                m._leave_timer.start(self._menu_close_delay)

    # ----- Filters → SessionGraph -----
    def _push_filters(self):
        g = self._dash.graph
        if hasattr(g, "set_os_filter"):
            g.set_os_filter(self.act_os_win.isChecked(), self.act_os_lin.isChecked())
        if hasattr(g, "set_transports_filter"):
            enabled = {p for p, a in self._proto_actions.items() if a.isChecked()}
            g.set_transports_filter(enabled)

    # ----- Max/restore -----
    def _toggle_max_restore(self):
        if self._win.isMaximized():
            self._win.showNormal()
            self.btn_max.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMaxButton))
        else:
            self._win.showMaximized()
            self.btn_max.setIcon(self.style().standardIcon(QStyle.SP_TitleBarNormalButton))

    # ========== Dragging ==========
    def _can_start_drag_here(self, pos):
        w = self.childAt(pos)
        if w in (self.btn_min, self.btn_max, self.btn_close):
            return False
        if w is self.menubar:
            mb_pos = self.menubar.mapFrom(self, pos)
            return self.menubar.actionAt(mb_pos) is None
        return True

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton and self._can_start_drag_here(e.pos()):
            self._close_all_menus()  # << close immediately on drag start
            self._drag_pos = e.globalPos() - self._win.frameGeometry().topLeft()
            e.accept(); return
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e):
        if self._drag_pos and (e.buttons() & Qt.LeftButton) and not self._win.isMaximized():
            self._win.move(e.globalPos() - self._drag_pos)
            e.accept(); return
        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e):
        self._drag_pos = None
        super().mouseReleaseEvent(e)

    def mouseDoubleClickEvent(self, e):
        if e.button() == Qt.LeftButton and self._can_start_drag_here(e.pos()):
            self._toggle_max_restore(); e.accept(); return
        super().mouseDoubleClickEvent(e)

    # Close menus when leaving the menubar entirely
    def _close_all_menus(self):
        for m in self.menubar.findChildren(QMenu):
            if m.isVisible():
                m.hide()
        self.menubar.setActiveAction(None)

    # Dragging from logo/menubar whitespace, and menu auto-close on leave
    def eventFilter(self, obj, ev):
        if obj is self._win and ev.type() in (QEvent.Move, QEvent.Resize, QEvent.WindowStateChange):
            self._close_all_menus()
            return False

        t = ev.type()
        if t in (QEvent.MouseMove, QEvent.Leave, QEvent.WindowDeactivate,
                QEvent.ApplicationDeactivate, QEvent.FocusOut):
            if self._open_graph_menus() and not self._pointer_in_any_menu():
                for m in self._open_graph_menus():
                    m._leave_timer.start(self._menu_close_delay)
            # never consume globally
            if obj is not self.menubar:
                return False

        # existing menubar-drag logic unchanged
        if obj is self.menubar:
            if ev.type() == QEvent.MouseButtonPress and ev.button() == Qt.LeftButton:
                if self.menubar.actionAt(ev.pos()) is None:
                    self._close_all_menus()  # << close when starting a drag from the menubar gap
                    self._drag_pos = ev.globalPos() - self._win.frameGeometry().topLeft()
                    return True

            elif ev.type() == QEvent.MouseMove and (ev.buttons() & Qt.LeftButton) and self._drag_pos:
                if not self._win.isMaximized():
                    self._win.move(ev.globalPos() - self._drag_pos)
                return True

            elif ev.type() == QEvent.MouseButtonRelease:
                self._drag_pos = None

        return super().eventFilter(obj, ev)
