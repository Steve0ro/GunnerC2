from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QTableView,
    QHeaderView, QAbstractItemView, QMessageBox, QMenu, QAction, QApplication
)
from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex, QVariant, QSortFilterProxyModel, QEvent, QRect
from PyQt5.QtGui import QColor, QBrush, QPen, QFont, QPainter, QPalette

# Progressive listener dialog (already in your project)
try:
    from .create_listener_dialog import CreateListenerDialog
except Exception:
    from create_listener_dialog import CreateListenerDialog

# -------------------- Columns --------------------
COLUMNS = [
    ("ID", "id"),
    ("Type", "type"),
    ("IP", "bind_ip"),
    ("Port", "port"),
    ("Status", "status"),
    ("Profile", "profile"),
]

# -------------------- Model ----------------------
class ListenersModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._rows = []    # list[dict]
        self._sort_col = 0
        self._sort_order = Qt.AscendingOrder

    def rowCount(self, _=QModelIndex()):
        return len(self._rows)

    def columnCount(self, _=QModelIndex()):
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section][0]
        return QVariant()

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return QVariant()
        row = self._rows[index.row()]
        key = COLUMNS[index.column()][1]
        val = row.get(key, "")

        if role == Qt.DisplayRole:
            if key == "port":
                return str(val)
            return "" if val is None else str(val)

        if role == Qt.TextAlignmentRole:
            if key in ("port", "type", "status"):
                return Qt.AlignCenter
            return Qt.AlignVCenter | Qt.AlignLeft

        if role == Qt.FontRole:
            if key in ("id",):
                f = QFont()
                f.setFamily("Consolas")
                f.setPointSizeF(f.pointSizeF() * 0.95)
                return f
        return QVariant()

    def sort(self, column, order):
        key = COLUMNS[column][1]
        def _key(r):
            v = r.get(key, "")
            if key == "port":
                try: return int(v)
                except Exception: return 0
            return str(v).lower()
        self.layoutAboutToBeChanged.emit()
        self._rows.sort(key=_key, reverse=(order == Qt.DescendingOrder))
        self._sort_col, self._sort_order = column, order
        self.layoutChanged.emit()

    # Public
    def set_rows(self, rows: list):
        self.layoutAboutToBeChanged.emit()
        self._rows = list(rows or [])
        self.layoutChanged.emit()
        # keep prior sort
        if self._sort_col is not None:
            self.sort(self._sort_col, self._sort_order)

    def row_at_proxy(self, proxy_row: int, proxy_model: QSortFilterProxyModel):
        if proxy_row < 0:
            return None
        src_row = proxy_model.mapToSource(proxy_model.index(proxy_row, 0)).row()
        if 0 <= src_row < len(self._rows):
            return self._rows[src_row]
        return None

# -------------------- Filter ---------------------
class ListenersFilter(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self._needle = ""

    def setFilterText(self, text: str):
        self._needle = (text or "").lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, parent):
        if not self._needle:
            return True
        model = self.sourceModel()
        for c in range(len(COLUMNS)):
            idx = model.index(source_row, c, parent)
            s = model.data(idx, Qt.DisplayRole)
            if s and self._needle in str(s).lower():
                return True
        return False

# -------------------- Chip Delegates -------------
from PyQt5.QtWidgets import QStyledItemDelegate

class ChipDelegateBase:
    RADIUS = 8
    def _paint_chip(self, painter, rect: QRect, text: str, bg: QColor, fg: QColor):
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(bg))
        painter.drawRoundedRect(rect.adjusted(6, 4, -6, -4), self.RADIUS, self.RADIUS)
        painter.setPen(QPen(fg))
        f = painter.font()
        f.setPointSizeF(f.pointSizeF() * 0.95)
        painter.setFont(f)
        painter.drawText(rect, Qt.AlignCenter, text)
        painter.restore()

class TypeDelegate(QStyledItemDelegate, ChipDelegateBase):
    def paint(self, painter, option, index):
        text = (index.data(Qt.DisplayRole) or "").lower()
        palette = {
            "tcp":   ("#2b5b8c", "#d7e8ff"),
            "tls":   ("#2f6b5f", "#d2fff2"),
            "http":  ("#6a4c2d", "#ffe9cf"),
            "https": ("#345f7a", "#d8f0ff"),
        }
        bg, fg = palette.get(text, ("#434a57", "#e6edf3"))
        self._paint_chip(painter, option.rect, text or "-", QColor(bg), QColor(fg))

class StatusDelegate(QStyledItemDelegate, ChipDelegateBase):
    def paint(self, painter, option, index):
        text = (index.data(Qt.DisplayRole) or "").upper()
        if text == "STARTED":
            bg, fg = QColor("#174a2a"), QColor("#a0f0c0")
        elif text == "STOPPED":
            bg, fg = QColor("#4a2a2a"), QColor("#f0a0a0")
        else:
            bg, fg = QColor("#3e4552"), QColor("#cfd6dd")
        self._paint_chip(painter, option.rect, text or "-", bg, fg)

# -------------------- Tab UI ---------------------
class ListenersTab(QWidget):
    def __init__(self, api):
        super().__init__()
        self.api = api

        # --- Toolbar: search (left), actions (right)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search listeners (ID, type, IP, port, status)…")
        self.search.setClearButtonEnabled(True)

        self.btn_new  = QPushButton("New Listener…")
        self.btn_stop = QPushButton("Stop")
        self.btn_refresh = QPushButton("Refresh")
        self.btn_stop.setEnabled(False)

        top = QHBoxLayout()
        top.addWidget(self.search, stretch=1)
        top.addStretch()
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_new)
        top.addWidget(self.btn_stop)

        # --- Table: QTableView (Model/View)
        self.model = ListenersModel()
        self.proxy = ListenersFilter()
        self.proxy.setSourceModel(self.model)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(3, Qt.AscendingOrder)  # by Port initially
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setTextElideMode(Qt.ElideRight)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.viewport().installEventFilter(self)  # allow blank-click to clear selection

        hdr = self.table.horizontalHeader()
        hdr.setHighlightSections(False)
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)

        # column widths
        self.table.setColumnWidth(0, 160)  # ID
        self.table.setColumnWidth(1, 100)  # Type
        self.table.setColumnWidth(2, 160)  # IP
        self.table.setColumnWidth(3, 90)   # Port
        self.table.setColumnWidth(4, 120)  # Status
        self.table.setColumnWidth(5, 180)  # Profile

        # Delegates for pills
        self.table.setItemDelegateForColumn(1, TypeDelegate(self.table))
        self.table.setItemDelegateForColumn(4, StatusDelegate(self.table))

        # Context menu
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)

        # Layout
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addLayout(top)
        root.addWidget(self.table)

        # Styling (match Sessions tab)
        self._apply_dark_theme()

        # Signals
        self.search.textChanged.connect(self.proxy.setFilterText)
        self.table.selectionModel().selectionChanged.connect(self._sel_changed)
        self.btn_new.clicked.connect(self.open_create_dialog)
        self.btn_stop.clicked.connect(self.stop_listener)
        self.btn_refresh.clicked.connect(self.reload)

        self.reload()

    # ----- Styling to match other tabs -----
    def _apply_dark_theme(self):
        pal = self.palette()
        pal.setColor(pal.Window, QColor("#141820"))
        pal.setColor(pal.Base, QColor("#151a22"))
        pal.setColor(pal.AlternateBase, QColor("#1b212b"))
        pal.setColor(pal.Text, QColor("#e6e6e6"))
        pal.setColor(pal.Button, QColor("#222834"))
        pal.setColor(pal.ButtonText, QColor("#e6e6e6"))
        pal.setColor(pal.Highlight, QColor("#2f3540"))
        pal.setColor(pal.HighlightedText, QColor("#ffffff"))
        self.setPalette(pal)
        self.setStyleSheet("""
            QLineEdit { padding:6px 10px; border:1px solid #3b404a; border-radius:6px; background:#1a1f29; }
            QLineEdit:focus { border-color:#5a93ff; }
            QPushButton { padding:6px 10px; border:1px solid #3b404a; border-radius:6px; background:#222834; }
            QPushButton:disabled { color:#9aa3ad; border-color:#333842; background:#1c212b; }
            QPushButton:hover { background:#2a3140; }
            /* Table + rows */
            QTableView {
                background:#151a22;
                color:#e6e6e6;
                gridline-color:#3b404a;
                alternate-background-color:#1b212b; /* make sure Qt doesn't use white */
            }
            QTableView::item { background:#151a22; }
            QTableView::item:alternate { background:#1b212b; }
            QHeaderView::section { background:#202633; color:#e6e6e6; border:1px solid #3b404a; padding:6px; }
            QTableView::item:selected { background:#2f3540; color:#ffffff; }
        """)

        spal = self.search.palette()
        spal.setColor(QPalette.Text, QColor("#ffffff"))
        spal.setColor(QPalette.PlaceholderText, QColor("#ffffff"))
        self.search.setPalette(spal)

    # ----- Data -----
    def reload(self):
        try:
            rows = self.api.list_listeners() or []
        except Exception:
            rows = []
        # Normalize expected keys
        norm = []
        for r in rows:
            norm.append({
                "id":       r.get("id") or r.get("name") or "",
                "type":     (r.get("type") or r.get("transport") or "").lower(),
                "bind_ip":  r.get("bind_ip") or r.get("ip") or "0.0.0.0",
                "port":     r.get("port") or r.get("bind_port") or 0,
                "status":   (r.get("status") or "").upper(),
                "profile":  r.get("profile") or r.get("base_path") or "",
            })
        self.model.set_rows(norm)
        self._sel_changed()

    # ----- Selection state -----
    def _sel_changed(self, *_):
        row = self._current_row()
        self.btn_stop.setEnabled(row is not None and (row.get("status") or "").upper() == "STARTED")

    def _current_row(self):
        idxs = self.table.selectionModel().selectedRows()
        if not idxs:
            return None
        return self.model.row_at_proxy(idxs[0].row(), self.proxy)

    # ----- Context menu -----
    def _context_menu(self, pos):
        row = self._current_row()
        m = QMenu(self)
        a1 = m.addAction("Stop", self.stop_listener)
        m.addSeparator()
        a2 = m.addAction("Copy ID", lambda: self._copy_field("id"))
        a3 = m.addAction("Copy IP:Port", self._copy_ip_port)
        a4 = m.addAction("Copy Row (TSV)", self._copy_row_tsv)
        if not row: 
            for a in (a1, a2, a3, a4): a.setEnabled(False)
        else:
            a1.setEnabled((row.get("status") or "").upper() == "STARTED")
        m.exec_(self.table.viewport().mapToGlobal(pos))

    def _copy_field(self, key):
        row = self._current_row()
        if not row: return
        QApplication.clipboard().setText(str(row.get(key, "")))

    def _copy_ip_port(self):
        row = self._current_row()
        if not row: return
        QApplication.clipboard().setText(f"{row.get('bind_ip','')}",)
        QApplication.clipboard().setText(f"{row.get('bind_ip','')}:{row.get('port','')}")

    def _copy_row_tsv(self):
        row = self._current_row()
        if not row: return
        vals = [str(row.get(k,'')) for _, k in COLUMNS]
        QApplication.clipboard().setText("\t".join(vals))

    # ----- Create / Stop -----
    def open_create_dialog(self):
        dlg = CreateListenerDialog(self, bind_check=self._bind_check, name_check=self._name_check)
        if dlg.exec_() != dlg.Accepted:
            return
        cfg = dlg.data()
        adv = getattr(self.api, "create_listener_v2", None) or getattr(self.api, "create_listener_advanced", None)
        try:
            if callable(adv):
                adv(cfg)
            else:
                t = cfg.get("transport", "tcp")
                ip = cfg.get("host", "0.0.0.0")
                port = int(cfg.get("port", 0))
                profile = cfg.get("base_path") if t in ("http", "https") else None
                self.api.create_listener(t, ip, port, profile)
        except Exception as e:
            QMessageBox.critical(self, "Create Listener", str(e))
            return
        self.reload()

    def stop_listener(self):
        row = self._current_row()
        if not row:
            return
        lid = row.get("id")
        try:
            self.api.stop_listener(lid)
        except Exception as e:
            QMessageBox.critical(self, "Stop Listener", str(e))
            return
        self.reload()

    # ----- Dialog helpers -----
    def _bind_check(self, host: str, port: int, transport: str):
        fn = getattr(self.api, "listener_can_bind", None)
        if callable(fn):
            try:
                ok, msg = fn(host, port, transport)
                return bool(ok), str(msg or "")
            except Exception as e:
                return False, f"{e}"
        return True, "Available"

    def _name_check(self, name: str):
        fn = getattr(self.api, "listener_name_available", None)
        if callable(fn):
            try:
                ok, msg = fn(name)
                return bool(ok), str(msg or "")
            except Exception as e:
                return False, f"{e}"
        # otherwise accept all (IDs are server-assigned in many setups)
        return True, ""

    # Clear selection by clicking empty space
    def eventFilter(self, obj, ev):
        if obj is self.table.viewport():
            if ev.type() == QEvent.MouseButtonPress and ev.button() == Qt.LeftButton:
                if not self.table.indexAt(ev.pos()).isValid():
                    self.table.clearSelection()
                    self.table.setCurrentIndex(QModelIndex())
                    self._sel_changed()
                    return True
        return super().eventFilter(obj, ev)