# gui/operators_tab.py
from PyQt5.QtWidgets import (
    QWidget, QTableView, QLineEdit, QComboBox, QPushButton, QHBoxLayout, QVBoxLayout,
    QHeaderView, QAbstractItemView, QMenu, QAction, QInputDialog, QMessageBox, QStyledItemDelegate,
    QApplication
)
from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex, QVariant, QSortFilterProxyModel
from PyQt5.QtGui import QPalette, QColor, QFont, QPainter, QBrush, QPen

try:
    from .websocket_client import OperatorsWSClient
except Exception:
    from websocket_client import OperatorsWSClient

from theme_center import theme_color

# -------- Helpers --------
def _ago(ts: str) -> str:
    # expects ISO or empty; keep simple to avoid deps
    import datetime
    if not ts: return "—"
    try:
        dt = datetime.datetime.fromisoformat(ts.replace("Z","+00:00"))
        if dt.tzinfo: dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        diff = (datetime.datetime.utcnow() - dt).total_seconds()
        if diff < 60: return "just now"
        if diff < 3600: return f"{int(diff//60)}m"
        if diff < 86400: return f"{int(diff//3600)}h"
        return f"{int(diff//86400)}d"
    except Exception:
        return ts

COLUMNS = [("Username","username"), ("Role","role"), ("ID","id"), ("Created","created_at")]

class IDElideDelegate(QStyledItemDelegate):
    def __init__(self, max_px=420, parent=None):
        super().__init__(parent)
        self.max_px = max_px
        self.mono = QFont("Consolas")

    def paint(self, p, opt, idx):
        text = idx.data(Qt.DisplayRole) or ""
        p.save()
        p.setFont(self.mono)
        r = opt.rect.adjusted(6, 0, -6, 0)
        fm = p.fontMetrics()
        # middle elide looks nice for UUIDs
        elided = fm.elidedText(text, Qt.ElideMiddle, self.max_px)
        p.setPen(opt.palette.color(QPalette.Text))
        p.drawText(r, Qt.AlignVCenter | Qt.AlignLeft, elided)
        p.restore()

class OpsModel(QAbstractTableModel):
    def __init__(self): 
        super().__init__(); self._rows=[]

    def rowCount(self,_=QModelIndex()): 
        return len(self._rows)

    def columnCount(self,_=QModelIndex()): 
        return len(COLUMNS)

    def headerData(self, s, o, r=Qt.DisplayRole):
        if r==Qt.DisplayRole and o==Qt.Horizontal: return COLUMNS[s][0]
        return QVariant()

    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid(): 
            return QVariant()

        r = self._rows[idx.row()]
        key = COLUMNS[idx.column()][1]

        if role == Qt.DisplayRole:
            if key == "created_at": return _ago(r.get(key,""))
            return str(r.get(key,""))

        # Full values on hover
        if role == Qt.ToolTipRole:
            if key == "id":
                return str(r.get("id", ""))          # full UUID
            if key == "created_at":
                return str(r.get("created_at", ""))   # raw timestamp if you like

        if role == Qt.TextAlignmentRole:
            if key in ("role", "id"): return Qt.AlignCenter
            return Qt.AlignVCenter | Qt.AlignLeft

        if role == Qt.FontRole and key == "id":
            f = QFont("Consolas"); f.setPointSizeF(f.pointSizeF()*0.95); return f
        return QVariant()

    def set_ops(self, rows): 
        self.layoutAboutToBeChanged.emit()
        self._rows=list(rows or [])
        self.layoutChanged.emit()

    def row_dict(self, proxy_row, proxy): 
        if proxy_row<0: return None
        src = proxy.mapToSource(proxy.index(proxy_row,0)).row()
        return self._rows[src] if 0<=src<len(self._rows) else None

"""class RoleChip(QStyledItemDelegate):
    def paint(self, p, opt, idx):
        text = idx.data(Qt.DisplayRole) or ""
        bg = QColor("#34425a") if text=="operator" else QColor("#5a3434")
        fg = QColor("#dbe7ff") if text=="operator" else QColor("#ffd6d6")
        p.save(); p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(Qt.NoPen); p.setBrush(QBrush(bg))
        r = opt.rect.adjusted(6,4,-6,-4); p.drawRoundedRect(r, 8, 8)
        p.setPen(QPen(fg)); p.drawText(r, Qt.AlignCenter, text or "—")
        p.restore()"""

class RoleChip(QStyledItemDelegate):
    def paint(self, p, opt, idx):
        text = (idx.data(Qt.DisplayRole) or "").lower()
        bg = theme_color("chip_operator_bg") if text == "operator" else theme_color("chip_admin_bg")
        fg = theme_color("chip_operator_fg") if text == "operator" else theme_color("chip_admin_fg")

        p.save(); p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(Qt.NoPen); p.setBrush(QBrush(bg))
        r = opt.rect.adjusted(6,4,-6,-4); p.drawRoundedRect(r, 8, 8)
        p.setPen(QPen(fg)); p.drawText(r, Qt.AlignCenter, text or "—")
        p.restore()

class RoleFilter(QSortFilterProxyModel):
    def __init__(self): super().__init__(); self._needle=""; self._role="all"
    def setText(self, t): self._needle=(t or "").lower(); self.invalidateFilter()
    def setRole(self, role): self._role=role; self.invalidateFilter()
    def filterAcceptsRow(self, r, parent):
        m = self.sourceModel()
        uname = (m.index(r,0,parent).data() or "").lower()
        role  = (m.index(r,1,parent).data() or "").lower()
        ident = (m.index(r,2,parent).data() or "").lower()
        blob = " ".join([uname, role, ident])
        if self._needle and self._needle not in blob: return False
        if self._role in ("operator","admin") and role != self._role: return False
        return True

class OperatorsTab(QWidget):
    def __init__(self, api):
        super().__init__()
        # top bar
        self.search = QLineEdit(); self.search.setPlaceholderText("Search (username, role, id)…"); self.search.setClearButtonEnabled(True)
        sp = self.search.palette(); sp.setColor(QPalette.Text, QColor("#ffffff")); sp.setColor(QPalette.PlaceholderText, QColor("#ffffff")); self.search.setPalette(sp)
        self.roleFilter = QComboBox(); self.roleFilter.addItems(["all","operator","admin"])
        self.uEdit = QLineEdit(); self.uEdit.setPlaceholderText("Username")
        self.pEdit = QLineEdit(); self.pEdit.setPlaceholderText("Password"); self.pEdit.setEchoMode(QLineEdit.Password)
        self.roleNew = QComboBox(); self.roleNew.addItems(["operator","admin"])
        self.btnAdd = QPushButton("Add"); self.btnRemove = QPushButton("Remove"); self.btnRemove.setEnabled(False)

        top = QHBoxLayout()
        top.addWidget(self.search, 1)
        top.addWidget(self.roleFilter)
        top.addStretch()
        top.addWidget(self.uEdit); top.addWidget(self.pEdit); top.addWidget(self.roleNew); top.addWidget(self.btnAdd); top.addWidget(self.btnRemove)

        # table
        self.model = OpsModel()
        self.proxy = RoleFilter(); self.proxy.setSourceModel(self.model)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)

        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.ElideRight)   # ← truncate with …
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)

        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setMinimumSectionSize(80)

        # Tight columns
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)   # Username: just as wide as text
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)   # Role chip
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)   # Created

        # Let ID absorb remaining width
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)            # ID stretches, not Username

        pal = self.table.palette()
        pal.setColor(QPalette.Base, QColor("#151a22"))          # normal row
        pal.setColor(QPalette.AlternateBase, QColor("#1b212b")) # alternate row
        pal.setColor(QPalette.Text, QColor("#e6e6e6"))
        pal.setColor(QPalette.Highlight, QColor("#2f3540"))
        pal.setColor(QPalette.HighlightedText, QColor("#ffffff"))
        self.table.setPalette(pal)

        # role chips
        self.table.setItemDelegateForColumn(1, RoleChip(self.table))

        # context menu
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)

        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)
        layout.addLayout(top); layout.addWidget(self.table)
        #self._apply_style()

        # signals
        self.search.textChanged.connect(self.proxy.setText)
        self.roleFilter.currentTextChanged.connect(self.proxy.setRole)
        self.table.selectionModel().selectionChanged.connect(self._sel_changed)
        self.btnAdd.clicked.connect(self._add)
        self.btnRemove.clicked.connect(self._remove)

        # WS
        self.ws = OperatorsWSClient(api, self)
        self.ws.error.connect(lambda e: None)
        self.ws.snapshot.connect(self.model.set_ops)
        self.ws.open()

    def _apply_style(self):
        self.setStyleSheet("""
            QLineEdit { padding:6px 10px; border:1px solid #3b404a; border-radius:6px; background:#1a1f29; color:#ffffff; }
            QLineEdit::placeholder { color:#ffffff; }
            QComboBox { padding:6px 10px; border:1px solid #3b404a; border-radius:6px; background:#222834; color:#e6e6e6; }
            QPushButton { padding:6px 10px; border:1px solid #3b404a; border-radius:6px; background:#222834; color:#e6e6e6; }
            QPushButton:hover { background:#2a3140; }
            QTableView { background:#151a22; color:#e6e6e6; }
            QHeaderView::section { background:#202633; color:#e6e6e6; border:1px solid #3b404a; padding:6px; }
            QTableView::item:selected { background:#2f3540; }
        """)

    # actions
    def _sel_changed(self, *_):
        self.btnRemove.setEnabled(bool(self._current_id()))

    def _current_row(self):
        idxs = self.table.selectionModel().selectedRows()
        return self.model.row_dict(idxs[0].row(), self.proxy) if idxs else None

    def _current_id(self):
        r = self._current_row()
        return r.get("id") if r else None

    def _add(self):
        u = self.uEdit.text().strip(); p = self.pEdit.text(); r = self.roleNew.currentText()
        if not u or not p:
            QMessageBox.warning(self, "Add Operator", "Username and password are required."); return
        self.ws.add(u, p, r, cb=lambda m: None)
        self.uEdit.clear(); self.pEdit.clear()

    def _remove(self):
        ident = self._current_id()
        if not ident: return
        if QMessageBox.question(self, "Remove Operator", "Delete selected operator?", QMessageBox.Yes|QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.ws.delete(ident, cb=lambda m: None)

    def _menu(self, pos):
        r = self._current_row()
        m = QMenu(self)
        m.addAction("Copy ID", self._copy_id).setEnabled(bool(r))
        m.addSeparator()    
        a_role_op = m.addAction("Set role: operator", lambda: self._update_role("operator"))
        a_role_ad = m.addAction("Set role: admin",    lambda: self._update_role("admin"))
        m.addSeparator()
        a_ren = m.addAction("Rename…", self._rename)
        a_pwd = m.addAction("Reset password…", self._reset_pw)
        m.addSeparator()
        a_rm  = m.addAction("Remove", self._remove)
        if not r:
            for a in (a_role_op, a_role_ad, a_ren, a_pwd, a_rm): a.setEnabled(False)
        m.exec_(self.table.viewport().mapToGlobal(pos))

    def _copy_id(self):
        r = self._current_row()
        if not r: return
        QApplication.clipboard().setText(str(r.get("id", "")))

    def _update_role(self, role):
        ident = self._current_id()
        if ident: self.ws.update(ident, role_new=role, cb=lambda m: None)

    def _rename(self):
        r = self._current_row()
        if not r: return
        text, ok = QInputDialog.getText(self, "Rename Operator", "New username:", QLineEdit.Normal, r.get("username",""))
        if ok and text.strip():
            self.ws.update(r.get("id"), username_new=text.strip(), cb=lambda m: None)

    def _reset_pw(self):
        r = self._current_row()
        if not r: return
        text, ok = QInputDialog.getText(self, "Reset Password", f"New password for {r.get('username')}:", QLineEdit.Password)
        if ok and text.strip():
            self.ws.update(r.get("id"), password_new=text.strip(), cb=lambda m: None)
