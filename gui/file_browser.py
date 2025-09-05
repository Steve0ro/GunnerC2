# gui/file_browser.py
from __future__ import annotations

from PyQt5.QtWidgets import (
	QWidget, QTableWidget, QTableWidgetItem, QPushButton, QLineEdit, QLabel,
	QHBoxLayout, QVBoxLayout, QFileDialog, QMessageBox, QHeaderView, QToolButton,
	QApplication, QStyle, QFrame, QProgressBar, QShortcut
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QKeySequence, QIcon
import random, os, time

from files_ws_client import FilesWSClient


# ---------- Small helpers ----------
def _sep_for(path: str, os_type: str) -> str:
	return "\\" if os_type.lower() == "windows" else "/"


class NameItem(QTableWidgetItem):
	def __init__(self, text: str, is_dir: bool, icon: QIcon = None):
		super().__init__(text); self.is_dir = bool(is_dir)
		if icon: self.setIcon(icon)
	def __lt__(self, other):
		if isinstance(other, NameItem):
			if self.is_dir != other.is_dir:
				return self.is_dir and not other.is_dir
			return self.text().lower() < other.text().lower()
		return super().__lt__(other)


class SizeItem(QTableWidgetItem):
	def __init__(self, size_display: str, raw_size: int | None):
		super().__init__(size_display); self.raw_size = int(raw_size or 0)
		self.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
	def __lt__(self, other):
		if isinstance(other, SizeItem): return self.raw_size < other.raw_size
		return super().__lt__(other)


class BusyOverlay(QFrame):
	def __init__(self, parent: QWidget, *, message: str = "Waiting for beacon…"):
		super().__init__(parent)
		self.setStyleSheet(
			"QFrame { background: rgba(0,0,0,120); border-radius: 8px; }"
			"QLabel { color: #e9eaec; font-size: 13px; }"
		)
		self.setVisible(False)
		self.setAttribute(Qt.WA_TransparentForMouseEvents, False)
		self.setFrameStyle(QFrame.NoFrame)
		lay = QVBoxLayout(self); lay.setContentsMargins(18,18,18,18); lay.setSpacing(10)
		self.lbl = QLabel(message, self)
		self.bar = QProgressBar(self); self.bar.setRange(0, 0); self.bar.setTextVisible(False)
		lay.addWidget(self.lbl, 0, Qt.AlignHCenter); lay.addWidget(self.bar)
		self.raise_()
	def setMessage(self, msg: str): self.lbl.setText(msg)
	def showCentered(self):
		p = self.parent() if isinstance(self.parent(), QWidget) else None
		if p: self.setGeometry(p.rect().adjusted(p.width()//4, p.height()//3, -p.width()//4, -p.height()//3))
		self.setVisible(True); self.raise_()
	def resizeEvent(self, e):
		self.showCentered(); super().resizeEvent(e)


class FileBrowser(QWidget):
	"""
	Live, OS- and transport-aware file browser with diffed UI updates.
	  • TCP: ~1s live updates.
	  • HTTP/HTTPS: auto-updates on beacon interval (with jitter). A translucent overlay
		shows while a list request is in-flight so users know we’re waiting on the next beacon.
	  • Only re-renders rows when something actually changed.
	"""
	def __init__(self, api, sid: str, start_path: str = ".", os_type: str = "",
				 transport: str = "", beacon_interval: float | None = None, beacon_jitter_pct: int | None = None):
		super().__init__()
		self.api = api
		self.sid = sid
		self.path = start_path
		self.os_type = (os_type or "").lower()
		self.transport = (transport or "").lower()
		self.beacon_interval = float(beacon_interval or 0.0)  # seconds
		self.beacon_jitter_pct = int(beacon_jitter_pct or 0)
		self._pending_path: str | None = None

		if self.path in ("", ".", "./"):
			self.path = "C:\\" if self.os_type == "windows" else "/"

		# Cache of last listing for diffing: {name: (is_dir, size)}
		self._last_listing: dict[str, tuple[bool, int]] = {}

		# ---------- Icons ----------
		sty = QApplication.style()
		self.icon_dir = sty.standardIcon(QStyle.SP_DirIcon)
		self.icon_file = sty.standardIcon(QStyle.SP_FileIcon)
		self.icon_up = sty.standardIcon(QStyle.SP_ArrowUp)

		# ---------- Top bar ----------
		self.path_edit = QLineEdit(self.path); self.path_edit.setReadOnly(True)
		self.crumbs = QHBoxLayout(); self.crumbs.setSpacing(6); self.crumbs.setContentsMargins(0, 0, 0, 0)
		self.crumbs_wrap = QHBoxLayout(); self.crumbs_wrap.addLayout(self.crumbs); self.crumbs_wrap.addStretch()
		self.btn_up = QPushButton(self.icon_up, "Up")

		toolbar = QHBoxLayout(); toolbar.setSpacing(8)
		toolbar.addWidget(QLabel("Path:")); toolbar.addLayout(self.crumbs_wrap, 1); toolbar.addWidget(self.btn_up)

		# ---------- Table ----------
		self.table = QTableWidget(0, 2)
		self.table.setHorizontalHeaderLabels(["Name", "Size"])
		self.table.setEditTriggers(QTableWidget.NoEditTriggers)
		self.table.setSelectionBehavior(QTableWidget.SelectRows)
		self.table.setAlternatingRowColors(True)
		self.table.verticalHeader().setVisible(False)
		hdr = self.table.horizontalHeader()
		hdr.setStretchLastSection(False)
		hdr.setSectionResizeMode(0, QHeaderView.Stretch)
		hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
		self.table.setSortingEnabled(True)
		self.table.itemDoubleClicked.connect(self._dbl)

		# ---------- Bottom bar ----------
		self.btn_download = QPushButton("Download")
		self.btn_upload = QPushButton("Upload")
		self.btn_download.setEnabled(False)
		self.table.itemSelectionChanged.connect(
			lambda: self.btn_download.setEnabled(bool(self.table.selectionModel().selectedRows()))
		)
		self.status = QLabel("Live"); self.status.setStyleSheet("color:#9aa1ac;")

		bottom = QHBoxLayout()
		bottom.addWidget(self.btn_upload); bottom.addWidget(self.btn_download)
		bottom.addStretch(); bottom.addWidget(self.status)

		# ---------- Root layout ----------
		root = QVBoxLayout(self); root.setContentsMargins(10, 8, 10, 10); root.setSpacing(8)
		root.addLayout(toolbar); root.addWidget(self.path_edit); root.addWidget(self.table); root.addLayout(bottom)

		# ---------- Shortcuts ----------
		QShortcut(QKeySequence(Qt.Key_Backspace), self, activated=self.up)
		QShortcut(QKeySequence("Ctrl+L"), self, activated=lambda: self.path_edit.setFocus())
		QShortcut(QKeySequence("Ctrl+U"), self, activated=self.upload)
		QShortcut(QKeySequence("Ctrl+D"), self, activated=self.download)
		QShortcut(QKeySequence(Qt.Key_Return), self, activated=self._open_selection)

		# ---------- Wiring ----------
		self.btn_up.clicked.connect(self.up)
		self.btn_download.clicked.connect(self.download)
		self.btn_upload.clicked.connect(self.upload)

		# ---------- WS client ----------
		self.fws = FilesWSClient(self.api.base_url, self.api.token, self)

		# connect ALL signals BEFORE opening
		self.fws.connected.connect(self._on_files_ws_connected)
		self.fws.listed.connect(self._on_list)
		self.fws.dl_begin.connect(self._on_dl_begin)
		self.fws.dl_chunk.connect(self._on_dl_chunk)
		self.fws.dl_end.connect(self._on_dl_end)
		self.fws.up_progress.connect(lambda w, t: None)
		self.fws.up_result.connect(self._on_up_result)
		self.fws.error.connect(self._on_error)

		self.fws.open()

		# Overlay for HTTP/S “waiting for beacon”
		self.overlay = BusyOverlay(self, message="Waiting for HTTP/HTTPS beacon…")

		# Live update timer
		self._busy = False
		self._auto_timer = QTimer(self)
		self._auto_timer.setSingleShot(True)
		self._auto_timer.timeout.connect(self._auto_tick)

		# NEW: busy guard to recover if first request was dropped
		self._busy_guard = QTimer(self)
		self._busy_guard.setSingleShot(True)
		self._busy_guard.timeout.connect(self._busy_timed_out)

		self._apply_theme()
		self._rebuild_breadcrumbs()
		#self._kick_live(initial=True)

	# ---------- Styling ----------
	def _apply_theme(self):
		self.setStyleSheet(
			"""
			QWidget { background: #1f242b; color: #e9eaec; font-size: 13px; }
			QLineEdit { background:#151a20; border:1px solid #2c313a; border-radius:6px; padding:6px 8px; }
			QPushButton {
				background:#2c313a; color:#e9eaec; border:1px solid #3b404a;
				border-radius:6px; padding:6px 12px; font-weight:600;
			}
			QPushButton:hover { border-color:#5a6270; }
			QPushButton:pressed { background:#23272e; }
			QTableWidget {
				background:#151a20; alternate-background-color:#12171d;
				border:1px solid #2c313a; border-radius:8px;
			}
			QHeaderView::section {
				background:#20252d; color:#cfd3da; padding:6px 8px; border:0px; border-right:1px solid #2c313a;
			}
			QTableWidget::item:selected { background:#314156; }
			QToolButton { color:#cfd3da; border:1px solid #3b404a; border-radius:14px; padding:4px 10px; background:#262c35; }
			QToolButton:hover { border-color:#5a6270; }
			"""
		)

	# ----- Inital Refresh Missed Fix -----
	def _busy_timeout_ms(self) -> int:
		# generous: 2× beacon + 2s for HTTP/S; short for TCP
		if self.transport in ("http", "https"):
			base = int((self.beacon_interval or 5.0) * 1000)
			return base * 2 + 2000
		return 4000

	def _busy_timed_out(self):
		# we never got a reply; clear busy and try again right away
		self._busy = False
		self.overlay.setVisible(False)
		self.status.setText("Retrying…")
		self._kick_live(immediate=True) 

	def _on_files_ws_connected(self):
		# first list as soon as the socket is ready
		self._kick_live(immediate=True)

	# ---------- Breadcrumbs ----------
	def _rebuild_breadcrumbs(self):
		while self.crumbs.count():
			it = self.crumbs.takeAt(0); w = it.widget()
			if w: w.deleteLater()

		path = self.path or ""
		sep = _sep_for(self.path, self.os_type)
		parts = []
		if self.os_type == "windows":
			p = path.replace("/", "\\")
			if p.startswith("\\\\"):
				chunks = [c for c in p.split("\\") if c]
				if len(chunks) >= 2:
					base = "\\\\" + chunks[0] + "\\" + chunks[1]
					parts.append(base); parts.extend(chunks[2:])
				else:
					parts = [p]
			else:
				parts = [c for c in p.split("\\") if c]
				if path.startswith("\\") and parts and not parts[0].endswith(":"):
					parts.insert(0, "\\")
		else:
			if path.startswith("/"):
				parts = ["/"] + [p for p in path.split("/") if p][1:]
			else:
				parts = [p for p in path.split("/") if p]

		def _make_btn(label: str, jump_to: str):
			btn = QToolButton(self); btn.setText(label if label else sep); btn.setAutoRaise(True)
			btn.clicked.connect(lambda: self._jump(jump_to)); return btn

		acc = ""
		if self.os_type == "windows":
			if parts and parts[0].endswith(":"):
				acc = parts[0] + "\\"
				self.crumbs.addWidget(_make_btn(parts[0], acc)); parts = parts[1:]
		elif path.startswith("/"):
			acc = "/"; self.crumbs.addWidget(_make_btn("/", "/"))

		for chunk in parts:
			if not chunk: continue
			if acc in ("", "/"): acc = (acc + chunk) if acc != "/" else (acc + chunk)
			else: acc = acc + sep + chunk
			self.crumbs.addWidget(_make_btn(chunk or sep, acc))

	def _jump(self, new_path: str):
		if not new_path:
			return
		self._pending_path = self._norm_path(new_path)
		self.status.setText("Listing…")
		self._kick_live(immediate=True)


	# ---------- Live logic ----------
	def _compute_next_ms(self) -> int:
		if self.transport in ("http", "https"):
			base = int((self.beacon_interval or 5.0) * 1000)
			j = max(0, min(self.beacon_jitter_pct or 0, 95))
			if j:
				delta = int(base * j / 100.0)
				return max(750, base + random.randint(-delta, delta))
			return max(750, base)
		return 1000  # TCP

	def _kick_live(self, initial: bool = False, immediate: bool = False):
		self._auto_timer.stop()
		if immediate or initial:
			self.refresh()
		self._auto_timer.start(self._compute_next_ms())

	def _auto_tick(self):
		if not self._busy:
			self.refresh()
		self._auto_timer.start(self._compute_next_ms())

	# ---------- Core ops ----------
	def refresh(self):
		self._busy = True
		target = self._pending_path or self.path
		if self.transport in ("http", "https"):
			self.overlay.setMessage("Waiting for HTTP/HTTPS beacon…")
			self.overlay.showCentered()
		self.status.setText("Listing…")
		self.fws.list_dir(self.sid, target)
		self._busy_guard.start(self._busy_timeout_ms())

	def _fmt_label(self, name: str, is_dir: bool) -> str:
		# Linux shows trailing slash on folders; Windows does not
		return name + ("/" if is_dir and self.os_type != "windows" else "")

	def _entries_to_map(self, entries: list[dict]) -> dict[str, tuple[bool, int]]:
		m: dict[str, tuple[bool, int]] = {}
		for r in entries or []:
			name = str(r.get("name", ""))
			is_dir = bool(r.get("is_dir"))
			sz = 0 if is_dir else int(r.get("size") or 0)
			m[name] = (is_dir, sz)
		return m

	def _on_list(self, path: str, entries: list):
		self._busy = False
		self._busy_guard.stop()
		self.overlay.setVisible(False)

		# Prefer server-reported path; fall back to pending; otherwise keep current.
		new_path = self._norm_path(path or self._pending_path or self.path)
		path_changed = (new_path != self.path)

		# Commit the confirmed path and clear pending.
		self.path = new_path
		self._pending_path = None
		self.path_edit.setText(self.path)
		self._rebuild_breadcrumbs()

		# Build new snapshot
		new_map = self._entries_to_map(entries)

		# If nothing changed in content AND path didn't change, keep as-is.
		if not path_changed and new_map == self._last_listing:
			self.status.setText(f"Live • {len(new_map)} item(s)")
			return

		# Preserve UX state
		vbar = self.table.verticalScrollBar(); scroll_pos = vbar.value()
		header = self.table.horizontalHeader()
		sort_col = header.sortIndicatorSection(); sort_order = header.sortIndicatorOrder()
		selected_names = [self.table.item(i.row(), 0).text().rstrip("/") for i in self.table.selectionModel().selectedRows()]

		# Current rows index
		cur_rows: dict[str, int] = {}
		for r in range(self.table.rowCount()):
			nm = self.table.item(r, 0).text().rstrip("/")
			cur_rows[nm] = r

		# Diff
		old = self._last_listing
		old_names = set(old.keys()); new_names = set(new_map.keys())
		removed = sorted(list(old_names - new_names))
		added   = sorted(list(new_names - old_names))
		intersect = old_names & new_names
		changed = sorted([n for n in intersect if old[n] != new_map[n]])

		# Patch table
		self.table.setUpdatesEnabled(False)
		try:
			for row in sorted([cur_rows[n] for n in removed if n in cur_rows], reverse=True):
				self.table.removeRow(row)

			for name in changed:
				row = cur_rows.get(name)
				if row is None: continue
				is_dir, size = new_map[name]
				icon = self.icon_dir if is_dir else self.icon_file
				self.table.setItem(row, 0, NameItem(self._fmt_label(name, is_dir), is_dir, icon))
				self.table.setItem(row, 1, SizeItem("" if is_dir else str(size), size))

			for name in added:
				is_dir, size = new_map[name]
				row = self.table.rowCount(); self.table.insertRow(row)
				icon = self.icon_dir if is_dir else self.icon_file
				self.table.setItem(row, 0, NameItem(self._fmt_label(name, is_dir), is_dir, icon))
				self.table.setItem(row, 1, SizeItem("" if is_dir else str(size), size))

			self.table.sortItems(sort_col, sort_order)
			self.table.clearSelection()
			if selected_names:
				name_to_row = { self.table.item(r, 0).text().rstrip("/"): r for r in range(self.table.rowCount()) }
				for nm in selected_names:
					r = name_to_row.get(nm)
					if r is not None: self.table.selectRow(r)

			vbar.setValue(scroll_pos)
		finally:
			self.table.setUpdatesEnabled(True)

		self._last_listing = new_map
		self.status.setText(f"Live • {len(new_map)} item(s)")

	def up(self):
		p = (self.path or "").rstrip("/\\")
		if "\\" in p and (self.os_type == "windows" or ("\\" in self.path and "/" not in self.path)):
			idx = p.rfind("\\")
		else:
			idx = p.rfind("/")
		if idx <= 0:
			new_path = "/" if ("/" in self.path and self.os_type != "windows") else "C:\\"
		else:
			new_path = p[:idx]
		self._pending_path = self._norm_path(new_path)
		self.status.setText("Listing…")
		self._kick_live(immediate=True)

	def _open_selection(self):
		rows = self.table.selectionModel().selectedRows()
		if rows: self._dbl(self.table.item(rows[0].row(), 0))

	def _dbl(self, item):
		row = item.row()
		name = self.table.item(row, 0).text()
		base = name[:-1] if name.endswith("/") else name
		if isinstance(item, NameItem) and item.is_dir:
			self._pending_path = self._join_path(self.path, base)
			self.status.setText("Listing…")
			# force a fresh render on next reply
			self._last_listing = {}
			self._kick_live(immediate=True)
		else:
			self.download()

	# ----- Helpers -----
	def _norm_path(self, p: str) -> str:
		"""Normalize separators and roots per OS."""
		if self.os_type == "windows":
			p = (p or "").replace("/", "\\")
			# Collapse repeated backslashes after UNC prefix handling
			if p.startswith("\\\\"):
				head = "\\\\"
				rest = p[2:]
				while "\\\\" in rest:
					rest = rest.replace("\\\\", "\\")
				p = head + rest
			else:
				while "\\\\" in p:
					p = p.replace("\\\\", "\\")
			# "C:" -> "C:\"
			if len(p) == 2 and p[1] == ":":
				p += "\\"
			return p or "C:\\"
		else:
			p = (p or "").replace("\\", "/")
			while "//" in p:
				p = p.replace("//", "/")
			return p or "/"

	def _join_path(self, base: str, name: str) -> str:
		sep = _sep_for(base, self.os_type)
		base = self._norm_path(base)
		name = name.rstrip("/\\")
		if base.endswith(sep):
			return self._norm_path(base + name)
		return self._norm_path(base + sep + name)

	# ---------- Download / Upload ----------
	def download(self):
		rows = self.table.selectionModel().selectedRows()
		if not rows: return
		name = self.table.item(rows[0].row(), 0).text().rstrip("/")
		sep = _sep_for(self.path, self.os_type)
		remote = self.path + ("" if self.path.endswith(sep) else sep) + name
		self._save_path, _ = QFileDialog.getSaveFileName(self, "Save As", name)
		if not self._save_path: return
		try:
			self._save_fp = open(self._save_path, "wb")
		except Exception as e:
			QMessageBox.critical(self, "Download", str(e)); return
		self.status.setText("Downloading…")
		self.fws.start_download(self.sid, remote)

	def _on_dl_begin(self, tid: str, fname: str): pass
	def _on_dl_chunk(self, data: bytes):
		try:
			if hasattr(self, "_save_fp") and self._save_fp: self._save_fp.write(data)
		except Exception: pass

	def _on_dl_end(self, tid: str, status: str, error: str):
		try:
			if hasattr(self, "_save_fp") and self._save_fp:
				self._save_fp.flush(); self._save_fp.close()
		except Exception: pass
		if status != "done":
			QMessageBox.critical(self, "Download", f"{status}: {error or 'failed'}")
			try: os.remove(getattr(self, "_save_path", "")) 
			except Exception: pass
			self.status.setText("Download failed")
		else:
			QMessageBox.information(self, "Download", "Download complete.")
			self.status.setText("Download complete")

	def upload(self):
		local, _ = QFileDialog.getOpenFileName(self, "Upload File")
		if not local: return
		sep = _sep_for(self.path, self.os_type)
		remote = self.path + ("" if self.path.endswith(sep) else sep) + os.path.basename(local)
		self.status.setText("Uploading…")
		self.fws.start_upload(self.sid, local, remote)

	def _on_up_result(self, status: str, error: str):
		if status != "done":
			QMessageBox.critical(self, "Upload", f"{status}: {error or 'failed'}")
			self.status.setText("Upload failed")
		else:
			QMessageBox.information(self, "Upload", "Upload complete.")
			self.status.setText("Upload complete")

	# ---------- Errors / overlay ----------
	def _on_error(self, e: str):
		self._busy = False
		self._busy_guard.stop()
		self.overlay.setVisible(False)
		QMessageBox.critical(self, "Files", e)

	def resizeEvent(self, e):
		if self.overlay.isVisible(): self.overlay.showCentered()
		super().resizeEvent(e)
