# gui/session_console.py
import os
from pathlib import Path
from html import escape as _esc

from PyQt5.QtWidgets import QWidget, QPlainTextEdit, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout, QShortcut, QLabel, QFrame
from PyQt5.QtCore import QUrl, Qt, pyqtSignal, QPoint
from PyQt5.QtGui import QKeySequence
from PyQt5.QtNetwork import QAbstractSocket
from PyQt5.QtWebSockets import QWebSocket

class _ConsoleHistoryLineEdit(QLineEdit):
	"""QLineEdit with persistent history + readline keys (Ctrl+A / Ctrl+K)."""
	def __init__(self, history_path: str = None, parent=None):
		super().__init__(parent)
		self._hist: list[str] = []
		self._idx: int = 0
		self._before_browse: str = ""
		self._history_path = history_path
		self.setFocusPolicy(Qt.StrongFocus)
		self._load()

		# ---- Kill ring ----
		self._kill_buf: str = ""
		self._last_cmd_was_kill: bool = False

		# ---------- reverse-i-search state & UI ----------
		self._ris_active = False
		self._ris_query = ""
		self._ris_idx = -1
		self._ris_saved_text = ""
		# Floating tooltip-style popup (sits just under the line edit)
		self._ris_popup = QFrame(self.window(), Qt.ToolTip | Qt.FramelessWindowHint)
		self._ris_popup.setAttribute(Qt.WA_ShowWithoutActivating)
		self._ris_popup.setStyleSheet(
			"QFrame{background:#1f232b;color:#e6e6e6;border:1px solid #3b404a;border-radius:6px;}"
			"QLabel{padding:4px 6px;}"
		)
		self._ris_label = QLabel("", self._ris_popup)
		self._ris_popup.hide()
		# Shortcuts so Ctrl+R / Ctrl+S always work
		self._sc_r_prev = QShortcut(QKeySequence("Ctrl+R"), self)
		self._sc_r_prev.setContext(Qt.WidgetShortcut)
		self._sc_r_prev.activated.connect(lambda: (self._ris_start() if not self._ris_active else self._ris_step(-1)))
		self._sc_r_next = QShortcut(QKeySequence("Ctrl+S"), self)
		self._sc_r_next.setContext(Qt.WidgetShortcut)
		self._sc_r_next.activated.connect(lambda: (self._ris_start() if not self._ris_active else self._ris_step(+1)))

	# prevent Tab from changing focus (to match GunnerShell behavior)
	def focusNextPrevChild(self, next: bool) -> bool:  # type: ignore[override]
		return False

	# ---- persistence ----
	def _load(self):
		try:
			if self._history_path and os.path.exists(self._history_path):
				with open(self._history_path, "r", encoding="utf-8", errors="ignore") as f:
					self._hist = [ln.rstrip("\n") for ln in f if ln.strip()]
			self._idx = len(self._hist)
		except Exception:
			pass

	def _flush(self):
		try:
			if not self._history_path:
				return
			Path(self._history_path).parent.mkdir(parents=True, exist_ok=True)
			with open(self._history_path, "w", encoding="utf-8") as f:
				f.write("\n".join(self._hist) + ("\n" if self._hist else ""))
		except Exception:
			pass

	def remember(self, cmd: str):
		if not cmd:
			return
		if self._hist and self._hist[-1] == cmd:
			self._idx = len(self._hist)
			return
		self._hist.append(cmd)
		if len(self._hist) > 500:
			self._hist = self._hist[-500:]
		self._idx = len(self._hist)
		self._flush()

	# ---------- helpers: kill ring ----------
	def _kill_range(self, a: int, b: int):
		"""Remove [a:b] and push to kill ring. Keep adjacent kills coalesced."""
		if a > b:
			a, b = b, a
		s = self.text()
		killed = s[a:b]
		if not killed:
			self._last_cmd_was_kill = False
			return
		if self._last_cmd_was_kill:
			self._kill_buf += killed
		else:
			self._kill_buf = killed
		self.setText(s[:a] + s[b:])
		self.setCursorPosition(a)
		self._last_cmd_was_kill = True

	def _word_left(self, pos: int) -> int:
		s = self.text()
		i = max(0, pos)
		while i > 0 and s[i-1].isspace():
			i -= 1
		while i > 0 and not s[i-1].isspace():
			i -= 1
		return i

	def _word_right(self, pos: int) -> int:
		s = self.text()
		n = len(s)
		i = min(n, pos)
		while i < n and s[i].isspace():
			i += 1
		while i < n and not s[i].isspace():
			i += 1
		return i

	# ---------- helpers: prefix navigation ----------
	def _hist_seek_prev_with_prefix(self, prefix: str, start_idx: int) -> int:
		for i in range(min(start_idx, len(self._hist)) - 1, -1, -1):
			if self._hist[i].startswith(prefix):
				return i
		return -1

	def _hist_seek_next_with_prefix(self, prefix: str, start_idx: int) -> int:
		for i in range(max(0, start_idx + 1), len(self._hist)):
			if self._hist[i].startswith(prefix):
				return i
		return -1

	# ---------- helpers: reverse-i-search ----------
	@staticmethod
	def _subseq_score(query: str, s: str) -> int:
		"""Light fuzzy: prefer substring, else subsequence; higher is better."""
		q = query.lower(); t = s.lower()
		if not q:
			return 1  # empty query matches everything so Ctrl+R/S can step
		if q in t:
			return 1000 - t.index(q) - (len(t) - len(q))
		it = iter(t)
		ok = all(ch in it for ch in q)
		return 100 if ok else -1

	def _ris_recompute(self, direction: int = -1):
		"""Recompute current match; direction -1=backward, +1=forward."""
		if not self._hist:
			self._ris_idx = -1
			self._ris_update_popup()
			return
		i = self._ris_idx if self._ris_idx >= 0 else len(self._hist)
		best = (-1, -1)  # (score, index)
		rng = range(i - 1, -1, -1) if direction < 0 else range(i + 1, len(self._hist), 1)
		for k in rng:
			sc = self._subseq_score(self._ris_query, self._hist[k])
			if sc > best[0]:
				best = (sc, k)
				if sc >= 900:
					break
		self._ris_idx = best[1]
		self._ris_update_popup()

	def _ris_update_popup(self):
		if not self._ris_active:
			self._ris_popup.hide()
			return
		idx_ok = 0 <= self._ris_idx < len(self._hist)
		match_txt = (self._hist[self._ris_idx] if idx_ok
					 else ("no history" if not self._hist else "no match"))
		self._ris_label.setText(f"reverse-i-search: “{_esc(self._ris_query)}”  →  {_esc(match_txt)}")
		self._ris_label.adjustSize()
		w = self._ris_label.sizeHint().width() + 12
		h = self._ris_label.sizeHint().height() + 8
		self._ris_popup.resize(w, h)
		base = self.mapToGlobal(QPoint(0, self.height()))
		self._ris_popup.move(base + QPoint(6, 6))
		self._ris_popup.show()

	def _ris_start(self):
		self._ris_active = True
		self._ris_saved_text = self.text()
		self._ris_query = ""
		self._ris_idx = -1
		self._ris_update_popup()

	def _ris_accept(self):
		if 0 <= self._ris_idx < len(self._hist):
			self.setText(self._hist[self._ris_idx])
			self.setCursorPosition(len(self.text()))
		self._ris_cancel(hide_only=True)

	def _ris_step(self, delta: int):
		if not self._ris_active:
			return
		self._ris_recompute(+1 if delta > 0 else -1)

	def _ris_cancel(self, hide_only: bool = False):
		if not hide_only:
			self.setText(self._ris_saved_text)
			self.setCursorPosition(len(self.text()))
		self._ris_active = False
		self._ris_popup.hide()

	def resizeEvent(self, ev):
		super().resizeEvent(ev)
		if self._ris_active:
			self._ris_update_popup()

	# ---- keys ----
	def keyPressEvent(self, e):
		# keep Tab from moving focus
		if e.key() in (Qt.Key_Tab, Qt.Key_Backtab):
			e.accept()
			return

		# ESC quickly cancels reverse-i-search
		if self._ris_active and e.key() == Qt.Key_Escape:
			self._ris_cancel(); e.accept(); return

		# ===== reverse-i-search active =====
		if self._ris_active:
			if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_R:
				self._ris_recompute(-1); e.accept(); return
			if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_S:
				self._ris_recompute(+1); e.accept(); return
			if e.key() in (Qt.Key_Return, Qt.Key_Enter):
				self._ris_accept(); e.accept(); return
			if e.key() in (Qt.Key_Backspace,):
				self._ris_query = self._ris_query[:-1]
				self._ris_idx = len(self._hist)
				self._ris_recompute(-1); e.accept(); return
			txt = e.text()
			if txt and not (e.modifiers() & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier)):
				self._ris_query += txt
				self._ris_idx = len(self._hist)
				self._ris_recompute(-1); e.accept(); return
			e.accept(); return  # swallow everything else while active

		# start reverse-i-search
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_R:
			self._ris_start(); e.accept(); return

		# Ctrl+A: start of line
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_A:
			self.setCursorPosition(0)
			e.accept()
			return

		# Ctrl+K: kill to end of line
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_K:
			cp = self.cursorPosition()
			self._kill_range(cp, len(self.text()))
			e.accept(); return

		# Ctrl+U: kill to start
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_U:
			cp = self.cursorPosition()
			self._kill_range(0, cp)
			e.accept(); return

		# Ctrl+W: kill previous word
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_W:
			cp = self.cursorPosition()
			self._kill_range(self._word_left(cp), cp)
			e.accept(); return

		# Alt+D: kill next word
		if (e.modifiers() & Qt.AltModifier) and e.key() == Qt.Key_D:
			cp = self.cursorPosition()
			self._kill_range(cp, self._word_right(cp))
			e.accept(); return

		# Ctrl+Y: yank last kill
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_Y:
			if self._kill_buf:
				cp = self.cursorPosition()
				s = self.text()
				self.setText(s[:cp] + self._kill_buf + s[cp:])
				self.setCursorPosition(cp + len(self._kill_buf))
			self._last_cmd_was_kill = False
			e.accept(); return

		# any non-kill key cancels coalescing
		self._last_cmd_was_kill = False

		# Up/Down: browse history
		if e.key() == Qt.Key_Up:
			if self._hist:
				cpfx = self.text()[:self.cursorPosition()]
				if cpfx:  # prefix mode
					if self._idx == len(self._hist):
						self._before_browse = self.text()
					j = self._hist_seek_prev_with_prefix(
						cpfx,
						self._idx if self._idx <= len(self._hist) else len(self._hist)
					)
					if j >= 0:
						self._idx = j
						self.setText(self._hist[self._idx])
						self.setCursorPosition(len(self.text()))
						return
				# fallback to classic behavior
				if self._idx > 0:
					if self._idx == len(self._hist):
						self._before_browse = self.text()
					self._idx -= 1
					self.setText(self._hist[self._idx])
					self.setCursorPosition(len(self.text()))
					return
		elif e.key() == Qt.Key_Down:
			if self._hist:
				cpfx = self.text()[:self.cursorPosition()]
				if cpfx:  # prefix mode
					j = self._hist_seek_next_with_prefix(
						cpfx,
						self._idx if self._idx < len(self._hist) else len(self._hist) - 1
					)
					if j >= 0:
						self._idx = j
						self.setText(self._hist[self._idx])
						self.setCursorPosition(len(self.text()))
						return
				# fallback to classic behavior
				if self._idx < len(self._hist) - 1:
					self._idx += 1
					self.setText(self._hist[self._idx])
					self.setCursorPosition(len(self.text()))
					return
				elif self._idx == len(self._hist) - 1:
					self._idx = len(self._hist)
					self.setText(self._before_browse)
					self.setCursorPosition(len(self.text()))
					return

		super().keyPressEvent(e)

class SessionConsole(QWidget):
	files_requested = pyqtSignal(str, str)  # sid, hostname

	def __init__(self, api, sid: str, hostname: str):
		super().__init__()
		self.api = api; self.sid = sid
		self.sid = sid
		self.hostname = hostname

		self.out = QPlainTextEdit(); self.out.setReadOnly(True)
		
		# --- history-enabled input (separate file from GunnerShell) ---
		hist_path = str(Path.home() / f".gunnerc2_sc_{sid}_history")
		self.inp = _ConsoleHistoryLineEdit(history_path=hist_path)

		self.btn_send = QPushButton("Send")

		# --- make the command bar a bit taller ---
		CMD_H = 36  # tweak to taste (34–40 looks good)
		fm = self.inp.fontMetrics()
		CMD_H = max(CMD_H, fm.height() + 14)   # keep comfortable vertical padding
		self.inp.setMinimumHeight(CMD_H)
		self.inp.setStyleSheet("QLineEdit { padding: 6px 10px; }")
		self.btn_send.setMinimumHeight(CMD_H)
		# if the button shows an icon, keep it proportional
		try:
			self.btn_send.setIconSize(QSize(CMD_H - 12, CMD_H - 12))
		except Exception:
			pass

		self.btn_files = QPushButton("Files")

		t = QHBoxLayout(); t.addWidget(self.btn_files); t.addStretch()
		layout = QVBoxLayout(); layout.addLayout(t); layout.addWidget(self.out)
		bottom = QHBoxLayout(); bottom.addWidget(self.inp); bottom.addWidget(self.btn_send)
		layout.addLayout(bottom); self.setLayout(layout)

		self.btn_send.clicked.connect(self._send)
		self.inp.returnPressed.connect(self._send)
		self.btn_files.clicked.connect(self._on_files_clicked)

		# Ctrl+L to clear the screen (works even when the input has focus)
		self._sc_clear = QShortcut(QKeySequence("Ctrl+L"), self)
		self._sc_clear.setContext(Qt.WidgetWithChildrenShortcut)
		self._sc_clear.activated.connect(self._clear_screen)

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

		self.ws.textMessageReceived.connect(self._on_msg)
		#self.ws.errorOccurred.connect(lambda _: self.out.appendPlainText("[websocket error]"))
		self.ws.open(QUrl(ws_url))

	def _send(self):
		cmd = self.inp.text().strip()
		if not cmd: return
		self.out.appendPlainText(f">>> {cmd}")
		self.inp.remember(cmd)
		self.ws.sendTextMessage(cmd)
		self.inp.clear()

	def _clear_screen(self):
		self.out.clear()

	def _on_msg(self, m: str):
		if m == "\x00CLEAR\x00":
			self._clear_screen()
		else:
			self.out.appendPlainText(m)

	# Files now handled by Dashboard (opens a tab)
	def _on_files_clicked(self):
		self.files_requested.emit(self.sid, self.hostname)
