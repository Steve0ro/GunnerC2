# gui/dashboard.py
from PyQt5.QtCore import Qt, QSettings, QByteArray, QTimer
from PyQt5.QtWidgets import (
	QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTabWidget, QSplitter, QMessageBox, QApplication, QSizePolicy
)

from session_graph import SessionGraph
from sessions_tab import SessionsTab
from listeners_tab import ListenersTab
from payloads_tab import PayloadsTab
from operators_tab import OperatorsTab
from session_console import SessionConsole
from gunnershell_console import GunnershellConsole

try:
	# same import pattern you used elsewhere
	from .websocket_client import SessionsWSClient
except Exception:
	from websocket_client import SessionsWSClient

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

		# ---------- Sessions WS (shared, for lookups) ----------
		self.sessions_ws = SessionsWSClient(self.api)
		self.sessions_ws.error.connect(lambda e: print("[ws] sessions:", e))
		self.sessions_ws.open()
		# (client maintains its own cache via snapshots)

		# ---------- Bottom tab browser ----------
		self.tabs = QTabWidget()
		self.tabs.setTabsClosable(True)
		self.tabs.setMovable(True)
		self.tabs.tabCloseRequested.connect(self._close_tab)

		# Use a vertical splitter so users can resize graph vs. tabs freely
		self.split = QSplitter(Qt.Vertical)
		self.split.setHandleWidth(8)
		self.split.setOpaqueResize(True)
		current = self.tabs.currentWidget()
		is_heavy = isinstance(current, PayloadsTab)

		if is_heavy:
			self.split.setChildrenCollapsible(False)
			# Let both panes shrink to 0 but still respect child minimums
			for w in (self.graph, self.tabs):
				w.setMinimumHeight(0)
				sp = w.sizePolicy()
				sp.setHorizontalPolicy(QSizePolicy.Expanding)
				# DO NOT use Ignored here for Payloads pages; keep MinimumExpanding
				sp.setVerticalPolicy(QSizePolicy.MinimumExpanding)
				w.setSizePolicy(sp)
		else:
			self.split.setChildrenCollapsible(True)

			# Let both panes shrink to 0 to avoid minimum-size blocking
			for w in (self.graph, self.tabs):
				w.setMinimumSize(0, 0)
				w.setMinimumHeight(0)
				sp = w.sizePolicy()
				# IMPORTANT: ignore vertical size hints so splitter can move freely
				sp.setVerticalPolicy(QSizePolicy.Ignored)
				w.setSizePolicy(sp)


		self.split.addWidget(self.graph)
		self.split.addWidget(self.tabs)

		# Track pre-payload sizes and pause-saving flag
		self._pre_payload_sizes = None
		self._suspend_split_save = False
		self._split_locked = False

		# Now that splitter exists, hook the signal and apply mode
		self.tabs.currentChanged.connect(self._apply_splitter_mode)
		self._apply_splitter_mode()

		# Make panes explicitly collapsible
		try:
			self.split.setCollapsible(0, True)
			self.split.setCollapsible(1, True)
		except Exception:
			pass

		# Persist splitter position
		self._settings = QSettings("GunnerC2", "Console")
		state = self._settings.value("dashboard/splitter_state", None)
		if state is not None:
			try:
				ba = state if isinstance(state, QByteArray) else QByteArray(state)
				self.split.restoreState(ba)
			except Exception:
				# fallback if stored state is incompatible
				self.split.setSizes([600, 260])
		else:
			self.split.setSizes([600, 260])

		# Ensure we do not start collapsed at the top/bottom
		QTimer.singleShot(0, self._normalize_initial_splitter)

		# Debounced save on move (prevents stutter while dragging)
		self._split_save_timer = QTimer(self)
		self._split_save_timer.setSingleShot(True)
		self._split_save_timer.setInterval(350)
		self._split_save_timer.timeout.connect(self._save_splitter_state)
		self.split.splitterMoved.connect(lambda *_: self._split_save_timer.start())

		# ---------- Layout ----------
		root = QVBoxLayout(self)
		root.setContentsMargins(0, 0, 0, 0)
		root.addLayout(buttons)
		root.addWidget(self.split)

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

	def _toggle_handle_appearance(self, hidden: bool):
		"""Hide/show the splitter grip dots and handle width."""
		try:
			if hidden:
				# remember the previous width once
				if not hasattr(self, "_prev_handle_width"):
					self._prev_handle_width = self.split.handleWidth()
				# fully hide grip dots & bar visuals
				self.split.setHandleWidth(0)
				self.split.setStyleSheet("QSplitter::handle { image: none; background: transparent; }")
			else:
				# restore visuals
				self.split.setStyleSheet("")
				self.split.setHandleWidth(getattr(self, "_prev_handle_width", 8))
		except Exception:
			pass


	def _normalize_initial_splitter(self):
		"""
		After the window shows, ensure we start with a reasonable split.
		If either pane is ~collapsed, restore to a 70/30 layout.
		"""
		try:
			sizes = self.split.sizes()
			if not sizes:
				return	
			if min(sizes) < 80:  # effectively collapsed
				h = max(self.height(), 600)
				self.split.setSizes([int(h * 0.70), int(h * 0.30)])
		except Exception:
			pass

	# NEW: lock/unlock the vertical splitter (prevents user dragging)
	def _set_splitter_locked(self, locked: bool):
		self._split_locked = bool(locked)
		try:
			# For a vertical QSplitter, there is one handle between its two widgets (index 1)
			for i in range(1, self.split.count()):
				h = self.split.handle(i)
				if h:
					h.setDisabled(locked)  # blocks mouse events & double-click collapse
					# nice cursor feedback
					h.setCursor(Qt.ArrowCursor if locked
								else (Qt.SplitVCursor if self.split.orientation() == Qt.Vertical
									  else Qt.SplitHCursor))
			self._toggle_handle_appearance(locked)

		except Exception:
			pass


	def _save_splitter_state(self):
		"""Don’t persist the temporary ‘payloads maximized’ layout."""
		if self._suspend_split_save:
			return
		self._settings.setValue("dashboard/splitter_state", self.split.saveState())

	def _apply_splitter_mode(self, *_):
		"""
		Rubber-band resize on heavy tab; auto-maximize tabs for Payloads,
		RESTORE sizes when leaving, and LOCK the splitter while on Payloads.
		"""
		w = self.tabs.currentWidget()
		is_payloads = isinstance(w, PayloadsTab)

		# smoother dragging elsewhere
		self.split.setOpaqueResize(not is_payloads)

		if is_payloads:
			# remember sizes once
			if self._pre_payload_sizes is None:
				self._pre_payload_sizes = self.split.sizes() or [self.height() - 280, 280]

			# maximize bottom, collapse top
			total = sum(self.split.sizes()) or max(1, self.split.height())
			self._suspend_split_save = True
			self.split.setSizes([0, max(1, total)])  # tabs fill window
			QTimer.singleShot(0, lambda: setattr(self, "_suspend_split_save", False))

			# LOCK: user cannot move the bar while in Payloads
			self._set_splitter_locked(True)

		else:
			# leaving Payloads → restore sizes and UNLOCK
			if self._pre_payload_sizes:
				self._suspend_split_save = True
				self.split.setSizes(self._pre_payload_sizes)
				self._pre_payload_sizes = None
				QTimer.singleShot(0, lambda: setattr(self, "_suspend_split_save", False))

			self._set_splitter_locked(False)

	# ---------- Helpers: open/focus singleton tabs ----------
	def _ensure_tab(self, attr_name: str, widget_factory, title: str):
		w = getattr(self, attr_name)
		if w is None:
			w = widget_factory()
			idx = self.tabs.addTab(w, title)
			# Give every admin tab the app icon for a polished look
			self.tabs.setTabIcon(idx, QApplication.windowIcon())
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
			t.gunnershell_requested.connect(self._open_gunnershell_tab)
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
		"""
		Kill a session using the realtime WS API only.
		"""
		# Find/reuse the SessionsWSClient from the graph
		ws = getattr(self, "sessions_ws", None)
		if ws is None:
			ws = getattr(self.graph, "sessions_ws", None)
			if ws is not None:
				self.sessions_ws = ws  # cache for next time

		if not ws:
			print("[dashboard] kill_session: sessions WS not ready")
			return

		def _done(msg: dict):
			t = str(msg.get("type", "")).lower()
			if t == "killed":
				# Only refresh after a confirmed kill
				try:
					if self._tab_sessions:
						self._tab_sessions.reload()
				except Exception:
					pass
				try:
					self.graph.reload()
				except Exception:
					pass
			else:
				err = msg.get("error") or "unknown error"
				print(f"[dashboard] kill_session failed: {err}")

		try:
			ws.kill(sid, _done)
		except Exception as e:
			print(f"[dashboard] kill_session send failed: {e}")

	# ---------- Console tabs ----------
	def _open_console_tab(self, sid: str, hostname: str):
		# Build "username@hostname" using WS cache only (no REST)
		ws = getattr(self, "sessions_ws", None)
		s = ws.get_cached(sid) if ws else {}
		username = (s.get("user") or s.get("username")
					or (s.get("metadata") or {}).get("user") or "")

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
		idx = self.tabs.addTab(w, title)
		self.tabs.setTabIcon(idx, QApplication.windowIcon())
		self.tabs.setCurrentIndex(idx)

		# If we didn’t have username yet, fetch it via WS and rename the tab once received
		if not username and ws:
			def _cb(msg):
				s2 = msg.get("session") or {}
				u2 = (s2.get("user") or s2.get("username")
					  or (s2.get("metadata") or {}).get("user") or "")
				if not u2:
					return
				new_title = f"{_strip_host_prefix(u2, hostname)}@{hostname}"
				j = self.tabs.indexOf(w)
				if j >= 0:
					self.tabs.setTabText(j, new_title)
			ws.get(sid, cb=_cb)

	def _open_gunnershell_tab(self, sid: str, hostname: str):
		# Prefer cached WS snapshot; if missing, ask WS 'get' and open on reply
		sess = self.sessions_ws.get_cached(sid) or {}

		if not sess:
			# one-shot fetch; open once we have it
			def _cb(msg):
				s = msg.get("session") or {}
				self._try_open_gs_from_session(sid, hostname, s)
			self.sessions_ws.get(sid, cb=_cb)
			return
		# have it already
		self._try_open_gs_from_session(sid, hostname, sess)

	
	def _try_open_gs_from_session(self, sid: str, hostname: str, sess: dict):
		# Block until metadata is present
		if not self._is_meta_ready(sess):
			QMessageBox.information(self, "Please wait",
									"You must wait for metadata to complete before launching GunnerShell.\n"
									"Try again in a few seconds.")
			return
		# Optional: also require command mode like the CLI does
		mode = str(sess.get("mode") or (sess.get("metadata") or {}).get("mode") or "")
		if mode and mode.lower() != "cmd":
			QMessageBox.information(self, "Agent not ready",
									"The agent hasn't switched to command mode yet. Try again shortly.")
			return

		# Build tab title and open
		username = (sess.get("user") or sess.get("username") or (sess.get("metadata") or {}).get("user") or "")
		title = f"GS — { _strip_host_prefix(username, hostname) }@{hostname}" if username else f"GS — {hostname}"

		for i in range(self.tabs.count()):
			if self.tabs.tabText(i) == title:
				self.tabs.setCurrentIndex(i)
				return

		w = GunnershellConsole(self.api, sid, hostname)
		idx = self.tabs.addTab(w, title)
		self.tabs.setTabIcon(idx, QApplication.windowIcon())
		self.tabs.setCurrentIndex(idx)

	# In-Class Helpers

	def _is_meta_ready(self, sess: dict) -> bool:
		# Accept both top-level or nested "metadata" layouts
		meta = (sess.get("metadata") or sess) if isinstance(sess, dict) else {}
		os_str = str(meta.get("os") or "").lower()
		hostname = meta.get("hostname") or sess.get("hostname")
		user = meta.get("user") or sess.get("user") or sess.get("username")
		return bool(hostname and user and os_str in ("windows", "linux"))
	
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
