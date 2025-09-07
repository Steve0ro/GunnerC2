# gui/gunnershell_console.py
import os
from pathlib import Path
from html import escape as _esc

from PyQt5.QtWidgets import (
	QWidget, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout, QShortcut,
	QLabel, QFrame
)
from PyQt5.QtNetwork import QAbstractSocket
from PyQt5.QtWebSockets import QWebSocket
from PyQt5.QtCore import QUrl, Qt, QPoint
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
		parts.append("text-shadow: 0 0 6px currentColor")
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
			if code == 38 and j+4 < len(toks) and toks[j+1] == 2:
				state["fg"] = _rgb(toks[j+2], toks[j+3], toks[j+4]); j += 5; continue
			if code == 48 and j+4 < len(toks) and toks[j+1] == 2:
				state["bg"] = _rgb(toks[j+2], toks[j+3], toks[j+4]); j += 5; continue
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

# =================== Built-in Commands ===================

COMMANDS = {
	# Core
	"help","exit","list","gunnerid","banner","sessions","switch","shell",
	"modhelp","run","search","bofexec",
	# File system
	"ls","cat","type","cd","pwd","cp","mv","rmdir","checksum","upload","download",
	"del","rm","mkdir","md","touch","drives","edit",
	# Network
	"netstat","ifconfig","portscan","portfwd","arp","hostname","socks","resolve","nslookup",
	"route","getproxy","ipconfig",
	# System
	"sysinfo","ps","getuid","whoami","getprivs","groups","getav","defenderoff","amsioff",
	"getpid","getenv","exec","kill","getsid","clearev","localtime","reboot","pgrep","pkill",
	"suspend","resume","shutdown","reg","services","netusers","netgroups","steal_token",
	# UI
	"screenshot",
	# Lateral movement
	"winrm","netexec","nxc","rpcexec","wmiexec",
	# AD
	"getusers","getgroups","getcomputers","getdomaincontrollers","getous","getdcs","getgpos",
	"getdomain","gettrusts","getforests","getfsmo","getpwpolicy","getdelegation","getadmins",
	"getspns","kerbrute",
	# AD ACL
	"enumacls","dcsyncenum","enumrbcd","enumgmsa",
	# Kerberos
	"klist","asktgt","asreproast",
	# Token & Identity
	"getintegrity","getuac","tokenprivs",
	# Persistence
	"adduser","enablerdp",
	# Evasion
	"getexclusions","getsecurity","driversigs","getsysmon","dumpsysmonconfig","killsysmon",
	"checkdebuggers",
}

# =================== BOF names (for `bofexec <TAB>`) ===================

BOF_NAMES = {
	# Situational Awareness
	"dir","env","getpwpolicy","useridletime","getsessinfo","listmods","netlocalgroup",
	"netloggedon","nettime","netuptime","netuser","netuserenum","whoami","tasklist","cacls",
	"enumdrives","enumdotnet","sc_enum","schtasksenum","schtasksquery","getrecentfiles",
	"enumlocalsessions",
	# System Information
	"winver","locale","dotnetversion","listinstalled","getkernaldrivers","hotfixenum",
	"resources","getgpu","getcpu","getbios",
	# Networking
	"arp","ipconfig","probe","listfwrules","listdns","netstat","openports","routeprint",
	"netview","netshares",
	# PrivEsc
	"noquotesvc","checkautoruns","hijackpath","enumcreds","enumautologons","checkelevated",
	# Credential Dumping
	"hivesave","hashdump","nanodump","credman","wifidump","dumpclip","dumpntlm","notepad",
	"autologon",
	# Active Directory
	"ldapsearch","domaininfo","adadmins","adusers","adgroups","adcomputers","adtrusts",
	"adous","adgpos","adspns","addns","addelegations","adpasswords","adstaleusers",
	"adcs_enum","adcs_enum_com","adcs_enum_com2",
	# AD ACL Enumeration
	"enumacls","dcsyncenum","enumrbcd","enumgmsa",
	# Kerberos Exploitation
	"klist","asktgt","asreproast",
	# Token & Identity
	"getintegrity","getuac","tokenprivs",
	# Persistence
	"adduser","enablerdp",
	# Evasion
	"getexclusions","getsecurity","driversigs","getsysmon","dumpsysmonconfig",
	"killsysmon","checkdebuggers",
}

# --- Command History (unchanged behavior) ------------------------------------

class HistoryLineEdit(QLineEdit):
	def __init__(self, history_path: str = None, parent=None):
		super().__init__(parent)
		self._hist: list[str] = []
		self._idx: int = 0
		self._before_browse: str = ""
		self._history_path = history_path
		self._complete_cb = None
		self._cycle_state = None
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
		# Floating tooltip-style popup (NOT a child of the line edit, so it can sit below it)
		self._ris_popup = QFrame(self.window(), Qt.ToolTip | Qt.FramelessWindowHint)
		self._ris_popup.setAttribute(Qt.WA_ShowWithoutActivating)
		self._ris_popup.setStyleSheet(
			"QFrame{background:#1f232b;color:#e6e6e6;border:1px solid #3b404a;border-radius:6px;}"
			"QLabel{padding:4px 6px;}"
		)
		self._ris_label = QLabel("", self._ris_popup)
		self._ris_popup.hide()
		# Shortcuts (so Ctrl+R / Ctrl+S always work even if keyPressEvent is bypassed)
		self._sc_r_prev = QShortcut(QKeySequence("Ctrl+R"), self)
		self._sc_r_prev.setContext(Qt.WidgetShortcut)
		self._sc_r_prev.activated.connect(lambda: (self._ris_start() if not self._ris_active else self._ris_step(-1)))
		self._sc_r_next = QShortcut(QKeySequence("Ctrl+S"), self)
		self._sc_r_next.setContext(Qt.WidgetShortcut)
		self._sc_r_next.activated.connect(lambda: (self._ris_start() if not self._ris_active else self._ris_step(+1)))

	# prevent Qt from using Tab to change focus as a fallback path
	def focusNextPrevChild(self, next: bool) -> bool:  # type: ignore[override]
		return False

	def remember(self, cmd: str):
		self._save(cmd)

	def set_complete_callback(self, fn):
		self._complete_cb = fn

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

	def _save(self, cmd: str):
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
		# coalesce if previous action was also a kill
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
		# skip spaces
		while i > 0 and s[i-1].isspace():
			i -= 1
		# go to start of word
		while i > 0 and not s[i-1].isspace():
			i -= 1
		return i

	def _word_right(self, pos: int) -> int:
		s = self.text()
		n = len(s)
		i = min(n, pos)
		# skip spaces
		while i < n and s[i].isspace():
			i += 1
		# go to end of word
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
		"""Very light fuzzy: prefer substring, else subsequence; higher is better."""
		q = query.lower(); t = s.lower()
		if not q:
			# empty query matches everything so Ctrl+R/S can step immediately
			return 1
		if q in t:
			# tighter (earlier/shorter) gets a slightly higher score
			return 1000 - t.index(q) - (len(t) - len(q))
		# crude subsequence check
		it = iter(t)
		ok = all(ch in it for ch in q)
		return 100 if ok else -1

	def _ris_recompute(self, direction: int = -1):
		"""Recompute current match; direction -1=backward, +1=forward."""
		if not self._hist:
			self._ris_idx = -1
			return
		# starting point (exclusive)
		i = self._ris_idx if self._ris_idx >= 0 else len(self._hist)
		best = (-1, -1)  # (score, index)
		rng = (
			range(i - 1, -1, -1) if direction < 0 else
			range(i + 1, len(self._hist), 1)
		)
		for k in rng:
			sc = self._subseq_score(self._ris_query, self._hist[k])
			if sc > best[0]:
				best = (sc, k)
				# perfect substring early -> stop at first best
				if sc >= 900:
					break
		self._ris_idx = best[1]
		self._ris_update_popup()

	def _ris_update_popup(self):
		if not self._ris_active:
			self._ris_popup.hide()
			return
		hint = "reverse-i-search"
		idx_ok = 0 <= self._ris_idx < len(self._hist)
		match_txt = (self._hist[self._ris_idx] if idx_ok
					 else ("no history" if not self._hist else "no match"))
		from html import escape as _esc
		self._ris_label.setText(f"{hint}: “{_esc(self._ris_query)}”  →  {_esc(match_txt)}")
		self._ris_label.adjustSize()
		w = self._ris_label.sizeHint().width() + 12
		h = self._ris_label.sizeHint().height() + 8
		self._ris_popup.resize(w, h)
		# position just under the line edit in GLOBAL coords
		base = self.mapToGlobal(QPoint(0, self.height()))
		self._ris_popup.move(base + QPoint(6, 6))
		self._ris_popup.show()

	def _ris_start(self):
		self._ris_active = True
		self._ris_saved_text = self.text()
		self._ris_query = ""
		# no selection yet; first Ctrl+R/S or a typed char will pick one
		self._ris_idx = -1
		self._ris_update_popup()

	def _ris_accept(self):
		if self._ris_idx >= 0:
			self.setText(self._hist[self._ris_idx])
			self.setCursorPosition(len(self.text()))
		self._ris_cancel(hide_only=True)

	def _ris_step(self, delta: int):
		"""
		Step through reverse-i-search matches.
		delta > 0 → next match (Ctrl+S), delta < 0 → previous match (Ctrl+R).
		Safe no-op if reverse-i-search isn't active.
		"""
		if not getattr(self, "_ris_active", False):
			return
		# _ris_recompute handles bounds and popup refresh
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

	# ---------- main key handling ----------
	def keyPressEvent(self, e):
		# ESC cancels reverse-i-search quickly
		if self._ris_active and e.key() == Qt.Key_Escape:
			self._ris_cancel(); e.accept(); return

		# Completion still first
		if e.key() in (Qt.Key_Tab, Qt.Key_Backtab):
			if self._complete_cb:
				reverse = (e.key() == Qt.Key_Backtab)
				new_text, new_pos, self._cycle_state = self._complete_cb(
					self.text(), self.cursorPosition(), reverse, self._cycle_state
				)
				if new_text is not None:
					self.setText(new_text)
					if new_pos is not None:
						self.setCursorPosition(new_pos)
			e.accept()
			return
		else:
			self._cycle_state = None

		# ===== reverse-i-search mode =====
		if self._ris_active:
			# navigation within search
			if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_R:
				self._ris_recompute(-1); e.accept(); return
			if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_S:
				self._ris_recompute(+1); e.accept(); return
			if e.key() in (Qt.Key_Return, Qt.Key_Enter):
				self._ris_accept(); e.accept(); return
			if e.key() == Qt.Key_Escape:
				self._ris_cancel(); e.accept(); return
			if e.key() in (Qt.Key_Backspace, ):
				self._ris_query = self._ris_query[:-1]
				self._ris_idx = len(self._hist)
				self._ris_recompute(-1); e.accept(); return
			# add literal characters to the query
			txt = e.text()
			if txt and not (e.modifiers() & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier)):
				self._ris_query += txt
				self._ris_idx = len(self._hist)
				self._ris_recompute(-1); e.accept(); return
			# swallow everything else while active
			e.accept(); return

		# start reverse-i-search
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_R:
			self._ris_start(); e.accept(); return

		# ---- Readline / kill-ring shortcuts ----
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_A:
			# Move cursor to the start of the line (no selection)
			self.setCursorPosition(0)
			e.accept()
			return

		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_K:
			# kill to end
			cp = self.cursorPosition()
			self._kill_range(cp, len(self.text()))
			e.accept(); return

		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_U:
			# kill to start
			cp = self.cursorPosition()
			self._kill_range(0, cp)
			e.accept(); return

		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_W:
			# kill previous word
			cp = self.cursorPosition()
			self._kill_range(self._word_left(cp), cp)
			e.accept(); return

		if (e.modifiers() & Qt.AltModifier) and e.key() == Qt.Key_D:
			# kill next word
			cp = self.cursorPosition()
			self._kill_range(cp, self._word_right(cp))
			e.accept(); return

		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_Y:
			# yank
			if self._kill_buf:
				cp = self.cursorPosition()
				s = self.text()
				self.setText(s[:cp] + self._kill_buf + s[cp:])
				self.setCursorPosition(cp + len(self._kill_buf))
			self._last_cmd_was_kill = False
			e.accept(); return

		# any non-kill key cancels coalescing
		self._last_cmd_was_kill = False

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

# --- Widget ------------------------------------------------------------------

class GunnershellConsole(QWidget):
	def __init__(self, api, sid: str, hostname: str):
		super().__init__()
		self.api = api
		self.sid = sid

		# Output
		self.out = QTextEdit()
		self.out.setReadOnly(True)
		self.out.setLineWrapMode(QTextEdit.NoWrap)
		self.out.document().setMaximumBlockCount(2000)
		self.out.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
		self.out.setStyleSheet(
			"QTextEdit { background:#0b0f14; color:#dce3ea; font-size:12.5px; }"
		)
		mono = QFontDatabase.systemFont(QFontDatabase.FixedFont)
		try: mono.setStyleHint(QFont.Monospace)
		except AttributeError: mono.setStyleHint(QFont.TypeWriter)
		mono.setStyleStrategy(QFont.NoFontMerging)
		self.out.setFont(mono)
		self.out.setWordWrapMode(QTextOption.NoWrap)

		# Input + send
		hist_path = str(Path.home() / f".gunnerc2_gs_{sid}_history")
		self.inp = HistoryLineEdit(history_path=hist_path)
		self.btn_send = QPushButton("Send")

		layout = QVBoxLayout(self)
		layout.addWidget(self.out)
		bottom = QHBoxLayout(); bottom.addWidget(self.inp); bottom.addWidget(self.btn_send)
		layout.addLayout(bottom)

		self.btn_send.clicked.connect(self._send)
		self.inp.returnPressed.connect(self._send)

		# Ctrl+L to clear
		self._sc_clear = QShortcut(QKeySequence("Ctrl+L"), self)
		self._sc_clear.setContext(Qt.WidgetWithChildrenShortcut)
		self._sc_clear.activated.connect(self._clear_screen)

		# Hook Tab completion
		self._cmd_set = set(COMMANDS)
		self._bof_set = set(BOF_NAMES)
		self.inp.set_complete_callback(self._tab_complete)

		# WS
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
		self.out.clear()

	def _append_html(self, html_str: str):
		cur = self.out.textCursor()
		cur.movePosition(QTextCursor.End)
		cur.insertHtml(html_str)
		cur.insertHtml("<br/>")
		self.out.setTextCursor(cur)
		self.out.ensureCursorVisible()

	def _on_msg(self, msg: str):
		if msg == "\x00CLEAR\x00":
			self._clear_screen(); return
		self._append_html(ansi_to_html(msg))

	# -------- Tab completion core -------------------------------------------

	@staticmethod
	def _lcp(strings):
		if not strings: return ""
		s1, s2 = min(strings), max(strings)
		i = 0
		for a, b in zip(s1, s2):
			if a.lower() != b.lower(): break
			i += 1
		return s1[:i]

	def _token_bounds(self, text: str, cursor: int):
		seps = " \t;|&"
		start = cursor
		while start > 0 and text[start-1] not in seps:
			start -= 1
		end = cursor
		while end < len(text) and text[end] not in seps:
			end += 1
		return start, end

	def _suggest(self, head: str, prefix: str):
		"""
		- First token → built-in COMMANDS
		- If head begins with 'bofexec ' and we are completing the first arg → BOF_NAMES
		"""
		head_stripped = head.lstrip()

		# `bofexec <TAB>` first argument completion
		if head_stripped.startswith("bofexec "):
			parts = head_stripped.split()
			# parts[0] == 'bofexec'; if len(parts)==1 we’re at first arg
			if len(parts) == 1:
				return sorted([b for b in self._bof_set if b.lower().startswith(prefix.lower())], key=str.lower)
			# No special completion for subsequent args
			return []

		# First token completion (built-ins)
		if len(head_stripped) == 0:
			return sorted([c for c in self._cmd_set if c.lower().startswith(prefix.lower())], key=str.lower)

		return []  # no completion for later tokens (by request)

	def _tab_complete(self, text: str, cursor_pos: int, reverse: bool, cycle_state):
		start, end = self._token_bounds(text, cursor_pos)
		prefix = text[start:cursor_pos]
		head = text[:start]
		tail = text[end:]

		state = cycle_state or {}
		recompute = (not state) or state.get("prefix") != prefix or state.get("start") != start

		if recompute:
			matches = self._suggest(head, prefix)
			if not matches:
				return (None, None, None)
			lcp = self._lcp(matches)
			if lcp and lcp.lower() != prefix.lower():
				new = head + lcp + tail
				new_pos = start + len(lcp)
				return (new, new_pos, {"prefix": lcp, "matches": matches, "i": 0, "start": start})
			idx = -1
		else:
			matches = state.get("matches", [])
			idx = state.get("i", -1)

		if not matches:
			return (None, None, None)

		step = -1 if reverse else 1
		idx = (idx + step) % len(matches)
		choice = matches[idx]
		new_text = head + choice + tail
		new_pos = start + len(choice)
		return (new_text, new_pos, {"prefix": choice, "matches": matches, "i": idx, "start": start})

	# ------------------------------------------------------------------------

	def _send(self):
		text = self.inp.text().strip()
		if not text:
			return
		self.inp.remember(text)
		self._append_html(
			f'<span style="color:#62a0ea;font-weight:600">&gt;&gt;&gt;</span> '
			f'<span style="color:#cfcfcf">{html.escape(text)}</span>'
		)
		self.ws.sendTextMessage(text)
		self.inp.clear()
