# gui/files_ws_client.py
from PyQt5.QtCore import QObject, pyqtSignal, QUrl
from PyQt5.QtWebSockets import QWebSocket
from PyQt5.QtNetwork import QAbstractSocket
import json, os

class FilesWSClient(QObject):
	connected = pyqtSignal()
	error = pyqtSignal(str)
	listed = pyqtSignal(str, list)          # path, entries
	dl_begin = pyqtSignal(str, str)         # tid, name
	dl_chunk = pyqtSignal(bytes)            # raw file bytes
	dl_end = pyqtSignal(str, str, str)      # tid, status, error
	up_progress = pyqtSignal(int, int)      # written, total
	up_result = pyqtSignal(str, str)        # status, error

	def __init__(self, base_url: str, token: str, parent=None):
		super().__init__(parent)
		self.base_url = base_url.rstrip("/")
		self.token = token
		self.ws = QWebSocket()
		self._pending_text: list[str] = []

		# robust error hookup across PyQt5 versions
		if hasattr(self.ws, "errorOccurred"):
			self.ws.errorOccurred.connect(lambda _: self.error.emit("websocket error"))
		else:
			self.ws.error.connect(lambda *_: self.error.emit("websocket error"))

		# flush when connected
		if hasattr(self.ws, "connected"):
			self.ws.connected.connect(self._on_connected)

		self.ws.textMessageReceived.connect(self._on_text)
		self.ws.binaryMessageReceived.connect(lambda b: self.dl_chunk.emit(bytes(b)))

	def _on_connected(self):
		self.connected.emit()
		# flush queued messages
		while self._pending_text:
			self.ws.sendTextMessage(self._pending_text.pop(0))

	def open(self):
		ws_url = self.base_url.replace("http", "ws", 1) + f"/ws/files?token={self.token}"
		self.ws.open(QUrl(ws_url))

	# -------- API --------
	def list_dir(self, sid: str, path: str):
		self._send({"action":"fs.list","sid":sid,"path":path,"req_id":"list"})

	def start_download(self, sid: str, remote_path: str):
		self._send({"action":"fs.download","sid":sid,"path":remote_path,"req_id":"dl"})

	def start_upload(self, sid: str, local_path: str, remote_path: str):
		size = os.path.getsize(local_path)
		self._send({"action":"fs.upload.begin","sid":sid,"remote_path":remote_path,"size":size,"req_id":"up"})
		# after accept, stream
		def _stream():
			with open(local_path, "rb") as f:
				chunk = f.read(256*1024)
				while chunk:
					self.ws.sendBinaryMessage(chunk)
					chunk = f.read(256*1024)
			# if server wants explicit finish (we do both auto and explicit)
			self._send({"action":"fs.upload.finish"})
		self._pending_upload_stream = _stream  # run when accept arrives

	# -------- internals --------
	def _send(self, obj: dict):
		s = json.dumps(obj, separators=(",", ":"))
		# queue if not connected yet
		if self.ws.state() != QAbstractSocket.ConnectedState:
			self._pending_text.append(s)
		else:
			self.ws.sendTextMessage(s)

	def _on_text(self, s: str):
		try:
			m = json.loads(s)
		except Exception:
			return
		t = (m.get("type") or "").lower()
		if t == "fs.list":
			self.listed.emit(m.get("path") or "", m.get("entries") or [])
		elif t == "fs.download.begin":
			self.dl_begin.emit(m.get("tid",""), m.get("name","file.bin"))
		elif t == "fs.download.end":
			self.dl_end.emit(m.get("tid",""), m.get("status",""), m.get("error") or "")
		elif t == "fs.upload.accept":
			# kick upload streaming now
			cb = getattr(self, "_pending_upload_stream", None)
			if cb:
				self._pending_upload_stream = None
				cb()
		elif t == "fs.upload.progress":
			self.up_progress.emit(int(m.get("written") or 0), int(m.get("total") or 0))
		elif t == "fs.upload.result":
			self.up_result.emit(m.get("status",""), m.get("error") or "")
		elif t == "pong":
			pass
		elif t == "error":
			self.error.emit(m.get("error") or "error")
