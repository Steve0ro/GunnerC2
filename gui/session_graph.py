from __future__ import annotations

import json
import inspect
import math
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import (
	QPoint, QPointF, QRectF, Qt, pyqtSignal, QSize, QTimer, QLineF, QEvent
)
from PyQt5.QtGui import (
	QBrush, QColor, QFont, QPainter, QPainterPath, QPen, QPixmap
)
from PyQt5.QtWidgets import (
	QGraphicsItem, QGraphicsObject, QGraphicsScene, QGraphicsSimpleTextItem,
	QGraphicsView, QHBoxLayout, QMenu, QPushButton, QStyleOptionGraphicsItem,
	QWidget, QScrollBar
)

try:
	from .websocket_client import SessionsWSClient

except Exception:
	from websocket_client import SessionsWSClient


# ---------- data models ----------
@dataclass
class SessionNode:
	sid: str
	hostname: str
	username: str
	os: str  # "windows" | "linux" | unknown
	protocol: str  # tcp|tls|http|https


# ---------- constants / styling ----------
BLACK = QColor(0, 0, 0)
NEON = QColor(57, 255, 20)  # #39ff14
NEON_DIM = QColor(45, 200, 16)
STEEL = QColor(180, 180, 200)
RED = QColor(232, 46, 46)
ORANGE = QColor(255, 140, 0)
CHARCOAL = QColor(28, 32, 36)
LABEL_GRAY = QColor(210, 210, 210)
ARROW_GLOW = False
ARROW_GAP = 6.0  # pixels to stop short of the C2 icon edge

NODE_W = 86
NODE_H = 66
NODE_RADIUS = 10

C2_SIZE = QSize(60, 60)
PROTOCOL_FONT = QFont("DejaVu Sans Mono", 10, QFont.DemiBold)
LABEL_FONT = QFont("DejaVu Sans", 9)
TITLE_FONT = QFont("DejaVu Sans", 9, QFont.Bold)

PERSIST_PATH = os.path.expanduser("~/.gunnerc2_graph_positions.json")

# ---- icon assets (lazy-loaded to avoid QPixmap-before-QApp) ---------------
def _asset_path(name: str) -> str:
	here = os.path.dirname(os.path.abspath(__file__))
	return os.path.join(here, "assets", name)

# Candidate file paths for each OS icon
_ICON_PATHS = {
	"windows": [
		_asset_path("windows_agent.png"),
		_asset_path("assets/windows_agent.png"),
	],
	"linux": [
		_asset_path("linux_agent.png"),
		_asset_path("assets/linux_agent.png"),
	],
}

# ---- firewall icon (PNG) ----------------------------------------------------
_FIREWALL_PATHS = [
	os.environ.get("GUNNERC2_FIREWALL_ICON") or "",
	_asset_path("firewall.png"),
]
_FIREWALL_PM: Optional[QPixmap] = None

_ICON_CACHE: Dict[str, QPixmap] = {}
AGENT_ICON_SCALE = 1.6

def _get_firewall_icon() -> QPixmap:
	"""Load and cache the firewall icon once a QApplication exists."""
	global _FIREWALL_PM
	if _FIREWALL_PM is not None:
		return _FIREWALL_PM
	from PyQt5.QtWidgets import QApplication
	if QApplication.instance() is None:
		return QPixmap()  # will retry later
	for pth in _FIREWALL_PATHS:
		if pth and os.path.exists(pth):
			pm = QPixmap(pth)
			if not pm.isNull():
				_FIREWALL_PM = pm
				return pm
	_FIREWALL_PM = QPixmap()
	return _FIREWALL_PM

def _draw_pixmap_aspect_fit(p: QPainter, rect: QRectF, pix: QPixmap, pad: float = 3.0):
	"""Aspect-fit the pixmap inside rect with a little padding."""
	if pix.isNull():
		return
	p.save()
	p.setRenderHint(QPainter.SmoothPixmapTransform, True)
	r = rect.adjusted(pad, pad, -pad, -pad)
	pw, ph = pix.width(), pix.height()
	if pw <= 0 or ph <= 0:
		p.drawPixmap(r, pix, QRectF(pix.rect()))
	else:
		s = min(r.width()/pw, r.height()/ph)
		w, h = pw*s, ph*s
		x = r.center().x() - w/2
		y = r.center().y() - h/2
		p.drawPixmap(QRectF(x, y, w, h), pix, QRectF(pix.rect()))
	p.restore()

def _get_os_icon(kind: str) -> QPixmap:
	"""Return cached QPixmap for OS kind ('windows' or 'linux'), loading on first use.
	If called before a QApplication exists, returns a null pixmap and will try again later.
	"""
	pm = _ICON_CACHE.get(kind)
	if pm is not None:
		return pm
	from PyQt5.QtWidgets import QApplication
	if QApplication.instance() is None:
		return QPixmap()  # will retry next paint
	for pth in _ICON_PATHS.get(kind, []):
		if os.path.exists(pth):
			pm = QPixmap(pth)
			if not pm.isNull():
				_ICON_CACHE[kind] = pm
				return pm
	_ICON_CACHE[kind] = QPixmap()
	return _ICON_CACHE[kind]

# ---- interaction tuning ----
DBLCLICK_BASE_TARGET_ZOOM = 2.0   # minimum zoom to reach on double click
DBLCLICK_ANIM_STEPS = 10          # frames
DBLCLICK_ANIM_INTERVAL_MS = 16    # ~160ms total

# ---- spawn placement tuning -----------------------------------------------
# New agents (no saved position) are placed on rings around the C2 and must be
# at least SPAWN_MIN_SEP away from every other agent.
SPAWN_RING_START   = 280.0   # px, first ring radius from C2 center
SPAWN_RING_STEP    = 180.0   # px, distance between rings
# Minimum separation depends on icon size; we’ll compute from item’s rect,
# but keep a floor here as well.
SPAWN_MIN_SEP_FLOOR = 160.0  # px

# ---------- Helpers ----------------
def _strip_host_prefix(username: str, hostname: str) -> str:
	"""
	If username looks like '<hostname>\\user', drop the '<hostname>\\'.
	Only strips when the prefix matches the *actual* hostname (case-insensitive).
	"""
	u = str(username or "")
	h = str(hostname or "")
	if u.lower().startswith(h.lower() + "\\"):
		return u[len(h) + 1 :]
	return u

# ---------- icon painters ----------
def _paint_firewall(p: QPainter, rect: QRectF):
	"""Draw the PNG firewall icon if available; otherwise use the vector fallback."""
	pm = _get_firewall_icon()
	if not pm.isNull():
		_draw_pixmap_aspect_fit(p, rect, pm, pad=2.0)
		return

	# --- Fallback: your existing vector drawing ---
	p.save()
	p.setRenderHint(QPainter.Antialiasing, True)
	wall = QRectF(rect.left()+6, rect.top()+18, rect.width()-20, rect.height()-18)
	p.setPen(Qt.NoPen)
	p.setBrush(QBrush(QColor(140, 28, 28)))
	p.drawRoundedRect(wall, 6, 6)
	p.setPen(QPen(QColor(90, 10, 10), 2))
	rows = 3
	for r in range(1, rows+1):
		y = wall.top() + r * wall.height()/(rows+1)
		p.drawLine(QLineF(wall.left()+4, y, wall.right()-4, y))
	p.drawLine(QLineF(wall.left()+4, wall.center().y(), wall.right()-4, wall.center().y()))
	for col in (0.25, 0.5, 0.75):
		x = wall.left() + wall.width()*col
		p.drawLine(QLineF(x, wall.top()+4, x, wall.bottom()-4))
	flame = QPainterPath()
	cx = rect.left()+rect.width()-20
	base = wall.bottom()
	flame.moveTo(cx, base-6)
	flame.cubicTo(cx-8, base-28, cx+12, base-28, cx-2, base-50)
	flame.cubicTo(cx-16, base-24, cx+10, base-22, cx-6, base-6)
	p.setPen(Qt.NoPen)
	p.setBrush(QBrush(ORANGE))
	p.drawPath(flame)
	p.restore()

def _paint_os_icon(p: QPainter, rect: QRectF, pix: QPixmap):
	"""Draw a pixmap nicely into rect (centered, aspect-fit, smooth)."""
	if pix.isNull():
		return
	p.save()
	p.setRenderHint(QPainter.SmoothPixmapTransform, True)
	# Fill the node rect (keeps it simple; swap to aspect-fit if you prefer)
	p.drawPixmap(QRectF(rect), pix, QRectF(pix.rect()))
	p.restore()


def _paint_windows_computer(p: QPainter, rect: QRectF):
	p.save()
	p.setRenderHint(QPainter.Antialiasing, True)
	# base monitor
	screen = QRectF(rect.left()+8, rect.top()+6, rect.width()-16, rect.height()-22)
	p.setPen(QPen(QColor(50, 55, 60), 2))
	p.setBrush(QBrush(QColor(210, 220, 230)))
	p.drawRoundedRect(screen.adjusted(-3, -3, 3, 3), 6, 6)
	# blue screen area
	p.setBrush(QBrush(QColor(41, 128, 255)))
	scr = screen.adjusted(4, 4, -4, -4)
	p.setPen(Qt.NoPen)
	p.drawRoundedRect(scr, 4, 4)
	# windows logo (four tiles)
	p.setBrush(QBrush(QColor(240, 240, 255)))
	w = scr.width()
	h = scr.height()
	tile_w = w*0.38
	tile_h = h*0.38
	margin_w = w*0.08
	margin_h = h*0.08
	x0 = scr.left()+margin_w
	y0 = scr.top()+margin_h
	p.drawRect(QRectF(x0, y0, tile_w, tile_h))
	p.drawRect(QRectF(x0+tile_w+margin_w, y0, tile_w, tile_h))
	p.drawRect(QRectF(x0, y0+tile_h+margin_h, tile_w, tile_h))
	p.drawRect(QRectF(x0+tile_w+margin_w, y0+tile_h+margin_h, tile_w, tile_h))
	# stand
	base = QRectF(rect.center().x()-14, rect.bottom()-16, 28, 6)
	neck = QRectF(rect.center().x()-4, screen.bottom()+2, 8, 10)
	p.setBrush(QBrush(QColor(120, 130, 140)))
	p.setPen(Qt.NoPen)
	p.drawRoundedRect(neck, 2, 2)
	p.drawRoundedRect(base, 2, 2)
	p.restore()


def _paint_linux_computer(p: QPainter, rect: QRectF):
	p.save()
	p.setRenderHint(QPainter.Antialiasing, True)
	# monitor
	screen = QRectF(rect.left()+8, rect.top()+6, rect.width()-16, rect.height()-22)
	p.setPen(QPen(QColor(50, 55, 60), 2))
	p.setBrush(QBrush(QColor(210, 220, 230)))
	p.drawRoundedRect(screen.adjusted(-3, -3, 3, 3), 6, 6)
	# amber screen
	p.setBrush(QBrush(QColor(245, 180, 80)))
	scr = screen.adjusted(4, 4, -4, -4)
	p.setPen(Qt.NoPen)
	p.drawRoundedRect(scr, 4, 4)
	# minimalist tux silhouette
	tux = QPainterPath()
	cx = scr.center().x()
	cy = scr.center().y()
	tux.addEllipse(QPointF(cx, cy-8), 6, 8)  # head
	body = QRectF(cx-10, cy-6, 20, 18)
	tux.addRoundedRect(body, 8, 8)
	p.setBrush(QBrush(QColor(40, 40, 40)))
	p.drawPath(tux)
	# belly
	p.setBrush(QBrush(QColor(250, 240, 200)))
	p.drawEllipse(QPointF(cx, cy+2), 6, 5)
	# stand
	base = QRectF(rect.center().x()-14, rect.bottom()-16, 28, 6)
	neck = QRectF(rect.center().x()-4, screen.bottom()+2, 8, 10)
	p.setBrush(QBrush(QColor(120, 130, 140)))
	p.setPen(Qt.NoPen)
	p.drawRoundedRect(neck, 2, 2)
	p.drawRoundedRect(base, 2, 2)
	p.restore()


# ---------- scene items ----------
class AgentItem(QGraphicsObject):
	"""Draggable agent node (windows/linux). Emits context menu actions."""
	open_console = pyqtSignal(str, str)  # sid, hostname
	kill_session = pyqtSignal(str, str)  # sid, hostname
	open_gunnershell = pyqtSignal(str, str)  # sid, hostname
	position_changed = pyqtSignal()      # emitted when user moves the item

	def __init__(self, node: SessionNode):
		super().__init__()
		self.node = node
		self._edges: List[EdgeItem] = []

		w = NODE_W * AGENT_ICON_SCALE
		h = NODE_H * AGENT_ICON_SCALE
		self.setFlag(QGraphicsItem.ItemIsMovable, True)
		self.setFlag(QGraphicsItem.ItemSendsScenePositionChanges, True)
		self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
		self.setAcceptHoverEvents(True)
		self.setCursor(Qt.OpenHandCursor)
		#self._rect = QRectF(-NODE_W/2, -NODE_H/2, NODE_W, NODE_H)
		self._rect = QRectF(-w/2, -h/2, w, h)

		clean_user = _strip_host_prefix(node.username, node.hostname)
		self._label = QGraphicsSimpleTextItem(f"{clean_user}@{node.hostname}", self)
		self._label.setBrush(LABEL_GRAY)
		self._label.setFont(LABEL_FONT)
		#self._label.setPos(-self._label.boundingRect().width()/2, NODE_H/2 + 6)
		self._label.setPos(-self._label.boundingRect().width()/2, h/2 + 6)

	def boundingRect(self) -> QRectF:
		br = self._rect.adjusted(-4, -4, 4, 20)
		# include label
		lb = self._label.mapRectToParent(self._label.boundingRect())
		return br.united(lb)

	def paint(self, p: QPainter, opt: QStyleOptionGraphicsItem, widget=None):
		osname = (self.node.os or "").lower()
		# Prefer icons; lazily load them once a QApplication exists.
		if osname.startswith("win"):
			pm = _get_os_icon("windows")
			if not pm.isNull():
				_paint_os_icon(p, self._rect, pm)
				return
		elif osname.lower().startswith("lin") or "linux" in osname:
			pm = _get_os_icon("linux")
			if not pm.isNull():
				_paint_os_icon(p, self._rect, pm)
				return
		# Fallback vectors (kept for robustness)
		if osname.startswith("win"):
			_paint_windows_computer(p, self._rect)
		elif osname.startswith("lin"):
			_paint_linux_computer(p, self._rect)
		else:
			_paint_windows_computer(p, self._rect)

	# subtle hover feedback
	def hoverEnterEvent(self, event):
		self.setCursor(Qt.ClosedHandCursor)
		super().hoverEnterEvent(event)

	def hoverLeaveEvent(self, event):
		self.setCursor(Qt.OpenHandCursor)
		super().hoverLeaveEvent(event)

	# right-click menu
	def contextMenuEvent(self, event):
		m = QMenu()
		act_console = m.addAction("Open Console")
		act_gs      = m.addAction("Open GunnerShell")
		act_kill = m.addAction("Kill Session")
		# PyQt5 can return QPoint or QPointF here; normalize to QPoint.
		sp = event.screenPos()
		pos = sp.toPoint() if hasattr(sp, "toPoint") else sp  # QPointF -> QPoint
		if not isinstance(pos, QPoint):
			# last resort: let Qt figure it out via the cursor position
			from PyQt5.QtGui import QCursor
			pos = QCursor.pos()
		chosen = m.exec_(pos)

		if chosen == act_console:
			self.open_console.emit(self.node.sid, self.node.hostname)

		elif chosen == act_gs:
			self.open_gunnershell.emit(self.node.sid, self.node.hostname)

		elif chosen == act_kill:
			self.kill_session.emit(self.node.sid, self.node.hostname)

	# inform the scene/view to persist
	def itemChange(self, change, value):
		if change == QGraphicsItem.ItemPositionHasChanged:
			#self.position_changed.emit()
			for e in self._edges:
				e.refresh()
		return super().itemChange(change, value)


class C2Item(QGraphicsItem):
	def __init__(self):
		super().__init__()
		w = NODE_W * AGENT_ICON_SCALE
		h = NODE_H * AGENT_ICON_SCALE
		self._rect = QRectF(-w/2, -h/2, w, h)
		self._edges: List["EdgeItem"] = []  # edges connected to this node
		# small "C2" title above
		self.title = QGraphicsSimpleTextItem("C2", self)
		self.title.setFont(TITLE_FONT)
		self.title.setBrush(QBrush(LABEL_GRAY))
		self.title.setPos(-self.title.boundingRect().width()/2, -h/2 - self.title.boundingRect().height() - 2)
		#self.title.setPos(-self.title.boundingRect().width()/2, -h/2 - self.title.boundingRect().height() - 2)

	def boundingRect(self) -> QRectF:
		# include some padding and the "C2" title area
		return self._rect.adjusted(-8, -8, 8, 8).united(
			self.title.mapRectToParent(self.title.boundingRect())
		)

	def paint(self, p: QPainter, opt: QStyleOptionGraphicsItem, widget=None):
		_paint_firewall(p, self._rect)

	def itemChange(self, change, value):
		# If C2 were ever moved, keep edges crisp
		if change == QGraphicsItem.ItemPositionHasChanged:
			for e in getattr(self, "_edges", []):
				e.refresh()
		return super().itemChange(change, value)

class EdgeItem(QGraphicsItem):
	"""Arrow from an Agent to the C2, with a protocol label."""
	def __init__(self, src: QGraphicsItem, dst: QGraphicsItem, protocol: str):
		super().__init__()
		self.src = src          # C2
		self.dst = dst          # Agent
		self.protocol = (protocol or "").lower()

		 # draw the line behind nodes
		self.setZValue(-5)
		self.setCacheMode(QGraphicsItem.NoCache)

		# --- label is a TOP-LEVEL item so it can float above everything ---
		self.label = QGraphicsSimpleTextItem(self.protocol)   # no parent
		self.label.setFont(PROTOCOL_FONT)
		self.label.setBrush(QBrush(NEON))
		self.label.setZValue(50)  # above C2 and agents
		self._gap_pad_scene = 14.0  # scene-units padding around the text gap

		# don't consume mouse input
		self.setAcceptedMouseButtons(Qt.NoButton)
		self.setAcceptHoverEvents(False)
		self.setFlag(QGraphicsItem.ItemIsSelectable, False)
		self.label.setAcceptedMouseButtons(Qt.NoButton)

		# track on both endpoints so they can notify us on movement
		for it in (self.src, self.dst):
			lst = getattr(it, "_edges", None)
			if lst is None:
				try:
					it._edges = []  # type: ignore[attr-defined]
				except Exception:
					pass
			try:
				it._edges.append(self)  # type: ignore[attr-defined]
			except Exception:
				pass

	# ---------- geometry helpers ----------
	def _c2_tip_point(self, c2_center: QPointF, agent_center: QPointF) -> QPointF:
		"""
		Point on the C2 icon's rectangle that lies on the line toward the agent,
		but 'ARROW_GAP' pixels BEFORE the edge (so the arrow never touches it).
		"""
		# unit vector from agent -> C2 center
		v = c2_center - agent_center
		L = math.hypot(v.x(), v.y())
		if L < 1e-6:
			return c2_center
		ux, uy = v.x() / L, v.y() / L

		# Use the C2 ICON rect, not the whole bounding rect (which includes the title)
		src_rect = getattr(self.src, "_rect", None)
		if isinstance(src_rect, QRectF):
			r = self.mapRectFromItem(self.src, src_rect)
		else:
			r = self.mapRectFromItem(self.src, self.src.boundingRect())

		hx, hy = r.width() / 2.0, r.height() / 2.0

		# distance from center to the rectangle boundary along direction -u
		tx = (hx / abs(ux)) if abs(ux) > 1e-6 else float("inf")
		ty = (hy / abs(uy)) if abs(uy) > 1e-6 else float("inf")
		t_edge = min(tx, ty)

		# stop short of the edge by ARROW_GAP
		t_tip = max(0.0, t_edge - ARROW_GAP)

		# from center toward the agent is direction -u
		return QPointF(c2_center.x() - ux * t_tip, c2_center.y() - uy * t_tip)

	def refresh(self):
		self.prepareGeometryChange()
		a = self.mapFromItem(self.src, 0, 0)   # C2 center
		b = self.mapFromItem(self.dst, 0, 0)   # Agent center
		tip = self._c2_tip_point(a, b)
		mid = (b + tip) * 0.5

		# make sure the top-level label is in the same scene
		if self.scene() and self.label.scene() is None:
			self.scene().addItem(self.label)

		# center the label exactly at the midpoint (it scales with the scene)
		br = self.label.boundingRect()
		self.label.setPos(mid.x() - br.width()/2, mid.y() - br.height()/2)

		self.update()

	def boundingRect(self) -> QRectF:
		a = self.mapFromItem(self.src, 0, 0)
		b = self.mapFromItem(self.dst, 0, 0)
		rect = QRectF(a, b).normalized().adjusted(-12, -12, 12, 12)
		lb = self.label.mapRectToParent(self.label.boundingRect())
		return rect.united(lb)

	def paint(self, p: QPainter, opt: QStyleOptionGraphicsItem, widget=None):
		a = self.mapFromItem(self.src, 0, 0)
		b = self.mapFromItem(self.dst, 0, 0)
		tip = self._c2_tip_point(a, b)

		v = tip - b
		L = math.hypot(v.x(), v.y())
		if L < 1e-6:
			return
		ux, uy = v.x()/L, v.y()/L

		mid = QPointF(b.x() + ux*(L*0.5), b.y() + uy*(L*0.5))

		# label width in *scene units* (since it now scales with the scene)
		label_scene_w = self.label.boundingRect().width()
		gap_len_scene = label_scene_w + self._gap_pad_scene
		half_gap = min(L * 0.45, gap_len_scene * 0.5)

		seg1_end   = QPointF(mid.x() - ux*half_gap, mid.y() - uy*half_gap)
		seg2_start = QPointF(mid.x() + ux*half_gap, mid.y() + uy*half_gap)

		pen = QPen(NEON, 2.6)
		if self.protocol in ("tls", "https"):
			pen.setStyle(Qt.DashLine)
		elif self.protocol == "http":
			pen.setStyle(Qt.DotLine)
		else:
			pen.setStyle(Qt.SolidLine)

		if ARROW_GLOW:
			glow = QPen(NEON_DIM, 5.0); glow.setStyle(pen.style())
			p.setPen(glow)
			p.drawLine(QLineF(b, seg1_end))
			p.drawLine(QLineF(seg2_start, tip))

		p.setPen(pen)
		p.drawLine(QLineF(b, seg1_end))
		p.drawLine(QLineF(seg2_start, tip))

		self._draw_arrow_head_into_c2(p, seg2_start, tip)

	def _draw_arrow_head_into_c2(self, p: QPainter, tail: QPointF, tip: QPointF):
		"""Draw a triangular arrowhead whose tip is at `tip` (near the C2)."""
		v = tip - tail
		L = math.hypot(v.x(), v.y())
		if L < 0.0001:
			return
		ux, uy = v.x()/L, v.y()/L
		size = 10.0
		perp = QPointF(-uy, ux)
		base = tip - QPointF(ux*size, uy*size)
		left = base + perp * size * 0.6
		right = base - perp * size * 0.6
		p.setBrush(QBrush(NEON))
		p.drawPolygon(tip, left, right)

	def cleanup(self):
		if self.label and self.label.scene():
			self.label.scene().removeItem(self.label)


# ---------- view widget ----------
class GraphView(QGraphicsView):
	"""Black canvas, wheel zoom, buttons, key panning."""
	zoomChanged = pyqtSignal(float)

	def __init__(self, scene: QGraphicsScene, parent=None):
		super().__init__(scene, parent)
		self.setRenderHint(QPainter.Antialiasing, True)
		#self.setViewportUpdateMode(QGraphicsView.BoundingRectViewportUpdate)
		self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
		self.setBackgroundBrush(QBrush(BLACK))
		self.setDragMode(QGraphicsView.NoDrag)
		self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
		self._panning = False
		self._pan_start = QPoint()
		self._zoom = 1.0
		self._dbl_timer: Optional[QTimer] = None
		self._is_panning = False
		self._pan_last = None  # type: Optional[QPoint]
		self._build_zoom_buttons()
		# Keep overlay buttons anchored on viewport changes
		self.viewport().installEventFilter(self)
		# First real placement after the view is on screen
		QTimer.singleShot(0, self._reposition_buttons)

	def _build_zoom_buttons(self):
		# Overlay container at top-left of the VIEW (not the scene)
		self._overlay = QWidget(self)
		self._overlay.setAttribute(Qt.WA_TransparentForMouseEvents, False)
		self._overlay.setStyleSheet("background: transparent;")
		self._btn_plus = QPushButton("+", self._overlay)
		self._btn_minus = QPushButton("−", self._overlay)
		for b in (self._btn_plus, self._btn_minus):
			b.setFixedSize(56, 56)
			b.setStyleSheet(
				"QPushButton { background:#121212; color:#eaeaea;"
				" border:1px solid #2b2b2b; border-radius:6px;"
				" font-size: 22px; font-weight: 800; }"
				"QPushButton:hover { border-color:#5a5a5a; }"
			)
		self._btn_plus.clicked.connect(lambda: self._apply_zoom(1.15))
		self._btn_minus.clicked.connect(lambda: self._apply_zoom(1/1.15))
		self._reposition_buttons()
		self._overlay.raise_()

	def resizeEvent(self, e):
		super().resizeEvent(e)
		self._reposition_buttons()

	def _reposition_buttons(self):
		# Anchor at the VIEW's top-left
		margin = 12
		self._overlay.resize(self._btn_plus.width(), self._btn_plus.height()*2 + 8)
		self._overlay.move(margin, margin)
		self._btn_plus.move(0, 0)
		self._btn_minus.move(0, self._btn_plus.height() + 8)

	def wheelEvent(self, event):
		# angleDelta is in 1/8th degree units; 120 ~= one notch
		delta = event.angleDelta().y()
		if delta == 0:
			event.ignore()
			return

		factor = 1.0 + (abs(delta) / 240.0)  # gentle
		if delta < 0:
			factor = 1.0 / factor
		self._apply_zoom(factor)
		# keep overlay crisp in place after zoom
		self._reposition_buttons()
		event.accept()

	def eventFilter(self, obj, ev):
		# Make sure buttons stick to the top-left of the viewport
		if obj is self.viewport() and ev.type() in (QEvent.Resize, QEvent.Show, QEvent.LayoutRequest):
			self._reposition_buttons()
		return super().eventFilter(obj, ev)

	def _apply_zoom(self, factor: float):
		# clamp scale
		new_zoom = self._zoom * factor
		new_zoom = max(0.05, min(6.0, new_zoom))
		factor = new_zoom / self._zoom
		if factor == 1.0:
			return
		self.scale(factor, factor)
		self._zoom = new_zoom
		self.zoomChanged.emit(self._zoom)

	# Arrow keys & WASD panning
	def keyPressEvent(self, e):
		step = 60
		if e.key() in (Qt.Key_Left, Qt.Key_A):
			self._pan(dx=step)
		elif e.key() in (Qt.Key_Right, Qt.Key_D):
			self._pan(dx=-step)
		elif e.key() in (Qt.Key_Up, Qt.Key_W):
			self._pan(dy=step)
		elif e.key() in (Qt.Key_Down, Qt.Key_S):
			self._pan(dy=-step)
		else:
			super().keyPressEvent(e)

	def _pan(self, dx=0, dy=0):
		# Use scrollbars for consistent panning speed regardless of zoom
		speed = 1.0  # tweak pan sensitivity (lower = slower)
		h = self.horizontalScrollBar()
		v = self.verticalScrollBar()
		h.setValue(h.value() - int(dx * speed))
		v.setValue(v.value() - int(dy * speed))

	# --- Double-click to fly to location & zoom in ---
	def mouseDoubleClickEvent(self, e):
		if e.button() != Qt.LeftButton:
			return super().mouseDoubleClickEvent(e)

		target_scene_pos = self.mapToScene(e.pos())
		# Aim for +60% zoom, but at least the base and at most 6x.
		target_zoom = min(6.0, max(DBLCLICK_BASE_TARGET_ZOOM, self._zoom * 1.6))
		self._fly_to(target_scene_pos, target_zoom)

	def _fly_to(self, scene_pos: QPointF, target_zoom: float):
		"""Smoothly pan+zoom to scene_pos."""
		# Stop any running animation
		if self._dbl_timer and self._dbl_timer.isActive():
			self._dbl_timer.stop()

		steps = max(1, DBLCLICK_ANIM_STEPS)
		start_zoom = self._zoom
		start_center = self.mapToScene(self.viewport().rect().center())
		dz = (target_zoom - start_zoom) / float(steps)
		dx = (scene_pos.x() - start_center.x()) / float(steps)
		dy = (scene_pos.y() - start_center.y()) / float(steps)

		# Anchor to view center during animation for stable flight
		self.setTransformationAnchor(QGraphicsView.AnchorViewCenter)

		i = {"k": 0}
		self._dbl_timer = QTimer(self)

		def _step():
			if i["k"] >= steps:
				self._dbl_timer.stop()
				# Final snap to exact target
				self.centerOn(scene_pos)
				self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
				return

			# Zoom incrementally
			curr = self._zoom
			next_zoom = curr + dz
			# Convert to scale factor expected by _apply_zoom
			factor = max(0.0001, next_zoom / max(0.0001, curr))
			if factor != 1.0:
				self._apply_zoom(factor)

			# Pan incrementally
			new_center = QPointF(start_center.x() + dx * (i["k"] + 1),
								 start_center.y() + dy * (i["k"] + 1))
			self.centerOn(new_center)

			i["k"] += 1

		self._dbl_timer.timeout.connect(_step)
		self._dbl_timer.start(DBLCLICK_ANIM_INTERVAL_MS)

	def _treat_as_background(self, item: QGraphicsItem) -> bool:
		"""Edges (and their children) are considered background for panning."""
		if item is None:
			return True
		# climb to the topmost parent under the cursor
		root = item
		while root.parentItem():
			root = root.parentItem()
		# pan if edge; don't pan if it’s a node
		return isinstance(root, EdgeItem)

	# Mouse drag panning (sideways & any direction)
	# Middle button always pans; left button pans only on empty background.
	def mousePressEvent(self, e):
		item = self.itemAt(e.pos())
		if (e.button() == Qt.MiddleButton) or (e.button() == Qt.LeftButton and self._treat_as_background(item)):
			self._panning = True
			self._pan_last = e.pos()
			self.setCursor(Qt.ClosedHandCursor)
			e.accept()
			return
		super().mousePressEvent(e)

	def mouseMoveEvent(self, e):
		if self._panning:
			delta = e.pos() - self._pan_last
			self._pan_last = e.pos()
			# Scrollbars give natural, speed-controlled panning
			speed = 0.85  # keep mouse-drag panning tame
			h = self.horizontalScrollBar()
			v = self.verticalScrollBar()
			h.setValue(h.value() - int(delta.x() * speed))
			v.setValue(v.value() - int(delta.y() * speed))
			e.accept()
			return
		super().mouseMoveEvent(e)

	def showEvent(self, e):
		super().showEvent(e)
		self._reposition_buttons()

	def mouseReleaseEvent(self, e):
		if self._panning and e.button() in (Qt.MiddleButton, Qt.LeftButton):
			self._panning = False
			self.setCursor(Qt.ArrowCursor)
			e.accept()
			return
		super().mouseReleaseEvent(e)


	# in GraphView
	def fit_all(self, rect: QRectF, margin: float = 80.0):
		if rect.isNull() or not rect.isValid():
			return
		r = rect.adjusted(-margin, -margin, margin, margin)
		self.fitInView(r, Qt.KeepAspectRatio)
		# keep internal zoom in sync with the new transform
		self._zoom = self.transform().m11()
		self._reposition_buttons()


# ---------- main widget ----------
class SessionGraph(QWidget):
	"""
	Public widget used by MainWindow.
	Signals mirror actions required by the rest of the GUI.
	"""
	open_console_requested = pyqtSignal(str, str)  # sid, hostname
	open_gunnershell_requested = pyqtSignal(str, str)  # sid, hostname
	kill_session_requested = pyqtSignal(str, str)  # sid, hostname

	# ---- WS signal names we’ll probe for (support multiple client versions)
	_WS_SIG_SNAPSHOT = ("snapshot", "full_snapshot")
	_WS_SIG_UPSERT   = ("upsert", "added", "updated", "session_upsert")
	_WS_SIG_REMOVE   = ("remove", "deleted", "session_removed")
	_WS_SIG_CONNECTED = ("connected", )

	def __init__(self, api, parent=None):
		super().__init__(parent)
		self.api = api

		self.scene = QGraphicsScene(self)
		self.scene.setSceneRect(-5000, -5000, 10000, 10000)

		self.view = GraphView(self.scene, self)
		lay = QHBoxLayout(self)
		lay.setContentsMargins(0, 0, 0, 0)
		lay.addWidget(self.view)

		# items
		self.c2 = C2Item()
		self.scene.addItem(self.c2)
		self.c2.setPos(0, 0)

		self.agent_items: Dict[str, AgentItem] = {}
		self.edge_items: List[EdgeItem] = []
		self._centered_once = False

		# lazy persistence saver
		self._save_timer = QTimer(self)
		self._save_timer.setSingleShot(True)
		self._save_timer.setInterval(400)  # debounce
		self._save_timer.timeout.connect(self._save_positions)

		# initial load
		self._positions_cache = self._load_positions()
		self._sessions_ws = None
		self._try_start_ws()

	@property
	def sessions_ws(self):
		return self._sessions_ws

	# ----- data & layout -----
	def _try_start_ws(self):
		"""Hook up to the realtime Sessions websocket if available."""
		if SessionsWSClient is None:
			return
		try:
			ws = SessionsWSClient(self.api)
			# wire signals defensively (client may have slightly different names)
			def _connect_if(sig_name_tuple, slot):
				for name in sig_name_tuple:
					sig = getattr(ws, name, None)
					if sig and hasattr(sig, "connect"):
						try:
							sig.connect(slot)
							return True
						except Exception:
							pass
				return False
			_connect_if(self._WS_SIG_SNAPSHOT, self._on_ws_snapshot)
			_connect_if(self._WS_SIG_UPSERT, self._on_ws_upsert)
			_connect_if(self._WS_SIG_REMOVE, self._on_ws_remove)
			# On connect, proactively request a snapshot if the client supports it
			def _on_connected():
				 # SessionsWSClient already sends list on connect, but allow explicit ask too.
				ask = getattr(ws, "list_now", None)
				if callable(ask):
					ask()
			_connect_if(self._WS_SIG_CONNECTED, _on_connected)
			# start/connect (support either .start() or .connect())
			# OPEN the websocket (new client API), else fall back to start/connect
			if hasattr(ws, "open"):
				ws.open()
			if hasattr(ws, "start"):
				ws.start()
			elif hasattr(ws, "connect"):
				ws.connect()
			self._sessions_ws = ws
		except Exception:
			self._sessions_ws = None

	def _dict_to_node(self, s: dict) -> SessionNode:
		sid = s.get("id") or s.get("sid") or ""
		hostname = s.get("hostname") or s.get("host") or "host"
		username = s.get("username") or s.get("user") or "user"
		osname = (s.get("os") or s.get("platform") or "windows").lower()
		protocol = (s.get("protocol") or s.get("transport") or "https").lower()
		return SessionNode(sid=sid, hostname=hostname, username=username, os=osname, protocol=protocol)

	def reload(self):
		"""
		WebSocket-only refresh. If the WS client exposes a request_snapshot(),
		ask the server to send a fresh snapshot. Otherwise, this is a no-op.
		"""
		ws = self._sessions_ws
		if ws:
			ask = getattr(ws, "list_now", None)
			if callable(ask):
				ask()

	def _rebuild_edges(self):
		# clear edges (and their labels)
		for e in self.edge_items:
			try:
				e.cleanup()
			except Exception:
				pass
			self.scene.removeItem(e)
		self.edge_items.clear()

		# reset edge registries
		try:
			self.c2._edges.clear()
		except Exception:
			self.c2._edges = []

		for item in self.agent_items.values():
			try:
				item._edges.clear()
			except Exception:
				item._edges = []

			edge = EdgeItem(self.c2, item, item.node.protocol)
			self.scene.addItem(edge)
			self.edge_items.append(edge)
			item._edges.append(edge)
			try:
				self.c2._edges.append(edge)
			except Exception:
				pass

			edge.refresh()  # <-- place label & gap from the very first frame

	# ----- websocket handlers -----------------------------------------------
	def _on_ws_snapshot(self, payload):
		"""
		Accepts either a list[dict] of sessions or a dict with 'sessions' key.
		"""
		try:
			sessions = payload.get("sessions") if isinstance(payload, dict) else payload
		except Exception:
			sessions = payload
		sessions = sessions or []

		# Compute add/update/remove vs. current state
		new_nodes = {self._dict_to_node(s).sid: self._dict_to_node(s) for s in sessions}
		present_ids = set(self.agent_items.keys())
		wanted_ids = set(new_nodes.keys())

		# remove gone
		for sid in list(present_ids - wanted_ids):
			it = self.agent_items.pop(sid)
			self.scene.removeItem(it)

		# add/update
		for sid, node in new_nodes.items():
			self._upsert_node(node)

		self._rebuild_edges()

		if not self._centered_once:
			if self.agent_items:
				self.view.fit_all(self.scene.itemsBoundingRect(), margin=80)
			else:
				self.view.centerOn(self.c2)
			self._centered_once = True

		"""if not self._centered_once:
			self.view.centerOn(self.c2); self._centered_once = True"""

		self._save_timer.start()

	def _on_ws_upsert(self, s: dict):
		node = self._dict_to_node(s or {})
		self._upsert_node(node)
		self._rebuild_edges()
		self._save_timer.start()

	def _on_ws_remove(self, sid: str):
		if not sid:
			return
		it = self.agent_items.pop(sid, None)
		if it:
			self.scene.removeItem(it)
			self._rebuild_edges()
			self._save_timer.start()

	def _upsert_node(self, node: SessionNode):
		def _scene_rect_of(item: QGraphicsItem) -> QRectF:
			# Use full boundingRect so labels are included
			try:
				return item.mapRectToScene(item.boundingRect())
			except Exception:
				r = getattr(item, "_rect", QRectF(-30, -30, 60, 60))
				return r.translated(item.scenePos())

		def _find_spawn_pos(new_item: AgentItem) -> QPointF:
			"""
			Choose a free position around C2 so the new node doesn't overlap others.
			We scan concentric rings; for each candidate we compute how much it would
			expand the overall union of node rectangles. Pick the one that keeps the
			layout compact while preserving a minimum separation.
			"""
			# Separation based on node footprint
			w = new_item._rect.width()
			h = new_item._rect.height()
			min_sep = max(SPAWN_MIN_SEP_FLOOR, max(w, h) * 1.15)  # padding

			# C2 center in scene coords (its local origin is already the center)
			c2c = self.c2.scenePos()

			# Start radius just outside the C2 icon + a bit
			c2_half = max(getattr(self.c2, "_rect", QRectF(-30, -30, 60, 60)).width(),
			              getattr(self.c2, "_rect", QRectF(-30, -30, 60, 60)).height()) * 0.5
			r0 = max(SPAWN_RING_START, c2_half + min_sep * 0.9)

			# Existing agents (positions & scene rects)
			existing_items = [it for it in self.agent_items.values() if it is not new_item]
			existing_pos = [it.pos() for it in existing_items]

			# Base union of current items (C2 + existing agents)
			union = _scene_rect_of(self.c2)
			for it in existing_items:
				union = union.united(_scene_rect_of(it))
			base_w, base_h = union.width(), union.height()

			best = None  # (score, QPointF)

			# Try rings; choose best score
			max_rings = 30
			for ring in range(max_rings):
				r = r0 + ring * SPAWN_RING_STEP
				circ = 2.0 * math.pi * r
				slots = max(8, int(circ / (min_sep * 1.05)))
				angle_offset = (ring * 0.37) % (2.0 * math.pi)  # golden-ish twist

				for s in range(slots):
					ang = angle_offset + (s / float(slots)) * (2.0 * math.pi)
					cand = QPointF(c2c.x() + math.cos(ang) * r,
					               c2c.y() + math.sin(ang) * r)

					# Enforce minimum separation
					nearest = float("inf")
					ok = True
					for p in existing_pos:
						d = QLineF(cand, p).length()
						nearest = min(nearest, d)
						if d < min_sep:
							ok = False
							break
					if not ok:
						continue

					# Compute union growth if we placed here
					# (translate the new item's bounding rect to 'cand')
					br_local = new_item.boundingRect()
					br_scene = br_local.translated(cand)
					new_union = union.united(br_scene)
					dw = new_union.width()  - base_w
					dh = new_union.height() - base_h

					# Score: prefer *compact* footprint (small dw/dh), then spacing.
					# Tune weights to taste.
					spread_penalty = (dw * 1.2) + (dh * 1.0)
					spacing_reward = min(nearest - min_sep, 1000.0) * 0.05

					# Tiny nudge to place slightly *below* the nearest neighbor
					# (helps to avoid label overlaps when there’s just one neighbor).
					nudge = 0.0
					if existing_pos:
						# nearest neighbor y delta (positive means “below”)
						y_deltas = sorted((cand.y() - p.y() for p in existing_pos),
						                  key=lambda v: abs(v))
						if y_deltas:
							nudge = (0.02 if y_deltas[0] > 0 else -0.02)

					score = -spread_penalty + spacing_reward + nudge

					if (best is None) or (score > best[0]):
						best = (score, cand)

				# Early exit: if we already found a candidate on an inner ring
				# with zero union growth (perfect compact fit), take it.
				if best is not None and best[0] > -1e-6:
					break

			if best is not None:
				return best[1]

			# Fallback: old grid (should rarely happen)
			idx = len(self.agent_items)
			spacing = min_sep * 1.25
			return QPointF(c2c.x() + (idx % 10) * spacing - 5 * spacing,
			                c2c.y() + (idx // 10) * (spacing * 0.7))

		item = self.agent_items.get(node.sid)
		if item is None:
			item = AgentItem(node)
			item.open_console.connect(self._emit_open_console)
			item.open_gunnershell.connect(self._emit_open_gunnershell)
			item.kill_session.connect(self._emit_kill_session)
			item.position_changed.connect(lambda: self._save_timer.start())
			self.scene.addItem(item)
			self.agent_items[node.sid] = item
			# position (persisted or basic layout)
			pos = self._positions_cache.get(node.sid)
			if pos:
				item.setPos(QPointF(pos[0], pos[1]))
			else:
				# NEW: smart first-time placement around C2, avoiding other agents
				item.setPos(_find_spawn_pos(item))
		else:
			item.node = node
			clean_user = _strip_host_prefix(node.username, node.hostname)
			item._label.setText(f"{clean_user}@{node.hostname}")
			item._label.setPos(-item._label.boundingRect().width()/2, item._rect.height()/2 + 6)
			#item._label.setPos(-item._label.boundingRect().width()/2, NODE_H/2 + 6)

	# ----- persistence -----
	def _load_positions(self) -> Dict[str, Tuple[float, float]]:
		try:
			with open(PERSIST_PATH, "r", encoding="utf-8") as f:
				data = json.load(f)
				if isinstance(data, dict):
					return {k: tuple(v) for k, v in data.items() if isinstance(v, list) and len(v) == 2}
		except Exception:
			pass
		return {}

	def _save_positions(self):
		data = {}
		for sid, item in self.agent_items.items():
			p = item.pos()
			data[sid] = [float(p.x()), float(p.y())]
		try:
			with open(PERSIST_PATH, "w", encoding="utf-8") as f:
				json.dump(data, f, indent=2)
		except Exception:
			pass

	# hook to save after user moves a node (debounced)
	def mouseReleaseEvent(self, e):
		super().mouseReleaseEvent(e)
		self._save_timer.start()

	# ----- signal emitters -----
	def _emit_open_console(self, sid: str, host: str):
		self.open_console_requested.emit(sid, host)

	def _emit_open_gunnershell(self, sid: str, host: str):
		self.open_gunnershell_requested.emit(sid, host)

	def _emit_kill_session(self, sid: str, host: str):
		self.kill_session_requested.emit(sid, host)