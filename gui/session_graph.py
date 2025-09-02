from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import (
    QPoint, QPointF, QRectF, Qt, pyqtSignal, QSize, QTimer, QLineF, QEvent
)
from PyQt5.QtGui import (
    QBrush, QColor, QFont, QPainter, QPainterPath, QPen
)
from PyQt5.QtWidgets import (
    QGraphicsItem, QGraphicsObject, QGraphicsScene, QGraphicsSimpleTextItem,
    QGraphicsView, QHBoxLayout, QMenu, QPushButton, QStyleOptionGraphicsItem,
    QWidget, QScrollBar
)


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

NODE_W = 86
NODE_H = 66
NODE_RADIUS = 10

C2_SIZE = QSize(60, 60)
PROTOCOL_FONT = QFont("DejaVu Sans Mono", 10, QFont.DemiBold)
LABEL_FONT = QFont("DejaVu Sans", 9)
TITLE_FONT = QFont("DejaVu Sans", 9, QFont.Bold)

PERSIST_PATH = os.path.expanduser("~/.gunnerc2_graph_positions.json")

# ---- interaction tuning ----
DBLCLICK_BASE_TARGET_ZOOM = 2.0   # minimum zoom to reach on double click
DBLCLICK_ANIM_STEPS = 10          # frames
DBLCLICK_ANIM_INTERVAL_MS = 16    # ~160ms total

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
    """Minimal firewall+flame icon (C2)"""
    p.save()
    p.setRenderHint(QPainter.Antialiasing, True)
    # brick wall
    wall = QRectF(rect.left()+6, rect.top()+18, rect.width()-20, rect.height()-18)
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(QColor(140, 28, 28)))
    p.drawRoundedRect(wall, 6, 6)

    # mortar lines
    p.setPen(QPen(QColor(90, 10, 10), 2))
    rows = 3
    for r in range(1, rows+1):
        y = wall.top() + r * wall.height()/(rows+1)
        p.drawLine(QLineF(wall.left()+4, y, wall.right()-4, y))
    p.drawLine(QLineF(wall.left()+4, wall.center().y(), wall.right()-4, wall.center().y()))

    # vertical brick separators
    for col in (0.25, 0.5, 0.75):
        x = wall.left() + wall.width()*col
        p.drawLine(QLineF(x, wall.top()+4, x, wall.bottom()-4))

    # flame
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
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemSendsScenePositionChanges, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.OpenHandCursor)
        self._rect = QRectF(-NODE_W/2, -NODE_H/2, NODE_W, NODE_H)
        clean_user = _strip_host_prefix(node.username, node.hostname)
        self._label = QGraphicsSimpleTextItem(f"{clean_user}@{node.hostname}", self)
        self._label.setBrush(LABEL_GRAY)
        self._label.setFont(LABEL_FONT)
        self._label.setPos(-self._label.boundingRect().width()/2, NODE_H/2 + 6)

    def boundingRect(self) -> QRectF:
        br = self._rect.adjusted(-4, -4, 4, 20)
        # include label
        lb = self._label.mapRectToParent(self._label.boundingRect())
        return br.united(lb)

    def paint(self, p: QPainter, opt: QStyleOptionGraphicsItem, widget=None):
        if self.node.os.lower().startswith("win"):
            _paint_windows_computer(p, self._rect)
        elif self.node.os.lower().startswith("lin"):
            _paint_linux_computer(p, self._rect)
        else:
            # fallback: a neutral monitor
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
        w = C2_SIZE.width()
        h = C2_SIZE.height()
        self._rect = QRectF(-w/2, -h/2, w, h)
        self._edges: List["EdgeItem"] = []  # edges connected to this node
        # small "C2" title above
        self.title = QGraphicsSimpleTextItem("C2", self)
        self.title.setFont(TITLE_FONT)
        self.title.setBrush(QBrush(LABEL_GRAY))
        self.title.setPos(-self.title.boundingRect().width()/2, -h/2 - self.title.boundingRect().height() - 2)

    def boundingRect(self) -> QRectF:
        return self._rect.adjusted(-8, -24, 8, 8)

    def paint(self, p: QPainter, opt: QStyleOptionGraphicsItem, widget=None):
        _paint_firewall(p, self._rect)

    def itemChange(self, change, value):
        # If C2 were ever moved, keep edges crisp
        if change == QGraphicsItem.ItemPositionHasChanged:
            for e in getattr(self, "_edges", []):
                e.refresh()
        return super().itemChange(change, value)


class EdgeItem(QGraphicsItem):
    """Lightweight edge between C2 and an Agent with protocol label."""
    def __init__(self, src: QGraphicsItem, dst: QGraphicsItem, protocol: str):
        super().__init__()
        self.src = src
        self.dst = dst
        self.protocol = (protocol or "").lower()
        self.setZValue(-1)  # behind nodes
        self.setCacheMode(QGraphicsItem.NoCache)

        self.label = QGraphicsSimpleTextItem(self.protocol, self)
        self.label.setFont(PROTOCOL_FONT)
        self.label.setBrush(QBrush(NEON))

        # Track on both endpoints so they can notify us on movement
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

    def refresh(self):
        """Recompute geometry after an endpoint moved."""
        self.prepareGeometryChange()
        a = self.mapFromItem(self.src, 0, 0)
        b = self.mapFromItem(self.dst, 0, 0)
        mid = (a + b) * 0.5
        self.label.setPos(mid.x() - self.label.boundingRect().width()/2,
                          mid.y() - 18)
        self.update()

    def boundingRect(self) -> QRectF:
        a = self.mapFromItem(self.src, 0, 0)
        b = self.mapFromItem(self.dst, 0, 0)
        rect = QRectF(a, b).normalized()
        # give pen width headroom
        rect = rect.adjusted(-12, -12, 12, 12)
        # include label area
        lb = self.label.mapRectToParent(self.label.boundingRect())
        return rect.united(lb)

    def paint(self, p: QPainter, opt: QStyleOptionGraphicsItem, widget=None):
        a = self.mapFromItem(self.src, 0, 0)
        b = self.mapFromItem(self.dst, 0, 0)

        # path
        path = QPainterPath(a)
        path.lineTo(b)

        # style by protocol
        pen = QPen(NEON, 2.6)
        if self.protocol in ("tls", "https"):
            pen.setStyle(Qt.DashLine)
        elif self.protocol == "http":
            pen.setStyle(Qt.DotLine)
        else:
            pen.setStyle(Qt.SolidLine)

        # faint outer glow (double stroke)
        glow = QPen(NEON_DIM, 5.0)
        glow.setStyle(pen.style())
        p.setPen(glow)
        p.drawPath(path)

        p.setPen(pen)
        p.drawPath(path)

        # arrow head pointing to agent
        self._draw_arrow(p, a, b)

        # place label at mid
        mid = (a + b) * 0.5
        self.label.setPos(mid.x() - self.label.boundingRect().width()/2,
                          mid.y() - 18)

    def _draw_arrow(self, p: QPainter, a: QPointF, b: QPointF):
        v = b - a
        L = math.hypot(v.x(), v.y())
        if L < 0.0001:
            return
        ux, uy = v.x()/L, v.y()/L
        size = 8.0
        perp = QPointF(-uy, ux)
        tip = b - QPointF(ux*6, uy*6)
        left = tip - QPointF(ux*size, uy*size) + perp*size*0.6
        right = tip - QPointF(ux*size, uy*size) - perp*size*0.6
        p.setBrush(QBrush(NEON))
        p.drawPolygon(tip, left, right)


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
        speed = 0.7  # tweak pan sensitivity (lower = slower)
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

    # Mouse drag panning (sideways & any direction)
    # Middle button always pans; left button pans only on empty background.
    def mousePressEvent(self, e):
        if e.button() == Qt.MiddleButton or (e.button() == Qt.LeftButton and self.itemAt(e.pos()) is None):
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
            speed = 0.5  # keep mouse-drag panning tame
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


# ---------- main widget ----------
class SessionGraph(QWidget):
    """
    Public widget used by MainWindow.
    Signals mirror actions required by the rest of the GUI.
    """
    open_console_requested = pyqtSignal(str, str)  # sid, hostname
    open_gunnershell_requested = pyqtSignal(str, str)  # sid, hostname
    kill_session_requested = pyqtSignal(str, str)  # sid, hostname

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

        # lazy persistence saver
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(400)  # debounce
        self._save_timer.timeout.connect(self._save_positions)

        # initial load
        self._positions_cache = self._load_positions()
        self.reload()

    # ----- data & layout -----
    def _fetch_sessions(self) -> List[SessionNode]:
        raw = []
        try:
            raw = self.api.list_sessions()
        except Exception:
            pass

        nodes: List[SessionNode] = []
        for s in raw or []:
            sid = s.get("id") or s.get("sid") or ""
            hostname = s.get("hostname") or s.get("host") or "host"
            username = s.get("username") or s.get("user") or "user"
            osname = (s.get("os") or s.get("platform") or "windows").lower()
            protocol = (s.get("protocol") or s.get("transport") or "https").lower()
            nodes.append(SessionNode(sid=sid, hostname=hostname, username=username, os=osname, protocol=protocol))
        return nodes

    def reload(self):
        sessions = self._fetch_sessions()
        present_ids = set(self.agent_items.keys())
        wanted_ids = set(n.sid for n in sessions)

        # remove gone
        for sid in list(present_ids - wanted_ids):
            item = self.agent_items.pop(sid)
            self.scene.removeItem(item)
        # clear edges
        for e in self.edge_items:
            self.scene.removeItem(e)
        self.edge_items.clear()

        # add/update nodes
        for node in sessions:
            item = self.agent_items.get(node.sid)
            if item is None:
                item = AgentItem(node)
                item.open_console.connect(self._emit_open_console)
                item.open_gunnershell.connect(self._emit_open_gunnershell)
                item.kill_session.connect(self._emit_kill_session)
                # track movement to persist
                item.position_changed.connect(lambda: self._save_timer.start())
                self.scene.addItem(item)
                self.agent_items[node.sid] = item
                # position (persisted or layout)
                pos = self._positions_cache.get(node.sid)
                if pos:
                    item.setPos(QPointF(pos[0], pos[1]))
                else:
                    # simple horizontal layout around C2
                    idx = len(self.agent_items) - 1
                    spacing = 220.0
                    x = (idx % 10) * spacing - 5 * spacing
                    row = idx // 10
                    y = row * 140.0 - 140.0
                    item.setPos(x, y)
            else:
                # update label if needed
                item.node = node
                clean_user = _strip_host_prefix(node.username, node.hostname)
                item._label.setText(f"{clean_user}@{node.hostname}")
                item._label.setPos(-item._label.boundingRect().width()/2, NODE_H/2 + 6)

            # make edge from C2 to agent (protocol label on edge)
            edge = EdgeItem(self.c2, item, node.protocol)
            self.scene.addItem(edge)
            self.edge_items.append(edge)

            # register edge on endpoints for live refresh during drags
            item._edges.append(edge)
            try:
                self.c2._edges.append(edge)
            except Exception:
                pass

        # center view on C2 only once (first load)
        if not hasattr(self, "_centered_once"):
            self.view.centerOn(self.c2)
            self._centered_once = True

        # persist soon (in case this is the first layout)
        self._save_timer.start()

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