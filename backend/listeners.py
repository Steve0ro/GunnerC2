# backend/listeners.py
from fastapi import APIRouter, HTTPException
from typing import Dict

from core.listeners.base import load_listeners, create_listener
from .schemas import NewListenerRequest, ListenerOut

router = APIRouter()

load_listeners()
_RUNNING: Dict[str, object] = {}

def _serialize_listener(inst) -> ListenerOut:
    return {
        "id": getattr(inst, "id", ""),
        "type": getattr(inst, "transport", ""),
        "bind_ip": getattr(inst, "ip", ""),
        "port": getattr(inst, "port", 0),
        "status": "RUNNING" if getattr(inst, "thread", None) and getattr(inst.thread, "is_alive", lambda: False)() else "STARTED",
        "profile": getattr(inst, "profiles", None) or None,
    }

@router.get("", response_model=list[ListenerOut])
def list_listeners():
    return [_serialize_listener(inst) for inst in _RUNNING.values()]

@router.post("", response_model=ListenerOut)
def start_listener(req: NewListenerRequest):
    try:
        inst = create_listener(req.bind_ip, req.port, req.type.lower(), profiles=req.profile)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to start listener: {e}")
    lid = getattr(inst, "id", "")
    if not lid:
        raise HTTPException(status_code=500, detail="Listener missing ID")
    _RUNNING[lid] = inst
    return _serialize_listener(inst)

@router.delete("/{listener_id}")
def stop_listener(listener_id: str):
    inst = _RUNNING.get(listener_id)
    if not inst:
        raise HTTPException(status_code=404, detail="Listener not found")
    for attr in ("stop", "shutdown", "close"):
        fn = getattr(inst, attr, None)
        if callable(fn):
            try:
                fn()
                break
            except Exception:
                pass
    _RUNNING.pop(listener_id, None)
    return {"status": "stopped", "id": listener_id}
