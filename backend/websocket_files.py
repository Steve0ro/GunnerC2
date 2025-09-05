# backend/websocket_files.py
from __future__ import annotations
import asyncio, json, os, ntpath, tempfile, time, shutil
from typing import Any, Dict, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import jwt

from contextlib import suppress

from . import config
from core.session_handlers import session_manager
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec
from transfers.manager import TransferManager, TransferOpts
from .schemas import FileInfo  # reuse your model

router = APIRouter()

# ----------------- shared helpers -----------------
async def _ws_send(ws: WebSocket, payload: Dict[str, Any]):
    try:
        await ws.send_text(json.dumps(payload, separators=(",", ":"), default=str))
    except WebSocketDisconnect:
        raise
    except Exception:
        pass

def _resolve_sid(sid: str) -> str:
    try:
        if hasattr(session_manager, "resolve_sid"):
            return session_manager.resolve_sid(sid) or sid
    except Exception:
        pass
    return sid

def _run_remote(sid: str, cmd: str, transport: str, timeout: float | None = 10.0) -> str:
    if transport in ("http", "https"):
        return http_exec.run_command_http(sid, cmd, op_id="files", timeout=timeout) or ""
    return tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, portscan_active=True, op_id="files") or ""

def _psq(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"

def _shq(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"

# ----------------- websocket route -----------------
@router.websocket("/ws/files")
async def files_ws(ws: WebSocket):
    await ws.accept()

    # ---- auth (same as sessions ws) ----
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=1008); return
    try:
        jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
    except jwt.InvalidTokenError:
        await ws.close(code=1008); return

    # Per-connection state
    tm = TransferManager()
    active_download_task: Optional[asyncio.Task] = None
    active_upload_tmp: Optional[str] = None
    active_upload_expect: int = 0
    active_upload_sid: Optional[str] = None
    active_upload_remote: Optional[str] = None

    async def _do_list(req: Dict[str, Any]):
        sid = _resolve_sid(req.get("sid",""))
        path = req.get("path","")
        req_id = req.get("req_id")
        sess = session_manager.sessions.get(sid)
        if not sess:
            return await _ws_send(ws, {"type":"error","req_id":req_id,"error":"Session not found"})
        os_type = (getattr(sess,"metadata",{}) or {}).get("os","").lower()
        transport = str(getattr(sess,"transport","")).lower()

        if os_type == "windows":
            ps = (
                f"$p = Get-Item -LiteralPath {_psq(path)} -ErrorAction SilentlyContinue; "
                f"if ($null -eq $p) {{ 'MISSING' }} else {{ "
                f"Get-ChildItem -LiteralPath {_psq(path)} -Force | "
                f"Select-Object @{ '{' }n='name';e={{$_.Name}}{ '}' }, "
                f"@{ '{' }n='is_dir';e={{$_.PSIsContainer}}{ '}' }, "
                f"@{ '{' }n='size';e={{ if ($_.PSIsContainer) {{ $null }} else {{ [int64]$_.Length }} }}{ '}' } "
                f"| ConvertTo-Json -Compress -Depth 2 }}"
            )
            out = _run_remote(sid, ps, transport)
            if "MISSING" in out:
                return await _ws_send(ws, {"type":"fs.list","req_id":req_id,"path":path,"entries":[]})
            try:
                rows = json.loads(out) if out.strip().startswith("[") else []
            except Exception:
                rows = []
            return await _ws_send(ws, {"type":"fs.list","req_id":req_id,"path":path,"entries":rows})

        # Linux/posix
        sh = (
            "bash -lc " +
            _shq(
                "P=%s;"
                "if [ ! -d \"$P\" ]; then echo MISSING; exit 0; fi; "
                "(find \"$P\" -maxdepth 1 -mindepth 1 -printf '%f\t%y\t%s\n' 2>/dev/null) || ("
                "shopt -s dotglob; "
                "for f in \"$P\"/* \"$P\"/.[!.]* \"$P\"/..?*; do "
                "[ -e \"$f\" ] || continue; "
                "bn=$(basename \"$f\"); "
                "if [ -d \"$f\" ]; then printf '%s\td\t0\n' \"$bn\"; "
                "else sz=$(stat -c %s \"$f\" 2>/dev/null || wc -c <\"$f\"); "
                "printf '%s\tf\t%s\n' \"$bn\" \"$sz\"; fi; "
                "done)"
            ) % path
        )
        out = _run_remote(sid, sh, transport)
        if "MISSING" in (out or ""):
            return await _ws_send(ws, {"type":"fs.list","req_id":req_id,"path":path,"entries":[]})

        entries = []
        for line in (out or "").splitlines():
            name, typ, sz = (line.split("\t") + ["","",""])[:3]
            entries.append({"name": name, "is_dir": typ.lower().startswith("d"), "size": None if typ.lower().startswith("d") else int(sz or 0)})
        await _ws_send(ws, {"type":"fs.list","req_id":req_id,"path":path,"entries":entries})

    async def _do_download(req: Dict[str, Any]):
        nonlocal active_download_task
        if active_download_task and not active_download_task.done():
            return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"Download already in progress on this socket"})

        sid = _resolve_sid(req.get("sid",""))
        path = req.get("path","")
        req_id = req.get("req_id")
        sess = session_manager.sessions.get(sid)
        if not sess:
            return await _ws_send(ws, {"type":"error","req_id":req_id,"error":"Session not found"})
        os_type = (getattr(sess,"metadata",{}) or {}).get("os","").lower()

        tmp_dir = tempfile.mkdtemp(prefix="gc2_dl_ws_")
        fname = (ntpath.basename(path) if os_type=="windows" or "\\" in path else os.path.basename(path)) or "file.bin"
        dest = os.path.join(tmp_dir, fname)

        # kick off transfer manager
        tid = tm.start_download(sid, path, dest, folder=False, opts=TransferOpts(quiet=True))
        await _ws_send(ws, {"type":"fs.download.begin","req_id":req_id,"tid":tid,"name":fname})

        async def _pump():
            try:
                last = 0
                part_path = None
                while True:
                    st = tm.store.load(sid, tid)
                    if st.status == "done" and os.path.exists(st.local_path):
                        src = st.local_path
                    else:
                        part_path = part_path or st.tmp_local_path
                        src = part_path

                    if os.path.exists(src):
                        # stream any new bytes since last
                        try:
                            with open(src, "rb") as f:
                                f.seek(last)
                                chunk = f.read(1024*256)
                                while chunk:
                                    last += len(chunk)
                                    await ws.send_bytes(chunk)
                                    chunk = f.read(1024*256)
                        except Exception:
                            pass

                    if st.status in ("done", "error", "cancelled", "paused"):
                        await _ws_send(ws, {"type":"fs.download.end","tid":tid,"status":st.status,"error":st.error})
                        break
                    await asyncio.sleep(0.12)
            finally:
                try: shutil.rmtree(tmp_dir, ignore_errors=True)
                except Exception: pass

        active_download_task = asyncio.create_task(_pump())

    async def _do_upload_begin(req: Dict[str, Any]):
        nonlocal active_upload_tmp, active_upload_expect, active_upload_sid, active_upload_remote
        if active_upload_tmp is not None:
            return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"Upload already in progress on this socket"})

        sid = _resolve_sid(req.get("sid",""))
        remote = req.get("remote_path","")
        size = int(req.get("size") or 0)
        if not sid or not remote or size <= 0:
            return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"Missing sid/remote_path/size"})

        fd, tmp_path = tempfile.mkstemp(prefix="gc2_ul_ws_")
        os.close(fd)
        active_upload_tmp = tmp_path
        active_upload_expect = size
        active_upload_sid = sid
        active_upload_remote = remote
        await _ws_send(ws, {"type":"fs.upload.accept","req_id":req.get("req_id")})

    async def _do_upload_finish():
        nonlocal active_upload_tmp, active_upload_expect, active_upload_sid, active_upload_remote
        # start TM upload and wait for completion
        tid = tm.start_upload(active_upload_sid, active_upload_tmp, active_upload_remote, folder=False, opts=TransferOpts(quiet=True))
        terminal = {"done","error","cancelled"}
        while True:
            st = tm.store.load(active_upload_sid, tid)
            if (st.status or "").lower() in terminal:
                await _ws_send(ws, {"type":"fs.upload.result","tid":tid,"status":st.status,"error":st.error})
                break
            await asyncio.sleep(0.2)
        # cleanup temp
        try: os.remove(active_upload_tmp)
        except Exception: pass
        active_upload_tmp = None
        active_upload_expect = 0
        active_upload_sid = None
        active_upload_remote = None

    # ---------- main loop ----------
    try:
        # state for receiving upload binary frames
        recv_written = 0
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.receive":
                if "text" in msg:
                    try:
                        req = json.loads(msg["text"])
                    except Exception:
                        await _ws_send(ws, {"type":"error","error":"Invalid JSON"})
                        continue
                    act = (req.get("action") or "").lower()

                    if act in ("fs.list","list"):
                        await _do_list(req)
                    elif act in ("fs.download","download"):
                        await _do_download(req)
                    elif act in ("fs.upload.begin","upload.begin"):
                        recv_written = 0
                        await _do_upload_begin(req)
                    elif act in ("fs.upload.finish","upload.finish"):
                        if active_upload_tmp is None:
                            await _ws_send(ws, {"type":"error","error":"No upload in progress"})
                        else:
                            await _do_upload_finish()
                    elif act in ("ping",):
                        await _ws_send(ws, {"type":"pong","req_id":req.get("req_id")})
                    else:
                        await _ws_send(ws, {"type":"error","error":f"Unknown action '{act}'"})
                elif "bytes" in msg:
                    # binary frame: part of an upload
                    if active_upload_tmp is None:
                        # ignore stray binary
                        continue
                    data: bytes = msg["bytes"]
                    try:
                        with open(active_upload_tmp, "ab") as f:
                            f.write(data)
                        recv_written += len(data)
                        await _ws_send(ws, {"type":"fs.upload.progress","written":recv_written,"total":active_upload_expect})
                        if active_upload_expect and recv_written >= active_upload_expect:
                            # auto-finish if size reached
                            await _do_upload_finish()
                    except Exception as e:
                        await _ws_send(ws, {"type":"error","error":f"Upload write failed: {e}"})
                        # reset
                        try: 
                            if active_upload_tmp: os.remove(active_upload_tmp)
                        except Exception: pass
                        active_upload_tmp = None
                        active_upload_expect = 0
                        active_upload_sid = None
                        active_upload_remote = None
            elif msg["type"] == "websocket.disconnect":
                break
    except WebSocketDisconnect:
        pass
    finally:
        # stop any background download streamer
        if active_download_task:
            active_download_task.cancel()
            with suppress(asyncio.CancelledError):
                await active_download_task
