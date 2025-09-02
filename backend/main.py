# backend/main.py
import os, sys
# Ensure the project root (the parent of this file's folder) is on sys.path when run directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ensure auth DB is initialized via your auth_manager
from core.teamserver import auth_manager as auth

# 🔧 use relative imports inside the backend package
from .auth import router as auth_router
from .listeners import router as listeners_router
from .sessions import router as sessions_router
from .files import router as files_router
from .payloads import router as payloads_router
from .websocket_console import router as ws_router
from .websocket_gunnershell import router as gs_router

app = FastAPI(title="GunnerC2 Integrated API", version="1.0")

# CORS: allow GUI app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def _startup():
    # Open DB / create schema / ensure default admin if empty (auth_manager handles this gracefully)
    auth._connect()
    ops = auth.list_operators() or []
    if not ops:
        auth.add_operator("admin", "admin", "admin")

# Routers
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(listeners_router, prefix="/listeners", tags=["listeners"])
app.include_router(sessions_router, prefix="/sessions", tags=["sessions"])
app.include_router(files_router, prefix="/files", tags=["files"])
app.include_router(payloads_router, prefix="/payloads", tags=["payloads"])
app.include_router(ws_router, tags=["websocket"])
app.include_router(gs_router, tags=["websocket"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("GUNNER_BACKEND_PORT", "8000")))
