# backend/payloads.py
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from core.payload_generator.windows.https.ps1.powershell_reverse_https import make_raw as ps_rev_https
from core.payload_generator.windows.http.ps1.powershell_reverse_http import make_raw as ps_rev_http
from core.payload_generator.linux.tcp import bash_reverse_tcp
from core.payload_generator.linux.http import bash_reverse_http

router = APIRouter()

@router.get("/windows/ps1")
def win_ps1(transport: str, host: str, port: int, beacon: int = 5):
    t = transport.lower()
    try:
        if t == "https":
            payload = ps_rev_https(host, port, beacon_interval=beacon, headers=None, useragent=None, accept=None, byte_range=None, jitter=None, profile=None)
        elif t == "http":
            payload = ps_rev_http(host, port, beacon_interval=beacon, headers=None, useragent=None, accept=None, byte_range=None, jitter=None, profile=None)
        else:
            raise HTTPException(status_code=400, detail="transport must be http or https")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return PlainTextResponse(payload)

@router.get("/linux/bash")
def linux_bash(transport: str, host: str, port: int):
    t = transport.lower()
    try:
        if t == "tcp":
            payload = bash_reverse_tcp(host, port)
        elif t == "http":
            payload = bash_reverse_http(host, port)
        else:
            raise HTTPException(status_code=400, detail="transport must be tcp or http")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return PlainTextResponse(payload)
