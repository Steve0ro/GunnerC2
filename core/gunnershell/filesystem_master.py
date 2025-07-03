import sys
import readline
import os
import shlex
import argparse
import subprocess

from core import shell, utils
from core.session_handlers import session_manager, sessions
from core.utils import portforwards, unregister_forward, list_forwards, defender
from core.shell import *

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
COLOR_RESET  = "\001\x1b[0m\002"

def _run_remote(sid: str, cmd: str) -> str:
    """
    Helper that picks HTTP vs TCP automatically.
    """
    sess = session_manager.sessions[sid]
    if sess.transport in ("http", "https"):
        return shell.run_command_http(sid, cmd) or ""
    else:
        return shell.run_command_tcp(sid, cmd) or ""


def ls(sid, os_type, path):
    """
    List files on the remote host.
    
    - sid:       the real session ID
    - os_type:   session.metadata.get("os") lower-cased ("windows" vs. "linux")
    - path:      directory or file to list
    
    Returns the raw output from the remote command.
    """
    # build the correct command for the OS
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        # /B gives bare format, /A shows all files (including hidden)
        cmd = f"Get-ChildItem \"{path}\""

    elif "linux" in os_type:
        cmd = f"ls -la \"{path}\""

    else:
        print(brightred + f"[!] Unsupported operating system on {display}")

    # pick the right transport
    sess = session_manager.sessions[sid]
    if sess.transport.lower() in ("http", "https"):
        out = shell.run_command_http(sid, cmd)
        return out

    elif sess.transport.lower() in ("tcp", "tls"):
        out =  shell.run_command_tcp(sid, cmd)
        return out

    else:
        try:
            print(brightred + f"[!] Unsupported shell type: {sess.transport.lower()}")

        except Exception as e:
            print(brightred + f"[!] An unknown error has ocurred: {e}")

def pwd(sid, os_type):
    """
    Print the remote working directory.

    - sid:      the real session ID
    - os_type:  session.metadata.get("os") lower-cased ("windows" vs. "linux")

    Returns the raw output from the remote command.
    """
    # resolve display name
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    # pick the right command
    if "windows" in os_type:
        # 'cd' via cmd.exe prints the current dir
        cmd = '(Get-Location).Path'

    elif "linux" in os_type:
        cmd = "pwd"

    else:
        print(brightred + f"[!] Unsupported operating system on {display}")
        return ""

    # look up session
    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return ""

    # send it via HTTP(S) or TCP/TLS
    transport = sess.transport.lower()
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, cmd)

    else:
        print(brightred + f"[!] Unsupported shell type: {transport}")
        return ""

    if out:
        return out

    else:
        return None

def cd(sid, os_type, path):
    """
    Change the remote working directory and return the new cwd.

    - sid:      the real session ID
    - os_type:  session.metadata.get("os") lower‐cased ("windows" vs. "linux")
    - path:     directory to cd into

    Returns the new cwd on success, or None on failure.
    """
    # resolve display name for error messages
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    # build the correct command for the OS
    if "windows" in os_type:
        # /d allows changing drive and directory, then print %CD%
        cmd = f"Set-Location -LiteralPath \"{path}\"; (Get-Location).Path"

    elif "linux" in os_type:
        cmd = f"cd \"{path}\" && pwd"

    else:
        print(brightred + f"[!] Unsupported operating system on {display}")
        return None

    # look up session
    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return None

    # send it via HTTP(S) or TCP/TLS
    transport = sess.transport.lower()
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, cmd)

    else:
        print(brightred + f"[!] Unsupported shell type: {transport}")
        return None

    # return the new cwd if we got one
    if out:
        return out

    else:
        return None



def cat(sid, os_type, path):
    """
    Print the contents of a file on the remote host.

    - sid:      the real session ID
    - os_type:  session.metadata.get("os") lower‐cased ("windows" vs. "linux")
    - path:     path to the file to read

    Returns the raw output from the remote command, or None on error.
    """
    # resolve display name for error messages
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    # build the correct command for the OS
    if "windows" in os_type:
        # PowerShell: get the file contents
        cmd = f"Get-Content -LiteralPath \"{path}\""

    elif "linux" in os_type:
        cmd = f"cat \"{path}\""

    else:
        print(brightred + f"[!] Unsupported operating system on {display}")
        return None

    # look up session
    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return None

    # send it via HTTP(S) or TCP/TLS
    transport = sess.transport.lower()
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, cmd)
        
    else:
        print(brightred + f"[!] Unsupported shell type: {transport}")
        return None

    return out or None

def rm(sid: str, path: str) -> str:
    return _run_remote(sid, f"rm -f {path}")

def mkdir(sid: str, path: str) -> str:
    return _run_remote(sid, f"mkdir -p {path}")

def mv(sid: str, src: str, dst: str) -> str:
    return _run_remote(sid, f"mv {src} {dst}")

def cp(sid: str, src: str, dst: str) -> str:
    return _run_remote(sid, f"cp {src} {dst}")

def search(sid: str, pattern: str) -> str:
    return _run_remote(sid, f"find . -iname '*{pattern}*'")

def checksum(sid: str, path: str) -> str:
    return _run_remote(sid, f"sha256sum {path}")

def show_mount(sid: str) -> str:
    return _run_remote(sid, "mount")

#
# — Local operations (aliases for l* commands) —
#
def lls(path: str = "."):
    return "\n".join(os.listdir(path))

def ldir(path: str = "."):
    return lls(path)

def lpwd():
    return os.getcwd()

def lcd(path: str):
    os.chdir(path)
    return lpwd()

def lcat(path: str):
    with open(path, "r", errors="ignore") as f:
        return f.read()

def lmkdir(path: str):
    os.makedirs(path, exist_ok=True)
    return f"Created local directory {path}"
