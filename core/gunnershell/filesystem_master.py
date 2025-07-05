import sys
import readline
import os
import shlex
import argparse
import subprocess
import shutil

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
        out =  shell.run_command_tcp(sid, cmd, timeout=0.5)
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
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

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
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

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
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    else:
        print(brightred + f"[!] Unsupported shell type: {transport}")
        return None

    return out or None

def cp(sid, os_type, src, dst):
    """
    Copy a file on the remote host.
      * Windows: uses PowerShell Copy-Item
      * Linux:   uses cp -f
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        # -Force to overwrite
        cmd = f"Copy-Item -Path \"{src}\" -Destination \"{dst}\" -Force"

    elif "linux" in os_type:
        cmd = f"cp -f \"{src}\" \"{dst}\""

    else:
        print(brightred + f"[!] Unsupported OS on {display}")
        return ""

    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return ""

    if sess.transport.lower() in ("http","https"):
        out = shell.run_command_http(sid, cmd)

    elif sess.transport.lower() in ("tls", "tcp"):
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    else:
        print(brightred + f"[!] Unsupported shell type: {transport}")
        return None

    return out or None

def delete(sid, os_type, path):
    """
    Delete a file on the remote host.

    - sid:      the real session ID
    - os_type:  session.metadata.get("os") lower‐cased ("windows" vs. "linux")
    - path:     file to delete

    Returns the raw output from the remote command, or None on error.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        # PowerShell: remove the item
        cmd = f'Remove-Item -LiteralPath "{path}" -Force'

    elif "linux" in os_type:
        cmd = f'rm -f "{path}"'

    else:
        print(brightred + f"[!] Unsupported operating system on {display}")
        return None

    sess = session_manager.sessions.get(sid)

    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return None

    transport = sess.transport.lower()
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    else:
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    return out or None

def mkdir(sid, os_type, path):
    """
    Create a directory on the remote host.

    - sid:      the real session ID
    - os_type:  session.metadata.get("os") lower-cased
    - path:     directory to create

    Returns raw output or None on error.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        # PowerShell: make folder
        cmd = f'New-Item -ItemType Directory -Force -Path "{path}"'

    elif "linux" in os_type:
        cmd = f'mkdir -p "{path}"'

    else:
        print(brightred + f"[!] Unsupported OS on {display}")
        return None

    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return None

    if sess.transport.lower() in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    else:
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    return out or None

def touch(sid, os_type, path):
    """
    Create an empty file on the remote host (or update timestamp).

    - sid:      the real session ID
    - os_type:  session.metadata.get("os") lower-cased
    - path:     file path to touch

    Returns raw output or None on error.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        cmd = f'if (Test-Path "{path}") {{ (Get-Item "{path}").LastWriteTime = Get-Date }} else {{ New-Item -ItemType File -Force -Path "{path}" }}'

    elif "linux" in os_type:
        cmd = f'touch "{path}"'

    else:
        print(brightred + f"[!] Unsupported OS on {display}")
        return None

    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return None

    if sess.transport.lower() in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    else:
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    return out or None

def mv(sid, os_type, src, dst):
    """
    Move or rename a file/directory on the remote host.
    - Windows: uses PowerShell Move-Item
    - Linux:   uses mv -f
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        cmd = f"Move-Item -LiteralPath \"{src}\" -Destination \"{dst}\" -Force"

    elif "linux" in os_type:
        cmd = f"mv -f \"{src}\" \"{dst}\""

    else:
        print(brightred + f"[!] Unsupported OS on {display}")
        return None

    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return None

    transport = sess.transport.lower()
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    else:
        print(brightred + f"[!] Unsupported shell type: {transport}")
        return None

    return out or None


def rmdir(sid, os_type, path):
    """
    Remove a directory on the remote host.
    - Windows: PowerShell Remove-Item -Recurse -Force
    - Linux:   rm -rf
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        cmd = f"Remove-Item -LiteralPath \"{path}\" -Recurse -Force"

    elif "linux" in os_type:
        cmd = f"rm -rf \"{path}\""

    else:
        print(brightred + f"[!] Unsupported OS on {display}")
        return None

    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return None

    transport = sess.transport.lower()
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    else:
        print(brightred + f"[!] Unsupported shell type: {transport}")
        return None

    return out or None


def checksum(sid, os_type, path):
    """
    Compute a SHA256 checksum of a file on the remote host.
    - Windows: Get-FileHash -Algorithm SHA256
    - Linux:   sha256sum
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        cmd = f"(Get-FileHash -Algorithm SHA256 -Path \"{path}\").Hash"

    elif "linux" in os_type:
        cmd = f"sha256sum \"{path}\""

    else:
        print(brightred + f"[!] Unsupported OS on {display}")
        return None

    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return None

    transport = sess.transport.lower()
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    else:
        print(brightred + f"[!] Unsupported shell type: {transport}")
        return None

    return out or None


def drives(sid, os_type):
    """
    List mounted drives / filesystems on the remote host.

    - sid:      the real session ID
    - os_type:  session.metadata.get("os") lower‐cased ("windows" vs. "linux")

    Returns the raw output from the remote command, or None on error.
    """
    # resolve display name for errors
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        # PowerShell: only filesystem drives
        cmd = "Get-PSDrive -PSProvider FileSystem | Format-Table Name, Root -AutoSize"

    elif "linux" in os_type:
        # show all mounted filesystems
        cmd = "df -hT"

    else:
        print(brightred + f"[!] Unsupported operating system on {display}")
        return None

    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return None

    if sess.transport.lower() in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    else:
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    return out or None

def edit(sid, os_type, remote_path):
    """
    Download a remote file, verify it’s text, open it in $EDITOR (or nano), then re-upload it.
    Returns a status message.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    sess = session_manager.sessions.get(sid)
    if not sess:
        return f"[!] No such session: {display}"

    # choose download/upload functions
    is_http = sess.transport.lower() in ("http", "https")
    dl = shell.download_file_http if is_http else shell.download_file_tcp
    ul = shell.upload_file_http   if is_http else shell.upload_file_tcp

    # create a temp file
    fname = os.path.basename(remote_path)
    fd, local_tmp = tempfile.mkstemp(prefix="gunner-edit-", suffix="-"+fname)
    os.close(fd)

    # download the remote file
    try:
        dl(sid, remote_path, local_tmp)

    except Exception as e:
        os.remove(local_tmp)
        return f"[!] Failed to download {remote_path}: {e}"

    # quick "is-text" sniff: look for any NUL byte in the first 8KiB
    try:
        with open(local_tmp, "rb") as f:
            sample = f.read(8192)

        if b"\x00" in sample:
            os.remove(local_tmp)
            return "[!] File appears to be binary, edit aborted"

    except Exception as e:
        os.remove(local_tmp)
        return f"[!] Couldn’t read temp file: {e}"

    # launch your editor
    # pick a local editor by probing common names
    editors = ["nano", "vim", "vi", "code", "notepad"]  # adjust to taste
    for ed in editors:
        if shutil.which(ed):
            editor = ed
            break
    else:
        os.remove(local_tmp)
        return "[!] No editor found (tried: {})".format(", ".join(editors))

    # launch the chosen editor
    try:
        subprocess.call([editor, local_tmp])

    except Exception as e:
        os.remove(local_tmp)
        return f"[!] Failed to launch editor ({editor}): {e}"

    # re-upload
    try:
        ul(sid, local_tmp, remote_path)
        
    except Exception as e:
        os.remove(local_tmp)
        return f"[!] Failed to re-upload {remote_path}: {e}"

    # cleanup & done
    os.remove(local_tmp)
    return f"Edited and re-uploaded {remote_path}"



def search(sid: str, pattern: str) -> str:
    return _run_remote(sid, f"find . -iname '*{pattern}*'")


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
