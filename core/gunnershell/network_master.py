import ntpath
import os
from core.session_handlers import session_manager
from core import shell
from colorama import Style, Fore

brightgreen = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred   = Style.BRIGHT + Fore.RED

def netstat(sid, os_type):
    """
    Show network connections on the remote host, very similar to Meterpreter's 'netstat'.

    - sid:     the real session ID
    - os_type: session.metadata.get("os") lower‐cased ("windows" vs. "linux")

    Returns the raw output of the appropriate netstat command.
    """
    # resolve display name
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    # pick the right command
    if "windows" in os_type:
        # -a all, -n numeric, -o include PID
        cmd = "Get-NetTCPConnection | Select-Object @{n='Proto';e={$_.Protocol}},@{n='Local';e={$_.LocalAddress+':'+$_.LocalPort}},@{n='Remote';e={$_.RemoteAddress+':'+$_.RemotePort}},State,@{n='PID';e={$_.OwningProcess}},@{n='Program';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize"
    else:
        # -t tcp, -u udp, -n numeric, -a all, -p show PID/program name, -e extra
        cmd = "netstat -tunape"

    # look up session
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    # dispatch over HTTP(S) or TCP/TLS
    transport = sess.transport.lower()
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    else:
        out = shell.run_command_tcp(sid, cmd, timeout=5)

    # ensure we at least return an empty string
    return out or None

# stubs for the other Meterpreter-style cmds you mentioned
def arp(sid, os_type):
    """
    Display the host ARP cache.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" in os_type:
        cmd = "arp -a"

    else:
        cmd = "ip neigh show"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        return shell.run_command_http(sid, cmd) or None

    else:
        return shell.run_command_tcp(sid, cmd, timeout=0.5) or None

def ipconfig(sid, os_type):
    """
    Display network interfaces on the remote host:
      - Windows: ipconfig /all
      - Linux/macOS: ifconfig -a
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    # pick command by OS
    if "windows" in os_type:
        cmd = "ipconfig /all"
    else:
        cmd = "ifconfig -a"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    # dispatch over HTTP(S) or TCP/TLS, with a slightly longer timeout on Windows
    if sess.transport.lower() in ("http", "https"):
        return shell.run_command_http(sid, cmd) or None
    else:
        timeout = 2.0 if "windows" in os_type else 0.5
        return shell.run_command_tcp(sid, cmd, timeout=timeout) or None

def resolve(sid, os_type, hostname):
    """
    Resolve a DNS name on the target.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" in os_type.lower():
        cmd = f"nslookup {hostname}"

    else:
        cmd = f"getent hosts {hostname} || host {hostname}"
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        return shell.run_command_http(sid, cmd) or None

    else:
        return shell.run_command_tcp(sid, cmd, timeout=0.5) or None

def route(sid, os_type):
    """
    View the routing table.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" in os_type:
        cmd = "route print"

    else:
        cmd = "ip route show"
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        return shell.run_command_http(sid, cmd) or None

    else:
        return shell.run_command_tcp(sid, cmd, timeout=0.5) or None

def getproxy(sid, os_type):
    """
    Display the current proxy configuration on the remote host.
    - Windows:  netsh winhttp show proxy
    - Linux/macOS: print any HTTP(S)_PROXY vars
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        cmd = "netsh winhttp show proxy"
    else:
        # catch both lowercase and uppercase env vars
        cmd = "env | grep -i proxy || echo No proxy vars set"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        return shell.run_command_http(sid, cmd) or None
    else:
        # give a bit longer in case env takes a moment
        return shell.run_command_tcp(sid, cmd, timeout=1) or None