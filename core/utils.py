import random
import string
import os, sys, subprocess
from core.session_handlers import session_manager, sessions
import re
import readline

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

tcp_listener_sockets = {}
tls_listener_sockets = {}
http_listener_sockets = {}
https_listener_sockets = {}
portforwards = {}

class SessionDefender:
    def __init__(self):
        self.is_active = True

        # commands that spawn a new shell / interpreter on Windows
        self.win_dangerous = {
            "powershell", "powershell.exe", "cmd", "cmd.exe",
            "curl", "wget", "telnet",
            "python", "python3", "php", "ruby", "irb", "perl",
            "jshell", "node", "ghci"
        }

        # editors & shells on Linux + same interpreters
        self.linux_dangerous = {
            "bash", "sh", "zsh", "tclsh",
            "less", "more", "nano", "pico", "vi", "vim", "gedit", "atom", "emacs", "telnet"
        } | self.win_dangerous

        # regexes for unclosed quotes/backticks
        self._pairings = [
            (r"(?<!\\)'", r"'"),
            (r'(?<!\\)"', r'"'),
            (r"(?<!\\)`", r"`"),
        ]

    def inspect_command(self, os_type: str, cmd: str) -> bool:
        """
        Return True if the command is safe to send, False if it should be blocked.
        """

        if not cmd:
            return True

        if not self.is_active:
            return True

        # 1) Unclosed quotes/backticks
        for pattern, char in self._pairings:
            if len(re.findall(pattern, cmd)) % 2 != 0:
                return False

        # 2) Trailing backslash (Linux only)
        if os_type == "linux" and cmd.rstrip().endswith("\\"):
            return False

        # 3) Dangerous binaries
        first = cmd.strip().split()[0].lower()
        if os_type == "windows":
            if first in self.win_dangerous:
                return False
        else:
            if first in self.linux_dangerous:
                return False

        # safe
        return True


def gen_session_id():
    return '-'.join(
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        for _ in range(3)
    )

def list_sessions():
    if not session_manager.sessions:
        print(brightyellow + "No active sessions.")

    print(brightgreen + (f"{'SID':<20} {'Alias':<15} {'Transport':<10} {'Hostname':<20} {'User':<25} {'OS':<10} {'Arch':<10}"))
    print(brightgreen +("-" * 110))

    for sid, session in session_manager.sessions.items():
        transport = session.transport
        meta = session.metadata

        hostname = meta.get("hostname", "N/A")
        user = meta.get("user", "N/A")
        os_info = meta.get("os")
        arch = meta.get("arch", "N/A")

        # Resolve alias if set
        alias = "N/A"
        for a, real_sid in session_manager.alias_map.items():
            if real_sid == sid:
                alias = a
                break


        if sid is None or transport is None or hostname is None or user is None or os_info is None or arch is None or alias is None:
            print(brightyellow + "Fetching metadata from agent please wait and run command again")
            continue
        else:
            print(brightred + (f"{sid:<20} {alias:<15} {transport:<10} {hostname:<20} {user:<25} {os_info:<10} {arch:<10}"))


def list_listeners():
    if not tcp_listener_sockets and not http_listener_sockets and not tls_listener_sockets and not https_listener_sockets:
        print(brightyellow + "No active listeners.")
    else:
        if http_listener_sockets:
            print(brightgreen + "\n[HTTP Listeners]")
            for name in http_listener_sockets:
                print(brightgreen + (f"- {name}"))

        if https_listener_sockets:
            print(brightgreen + "\n[HTTPS Listeners]")
            for name in https_listener_sockets:
                print(brightgreen + (f"- {name}"))

        if tcp_listener_sockets:
            print(brightgreen + "\n[TCP Listeners]")
            for name in tcp_listener_sockets:
                print(brightgreen + (f"- {name}"))

        if tls_listener_sockets:
            print(brightgreen + "\n[TLS Listeners]")
            for name in tls_listener_sockets:
                print(brightgreen + (f"- {name}"))

def shutdown():
    for name, sock in tcp_listener_sockets.items():
        try:
            sock.close()
            #print("TEST")
            print(brightyellow + f"Closed TCP {name}")
        except:
            pass

    for name, httpd in http_listener_sockets.items():
        try:
            httpd.shutdown()
            print(brightyellow + f"Closed HTTP {name}")
        except:
            pass


def async_note(msg, prompt):
    """
    Prints msg on its own line, then re-draws `prompt`
    and whatever the user has typed so far.
    """
    # 1) grab current buffer
    buf = readline.get_line_buffer()

    # 2) move to start-of-line and clear it
    sys.stdout.write('\r\033[K')

    # 3) print your note
    print(msg)

    # 4) redraw prompt + saved buffer
    sys.stdout.write(prompt + buf)
    sys.stdout.flush()

def register_forward(rule_id, sid, local_host, local_port, remote_host, remote_port, thread, listener):
    """
    Register an active port-forward rule.

    Args:
        rule_id (str): Unique identifier for this forward.
        sid (str): Session ID.
        local_host (str): Local host/interface to bind.
        local_port (int): Local port to listen on.
        remote_host (str): Remote host to forward to.
        remote_port (int): Remote port to forward to.
        thread (threading.Thread): Thread handling this forward.
        listener (socket.socket): Listening socket for this forward.
    """
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    portforwards[rule_id] = {
        "sid": display,
        "local_host": local_host,
        "local": local_port,
        "remote": f"{remote_host}:{remote_port}",
        "thread": thread,
        "listener": listener
    }

def unregister_forward(rule_id):
    """
    Remove and stop a port-forward rule, closing its listener and joining its thread.
    """
    entry = portforwards.pop(rule_id, None)
    if not entry:
        return
        
    try:
        entry["listener"].close()

    except:
        pass

    entry["thread"].join(timeout=1)

def list_forwards():
    """
    Return all currently registered port-forward rules.
    """
    return portforwards



commands = {
    "start": {
        "_desc": """start <subcommand>\nSubcommands:\n  start http  <ip> <port>   Start HTTP listener\n  start https <ip> <port>   Start HTTPS listener\n  start tcp   <ip> <port>   Start TCP listener\n\nType 'help start http', 'help start https' or 'help start tcp' for more details.""",
        "http": """start http <ip> <port>\nStarts an HTTP listener on the specified IP and port.\nExample: start http 0.0.0.0 443""",
        "https": """start https <ip> <port> [-c <certfile> -k <keyfile>]
Starts an HTTPS listener on the specified IP and port. If no cert/key are provided, a self-signed certificate will be generated.

Options:
  -c <certfile>
      Path to TLS certificate (PEM format)
  -k <keyfile>
      Path to TLS private key (PEM format)

Examples:
  start https 0.0.0.0 8443
  start https 0.0.0.0 8443 -c cert.pem -k key.pem""",
        "tcp": """start tcp <ip> <port> [--ssl] [-c <certfile> -k <keyfile>]
Starts a TCP listener. By default runs raw TCP, add --ssl (and optionally -c/-k) to enable TLS.

Options:
  --ssl
      Enable SSL/TLS on the listener
  -c <certfile>
      Path to TLS certificate (requires --ssl)
  -k <keyfile>
      Path to TLS private key (requires --ssl)

Examples:
  start tcp 0.0.0.0 9001                                  # raw TCP listener
  start tcp 0.0.0.0 9001 --ssl                            # TLS with generated self-signed cert
  start tcp 0.0.0.0 9001 --ssl -c cert.pem -k key.pem     # TLS with custom cert/key""",
    },

    "portfwd": {
    "_desc": """portfwd <subcommand>
Subcommands:
  portfwd add    -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
  portfwd list
  portfwd delete -i <rule_id>

Type 'help portfwd <subcommand>' for more details.""",
    "add": """portfwd add -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
Start a new port-forward on session <sid>. On Linux agents this will upload chisel and establish the reverse tunnel.

Example:
  portfwd add -i session123 -lh 127.0.0.1 -lp 8000 -rh 10.0.0.5 -rp 443 -cp 7070""",
    "list": """portfwd list
List all currently active port-forward rules.""",
    "delete": """portfwd delete -i <rule_id>
Remove the specified port-forward by rule ID.

Example:
  portfwd delete -i 1"""
},
    "sessions": """sessions\nLists all active sessions with metadata: hostname, user, OS, architecture.""",
    "listeners": """listeners\nLists all currently running HTTP, HTTPS, and TCP listeners.""",
    "alias": """alias <OLD_SID_or_ALIAS> <NEW_ALIAS>\nAssign an alias to a session ID for easier reference. Example: alias abc12-def34-ghi56 pwned""",
    "shell": """shell <session_id>\nStarts an interactive shell with a specific session ID.\nExample: shell gunner""",
    "kill": """kill -i <session_id>\n\nTerminates the specified session (HTTP, HTTPS or TCP).\n\nExample:\n  kill -i abc123""",
    "jobs": """jobs [--print] [-i <job_id>]
Lists background jobs or prints a job’s buffered output.

Usage:
  jobs
    List all background jobs with their ID, Module and Status.

  jobs --print -i <job_id>
    Show the captured stdout/stderr for the given job ID.

Examples:
  jobs
  jobs --print -i 1
""",
    "generate": """
generate - Builds an agent payload.

Syntax:
  generate -f <format> -obs <level> -p <payload> [payload arguments] -o <output_file>

Format (-f):
  ps1           Generate PowerShell script

Obfuscation (-obs):
  1   Light obfuscation
  2   Heavy obfuscation + AMSI bypass
  3   Maximum obfuscation (AMSI bypass, ETW patching, randomized variables, jitter)

Payload Types (-p):
  tcp-win
    Required: -lh <local_host> -lp <local_port>

  http-win
    Required: -lh <local_host> -lp <local_port> --beacon_interval <seconds>

Example (TCP):
  generate -f ps1 -obs 3 -p tcp-win -lh 192.168.2.228 -lp 9001 -o payload.ps1

Example (HTTP):
  generate -f ps1 -obs 2 -p http-win -lh 192.168.2.228 -lp 8080 --beacon_interval 5 -o payload.ps1
""",
    "download": """download -i <session_id> -f <remote_file> -o <local_file>\n-i <session_id>   Specify the session ID from which to download the file.\n-f <remote_file>  The path of the remote file to download.\n-o <local_file>   The local path where the file will be saved.\n\nExample:\ndownload -i 12345 -f /home/user/file.txt -o /tmp/file.txt""",
    "upload": """upload -i <session_id> -l <local_file> -r <remote_file>\n-i <session_id>   Specify the session ID to which to upload the file.\n-l <local_file>   The local file to upload.\n-r <remote_file>  The path on the remote system to upload the file to.\n\nExample:\nupload -i 12345 -l /tmp/localfile.txt -r /home/user/remotefile.txt""",
    "banner": """banner
Clears the screen and displays the GUNNER ASCII-art banner.
Example: banner
""",
"search": """search <keyword>
Searches for available modules that match the provided keyword. Supports partial matching.

Example:
  search whoami
  search windows/x64
""",
"use": """use <module_name_or_number>
Selects a module by its full path or the number shown in the last `search` results, then enters its module prompt.

Inside the module prompt:
  show options       - List all configurable options
  set <opt> <value>  - Set a module option
  info               - Show module description and options
  run                - Execute the module
  back               - Exit module prompt and return to main

Examples:
  use linux/privilege_escalation/linpeas
  use 4
""",
"shelldefence": """shelldefence <on|off>
Toggle the Session-Defender runtime checks.

Usage:
  shelldefence on    Enable command‐inspection guard
  shelldefence off   Disable command‐inspection guard""",
  "gunnershell": """gunnershell <session_id_or_alias>
Starts a Meterpreter-style Gunner subshell on the specified session."""
}


def print_help(cmd=None):
    if cmd is None:
        print(brightyellow + "\nAvailable Commands:\n")
        for key in commands:
            print(brightgreen + f"  {key}")
        print(brightyellow + "\nUsage: help or help <command> [subcommand]\n")
        return

    parts = cmd.split()

    # Top-level
    if len(parts) == 1:
        c = parts[0]
        if c not in commands:
            print(brightyellow + f"No help available for '{c}'.")
            return

        if isinstance(commands[c], str):
            print(brightgreen + f"\n{commands[c]}\n")
        elif isinstance(commands[c], dict):
            print(brightgreen + f"\n{commands[c]['_desc']}\n")
        return

    # Nested help (subcommands)
    if len(parts) == 2:
        c, sub = parts
        if c in commands and isinstance(commands[c], dict):
            if sub in commands[c]:
                print(brightgreen + f"\n{commands[c][sub]}\n")
            else:
                print(brightyellow + f"No help available for '{cmd}'.")
        else:
            print(brightyellow + f"No help available for '{cmd}'.")
        return

    print(brightyellow + "Too deep nesting in help. Only 'help' or 'help <command> [sub]' allowed.")


# -----------------------------------------------------------------------------
# GunnerShell mini–help
# -----------------------------------------------------------------------------
gunnershell_commands = {
    "list":    "Show all available modules.",
    "help":    "Show this help menu.",
    "sessions": """sessions\nLists all active sessions with metadata: hostname, user, OS, architecture.""",
    "alias": """alias <OLD_SID_or_ALIAS> <NEW_ALIAS>\nAssign an alias to a session ID for easier reference. Example: alias abc12-def34-ghi56 pwned""",
    "exit":    "Exit the GunnerShell subshell and return to main prompt.",
    "upload":  "Usage: upload <local_path> <remote_path>    Upload a file.",
    "download":"Usage: download <remote_path> <local_path>  Download a file.",
    "shell":   "Usage: shell    Drop into a full interactive shell.",
    "switch": "switch <session_id>   Launch a Gunnershell on another session (can't switch to yourself).",
    "portfwd": {
        "_desc": """portfwd <subcommand>
Subcommands:
  portfwd add    -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
  portfwd list
  portfwd delete -i <rule_id>

Type 'help portfwd <subcommand>' for more details.""",
        "add": """portfwd add -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
Start a new port-forward on session <sid>. On Linux agents this will upload chisel and establish the reverse tunnel.

Example:
  portfwd add -i session123 -lh 127.0.0.1 -lp 8000 -rh 10.0.0.5 -rp 443 -cp 7070""",
        "list": """portfwd list
List all currently active port-forward rules.""",
        "delete": """portfwd delete -i <rule_id>
Remove the specified port-forward by rule ID.

Example:
  portfwd delete -i 1""",
    },

    "modhelp":  "modhelp <module_name>\n    Show options and usage for the named module.",
    "run":      "run <module_name> [opt=val]\n    Execute module with inline option assignments.",
    "search": """search <keyword>
Searches for available modules that match the provided keyword. Supports partial matching.

Example:
  search whoami
  search windows/x64
""",
    # ────────────────────────────────────────────────────────────────────────────────
    # File system commands help
    # ────────────────────────────────────────────────────────────────────────────────
    "ls":   "ls [<path>]\n    List files on the remote host (defaults to current working directory).",
    "cat":  "cat <filepath>\n    Read and display the contents of the given file.",
    "cd":   "cd <path>\n    Change the remote working directory to <path>.",
    "pwd":  "pwd\n    Print the current remote working directory.",
    "cp":   "cp <src> <dst>   Copy file on the remote host.",
    "mv":        "Move or rename a file/directory",
    "rmdir":     "Remove a directory (recursive)",
    "checksum":  "Compute SHA256 of a file",
    "del":  "del <file>   Delete a file on the remote host.",
    "rm":   "Alias for del",
    "mkdir":"mkdir <path>   Create a directory on the remote host.",
    "md":   "Alias for mkdir",
    "touch":"touch <path>   Create or update a file on the remote host",
    "drives":   "List mounted drives/filesystems",
    "edit": "edit <path>\n    Download, verify text, open in $EDITOR, then re-upload.",
    # ────────────────────────────────────────────────────────────────────────────────
    # Networking Commands
    # ────────────────────────────────────────────────────────────────────────────────
    "netstat":   "netstat\n    Show active TCP/UDP connections on the remote host.",
    "ifconfig":  "ifconfig / ipconfig\n    Display network interfaces.",
    "arp":       "arp\n    Display the ARP cache.",
    "resolve":   "resolve <host>\n    Resolve a hostname on the remote system.",
    "nslookup":  "Alias for resolve",
    "route":     "route\n    View the remote host’s routing table.",
    "getproxy":  "getproxy\n    Display the remote Windows proxy settings.",
    "ipconfig":  "ipconfig    Display network interfaces (Windows: ipconfig /all; Linux/macOS: ifconfig -a)",
    "ifconfig":  "Alias for ipconfig",
    # ────────────────────────────────────────────────────────────────────────────────
    # System Commands
    # ────────────────────────────────────────────────────────────────────────────────
    "sysinfo":   "sysinfo\n    Display system information (OS, hostname, arch).",
    "ps":        "ps\n    List running processes on the remote host.",
    "getuid":    "getuid\n    Show the user the server is running as.",
    "getprivs":  "getprivs\n    Show/enumerate process privileges.",
    "getpid":    "getpid\n    Print the process ID of the remote agent.",
    "steal_token": """
Usage:
  steal_token <PID> -f <format> -p <tcp-win|http-win|https-win>
               -lh <local_host> -lp <local_port> -x <http_port>
               [--serve_https] [--ssl] [-obs <1|2|3>]
               [--beacon_interval <sec>]

Description:
  Steal a Windows token via CreateProcessWithTokenW and immediately spawn
  a stage-1 PowerShell payload on the target.

Options:
  -f, --format <format>            Payload format (only “ps1” supported)
  -p, --payload <tcp-win|http-win|https-win>
                                   Which stager to use
  -lh, --local_host <ip>           IP for the stager to call back to
  -lp, --local_port <port>         Port for the stager callback
  -x,  --http_port <port>          Port for the temporary HTTP(S) server
      --serve_https                Serve the stage-1 script over HTTPS
                                   (self-signed cert)
      --ssl                        Force SSL on the reverse shell channel
  -obs <1|2|3>                     Obfuscation strength (1=low, 3=high)
      --beacon_interval <sec>      Beacon interval (required for http-win/https-win)
""",
    "getenv":    "getenv <VAR1> [<VAR2> ...]\n    Retrieve one or more environment variables from the remote host.",
    "exec":      "exec <command> [args...]\n    Execute an arbitrary OS command.",
    "kill":      "kill <pid>\n    Terminate the given process ID.",
    "getsid":    "getsid\n    Show the Windows user SID of the current token.",
    "clearev": """
clearev [-f|--force]
    Clear all Windows event logs. Requires local Administrator or SeSecurityPrivilege;
    use -f/--force to override privilege check.
""",
    "localtime": "Display the remote system’s date and time.",
    "reboot":    "Reboot the remote host immediately.",
    "pgrep":     "pgrep <pattern>   Filter processes by name/pattern",
    "pkill":     "pkill <pattern>   Terminate processes by name/pattern",
    "suspend":  "suspend <pid>\n    Suspend the given process ID.",
    "resume":   "resume <pid>\n    Resume the given suspended process.",
    "shutdown":"shutdown [-r|-h]\n    Shutdown (`-h`) or reboot (`-r`) the host.",
    "reg": {
    "_desc": "reg <query|get|set|delete> …\n    Interact with the Windows registry.",
    "query":  "reg query <hive>\\\\<path> [/s]\n    List subkeys and values (use /s to recurse).",
    "get":    "reg get <hive>\\\\<path> <ValueName>\n    Read a single value.",
    "set":    "reg set <hive>\\\\<path> <Name> <Data>\n    Create or update a string value.",
    "delete": "reg delete <hive>\\\\<path> [/f]\n    Delete a value or entire key (use /f to force).",
    },
    "services":   "services <list|start|stop|restart> [name]   Manage services",
    "netusers":   "netusers    List local user accounts",
    "netgroups":  "netgroups   List local group accounts",
 }

def print_gunnershell_help(cmd: str=None):
    """Like print_help, but grouped and with two‐level detail."""
    # 1) Top‐level: show grouped summary
    if cmd is None:
        core_cmds = {
            "help":     "Help menu",
            "exit":     "Exit the subshell and return to main prompt",
            "list":     "List all available modules",
            "switch":   "Switch to another session's GunnerShell",
            "shell":    "Drop into a full interactive shell",
            "modhelp":  "Show module options for a module",
            "run":      "Execute module with inline options",
            "search":   "Filter available modules by keyword or show all",
        }
        fs_cmds = {
            "ls":       "List files on the remote host",
            "cat":      "Print contents of a file",
            "cd":       "Change remote working directory",
            "pwd":      "Print remote working directory",
            "cp":       "Copy file from source → destination",
            "mv":       "Move or rename a file/directory",
            "rmdir":    "Remove a directory (recursive)",
            "checksum": "Compute SHA256 of a file",
            "upload":   "Upload a file to the session",
            "download": "Download a file or directory",
            "del":      "Delete a file on the remote host",
            "rm":       "Alias for del",
            "mkdir":    "Create a directory on the remote host",
            "md":       "Alias for mkdir",
            "touch":    "Create or update a file on the remote host",
            "drives":   "List mounted drives/filesystems",
            "edit":     "Edit a remote text file in your local editor",
        }
        net_cmds = {
            "netstat":   "Show sockets and listening ports",
            "ifconfig":  "List network interfaces",
            "portfwd":   "Manage port-forwards on this session",
            "arp":       "Display ARP table",
            "resolve":   "Resolve hostname(s)",
            "nslookup":  "Alias for resolve",
            "route":     "Show routing table",
            "getproxy":  "Show Windows proxy config",
            "ipconfig":  "Display network interfaces (alias: ifconfig)",
            "ifconfig":  "Alias for ipconfig",
        }
        sys_cmds = {
            "sysinfo":   "Display remote system information",
            "ps":        "List running processes",
            "getuid":    "Show the current user",
            "getprivs":  "Enumerate process privileges",
            "getpid":    "Print the remote agent’s process ID",
            "getenv":    "Retrieve one or more environment variables",
            "exec":      "Execute an arbitrary OS command",
            "kill":      "Terminate a process by PID",
            "getsid":    "Show Windows SID of current token",
            "clearev":   "Clear all Windows event logs",
            "localtime": "Display target local date/time",
            "reboot":    "Reboot the remote host",
            "pgrep":     "Filter processes by name/pattern",
            "pkill":     "Terminate processes by name/pattern",
            "suspend":   "Suspend a process by PID",
            "resume":    "Resume a suspended process",
            "shutdown":  "Shut down or reboot the remote host",
            "reg":       "Windows registry operations (query/get/set/delete)",
            "services":  "Manage services",
            "netusers":  "List local user accounts",
            "netgroups": "List local group accounts",
            "steal_token":"Steal Windows token and inject stage-1 PowerShell payload",
        }

        # print Core
        print(brightyellow + "\nCore Commands\n=============\n")
        for name, desc in core_cmds.items():
            print(brightgreen + f"{name:<25} {desc}")
        print()
        # print File system
        print(brightyellow + "File system Commands\n=====================\n")
        for name, desc in fs_cmds.items():
            print(brightgreen + f"{name:<25} {desc}")
        print()
        # print networking commands
        print(brightyellow + "\nNetwork Commands\n================\n")
        for name, desc in net_cmds.items():
            print(brightgreen + f"{name:<25} {desc}")
        print()
        print(brightyellow + "System Commands\n===============\n")
        for name, desc in sys_cmds.items():
            print(brightgreen + f"{name:<25} {desc}")
        print(brightyellow + "\nFor detailed help run: help <command> [subcommand]\n")
        return

    # 2) Single‐level detail: help <cmd>
    parts = cmd.split()
    if len(parts) == 1:
        c = parts[0]
        entry = gunnershell_commands.get(c)
        if entry is None:
            print(brightyellow + f"No help available for '{c}'.\n")
        elif isinstance(entry, str):
            print(brightgreen + f"\n{entry}\n")
        else:
            # nested dict: print the overview
            print(brightgreen + f"\n{entry.get('_desc')}\n")
        return

    # 3) Two‐level detail: help <cmd> <subcmd>
    if len(parts) == 2:
        c, sub = parts
        entry = gunnershell_commands.get(c)
        if isinstance(entry, dict) and sub in entry:
            print(brightgreen + f"\n{entry[sub]}\n")
        else:
            print(brightyellow + f"No help available for '{c} {sub}'.\n")
        return

    # 4) Too deep
    print(brightyellow +
          "Too deep nesting in help. Only:\n"
          "  help\n"
          "  help <command>\n"
          "  help <command> <subcommand>\n")



defender = SessionDefender()