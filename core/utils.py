import random
import string
import os
from core import session_manager, sessions

tcp_listener_sockets = {}
http_listener_sockets = {}

def gen_session_id():
    return '-'.join(
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        for _ in range(3)
    )

def list_sessions():
    if not session_manager.sessions:
        print("No active sessions.")

    print(f"{'SID':<20} {'Alias':<15} {'Transport':<10} {'Hostname':<20} {'User':<25} {'OS':<10} {'Arch':<10}")
    print("-" * 110)

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
            print("Fetching metadata from agent please wait and run command again")
            continue
        else:
            print(f"{sid:<20} {alias:<15} {transport:<10} {hostname:<20} {user:<25} {os_info:<10} {arch:<10}")


def list_listeners():
    if not tcp_listener_sockets and not http_listener_sockets:
        print("No active listeners.")
    else:
        if http_listener_sockets:
            print("[HTTP Listeners]")
            for name in http_listener_sockets:
                print(f"- {name}")
        if tcp_listener_sockets:
            print("[TCP Listeners]")
            for name in tcp_listener_sockets:
                print(f"- {name}")

def shutdown():
    for name, sock in tcp_listener_sockets.items():
        try:
            sock.close()
            #print("TEST")
            print(f"Closed TCP {name}")
        except:
            pass

    for name, httpd in http_listener_sockets.items():
        try:
            httpd.shutdown()
            print(f"Closed HTTP {name}")
        except:
            pass

commands = {
    "start": {
        "_desc": """start <subcommand>\nSubcommands:\n  start http <ip> <port>   Start HTTP listener\n  start tcp <ip> <port>    Start TCP listener\nType 'help start http' or 'help start tcp' for more details.""",
        "http": """start http <ip> <port>\nStarts an HTTP listener on the specified IP and port.\nExample: start http 0.0.0.0 443""",
        "tcp": """start tcp <ip> <port>\nStarts a TCP listener on the specified IP and port.\nExample: start tcp 0.0.0.0 9001"""
    },
    "sessions": """sessions\nLists all active sessions with metadata: hostname, user, OS, architecture.""",
    "listeners": """listeners\nLists all currently running HTTP and TCP listeners.""",
    "alias": """alias <OLD_SID_or_ALIAS> <NEW_ALIAS>\nAssign an alias to a session ID for easier reference. Example: alias abc12-def34-ghi56 pwned""",
    "shell": """shell <session_id>\nStarts an interactive shell with a specific session ID.\nExample: shell gunner""",
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
"""
}


def print_help(cmd=None):
    if cmd is None:
        print("\nAvailable Commands:\n")
        for key in commands:
            print(f"  {key}")
        print("\nUsage: help or help <command> [subcommand]\n")
        return

    parts = cmd.split()

    # Top-level
    if len(parts) == 1:
        c = parts[0]
        if c not in commands:
            print(f"No help available for '{c}'.")
            return

        if isinstance(commands[c], str):
            print(f"\n{commands[c]}\n")
        elif isinstance(commands[c], dict):
            print(f"\n{commands[c]['_desc']}\n")
        return

    # Nested help (subcommands)
    if len(parts) == 2:
        c, sub = parts
        if c in commands and isinstance(commands[c], dict):
            if sub in commands[c]:
                print(f"\n{commands[c][sub]}\n")
            else:
                print(f"No help available for '{cmd}'.")
        else:
            print(f"No help available for '{cmd}'.")
        return

    print("Too deep nesting in help. Only 'help' or 'help <command> [sub]' allowed.")