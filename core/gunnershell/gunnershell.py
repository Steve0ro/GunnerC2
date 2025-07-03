import shlex
import readline
import os, sys, subprocess
from core.module_loader import load_module, discover_module_files, search_modules, MODULE_DIR as BASE_MODULE_DIR
from core.session_handlers.session_manager import resolve_sid
from core.utils import print_help, print_gunnershell_help, gunnershell_commands
from core import shell, portfwd, utils
from core.session_handlers import session_manager
from core.gunnershell.filesystem_master import *
from colorama import init, Fore, Style
import ntpath

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"

#MODULE_DIR = os.path.join(os.path.dirname(__file__), "modules")

MODULE_DIR = BASE_MODULE_DIR

class Gunnershell:
    """
    A Meterpreter-like subshell that can load and run Gunner modules against a session.
    Usage:
      gs = Gunnershell(session_id)
      gs.interact()
    """
    def __init__(self, sid):
        real = resolve_sid(sid)
        if not real or real not in session_manager.sessions:
            raise ValueError(brightred + f"Invalid session: {sid}")

        display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
        self.sid = real
        self.display = display
        self.session = session_manager.sessions[self.sid]
        self.prompt = f"{UNDERLINE_ON}{brightblue}GunnerShell{UNDERLINE_OFF} > "
        # discover available modules once
        self.available = discover_module_files(MODULE_DIR)
        os_type = self.session.metadata.get("os","").lower()
        self.cwd = pwd(self.sid, os_type) or ""
        """find_dir = pwd(self.sid, os_type)
        if "\\" in find_dir:
            self.cwd = find_dir.replace("\\", "\\\\")

        elif "\\" not in find_dir:
            self.cwd = find_dir

        else:
            print(brightred + f"[!] An unknown error has ocurred!")"""


    def completer(self, text, state):
        # simple tab completion: modules and built-in commands
        builtins = list(gunnershell_commands.keys())
        options  = [c for c in self.available + builtins if c.startswith(text)]

    def run_module(self, modname):
        """
        Load and run a module by name, using default options from session metadata.
        """
        module = load_module(modname)
        if not module:
            print(f"[!] Module not found: {modname}")
            return
        # auto-set common options if present
        meta = self.session.metadata
        for opt in ("sid", "session_id", "target", "host", "user"):  # example keys
            if opt in module.options and "sid" in module.options:
                module.set_option(opt, self.sid)
        missing = module.validate()
        if missing is not True:
            print(f"[!] Missing options: {', '.join(missing)}")
            return
        module.run()

    def interact(self):
        readline.set_completer(self.completer)
        readline.parse_and_bind("tab: complete")
        try:
            while True:
                user = input(self.prompt).strip()
                if not user:
                    continue

                # exit subshell
                if user in ("exit", "quit", "back"):
                    break

                # help
                elif user.startswith("help"):
                    parts = user.split()

                    # help
                    if len(parts) == 1:
                        print_gunnershell_help()

                    # help <command>
                    elif len(parts) == 2:
                        print_gunnershell_help(parts[1])

                    # help <command> <subcommand>
                    elif len(parts) == 3:
                        print_gunnershell_help(f"{parts[1]} {parts[2]}")

                    else:
                        print(brightyellow + "Usage: help or help <command> [subcommand]")
                    continue

                # list modules
                elif user == "list":
                    print(brightgreen + "Available modules:")
                    for m in self.available:
                        print(brightgreen + f"  {m}")
                    continue

                elif user == "sessions":
                    utils.list_sessions()

                elif user.startswith("alias"):
                    parts = shlex.split(user)
                    if len(parts) != 3:
                        print(brightyellow + "Usage: alias <OLD_SID_or_ALIAS> <NEW_ALIAS>")
                        continue

                    old, new = parts[1], parts[2]
                    real = session_manager.resolve_sid(old)
                    if not real:
                        print(brightred + f"No such session or alias: {old}")
                        continue

                    session_manager.set_alias(new, real)
                    print(brightgreen + f"Alias set: {new!r} → {real}")

                    old_display = old
                    for entry in portforwards.values():
                        if entry["sid"] == old_display:
                            entry["sid"] = new

                    continue

                elif user.startswith("switch"):
                    parts = shlex.split(user)
                    if len(parts) != 2:
                        print(brightyellow + "Usage: switch <session_id_or_alias>")
                        continue

                    raw = parts[1]
                    new_sid = resolve_sid(raw)
                    if not new_sid or new_sid not in session_manager.sessions:
                        print(brightred + f"No such session or alias: {raw}")
                        continue

                    if new_sid == self.sid:
                        print(brightyellow + f"Already in GunnerShell for session {self.display}")
                        continue

                    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == new_sid), new_sid)
                    print(brightgreen + f"[*] Switching out of this subshell and into session {display}...")
                    # return the new SID so the caller can re-spawn at top level
                    return new_sid

                elif user.startswith("shelldefence"):
                    parts = user.split()
                    try:
                        if len(parts) != 2 or parts[1] not in ("on", "off"):
                            print(brightyellow + "Usage: shelldefence <on|off>")

                        if parts[1] == "on":
                            defender.is_active = True

                        elif parts[1] == "off":
                            defender.is_active = False

                    except IndexError:
                        pass

                    except Exception as e:
                        print(brightred + f"[!] An unknown error has ocurred: {e}")

                # upload: upload <local> <remote>
                elif user.startswith("upload"):
                    parts = shlex.split(user)
                    if len(parts) != 3:
                        print(brightyellow + "Usage: upload <local_path> <remote_path>")

                    else:
                        local, remote = parts[1], parts[2]
                        if session_manager.sessions[self.sid].transport in ("http", "https"):
                            shell.upload_file_http(self.sid, local, remote)

                        else:
                            shell.upload_file_tcp(self.sid, local, remote)
                    continue

                # download: download <remote> <local>
                elif user.startswith("download"):
                    parts = shlex.split(user)

                    if len(parts) != 3:
                        print(brightyellow + "Usage: download <remote_path> <local_path>")

                    else:
                        remote, local = parts[1], parts[2]
                        if session_manager.sessions[self.sid].transport in ("http", "https"):
                            shell.download_file_http(self.sid, remote, local)

                        else:
                            shell.download_file_tcp(self.sid, remote, local)
                    continue

                # shell: drop into full interactive shell
                elif user.startswith("shell"):
                    if session_manager.sessions[self.sid].transport in ("http","https"):
                        shell.interactive_http_shell(self.sid)
                    else:
                        shell.interactive_tcp_shell(self.sid)
                    continue

                # modhelp: show a module’s options
                elif user.startswith("modhelp"):
                    parts = shlex.split(user)
                    if len(parts) != 2:
                        print(brightyellow + "Usage: modhelp <module_name>")
                    else:
                        modname = parts[1]
                        module = load_module(modname)
                        if module:
                            print(brightyellow + f"Module: {module.name}\n")
                            print(brightgreen + f"{module.description}\n")
                            module.show_options()
                    continue

                elif user.startswith("search"):
                    parts = shlex.split(user)
                    if len(parts) != 2:
                        print(brightyellow + "Usage: search <keyword>   or   search all")

                    else:
                        term = parts[1]
                        if term.lower() == "all":
                            results = discover_module_files(MODULE_DIR)
                        else:
                            results = search_modules(term)

                        if not results:
                            print(brightred + f"No modules found matching '{term}'.")
                        else:
                            self.available = results
                            print(brightgreen + f"Found {len(results)} modules:")
                            for idx, m in enumerate(results, 1):
                                print(brightgreen + f"  [{idx}] {m}")
                    continue

                # run: execute a module with inline key=val args
                elif user.startswith("run"):
                    parts = shlex.split(user)
                    if len(parts) < 2:
                        print(brightyellow + "Usage: run <module_name> [KEY=VALUE ...]")
                    else:
                        modname = parts[1]
                        module = load_module(modname)
                        if not module:
                            continue
                        # parse key=val pairs
                        for kv in parts[2:]:
                            if "=" in kv:
                                key, val = kv.split("=",1)
                                try:
                                    module.set_option(key, val)
                                except Exception:
                                    print(brightred + f"Unknown option '{key}'")
                        missing = module.validate()
                        if missing is True:
                            module.run()
                        else:
                            print(brightred + "[!] Missing required options: " + ", ".join(missing))
                    continue

                elif user.startswith("portfwd"):
                    parts = shlex.split(user)
                    # must have at least: portfwd <subcommand>
                    if len(parts) < 2 or parts[1] not in ("add","list","delete"):
                        print(brightyellow + "Usage: portfwd <add|list|delete> [options]")
                        continue

                    sub = parts[1]

                    # portfwd list
                    if sub == "list":
                        from core.utils import list_forwards
                        fwd = list_forwards()
                        if not fwd:
                            print(brightyellow + "No active port-forwards.")
                        else:
                            for rid, info in fwd.items():
                                print(brightgreen + f"{rid}: {info['local_host']}:{info['local']} → {info['sid']} → {info['remote']}")
                        continue

                    # portfwd delete -i <rule_id>
                    if sub == "delete":
                        if "-i" not in parts:
                            print(brightyellow + "Usage: portfwd delete -i <rule_id>")
                        else:
                            rid = parts[parts.index("-i")+1]
                            from core.utils import unregister_forward
                            unregister_forward(rid)
                            print(brightyellow + f"Removed forward {rid}")
                        continue

                    # portfwd add -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
                    if sub == "add":
                        try:
                            opts = dict(zip(parts[2::2], parts[3::2]))
                            lh = opts["-lh"]
                            lp = int(opts["-lp"])
                            rh = opts["-rh"]
                            rp = int(opts["-rp"])
                            cp = int(opts["-cp"])
                        except Exception:
                            print(brightyellow + "Usage: portfwd add -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>")
                            continue

                        # start the listener thread
                        from core import portfwd as _pfwd
                        import threading
                        rid = str(len(utils.portforwards) + 1)
                        sid = session_manager.resolve_sid(self.sid)
                        t = threading.Thread(
                            target=_pfwd.portfwd_listener,
                            args=(rid, sid, lh, lp, rh, rp, cp),
                            daemon=True
                        )
                        t.start()

                        # register it so `list` can see it
                        utils.register_forward(rid, self.sid, lh, lp, rh, rp, t, _pfwd.last_listener_socket)
                        print(brightgreen + f"[+] Forward #{rid} {lh}:{lp} → {self.sid} → {rh}:{rp}")
                        continue

                #################################################################################################
                ##################################File System Commands###########################################
                #################################################################################################
                #################################################################################################

                elif user.startswith("ls") or user.startswith("dir"):
                    try:
                        parts = shlex.split(user)

                    except ValueError:
                        # fall back if they had an unescaped trailing backslash
                        parts = user.split(maxsplit=1)

                    os_type = self.session.metadata.get("os", "").lower()
 
                    
                    # 1) exactly "ls" → default to current dir
                    if len(parts) == 1:
                        target = self.cwd

                    # 2) "ls <path>"
                    elif len(parts) == 2:
                        raw = parts[1]
                        # on Linux: absolute if starts with "/"
                        if "linux" in os_type and raw.startswith("/"):
                            target = raw
                        # on Windows: absolute if drive letter like "C:\"
                        elif "windows" in os_type and ntpath.isabs(raw):
                            target = raw
                        else:
                            if "windows" in os_type:
                                # use ntpath so “..” works against a C:\ drive path
                                combined = ntpath.join(self.cwd, raw)
                                target   = ntpath.normpath(combined)
                            else:
                                combined = os.path.join(self.cwd, raw)
                                target   = os.path.normpath(combined)

                    # 3) too many args
                    else:
                        print(brightyellow + "Usage: ls [<path>]")
                        continue

                    out = ls(self.sid, os_type, target)
                    if out:
                        print(brightgreen + f"\n{out}")

                    else:
                        print(brightyellow + "[*] No output")
                    continue

                elif user == "pwd":
                    os_type = self.session.metadata.get("os", "").lower()
                    cwd = pwd(self.sid, os_type)
                    if cwd:
                        print(cwd)

                    else:
                        print(brightyellow + "[*] No output or error")
                    continue

                elif user.startswith("cd"):
                    try:
                        parts = shlex.split(user, 1)

                    except ValueError:
                        # fall back if they had an unescaped trailing backslash
                        parts = user.split(maxsplit=1)

                    if len(parts) < 2 or len(parts) > 2:
                        print(brightyellow + "Usage: cd <path>")
                        continue


                    target = parts[1]
                    os_type = self.session.metadata.get("os", "").lower()
                    new_cwd = cd(self.sid, os_type, target)

                    if new_cwd:
                        self.cwd = new_cwd     # store for later prefixes
                        print(brightgreen + new_cwd)

                    else:
                        print(brightred + f"[!] Failed to cd to '{target}'")
                    continue

                elif user.startswith("cat"):
                    parts = None
                    try:
                        parts = shlex.split(user, 1)
                        
                    except ValueError:
                        # fallback if they had an unescaped trailing backslash
                        parts = user.split(maxsplit=1)

                    # require exactly one argument
                    if len(parts) != 2:
                        print(brightyellow + "Usage: cat <filepath>")
                        continue

                    raw = parts[1]
                    os_type = self.session.metadata.get("os", "").lower()

                    # decide absolute vs relative
                    if "linux" in os_type and raw.startswith("/"):
                        target = raw

                    elif "windows" in os_type and ntpath.isabs(raw):
                        target = raw

                    else:
                        # relative → resolve against self.cwd
                        if "windows" in os_type:
                            joined = ntpath.join(self.cwd, raw)
                            target = ntpath.normpath(joined)

                        else:
                            joined = os.path.join(self.cwd, raw)
                            target = os.path.normpath(joined)

                    # finally invoke remote cat
                    out = cat(self.sid, os_type, target)
                    if out:
                        print(brightgreen + out)

                    else:
                        print(brightyellow + "[*] No output or file not found")
                    continue

                else:
                    print(brightred + f"[!] Unknown command!")
        except (EOFError, KeyboardInterrupt):
            print()
        finally:
            readline.set_completer(None)
