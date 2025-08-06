#!/usr/bin/env python3

import logging
# ─── configure root logger ────────────────────────────────────────────────
logging.basicConfig(
	filename="gunnerc2-dispatch.log",
	level=logging.DEBUG,
	format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


from core import print_override
from core.print_override import set_output_context

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
import re
import base64
import queue
import atexit
from collections import defaultdict
from time import sleep
import datetime
import requests
import uuid
from core import help_menus

from core.module_loader import load_module
from core.module_loader import search_modules, discover_module_files
from core import shell, utils, banner, portfwd
from core.listeners import tcp_listener, https_listener, http_handler
from core.session_handlers import session_manager, sessions
from core.teamserver import operator_manager as op_manage
from core.teamserver import auth_manager as auth
from core.teamserver import rbac_manager as rbac
from core.background_module_runner import run_in_background, list_jobs
from core.utils import portforwards, unregister_forward, list_forwards, defender, echo
from core.gunnershell.gunnershell import Gunnershell

from core.payload_generator.payload_generator import *
from core.malleable_c2 import malleable_c2 as malleable
from core.banner import print_banner
from core.prompt_manager import prompt_manager

# Command Execution Imports

from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
brightmagenta = "\001" + Style.BRIGHT + Fore.MAGENTA + "\002"
brightcyan    = "\001" + Style.BRIGHT + Fore.CYAN    + "\002"
brightwhite   = "\001" + Style.BRIGHT + Fore.WHITE   + "\002"
COLOR_RESET  = "\001\x1b[0m\002"
reset = Style.RESET_ALL

parser = argparse.ArgumentParser(
	description="GunnerC2 teamserver",
	formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument(
	"-x", "--port",
	type=int,
	default=5555,
	required=False,
	help="TCP port to listen on for operator connections"
)
parser.add_argument(
	"-lh", "--host",
	dest="host",
	default="0.0.0.0",
	required=False,
	help="Interface / IP to bind the operator listener on"
)
args = parser.parse_args()

# store last search results and the currently selected module
search_results = []
current_module = None

PROMPT = brightblue + "GunnerC2 > " + brightblue

MODULE_DIR = os.path.join(os.path.dirname(__file__), "core/modules")  # ensure correct path

COMMANDS = sorted(utils.commands.keys())

HISTORY_FILE = os.path.expanduser("~/.gunnerc2_history")

def delete_history_file():
	try:
		os.remove(HISTORY_FILE)
	except FileNotFoundError:
		pass

atexit.register(delete_history_file)


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
	if is_dir:
		if not (os.path.exists(local_path)):
			try:
				os.makedirs(local_path, exist_ok=True)
			except Exception as e:
				print(brightred + f"[!] Failed to create directory {local_path}: {e}")
				return

			return True
	
	if is_dir:
		return True

	elif not is_dir:
		return False

	else:
		print(brightred + f"[-] ERROR an error ocurred when checking the object type.")

def process_command(user: str, to_console: bool = True, to_op: str = None):
	"""
	user:     the raw command line
	to_console: print to local terminal?
	to_op:    operator ID to reply to (if any)
	"""
	set_output_context(to_console=to_console, to_op=to_op, world_wide=False)

	def printer(msg, color=None):
		if to_console:
			printer = echo(msg, to_console=True, to_op=False, world_wide=False, color=color)

		elif to_op:
			printer = echo(msg, to_console=False, to_op=to_op, world_wide=False, color=color)

	#printer("Test", color=brightred)

	if to_op and user.split()[0] in rbac.ADMIN_ONLY:
		op = op_manage.operators[to_op]
		if op.role != "admin":
			print(brightred + f"[!] Admin privileges required to run {user.split()[0]}.")
			return

	if user == "\x0c":  # Control+L
		os.system("clear")
		prompt_manager.print_prompt()
		

	if user:
		try:
			readline.write_history_file(HISTORY_FILE)

		except Exception:
			pass

	# --- Help system ---
	if user.startswith("help"):
		parts = shlex.split(user)

		if len(parts) == 1:
			utils.print_help()

		elif len(parts) == 2:
			utils.print_help(parts[1])

		elif len(parts) == 3:
			utils.print_help(f"{parts[1]} {parts[2]}")

		else:
			print(brightyellow + "Usage: help or help <command> [subcommand]")

		return

	elif user.startswith("banner"):
		os.system("clear")
		print_banner()
		return

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
					parsed_args = parser.parse_args(args[1:])

				except SystemExit:
					print(brightyellow + "Usage: download -i <session_id> -f <remote_file> -o <local_file>")
					return

			except Exception as e:
				return

			#sid = parsed_args.i
			raw_id = parsed_args.i
			try:
				sid = session_manager.resolve_sid(raw_id)

			except ValueError as e:
				print(brightred + str(e))
				return

			session = session_manager.sessions[sid]
			meta = session.metadata
			operatingsystem = meta.get("os", "").lower()

			if not sid:
				print(brightred + f"Invalid session or alias: {raw_id}")
				return

			remote_file = parsed_args.f

			if "\\" not in remote_file and operatingsystem == "windows":
				print(brightred + "Use double backslashes when specifying file paths.")
				return

			local_file = parsed_args.o

			"""if sid not in session_manager.sessions:
				print(f"Invalid session ID: {sid}")
				continue"""

			if session_manager.sessions[sid].transport in ("http", "https"):
				check = upload_any(sid, local_file, remote_file)
				if check is True:
					shell.download_folder_http(sid, remote_file, local_file)

				elif check is False:
					shell.download_file_http(sid, remote_file, local_file, op_id=to_op)

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
			return


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
				return

				
			if not sid:
				print(brightred + f"Invalid session or alias: {raw_id}")
				return

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
			return
			#print("Usage: upload -i <session_id> -l <local_file> -r <remote_file>")

	elif user.startswith("gunnershell") or user.startswith("gs"):
		try:
			parts = shlex.split(user)

		except ValueError:
			print(brightred + "[!] No escape character!")
			return

		if len(parts) != 2:
			print(brightyellow + "Usage: gunnershell <session_id_or_alias>")
			return

		sid = session_manager.resolve_sid(parts[1])
		try:
			session = session_manager.sessions[sid]

		except KeyError:
			print(brightred + f"No such session or alias!")
			return
			
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		if not sid or sid not in session_manager.sessions:
			print(brightred + f"No such session or alias: {parts[1]}")
			return

		try:
			while True:
				if session.mode != "cmd":
					continue

				else:
					break

			meta = session.metadata
			os_type = meta.get("os", "").lower()

			if os_type not in ("linux", "windows"):
				print(brightred + f"Unsupported operating system on {display}")
				return

			print(brightgreen + f"[*] Starting GunnerShell on {display}...")
			sleep(0.1)
			if to_op:
				operator = op_manage.operators[to_op]
				logger.debug(f"Scheduling GunnerShell init for SID {sid} operator {to_op}")

				def init_gs(operator, to_op):
					try:
						gs = Gunnershell(sid, to_op)
						logger.debug(f"Initialized GS for {to_op}@{sid}: {gs!r}")
						operator.shell = "gunnershell"
						sleep(0.01)
						operator.gs    = gs

					except Exception as e:
						logger.exception(f"Error initializing GunnerShell for {to_op}@{sid}: {e}")

				#fire-and-forget: don’t block the dispatcher
				threading.Thread(target=init_gs, args=(operator, to_op), daemon=True).start()

			else:
				logger.debug(brightblue + f"CONSOLE ENTERING GUNNERSHELL SID: {sid}")
				gs = Gunnershell(sid, None)

			logger.debug("CHECKING IF OP ID EXISTS")
			if not to_op:
				#new = gs.loop(to_console=to_console, op_id=to_op)
				logger.debug(brightblue + "USING CONSOLE GUNNERSHELL")
				while True:
					result = gs.loop(to_console=to_console, op_id=to_op)

					if not result:
						continue

					if result == "exit":
						break

					# handle a “switch” from inside the subshell
					if result.startswith("SIDSWITCH"):
						_, new_sid = result.split(maxsplit=1)
						display = next((a for a, rsid in session_manager.alias_map.items() if rsid == new_sid), new_sid)
						print(brightgreen + f"[*] Switching into GunnerShell on {display}...")
						gs = Gunnershell(new_sid)
						continue

					# any other return value we don’t understand → back to main
					continue

				prompt_manager.set_prompt(PROMPT)
				bind_keys()
				return

			else:
				return

		except ValueError as e:
			print(brightred + str(e))
		return

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
		return


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
				utils.print_help("start https", False)
				return

			if to_console:
				threading.Thread(
					target=https_listener.start_https_listener,
					args=(parsed.ip, parsed.port, parsed.certfile, parsed.keyfile, True, to_op),
					daemon=True
				).start()

			else:
				threading.Thread(
					target=https_listener.start_https_listener,
					args=(parsed.ip, parsed.port, parsed.certfile, parsed.keyfile, False, to_op),
					daemon=True
				).start()

		except Exception:
			utils.print_help("start https", False)
			pass

				

	elif user.startswith("start http"):
		# parse start http flags
		parts = shlex.split(user)
		parser = SilentParser(prog="start http", add_help=False)
		parser.add_argument("start")
		parser.add_argument("http")
		parser.add_argument("ip")
		parser.add_argument("port", type=int)
		parser.add_argument("--profile", dest="profile", help="Path to malleable C2 profile (.cna)", default=None, required=False)

		try:
			parsed = parser.parse_args(parts)

		except SystemExit:
			utils.print_help("start http", False)
			return

		ip = parsed.ip
		port = parsed.port
		if parsed.profile:
			profile = parsed.profile

		else:
			profile = None

		if to_console:
			threading.Thread(target=http_handler.start_http_listener, args=(ip, port, True, to_op, profile), daemon=True).start()

		else:
			threading.Thread(target=http_handler.start_http_listener, args=(ip, port, False, to_op, profile), daemon=True).start()

	elif user.startswith("start tls"):
		# shorthand for "start tcp … --ssl"
		try:
			parts = shlex.split(user)
			parser = SilentParser(prog="start tls", add_help=False)
			parser.add_argument("start")
			parser.add_argument("tls")
			parser.add_argument("ip")
			parser.add_argument("port", type=int)
			parser.add_argument("-c", dest="certfile", help="TLS certificate file", required=False)
			parser.add_argument("-k", dest="keyfile", help="TLS key file", required=False)
			parsed = parser.parse_args(parts)

		except SystemExit:
			utils.print_help("start tls", False)
			return

		# call the exact same TCP listener, but force SSL on
		if to_console:
			threading.Thread(
				target=tcp_listener.start_tcp_listener,
				args=(parsed.ip, parsed.port, parsed.certfile, parsed.keyfile, True, True, to_op),
				daemon=True
			).start()
			return

		else:
			threading.Thread(
				target=tcp_listener.start_tcp_listener,
				args=(parsed.ip, parsed.port, parsed.certfile, parsed.keyfile, True, False, to_op),
				daemon=True
			).start()
			return

	elif user.startswith("start tcp"):
		try:
			parts = shlex.split(user)
			parser = SilentParser(prog="start tcp", add_help=False)
			parser.add_argument("start")
			parser.add_argument("tcp")
			parser.add_argument("ip")
			parser.add_argument("port", type=int)

			try:
				parsed = parser.parse_args(parts)

			except SystemExit:
				utils.print_help("start tcp", False)
				#print(brightyellow + "Usage: start tcp <ip> <port> [-c <certfile> -k <keyfile>]")

			ip = parsed.ip
			port = parsed.port
			certfile = None
			keyfile = None
			is_ssl = False

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

			if to_console:
				threading.Thread(
					target=tcp_listener.start_tcp_listener,
					args=(ip, port, certfile, keyfile, is_ssl, True, to_op),
					daemon=True
				).start()

			else:
				threading.Thread(
					target=tcp_listener.start_tcp_listener,
					args=(ip, port, certfile, keyfile, is_ssl, False, to_op),
					daemon=True
				).start()

		except Exception:
			utils.print_help("start tcp", False)
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
			print(brightyellow + "Usage: shell <session_id>")

	elif user.startswith("alias"):
		parts = shlex.split(user)

		# ───────────────────────────────────────────────────────────────────────────
		# parse the -o/--operator flag
		# ───────────────────────────────────────────────────────────────────────────
		parser = argparse.ArgumentParser(prog="alias", add_help=False)
		parser.add_argument(
			"-o", "--operator",
			action="store_true",
			dest="is_op",
			help="Alias an operator ID instead of a session ID"
		)
		parser.add_argument("old", help="Existing session‑ID/alias or operator‑ID")
		parser.add_argument("new", help="New alias to assign")

		try:
			args = parser.parse_args(parts[1:])
		except SystemExit:
			print(brightyellow + "Usage: alias <OLD_ID> <NEW_ALIAS> [-o|--operator]" + reset)
			return

		if args.is_op:
			# ─────────────────────────────────────────────────────────────────────────
			# operator aliasing
			# ─────────────────────────────────────────────────────────────────────────
			from core.teamserver.operator_manager import operators, operator_lock

			with operator_lock:
				op = operators.get(args.old)
				if not op:
					print(brightred + f"[!] No such operator: {args.old}" + reset)
					return
				op.alias = args.new

			print(brightgreen + f"[+] Operator alias set: {args.new!r} → {args.old}" + reset)

		else:
			# ─────────────────────────────────────────────────────────────────────────
			# session aliasing (existing behavior)
			# ─────────────────────────────────────────────────────────────────────────
			real = session_manager.resolve_sid(args.old)
			if not real:
				print(brightred + f"[!] No such session or alias: {args.old}" + reset)
				return

			session_manager.set_alias(args.new, real)
			print(brightgreen + f"[+] Session alias set: {args.new!r} → {real}" + reset)

			# update port‑forwards that used the old display name
			for entry in portforwards.values():
				if entry["sid"] == args.old:
					entry["sid"] = args.new

		return

	elif user.startswith("generate"):
		# Split input
		try:
			parts = shlex.split(user)

		except Exception as e:
			print(brightred + f"[!] We hit an error while parsing your command: {e}")

		if "-p" not in parts:
			print(brightyellow + "You must specify payload type first with -p")
			return

		# Extract payload type early
		try:
			payload_index = parts.index("-p") + 1
			payload_type = parts[payload_index]

		except IndexError:
			print(brightred + f"[!] You must specify a value for -p")
			return

		#### Profile-based parsing starts here ####

		if payload_type == "tcp":
			parser = SilentParser(prog="generate (tcp)", add_help=False)
			parser.add_argument("-f", "--format", choices=["ps1", "bash", "shellcode", "exe"], required=True)
			parser.add_argument("-obs", "--obfuscation", type=int, choices=[1, 2, 3], default=False, required=False)
			parser.add_argument("-p", "--payload", choices=["tcp"], required=True)
			parser.add_argument("-o", "--output", required=False)
			parser.add_argument("--os", choices=["windows","linux"], default=False, help="Target OS for the payload", required=False)
			parser.add_argument("-lh", "--local_host", required=True)
			parser.add_argument("-lp", "--local_port", required=True)
			parser.add_argument("--stager-ip",    help="IP address where the .exe stager will be hosted")
			parser.add_argument("--stager-port",  type=int, help="Port where the .exe stager will listen")

		elif payload_type == "tls":
			parser = SilentParser(prog="generate (tls)", add_help=False)
			parser.add_argument("-f", "--format", choices=["ps1", "bash", "shellcode", "exe"], required=True)
			parser.add_argument("-obs", "--obfuscation", type=int, choices=[1, 2, 3], default=False, required=False)
			parser.add_argument("-p", "--payload", choices=["tls"], required=True)
			parser.add_argument("-o", "--output", required=False)
			parser.add_argument("--os", choices=["windows","linux"], default=False, help="Target OS for the payload", required=False)
			parser.add_argument("-lh", "--local_host", required=True)
			parser.add_argument("-lp", "--local_port", required=True)
			parser.add_argument("--stager-ip",    help="IP address where the .exe stager will be hosted", required=False)
			parser.add_argument("--stager-port",  type=int, help="Port where the .exe stager will listen", required=False)

		elif payload_type == "http":
			parser = SilentParser(prog="generate (http)", add_help=False)
			parser.add_argument("-f", "--format", choices=["ps1", "bash"], required=True)
			parser.add_argument("-obs", "--obfuscation", type=int, choices=[1, 2, 3], default=False, required=False)
			parser.add_argument("-p", "--payload", choices=["http"], required=True)
			parser.add_argument("-o", "--output", required=False)
			parser.add_argument("--profile", dest="profile", help="Path to malleable C2 profile (.profile)", required=False, default=False)
			parser.add_argument("--jitter", type=int, default=0, help="Jitter percentage to randomize beacon interval (e.g., 30 = ±30%)")
			parser.add_argument("-H", "--headers", dest="headers", action="append", type=malleable.parse_headers, help="Custom HTTP header; either 'Name: Value' or JSON dict")
			parser.add_argument("--useragent", required=False, help="Custom User-Agent string")
			parser.add_argument("--accept", required=False, default=False, help="Set the Accept header value")
			parser.add_argument("--range", required=False, default=False, help="Set the Range header value (e.g., 'bytes=0-1024')")
			parser.add_argument("--os", choices=["windows","linux"], default=False, help="Target OS for the payload", required=False)
			parser.add_argument("-lh", "--local_host", required=True)
			parser.add_argument("-lp", "--local_port", required=True)
			parser.add_argument("--interval", required=True)

		elif payload_type == "https":
			parser = SilentParser(prog="generate (https)", add_help=False)
			parser.add_argument("-f", "--format", choices=["ps1", "bash"], required=True)
			parser.add_argument("-obs", "--obfuscation", type=int, choices=[1,2,3], default=False, required=False)
			parser.add_argument("-p", "--payload", choices=["https"], required=True)
			parser.add_argument("-o", "--output", required=False)
			parser.add_argument("--profile", dest="profile", help="Path to malleable C2 profile (.profile)", required=False, default=False)
			parser.add_argument("--jitter", type=int, default=0, help="Jitter percentage to randomize beacon interval (e.g., 30 = ±30%)")
			parser.add_argument("-H", "--headers", dest="headers", action="append", type=malleable.parse_headers, help="Custom HTTP header; either 'Name: Value' or JSON dict")
			parser.add_argument("--useragent", required=False, default=False, help="Custom User-Agent string")
			parser.add_argument("--accept", required=False, default=False, help="Set the Accept header value")
			parser.add_argument("--range", required=False, default=False, help="Set the Range header value (e.g., 'bytes=0-1024')")
			parser.add_argument("--os", choices=["windows","linux"], default=False, help="Target OS for the payload", required=False)
			parser.add_argument("-lh", "--local_host", required=True)
			parser.add_argument("-lp", "--local_port", required=True)
			parser.add_argument("--interval", required=True)

		else:
			print(brightred + f"Unknown payload type: {payload_type}")
			return

		# Parse remaining args
		try:
			args = parser.parse_args(parts[1:])
			all_headers = {}

			if payload_type in ("http", "https"):
				useragent = args.useragent
				accept = args.accept
				byte_range = args.range
				profile = args.profile

			else:
				useragent = None
				accept = None
				byte_range = None
				profile = None

			if payload_type in ("tcp", "tls") and args.format == "exe":
				if not args.stager_ip or not args.stager_port:
					print(brightred + "[!] For exe payloads you must also supply --stager-ip and --stager-port")
					return

			if payload_type in ("http", "https"):

				if getattr(args, "headers", None):
					for hdr in args.headers:
						all_headers.update(hdr)

					# Header keys to normalize and extract
					key_map = {
						"user-agent": "useragent",
						"accept": "accept",
						"range": "byte_range"
					}

					for k, var_name in key_map.items():
						found_keys = [h for h in all_headers if h.lower() == k]

						if found_keys:
							if locals()[var_name] is False:  # Not explicitly set via flag
								locals()[var_name] = all_headers[found_keys[0]]

							for key in found_keys:
								del all_headers[key]

				else:
					all_headers = {}

		except SystemExit:
			print(brightyellow + utils.commands["generate"])
			return


		"""if payload_type == "tcp":
			if args.ssl:
				args.ssl = True
				ssl_flag = args.ssl

			else:
				args.ssl = False
				ssl_flag = args.ssl

		else:
			ssl_flag = False"""

		if payload_type not in ("http", "https"):
			beacon_interval = False

		else:
			beacon_interval = args.interval

		if payload_type in ("http", "https"):
			jitter = getattr(args, "jitter", 0)
			stager_ip = False
			stager_port = False

		else:
			jitter = None
			stager_ip = args.stager_ip
			stager_port = args.stager_port

		if args.obfuscation == False:
			obfuscation = 0

		else:
			obfuscation = args.obfuscation

		if not args.os:
			format_type = args.format.lower()
			if format_type in ("ps1", "exe", "shellcode"):
				os_type = "windows"

			elif format_type == "bash":
				os_type = "linux"
		else:
			try:
				os_type = args.os.lower()
				format_type = args.format.lower()

			except Exception as e:
				print(brightred + f"[!] The -f argument are required: {e}")

		if os_type == "windows":
			raw = generate_payload_windows(args.local_host, args.local_port, obfuscation, format_type, payload_type, beacon_interval, headers=all_headers, useragent=useragent, accept=accept, byte_range=byte_range, jitter=jitter,
				stager_ip=stager_ip, stager_port=stager_port, profile=profile)

		elif os_type == "linux":
			raw = generate_payload_linux(args.local_host, args.local_port, obfuscation, format_type, payload_type, beacon_interval, headers=all_headers, useragent=useragent, accept=accept, byte_range=byte_range, jitter=jitter)

		else:
			print(brightred + f"[!] Unsupported operating system selected!")


		if args.output and format_type not in ("exe", "shellcode"):
			try:
				with open(args.output, "w") as f:
					f.write(raw)

			except Exception as e:
				print(brightred + f"[!] Failed to open local file {args.output}: {e}")

			print(brightgreen + f"[+] Payload written to {args.output}")
		return

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
			return

		modname = parts[1]

		# if numeric, pick from last search results
		if modname.isdigit():
			idx = int(modname) - 1
			if idx < 0 or idx >= len(search_results):
				print(brightred + f"Invalid module number: {modname}")
				return
			modname = search_results[idx]
		else:
			modname = modname

		current_module = load_module(modname)
	
		if not current_module:
			return

		while True:
			subcmd = input(brightblue + f"module({current_module.name}) > ").strip()

			if not subcmd:
				return
		
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
					return

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
					return

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

				return

			else:
				print(brightred + f"Unknown command: {subcmd}")
				print(brightyellow + "Type 'help' to see available commands.")


	elif user.startswith("kill"):
		parts = shlex.split(user)
		if len(parts) == 3 and parts[1] == "-i":
			raw = parts[2]
							
			sid = session_manager.resolve_sid(raw)
			if sid:
				display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

			else:
				print(brightred + f"[!] Failed to resolve SID {raw}")

			if display == sid:
				display = sid

			if not sid or sid not in session_manager.sessions:
				print(brightred + f"[!] Invalid session or alias: {raw}")

			else:
				session = session_manager.sessions[sid]
				meta = session.metadata
				os_type = meta.get("os", "").lower()
				if session_manager.sessions[sid].transport in ("http", "https"):
					if session_manager.kill_http_session(sid, os_type):
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
		return

	elif user.startswith("jobs"):
		try:
			parts = shlex.split(user)
			parser = SilentParser(prog="jobs", add_help=False)
			parser.add_argument("--print", action="store_true", dest="want_output")
			parser.add_argument("-i", type=int, dest="job_id")

			try:
				args = parser.parse_args(parts[1:])

			except SystemExit:
				print(brightyellow + "Usage: jobs [--print] [-i <job_id>]")
				return

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

			return

		except Exception as e:
			print(brightred + f"[-] ERROR failed to list jobs: {e}")
		return

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
					return

				sid = session_manager.resolve_sid(sid)
					
				if not sid:
					print(brightred + "Invalid session.")
					return

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
					return

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

	elif user.startswith("exec"):
		parts = shlex.split(user)
		parser = SilentParser(prog="exec", add_help=False)
		parser.add_argument("-i", "--session", dest="sid", required=True, help="Session ID or alias (supports wildcards)")
		parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run on remote host")

		try:
			args = parser.parse_args(parts[1:])

		except SystemExit:
			print(brightyellow + "Usage: exec -i <session_id> <command> [args...]")
			return

		raw_id = args.sid

		try:
			sid = session_manager.resolve_sid(raw_id)

		except ValueError as e:
			print(brightred + str(e))
			return

		if not sid or sid not in session_manager.sessions:
			print(brightred + f"Invalid session or alias: {raw_id}")
			return

		cmd_str = " ".join(args.cmd)
		if not cmd_str:
			print(brightyellow + "Usage: exec -i <session_id> <command> [args...]")
			return

		# pick HTTP vs TCP
		session = session_manager.sessions[sid]
		if session.transport in ("http", "https"):

			out = http_exec.run_command_http(sid, cmd_str, op_id=to_op)

		else:
			out = tcp_exec.run_command_tcp(sid, cmd_str, timeout=0.5, portscan_active=True, op_id=to_op)

		if out is not None and out != "":
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output or command failed")
		return

	elif user.startswith("operators"):
		parts = shlex.split(user)
		parser = SilentParser(prog="operators", add_help=False)
		parser.add_argument(
			"-n", "--name",
			dest="name",
			help="Operator ID or alias (supports wildcards)"
		)
		parser.add_argument(
			"--users", "--hackers", "--players", action="store_true", dest="list_users",
			help="List all persistent operator accounts (from DB)"
		)

		try:
			args = parser.parse_args(parts[1:])

		except SystemExit:
			# bad flags → show usage
			print(brightgreen + help_menus.commands["operators"])
			return

		# --- persistent DB listing?
		if args.list_users:
			# fetch from auth_manager
			accounts = auth.list_operators()
			if not accounts:
				print(brightyellow + "[*] No operator accounts found." + reset)
				return

			# print header
			hdr = f"{'Username':<20}  {'Role':<10}  {'Created At'}"
			print(brightgreen + hdr + reset)
			print(brightgreen + "-" * len(hdr) + reset)
			# rows
			for acct in accounts:
				uname = acct["username"]
				role = acct["role"]
				try:
					ts = datetime.fromisoformat(acct["created_at"])
					created = ts.strftime("%Y-%m-%d %H:%M:%S")

				except Exception:
					created = acct["created_at"]

				print(
					brightred
					+ f"{uname:<20}  {role:<10}  {created}"
					+ reset
				)
			return

		out = op_manage.list_operators(name=args.name)
		if out:
			if "NO OPERATORS FOUND" in out:
				print(brightyellow + "[*] No operators connected.")

			elif "NO OPERATOR FOUND" in out:
				print(brightyellow + "[*] Operator not found.")
			return
		return

	elif user.startswith("alert"):
		# parse: positional message + optional color flags
		parts = shlex.split(user)
		parser = SilentParser(prog="alert", add_help=False)
		parser.add_argument(
			"message", nargs="+",
			help="The message to broadcast to all operators"
		)
		parser.add_argument(
			"-o", "--operator",
			help="Send message only to this operator ID, alias, or wildcard"
		)
		# support one of these flags for color; default to white
		for col in ("red","green","yellow","blue","magenta","cyan","white"):
			parser.add_argument(f"--{col}", action="store_true", help=f"Use {col} text")
		try:
			args = parser.parse_args(parts[1:])
		except SystemExit:
			print(brightgreen + help_menus.commands["alert"])
			return

		# reassemble the message
		msg = " ".join(args.message)

		# pick the first color flag found, else default to white
		for col in ("red","green","yellow","blue","magenta","cyan","white"):
			if getattr(args, col):
				color = col
				break
		else:
			color = "white"

		# look up our brightXXX variable
		prefix = globals().get(f"bright{color}", brightwhite)

		if args.operator:
			op_id = op_manage.resolve_operator(args.operator)
			if not op_id:
				print(brightred + f"No such operator: {args.operator}")
				return
			set_output_context(to_console=False, to_op=op_id)

		else:
			set_output_context(world_wide=True)

		print("GUNNEROPERATORALERT{(::)} " + prefix + msg + COLOR_RESET)

		# restore to console‐only
		if to_console:
			set_output_context(to_console=True)

		elif to_op:
			set_output_context(to_console=False, to_op=to_op)
		return

	elif user.startswith("kick"):
		parts = shlex.split(user)
		parser = SilentParser(prog="kick", add_help=False)
		group = parser.add_mutually_exclusive_group(required=True)
		group.add_argument(
			"-o", "--operator",
			help="Comma‑separated operator ID(s) or alias(es) to kick"
		)
		group.add_argument(
			"-a", "--all",
			action="store_true",
			help="Kick all connected operators"
		)

		try:
			args = parser.parse_args(parts[1:])
		except SystemExit:
			print(brightgreen + help_menus.commands["kick"])
			return

		# send the kick notice
		if args.all:
			set_output_context(world_wide=True)
			print("GUNNEROPERATORKICK{(::)}")
		else:
			for op_identify in args.operator.split(","):
				set_output_context(to_console=False, to_op=op_identify.strip())
				print("GUNNEROPERATORKICK{(::)}")

		# restore your previous output context
		if to_console:
			set_output_context(to_console=True)

		elif to_op:
			set_output_context(to_console=False, to_op=to_op)
		return

	elif user.startswith("addop"):
		# Create a new operator account
		parts = shlex.split(user)
		parser = SilentParser(prog="addop", add_help=False)
		parser.add_argument(
			"-u","--username","--user",
			dest="username", required=True,
			help="Username for the new operator"
		)
		parser.add_argument(
			"-p","--password","--pass",
			dest="password", required=True,
			help="Password for the new operator"
		)
		parser.add_argument(
			"-r","--role",
			dest="role", required=False,
			choices=["admin", "operator"] ,default="operator",
			help="Role for the new operator (default: operator)"
		)
		try:
			args = parser.parse_args(parts[1:])
		except SystemExit:
			# show our help text on bad flags
			print(brightgreen + help_menus.commands["addop"] + reset)
			return

		# actually add them
		try:
			new_id = auth.add_operator(args.username, args.password, args.role)
			if "ALREADY EXISTS" in new_id:
				print(brightyellow + f"[*] Operator {args.username} already exists in database.")
				return

			elif "USERNAME REGEX FAIL" in new_id:
				print(brightred + f"[!] Special characters not allowed in username!")
				return

			elif "PASSWORD REGEX FAIL" in new_id:
				print(brightred + f"[!] Invalid password format!")

			elif new_id:
				print(brightgreen + f"[+] Added operator {args.username!r} with ID {new_id} and role {args.role}" + reset)
				return

			else:
				print(brightred + f"[!] Failed to add new operator!")
				return

		except Exception as e:
			print(brightred + f"[!] Failed to add operator: {e}" + reset)
		return

	elif user.startswith("delop"):
		# delete operator(s) from persistent DB
		parts = shlex.split(user)
		if len(parts) != 2:
			print(brightyellow + "Usage: delop <operator1[,operator2,...]>" + reset)
			return

		invalid_user = False

		# comma‑separated list of names
		raws = [r.strip() for r in parts[1].split(",") if r.strip()]
		invalid_names = []
		op_uuids = []

		for raw in raws:
			name = raw.strip()
			op_id = auth.verify_username(name)
			if not op_id:
				invalid_names.append(raw)
			else:
				op_uuids.append(op_id)

		if invalid_names:
			if len(invalid_names) == 1:
				print(brightred + f"[!] No such operator: {invalid_names[0]!r}" + reset)
				
			else:
				print(brightred + f"[!] No such operators: {', '.join(map(repr, invalid_names))}" + reset)
			return

		bad_delete = False

		for operator_id in op_uuids:
			delete_status = auth.delete_operator(operator_id)
			if not delete_status:
				bad_delete = True

		if bad_delete:
			if len(raws) > 1:
				print(brightred + f"[!] Failed to delete operators!")
				return

			else:
				print(brightred + f"[!] Failed to delete operator!")
				return

		else:
			if len(raws) == 1:
				print(brightgreen + f"[+] Removed operator {name!r} from database" + reset)
				return

			else:
				print(brightgreen + f"[+] Successfully removed operarors from database" + reset)
				return
		return

	elif user.startswith("modop"):
		parts = shlex.split(user)
		parser = SilentParser(prog="modop", add_help=False)
		parser.add_argument("-o","--operator", dest="target", required=True, help="Operator ID or alias")
		parser.add_argument("-n","--name", dest="new_username", help="New username for the operator")
		parser.add_argument("-p","--password", dest="new_password", help="New password for the operator")
		parser.add_argument("-r","--role", dest="new_role", choices=["operator","admin"], help="New role for the operator")

		try:
			args = parser.parse_args(parts[1:])
		except SystemExit:
			print(brightyellow + "Usage: modop -o <operator> [-n <name>] [-p <password>] [-r <operator|admin>]")
			return

		if not (args.new_username or args.new_password or args.new_role):
			print(brightred + "[!] You must specify at least one of -n, -p, or -r")
			return

		# resolve operator UUID
		op_id = auth.verify_username(args.target)
		if not op_id:
			print(brightred + f"[!] No such operator: {args.target}")
			return

		# persistent update
		result = auth.update_operator(
			op_id,
			new_username=args.new_username,
			new_password=args.new_password,
			new_role=args.new_role
		)
		if result is True:
			# reflect live change if connected
			if op_id in op_manage.operators:
				op = op_manage.operators[op_id]

				if args.new_username:
					op.username = args.new_username

				if args.new_role:
					op.role = args.new_role

			print(brightgreen + f"[+] Modified operator {args.target}")
			return

		elif result == "USERNAME REGEX FAIL":
			print(brightred + f"[!] Invalid username format!")
			return

		elif result == "PASSWORD REGEX FAIL":
			print(brightred + f"[!] Invalid password format!")
			return

		elif result == "ROLE INVALID":
			print(brightred + f"[!] Choose between the roles: admin or operator")
			return

		else:
			print(brightred + "[!] Failed to modify operator!")
		return

	elif user in ("exit", "quit"):
		utils.shutdown()
		print(brightyellow + "Exiting.")
		exit(0)

	else:
		#print("TEST")
		print(brightred + "Unknown command.")


def operator_loop():
	global search_results, current_module
	try:
		while True:
			readline.clear_history()
			bind_keys()
			if not os.path.exists(HISTORY_FILE):
				# create an empty history file
				open(HISTORY_FILE, 'a').close()
		
			readline.read_history_file(HISTORY_FILE)

			try:
				sleep(0.1)
				user = input(prompt_manager.get_prompt()).strip()

				if not user:
					continue

				else:
					process_command(user, to_console=True)

			except Exception as e:
				print(brightred + f"ERROR: {e}")

			finally:
				try:
					readline.write_history_file(HISTORY_FILE)

				except Exception:
					pass

	finally:
		readline.clear_history()
		delete_history_file()

def teamserver():
	userstart = auth.startup_useradd()

	if not userstart:
		print(brightred + "Teamserver failed to start, delete ~/.gunnerc2/operators.db")
		return "KILL"


if __name__ == "__main__":
	print_banner()
	logger.debug("=== starting teamserver ===")
	teamsrv_startup = teamserver()
	if teamsrv_startup == "KILL":
		logger.error("teamserver() returned KILL, exiting")
		sys.exit(1)

	def dispatch_operators():
		try:
			logger.debug("dispatch_operators thread started")
			while True:
				# for each connected operator…
				for _, operator in list(op_manage.operators.items()):
					#logger.debug("checking operator %s (shell=%r)", operator.op_id, operator.shell)
					op_id = operator.op_id
					q = operator.op_queue
					shell_type = operator.shell
					#print(operator.handler)
					#logger.debug("operator.handler = %r", operator.handler)
					#logger.debug(f"CONSOLE: {print_override._ctx.to_console}, TO_OP: {print_override._ctx.to_op}")

					try:
						line = q.get_nowait()
						logger.debug("got queued line for %s: %r", op_id, line)

					except queue.Empty:
						continue

					shell_type = operator.shell

					set_output_context(to_console=False, to_op=op_id)

					#print("I AM SEXIST")

					if shell_type == "gunnershell":
						threading.Thread(
							target=_handle_gunnershell_line,
							args=(operator, line),
							daemon=True
						).start()
						"""logger.debug(f"GUNNERSHELL OBJ: {operator.gs}")
						logger.debug(f"OPERATOR HANDLE: {operator.handler}")
						logger.debug(f"OPERATOR SHELL TYPE: {shell_type}")
						#ret = operator.gs.loop(cmd=line, to_console=False, op_id=operator.op_id)
						logger.debug("→ dispatching to GunnerShell for %s", op_id)
						ret = operator.gs.loop(cmd=line, to_console=False, op_id=operator.op_id)
						logger.debug("   interact() returned: %r", ret)
						

						if not ret:
							logger.debug("   no return value (empty), skipping")
							continue


						if ret == "exit":
							logger.debug("   GunnerShell requested exit, switching back to main")
							operator.shell = "main"
							operator.gs    = None

						if ret:
							if "SIDSWITCH" in ret:
								logger.debug("   SIDSWITCH detected: %r", ret)
								parts = ret.split(maxsplit=1)
								if len(parts) != 2:
									# malformed return, drop back to main
									logger.warning("   malformed SIDSWITCH %r", ret)
									operator.shell = "main"
									operator.gs = None
									continue

								new_sid = parts[1]
								logger.debug("   new SID = %s", new_sid)
								print(f"GUNNERSHELLSID: {new_sid}")

								try:
									operator.gs = Gunnershell(new_sid, operator.op_id)
									operator.shell = "gunnershell"
									logger.debug("   spawned new GunnerShell object for %s", new_sid)

								except Exception as e:
									logger.exception("   error creating new GunnerShell for %s", new_sid)
									print(brightred + f"ERROR: {e}")
									continue
							else:
								from core import utils
								set_output_context(to_console=False, to_op=op_id)
								logger.debug("   dispatching output to main via echo: %r", ret)
								#set_output_context(to_console=False, to_op=op_id, world_wide=False)
								utils.echo(ret, False, op_id, world_wide=False)
								#operator.handler.sendall((ret + "\n").encode())
							

						else:
							logger.debug("   no output returned from interact()")"""
		
					else:
						logger.debug("→ dispatching to main shell for %s: %r", op_id, line)
						#process_command(line, to_console=False, to_op=op_id)
						threading.Thread(
							target=_handle_main_line,
							args=(operator, line),
							daemon=True
						).start()
				sleep(0.01)

		except Exception as e:
			logger.debug(f"ERRRRRROR IN DISPATCH OPERATORS: {e}")

	def _handle_gunnershell_line(operator, line):
		try:
			# this will block per-operator, not stall the dispatcher
			ret = operator.gs.interact(cmd=line, to_console=False, op_id=operator.op_id)

			if not ret:
				logger.debug("   no return value (empty), skipping")
				return


			if ret == "exit":
				logger.debug("   GunnerShell requested exit, switching back to main")
				operator.shell = "main"
				operator.gs    = None

			if ret:
				if "SIDSWITCH" in ret:
					logger.debug("   SIDSWITCH detected: %r", ret)
					parts = ret.split(maxsplit=1)
					if len(parts) != 2:
						# malformed return, drop back to main
						logger.warning("   malformed SIDSWITCH %r", ret)
						operator.shell = "main"
						operator.gs = None
						return

					new_sid = parts[1]
					logger.debug("   new SID = %s", new_sid)
					print(f"GUNNERSHELLSID: {new_sid}")

					try:
						operator.gs = Gunnershell(new_sid, operator.op_id)
						operator.shell = "gunnershell"
						logger.debug("   spawned new GunnerShell object for %s", new_sid)

					except Exception as e:
						logger.exception("   error creating new GunnerShell for %s", new_sid)
						print(brightred + f"ERROR: {e}")
						return
				else:
					from core import utils
					set_output_context(to_console=False, to_op=operator.op_id)
					logger.debug("   dispatching output to main via echo: %r", ret)
					#set_output_context(to_console=False, to_op=op_id, world_wide=False)
					utils.echo(ret, False, operator.op_id, world_wide=False)
					#operator.handler.sendall((ret + "\n").encode())
	
		except Exception as e:
			logger.exception("Error in gunnershell interact for %s: %s", operator.op_id, e)

	def _handle_main_line(operator, line):
		try:
			process_command(line, to_console=False, to_op=operator.op_id)

		except Exception as e:
			logger.exception("Error in main shell for %s: %s", operator.op_id, e)

	op_manage.start_operator_listener(host=args.host, port=args.port)
	threading.Thread(target=dispatch_operators, daemon=True).start()
	operator_loop()
