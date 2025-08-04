#!/usr/bin/env python3
import argparse
import socket
import threading
import sys
import os
import struct
import select
import readline
import getpass
from time import sleep
import logging
from colorama import init, Fore, Style
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

# ANSI color shortcuts
brightgreen  = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred    = Style.BRIGHT + Fore.RED
brightblue   = Style.BRIGHT + Fore.BLUE
reset        = Style.RESET_ALL
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"

# ————————————————
# wire up a client-side log file
logging.basicConfig(
    filename=os.path.expanduser("gunnerc2_client.log"),
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("gunnerclient")

_SECRET = "Sh3DNNG7km6W0nVIQVdl6L1Zyeg76v80OZT0ghritXsvuAuLqiN6VZMT5NNFfp0W"
_KEY    = hashlib.sha256(_SECRET.encode()).digest()
_AESGCM = AESGCM(_KEY)

# initialize colorama
init()

# global state
prompt_main = brightblue + "GunnerC2 > " + reset
prompt_gs = f"{UNDERLINE_ON}{brightblue}GunnerShell{UNDERLINE_OFF} > "
prompt = prompt_main
response_event = threading.Event()
shutdown_event = threading.Event()
notcmd = False

GS_COMMANDS_LIST = [
	"help", "list", "gunnerid", "help", "banner", "sessions", "alias", "exit",
	"upload", "download", "shell", "switch", "portfwd", "modhelp", "run",
	"search", "ls", "cat", "cd", "pwd", "cp", "mv", "rmdir", "checksum",
	"del", "rm", "mkdir", "md", "touch", "drives", "edit", "netstat",
	"ifconfig", "arp", "resolve", "nslookup", "route", "getproxy",
	"portscan", "hostname", "socks", "sysinfo", "ps", "getuid", "getprivs",
	"groups", "getav", "defenderoff", "amsioff", "getpid", "steal_token",
	"getenv", "exec", "kill", "getsid", "clearev", "localtime", "reboot",
	"pgrep", "pkill", "suspend", "resume", "shutdown", "reg", "services",
	"netusers", "netgroups", "screenshot", "winrm", "netexec", "rpcexec",
	"wmiexec", "getusers", "getgroups", "getcomputers", "getdomaincontrollers",
	"getous", "getgpos", "getdomain", "gettrusts", "getforests", "getfsmo",
	"getpwpolicy", "getdelegation", "getadmins", "getspns", "kerbrute"
]

MAIN_COMMANDS_LIST = [
	"help", "start", "portfwd", "sessions", "listeners", "alias", "shell", "kill",
	"jobs", "generate", "exec", "download", "upload", "banner", "search",
	"use", "shelldefence", "gunnershell"
]


HISTORY_MAIN = os.path.expanduser("~/.gunnerc2_client_main_history")
HISTORY_GS   = os.path.expanduser("~/.gunnerc2_client_gs_history")
global current_gs_sid, gunnershell_sids
current_gs_sid = None
gunnershell_sids = []

def completer(text, state):
	cmds = MAIN_COMMANDS_LIST if prompt == prompt_main else GS_COMMANDS_LIST
	options = [c for c in cmds if c.startswith(text)]

	try:
		return options[state]

	except IndexError:
		return None

def bind_keys():
	readline.parse_and_bind('"\\C-l": clear-screen')
	readline.parse_and_bind("tab: complete")
	readline.set_completer(completer)

def delete_history_file(sids):
	try:
		os.remove(HISTORY_MAIN)

	except FileNotFoundError:
		pass

	try:
		for sid in sids:
			try:
				path = os.path.expanduser(f"~/.gunnerc2_client_gs_{sid}_history")
				os.remove(path)

			except Exception:
				pass

	except Exception:
		pass

class Gunnershellmanagement:
	def __init__(self):
		self.gs_sid = None

	def set_gs_sid(self, sid):
		if sid:
			self.gs_sid = sid

	def get_gs_sid(self):
		return self.gs_sid

gunmanage = Gunnershellmanagement()


def _recvall(sock, n):
	data = b''
	while len(data) < n:
		chunk = sock.recv(n - len(data))
		if not chunk:
			raise ConnectionError("connection closed")
		data += chunk
	return data

def send_encrypted(raw_sock, plaintext: bytes):
	nonce = os.urandom(12)
	ct    = _AESGCM.encrypt(nonce, plaintext, None)
	payload = nonce + ct
	header  = len(payload).to_bytes(4, 'big')
	raw_sock.sendall(header + payload)

def recv_encrypted(raw_sock) -> bytes:
	header = _recvall(raw_sock, 4)
	length = int.from_bytes(header, 'big')
	blob   = _recvall(raw_sock, length)
	nonce, ct = blob[:12], blob[12:]
	return _AESGCM.decrypt(nonce, ct, None)

class EncryptedSocket:
	def __init__(self, sock): self.sock = sock
	def sendall(self, data):    return send_encrypted(self.sock, data)
	def send(self, data):       return send_encrypted(self.sock, data)
	def recv(self, _):          return recv_encrypted(self.sock)
	def close(self):
		try:
			self.sock.close()

		except Exception:
			pass

	def shutdown(self, how=socket.SHUT_RDWR):
		"""Expose socket.shutdown() so callers don’t need to touch .sock."""
		try:
			self.sock.shutdown(how)

		except Exception:
			pass

	def __getattr__(self, n):   return getattr(self.sock, n)

def recv_loop(sock, shutdown_event):
	"""Continuously read from the server socket and print whatever comes in."""
	global prompt, start, notcmd
	try:
		logger.debug(">>> recv_loop starting")
		while not shutdown_event.is_set():
			data = sock.recv(30000)
			logger.debug("<<< raw recv %d bytes: %r", len(data or b""), data)
			if not data:
				logger.info("<<< server closed connection")
				shutdown_event.set()
				sys.stdout.write('\r\n' + brightred + "[!] Server closed connection, exiting...\n" + reset)
				sys.stdout.flush()
				break

			buf = data
			
			while True:
				ready, _, _ = select.select([sock], [], [], 0.05)
				if not ready:
					break
				more = sock.recv(4096)
				logger.debug("<<< raw recv more %d bytes: %r", len(more or b""), more)
				if not more:
					break
				buf += more

			msg = buf.decode(errors="ignore")
			saved = readline.get_line_buffer()
			logger.debug("    → decrypted message: %r", msg)

			
			if "Usage: gunnershell" in msg:
				prompt = prompt_main

			for keyword in ("new tcp agent", "new tls agent", "new http agent", "new https agent"):
				if keyword in msg.lower():
					notcmd = True
					break

			if "gunneroperatoralert{(::)}" in msg.lower():
				if not selfalert:
					notcmd = True
				parts = msg.split("{(::)}")
				msg = parts[1]
				msg = "\n" + msg.lstrip()

			if "gunneroperatorkick{(::)}" in msg.lower():
				print(brightred + f"\n[!] You have been kicked from the C2.\n")
				shutdown_event.set()
				break

			# print server reply, then redraw prompt+buffer
			if "GUNNERSHELLSID" not in msg:
				sys.stdout.write('\r\n' + msg + '\r\n')
				#saved = readline.get_line_buffer()

				if not start and notcmd:
					sys.stdout.write(prompt + saved)

				elif notcmd:
					sys.stdout.write(prompt + saved)

				readline.redisplay()
				sys.stdout.flush()

			else:
				parts = msg.split()
				sid = parts[1]
				gunmanage.set_gs_sid(sid)
				gunnershell_sids.append(sid)

				if not start and notcmd:
					sys.stdout.write(prompt + saved)

				elif notcmd:
					sys.stdout.write(prompt + saved)

				readline.redisplay()
				sys.stdout.flush()
				
			notcmd = False
			logger.debug("    → setting response_event")
			#print("SETTING RESPONSE EVENT")
			response_event.set()

	except Exception as e:
		# unrecoverable error → log, signal shutdown, and exit
		sys.stderr.write(brightred + f"\n[!] recv_loop error: {e}\n" + reset)

		shutdown_event.set()

def main():
	global prompt
	p = argparse.ArgumentParser(description="GunnerC2 CLI client")
	p.add_argument("--server", required=True, help="GunnerC2 host or IP")
	p.add_argument("--port",   type=int, required=True, help="GunnerC2 operator port")
	p.add_argument("--prompt-timeout", dest="prompt_timeout", type=int, required=False, default=0.1, help="Timeout between each prompt print")

	# operator auth
	p.add_argument("-u","--username", help="Operator username")
	p.add_argument("-p","--password", help="Operator password")
	args = p.parse_args()

	bind_keys()

	# connect to server
	raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	raw.settimeout(5.0)
	try:
		raw.connect((args.server, args.port))
		raw.settimeout(None)
	except (ConnectionRefusedError, socket.timeout, OSError):
		print(brightred + f"[!] Server {args.server} refused our connection on port {args.port}" + reset)
		return

	# wrap & authenticate
	sock = EncryptedSocket(raw)

	# Start teamserver authentication process
	"""starting_data = ''
	sock.sendall((starting_data + "\n").encode())"""

	# ─── flush the server's "Username:" prompt ─────────────────────────────────
	_ = sock.recv(1024)

	# prompt locally if not passed in
	if not args.username:
		args.username = input("Username: ")
	sock.sendall((args.username + "\n").encode())

	# ─── flush the server's "Password:" prompt ─────────────────────────────────
	_ = sock.recv(1024)

	sleep(0.1)

	if not args.password:
		args.password = getpass.getpass("Password: ")
	sock.sendall((args.password + "\n").encode())

	# ─── read authentication result ────────────────────────────────────────────
	resp = sock.recv(1024)
	if not resp:
		print(brightred + "[!] No response from server, exiting." + reset)
		return

	text = resp.decode(errors="ignore").strip()
	if "Invalid credentials" in text:
		print(brightred + text + reset)
		return

	elif "SQL injection" in text:
		print(brightred + text + reset)
		return

	print(brightgreen + text + reset + "\n")

	global start
	global notcmd
	global selfalert
	start = True
	selfalert = False
	# start background reader
	sock = EncryptedSocket(raw)
	t = threading.Thread(target=recv_loop, args=(sock, shutdown_event), daemon=True)
	t.start()

	# set up prompts

	try:
		while not shutdown_event.is_set():
			try:
				current_gs_sid = gunmanage.get_gs_sid()
				if prompt == prompt_main:
					hist = HISTORY_MAIN

				elif prompt == prompt_gs and current_gs_sid:
					# per-session history
					hist = os.path.expanduser(f"~/.gunnerc2_client_gs_{current_gs_sid}_history")

				else:
					hist = HISTORY_GS

				readline.clear_history()
				if os.path.exists(hist):
					try:
						readline.read_history_file(hist)

					except Exception:
						pass

				else:
					try:
						open(hist, 'a').close()

					except Exception:
						pass

				try:
					sleep(args.prompt_timeout)
					line = input(prompt)
				except EOFError:
					break

				cmd = line.strip()
				if not cmd:
					continue  # just hit enter

				parts = cmd.split()

				if parts[0] == "alert":
					selfalert = True

				if parts[0] == "banner":
					os.system("clear")

				# local exits
				if cmd in ("exit", "quit", "back") and prompt == prompt_main:
					print(brightyellow + "[*] Exiting" + reset)
					break

				if cmd in ("exit", "quit", "back") and prompt == prompt_gs:
					prompt = prompt_main
					response_event.clear()
					logger.debug(">>> sending command: %r", cmd + "\n")
					sock.send((cmd + "\n").encode())
					continue

				# send to server
				response_event.clear()
				logger.debug(">>> sending command: %r", cmd + "\n")
				sock.send((cmd + "\n").encode())
				logger.debug(f"SENT COMMAND TO SERVER: {cmd}")


				logger.debug("PAST SEND LOGGER")
				logger.debug("SETTING START TO FALSE")
				start = False  

				# switch prompt if entering/leaving subshell
				logger.debug("CHECKING IF CMD STARTS WITH GS OR GUNNERSHELL")
				if cmd.startswith(("gunnershell", "gs")):
					logger.debug("CMD STARTS WITH GS OR GUNNERSHELL")
					prompt = prompt_gs
					logger.debug("CHECKING IF WERE IN GUNNERSHELL AND CMD IS EXIT")

				elif prompt == prompt_gs and cmd in ("exit", "quit", "back"):
					logger.debug("IN GUNNERSHELL AND CMD IS EXIT, QUIT OR BACK")
					prompt = prompt_main
					current_gs_sid = None

				logger.debug("THROUGH ALL CHECKS")

				logger.debug("RUNNING .WAIT ON RESPONSE_EVENT")
				response_event.wait()
				response_event.clear()

			except Exception as e:
				print(brightred + f"ERROR: {e}")

			finally:
				try:
					readline.write_history_file(hist)

				except Exception:
					pass

	except KeyboardInterrupt:
		print()

	finally:
		shutdown_event.set()
		readline.clear_history()
		delete_history_file(gunnershell_sids)
		try:
			sock.shutdown()

		except Exception:
			pass

		t.join(timeout=1.0)

		readline.clear_history()
		delete_history_file(gunnershell_sids)

		sock.close()
		return

if __name__ == "__main__":
	main()
