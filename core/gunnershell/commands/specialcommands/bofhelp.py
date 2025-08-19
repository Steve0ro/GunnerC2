from __future__ import annotations
import io
import re
from contextlib import redirect_stdout
from typing import List, Tuple

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED   + "\002"
reset       = Style.RESET_ALL

from core.gunnershell.commands.base import register, Command, QuietParser
from core.gunnershell.bofs.base import BOFS, load as load_bof_registry

# ---- Configure which BOFs belong to this section (order preserved) ----
SA_ORDER: List[str] = [
	"whoami",
	"dir",
	# add more situational awareness BOF names here, in the order you want
]

# ---- Helpers to extract a one-liner description from each provider ----
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
CTRL_RE = re.compile(r"[\001\002]")

def _clean(s: str) -> str:
	s = ANSI_RE.sub("", s)
	s = CTRL_RE.sub("", s)
	return s.strip()

def _one_liner_for(name: str):
	"""Prefer first line of docstring; else first non-empty line from help_menu()."""
	cls = BOFS.get(name)
	if not cls:
		return ""

	# Fallback: capture provider's help_menu() output
	help_fn = getattr(cls, "help_menu", None)
	if callable(help_fn):
		try:
			buf = io.StringIO()
			with redirect_stdout(buf):
				out = help_fn()
				if isinstance(out, str) and out.strip():
					print(out)
			for line in _clean(buf.getvalue()).splitlines():
				L = line.strip()
				# Skip generic "Usage:" header lines
				if L and not L.lower().startswith("usage"):
					return L
		except Exception:
			pass
	return ""

def _gather_sa(term: str | None) -> List[Tuple[str, str]]:
	"""Return [(name, desc)] for SA BOFs that exist in registry (optionally filtered)."""
	items: List[Tuple[str, str]] = []
	hay_term = term.lower() if term else None

	for name in SA_ORDER:
		if name not in BOFS:
			# silently skip if not registered
			continue
		desc = _one_liner_for(name)
		if hay_term:
			combined = f"{name} {desc}".lower()
			if hay_term not in combined:
				continue
		items.append((name, desc))
	return items

@register("bofhelp")
class BOFHelp(Command):
	"""
	bofhelp [TERM] — Lists BOFs in sections like GunnerShell help.
	Currently prints the 'Situational Awareness' section.
	If TERM is provided, results are filtered by that search term.
	"""
	@property
	def help(self):
		return "bofhelp [TERM]  — list BOFs by section (Situational Awareness). If TERM is provided, filter matches."

	def _parse(self, args):
		p = QuietParser(prog="bofhelp", add_help=False)
		p.add_argument("term", nargs="?", default=None, help="optional search term")
		try:
			return p.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help + reset)
			return None

	def execute(self, args):
		ns = self._parse(args)
		if not ns:
			return

		self.logic(ns)
		return

	def logic(self, ns):

		# Ensure registry is available
		if not BOFS:
			load_bof_registry()

		if not ns.term:
			# ---- Situational Awareness section ----
			sa_bofs = {
				"arp":              "Display ARP table",
				"dir":              "Display directory contents",
				"env":              "Display environment variables",
				"driversigs":       "Enumerate common EDR drivers",
				"getpwpolicy":      "Get server or domain password policy",
				"getsessinfo":      "Get local session info",
				"ipconfig":         "Get network information",
				"listfwrules":      "List all firewall rules",
				"listdns":          "List all cached DNS records",
				"listmods":         "List a process's imported DLL's",
				"locale":           "Get system locale information",
				"netlocalgroup":    "List local groups/local group members",
				"netloggedon":      "List all active user sessions",
				"netstat":          "Show sockets and listening ports",
				"nettime":          "Display local time on agent",
				"netuptime":        "Show uptime of machine",
				"netuser":          "Enumerate users in the AD domain",
				"netuserenum":      "Enumerate users in AD domain or local server",
				"routeprint":       "Print the entire route table",
				"whoami":           "Run internal command whoami /all",
				"tasklist":         "Lists currently running processes",
				"resources":        "Display computer memory information",
				"cacls":            "Display file permissions (Wildcards supported!)",
				"notepad":          "Steals text from any active notepad window",
				"netview":          "Lists local workstations and servers"
			}

			print()
			print(brightyellow + "Situational Awareness\n=====================\n")
			for name, desc in sa_bofs.items():
				print(brightgreen + f"{name:<25} {desc}")
			print()
			print(brightyellow + "\nFor detailed help run: bofhelp <bof>\n")

		else:
			bofclass = BOFS.get(ns.term)
			if bofclass:
				bofclass.help_menu()
				return

			else:
				print(brightred + f"[!] No Such BOF {ns.term} In BOF Library" + reset)
				return


		"""rows = _gather_sa(ns.term)

		if not rows:
			if ns.term:
				print(brightyellow + f"No BOFs matching '{ns.term}' in Situational Awareness." + reset)
			else:
				print(brightyellow + "No BOFs found in Situational Awareness." + reset)
			print()
			print(brightyellow + "For detailed help run: " + brightgreen + "bofexec <bof> -h" + reset)
			return

		# Align with your help menu: name padded to 25 then description
		for name, desc in rows:
			if desc:
				print(brightgreen + f"{name:<25} " + reset + f"{desc}")
			else:
				print(brightgreen + f"{name:<25} " + reset)

		print()
		print(brightyellow + "For detailed help run: " + brightgreen + "bofexec <bof> -h" + reset)"""
