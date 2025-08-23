from __future__ import annotations
import base64
import argparse
from typing import List, Optional, Type, Any

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred    = "\001" + Style.BRIGHT + Fore.RED    + "\002"
reset = Style.RESET_ALL

# Gunnershell Special Imports
from core.gunnershell.commands.base import register, Command, QuietParser
from core.session_handlers import session_manager
from core.gunnershell.bofs.base import _resolve_bof_bytes, BOFS

@register("bofexec")
class BofExecCommand(Command):
	"""
	Execute a BOF either by registered name (from the BOF registry) or by filesystem path.

	SAFE SKELETON: This command resolves and packages the BOF but DOES NOT transmit
	or execute anything. Wire to your own transport/agent in the TODO section.

	Usage:
	  bofexec <bof_name_or_path> [-z ASCII_STR ...] [-Z WIDE_STR ...]
	"""

	@property
	def help(self):
		return ("bofexec <bof_name_or_path> [-z STR ...] [-Z WSTR ...]   "
				"resolve a BOF and execute it on agent.")

	def _parse_args(self, args: List[str]):
		p = QuietParser(prog="bofexec", add_help=False)
		p.add_argument("bof", help="BOF name (from registry) or filesystem path to .o/.obj")
		p.add_argument("--x86", dest="x86", action="store_true", default=False, required=False, help="Execute x86 BOF")
		p.add_argument("-z", dest="zargs", action="append", default=[], help="ASCII string argument (repeatable)")
		p.add_argument("-Z", dest="Zargs", action="append", default=[], help="WIDE string argument (repeatable)")
		p.add_argument("-s", dest="int16", action="append", default=[], help="16 bit Intger argument (repeatable)")
		p.add_argument("-i", dest="int32", action="append", default=[], help="32 bit Intger argument (repeatable)")
		p.add_argument("-h", "--help", dest="help", action="store_true", default=False, help="Display help menu for BOF")
		try:
			opts = p.parse_args(args)
		except SystemExit:
			print(brightyellow + self.help)
			return

		return opts

	def execute(self, args):
		ns = self._parse_args(args)
		if not ns:
			return None

		if ns.help:
			cls: Optional[Type[Any]] = BOFS.get(ns.bof)
			out = cls.help_menu()
			#print(brightyellow + f"{out}" + reset)
			return

		if ns.x86:
			arch = "x86"

		else:
			arch = "x64"

		out = self.logic(
			bof_ref=ns.bof,
			bofarch=arch,
			zargs=ns.zargs,
			Zargs=ns.Zargs,
			int16=ns.int16,
			int32=ns.int32,
		)
		if out:
			print(out)

	def logic(self, bof_ref: str, bofarch: str, zargs: List[str], Zargs: List[str], int16: List[int], int32: List[int]):
		# Resolve BOF bytes via file or registry
		args, res = _resolve_bof_bytes(bof_ref, bofarch, zargs, Zargs, int16, int32)
		if not res:
			hint = ""
			if not self.gs.bofs_enabled:
				hint = (f"\n{brightyellow}Note:{brightgreen} BOF registry not loaded "
						f"(gunnerplant={self.gs.gunnerplant}).")
			return brightred + f"[!] BOF not found: {bof_ref}" + hint

		b64 = res
		if not b64:
			return brightred + f"[!] Failed to load BOF: {bof_ref}"

		# Prepare a payload package (base64 for display; do not transmit here)
		#b64 = base64.b64encode(data).decode("ascii")

		# Minimal quoting for display
		def q(s) -> str:
			if ('"') in s:
				return s.replace('"', '')

			else:
				return s
			#return '"' + s.replace('"', '\\"') + '"'

		parts = [f"bofexec {b64}"]
		for s in (zargs or []):
			parts.append(f"-z:{q(s)}")

		for s in (Zargs or []):
			parts.append(f"-Z:{q(s)}")

		for s in (int16 or []):
			parts.append(f"-s:{q(s)}")
			
		for s in (int32 or []):
			parts.append(f"-i:{q(s)}")

		if args:
			for s in args:
				if bof_ref in ("schtasksquery"):
					parts.insert(1, s)

				else:
					parts.append(s)

		#print(parts)

		preview = " ".join(parts)

		sid = self.gs.sid

		sess = session_manager.sessions.get(sid)
		transport = sess.transport.lower()

		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, preview, op_id=self.op_id)

		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, preview, timeout=0.5, portscan_active=True, op_id=self.op_id)

		else:
			out = brightred + f"[!] Transport unknown {transport}"
			return out

		return(
			brightgreen + f"[+] BOF Output:\n"
			+ f"{out}"
			)