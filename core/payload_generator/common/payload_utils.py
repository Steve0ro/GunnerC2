import os
import sys
import subprocess
import base64
import pyperclip
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


def copy_and_print(payload):
	if payload:
		final_cmd = payload
		pyperclip.copy(final_cmd)
		print(brightyellow + final_cmd)
		print(brightgreen + "[+] Payload copied to clipboard")
		return final_cmd

	else:
		print(brightred + f"[!] You must provide a payload!")


def encode_win_payload(payload, no_child):
	#payload = ";".join(payload)
	encoded = base64.b64encode(payload.encode('utf-16le')).decode()
	print(no_child)

	if not no_child or no_child is None or no_child == "" or no_child is not True:
		final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

	else:
		final_cmd = encoded

	return final_cmd


def build_powershell_headers(headers, nostart=False, first=False):
	ps_hdr_lines = []
	print(headers)
	print(type(headers))
	for name, val in headers.items():
		if nostart == False and first is True:
			ps_hdr_lines.append(f"$req.Headers.Add('{name}','{val}');")

		elif nostart == False and first is False:
			ps_hdr_lines.append(f"$req2.Headers.Add('{name}','{val}');")

		elif nostart == True and first is False:
			ps_hdr_lines.append(f"$req2.Headers.Add('{name}', '{val}');")

		elif nostart == True and first is True:
			ps_hdr_lines.append(f"$req.Headers.Add('{name}', '{val}');")

		else:
			print(brightred + f"[!] Unable to build headers dynamically!")
			return None

	# join into one block
	hdr_block = "".join(ps_hdr_lines)

	return hdr_block