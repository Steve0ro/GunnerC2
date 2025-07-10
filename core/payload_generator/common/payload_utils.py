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
	encoded = base64.b64encode(payload.encode('utf-16le')).decode()

	if not no_child:
		final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

	else:
		final_cmd = encoded

	return final_cmd
