import logging
logger = logging.getLogger(__name__)

from core.utils import print_gunnershell_help

# Colorama variables
from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"
reset = Style.RESET_ALL


def help_menu(parts, to_console=True, op_id="console"):
	# help <command>
	if len(parts) == 1:
		print_gunnershell_help(parts[0])
		return True

	# help <command> <subcommand>
	elif len(parts) == 2:
		print_gunnershell_help(f"{parts[0]} {parts[1]}")
		return True

	else:
		print(brightyellow + "Usage: help or help <command> [subcommand]")
		return True

	return False