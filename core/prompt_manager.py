import threading
import os
import sys
import subprocess
from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

class PromptManager:
    def __init__(self):
        self._prompt = brightblue + "GunnerC2 > " + brightblue  # default
        self._lock = threading.Lock()
        self.block_next_prompt = False

    def set_prompt(self, prompt_str):
        with self._lock:
            self._prompt = prompt_str

    def get_prompt(self):
        if self.block_next_prompt is False:
            with self._lock:
                return self._prompt
        else:
            return ""

    def print_prompt(self):
        # Always flush so it shows up immediately
        sys.stdout.write(self.get_prompt())
        sys.stdout.flush()


prompt_manager = PromptManager()
