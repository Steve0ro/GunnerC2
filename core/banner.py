from colorama import init, Fore, Style
brightgreen = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred = Style.BRIGHT + Fore.RED
brightblue = Style.BRIGHT + Fore.BLUE


def print_banner():
    """
    Print a red ASCII-art banner saying 'GUNNER'.
    """
    # Initialize colorama
    init(autoreset=True)

    banner = r"""
   ______   __  __    _   __    _   __    ______    ____ 
  / ____/  / / / /   / | / /   / | / /   / ____/   / __ \
 / / __   / / / /   /  |/ /   /  |/ /   / __/     / /_/ /
/ /_/ /  / /_/ /   / /|  /   / /|  /   / /___    / _, _/ 
\____/   \____/   /_/ |_/   /_/ |_/   /_____/   /_/ |_|
"""

    print(brightred + banner)
    print("\n")
    #print("\n")