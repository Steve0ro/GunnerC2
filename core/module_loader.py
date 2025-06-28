import os
import importlib.util

from colorama import init, Fore, Style
brightgreen = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred = Style.BRIGHT + Fore.RED
brightblue = Style.BRIGHT + Fore.BLUE

MODULE_DIR = os.path.join(os.path.dirname(__file__), "modules")

def search_modules():
    return [
        file[:-3]
        for file in os.listdir(MODULE_DIR)
        if file.endswith(".py") and file != "module_base.py" and not file.startswith("__")
    ]

def load_module(name):
    try:
        module_path = os.path.join(MODULE_DIR, f"{name}.py")

        if not os.path.isfile(module_path):
            print(brightred + f"[-] Module file not found: {module_path}")
            return None

        spec = importlib.util.spec_from_file_location(name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        class_name = [i for i in dir(module) if i.lower().endswith("module")][0]
        instance = getattr(module, class_name)()

        print(brightyellow + f"[*] Using module: {instance.name}\n")
        return instance

    except IndexError:
        print(brightred + f"[!] Failed: No class ending in 'module' found in {name}.py")

    except Exception as e:
        print(brightred + f"[!] Error loading module: {e}")

    return None