import ssl
import threading
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from core.listeners.http_handler import C2HTTPRequestHandler, generate_http_session_id
from core.listeners.tcp_listener import generate_tls_context
from core.prompt_manager import prompt_manager
from core import utils
from colorama import init, Fore, Style
import os, sys, subprocess

brightgreen  = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred    = Style.BRIGHT + Fore.RED

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

def start_https_listener(ip: str, port: int, certfile: str = None, keyfile: str = None):
    try:
        utils.async_note(brightyellow + f"[+] HTTPS listener starting on {ip}:{port}", prompt_manager.get_prompt(), firstnewline=False, secondnewline=True, blockprompt=True)
        # Create the HTTP server
        httpd = ThreadingHTTPServer((ip, port), C2HTTPRequestHandler)
        utils.https_listener_sockets[f"https-{ip}:{port}"] = httpd

        httpd.scheme = "https"

        prompt_manager.get_prompt()
        # Build or load TLS context
        if certfile and keyfile:
            if not (os.path.isfile(certfile) and os.path.isfile(keyfile)):
                prompt_manager.block_next_prompt = False
                utils.async_note(brightred + "[-] Cert or key file not found, aborting HTTPS listener.", prompt_manager.get_prompt())
                return
            
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            utils.async_note(brightgreen + f"[*] Loaded certificate {certfile} and key {keyfile}", prompt_manager.get_prompt())

        else:
            context = generate_tls_context(ip)
            utils.async_note(brightgreen + "[*] Using generated self-signed certificate", prompt_manager.get_prompt(), firstnewline=False, secondnewline=True, blockprompt=True)

        # Wrap the HTTPServer socket
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        prompt_manager.block_next_prompt = False
        utils.async_note(brightgreen + f"[+] HTTPS listener ready on {ip}:{port}", prompt_manager.get_prompt(), firstnewline=False, secondnewline=True, reprint=True, blockprompt=False)
        try:
            httpd.serve_forever()

        except (KeyboardInterrupt, SystemExit):
            httpd.shutdown()
            utils.async_note(brightyellow + "[*] HTTPS listener stopped", prompt_manager.get_prompt())

        except (ConnectionResetError, BrokenPipeError):
            utils.async_note(brightred + f"[!] Connection reset from one of your agents!", prompt_manager.get_prompt())

    except (ConnectionResetError, BrokenPipeError):
        prompt_manager.block_next_prompt = False
        utils.async_note(brightred + f"[!] Connection reset from one of your agents!", prompt_manager.get_prompt())

    except Exception as e:
        prompt_manager.block_next_prompt = False
        utils.async_note(brightred + f"[!] An unknown error has ocurred in your HTTPS listener: {e}", prompt_manager.get_prompt())
