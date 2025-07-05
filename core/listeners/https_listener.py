import ssl
from http.server import HTTPServer
from core.listeners.http_handler import C2HTTPRequestHandler, generate_http_session_id
from core.listeners.tcp_listener import generate_tls_context
from core import utils
from colorama import init, Fore, Style
import os, sys, subprocess

brightgreen  = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred    = Style.BRIGHT + Fore.RED

def start_https_listener(ip: str,
                         port: int,
                         certfile: str = None,
                         keyfile: str = None):
    """
    Start an HTTPS listener on (ip, port).
    If certfile+keyfile are provided, use them; otherwise generate a self-signed cert.
    """
    print(brightyellow + f"[+] HTTPS listener starting on {ip}:{port}")
    # Create the HTTP server
    httpd = HTTPServer((ip, port), C2HTTPRequestHandler)
    utils.https_listener_sockets[f"https-{ip}:{port}"] = httpd

    httpd.scheme = "https"

    # Build or load TLS context
    if certfile and keyfile:
        if not (os.path.isfile(certfile) and os.path.isfile(keyfile)):
            print(brightred + "[-] Cert or key file not found, aborting HTTPS listener.")
            return
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        print(brightgreen + f"[*] Loaded certificate {certfile} and key {keyfile}")
    else:
        context = generate_tls_context(ip)
        print(brightgreen + "[*] Using generated self-signed certificate")

    # Wrap the HTTPServer socket
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(brightgreen + f"[+] HTTPS listener ready on {ip}:{port}\n")

    try:
        httpd.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        httpd.shutdown()
        print(brightyellow + "[*] HTTPS listener stopped")
