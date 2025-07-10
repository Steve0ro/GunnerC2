import socket
from core import utils
from core.session_handlers import session_manager
import os, sys, subprocess
import ssl
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import tempfile
import readline
from core.prompt_manager import prompt_manager

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

PROMPT = brightblue + "GunnerC2 > " + brightblue

global prompt_print
prompt_print = 1


def generate_tls_context(listen_ip):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"GunnerC2")
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    )

    san = x509.SubjectAlternativeName([
        x509.DNSName("GunnerC2"),
        x509.IPAddress(ipaddress.IPv4Address(listen_ip))
    ])

    builder = builder.add_extension(san, critical=False)

    # 5) Sign the cert
    cert = builder.sign(key, hashes.SHA256())

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

    # Write to temporary files
    key_file = tempfile.NamedTemporaryFile(delete=False)
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    key_file.write(key_bytes)
    cert_file.write(cert_bytes)
    key_file.close()
    cert_file.close()

    # Load into SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
    return context

def collect_tcp_metadata(sid):
    session = session_manager.sessions[sid]
    sock = session.handler

    try:
        # Step 1: OS Detection via uname -a
        sock.sendall(b"uname\n")
        sock.settimeout(0.5)
        response = b""

        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        output = response.decode(errors="ignore").strip()
        #print(f"[DEBUG] TCP agent {sid} OS check: {output}")
        session.detect_os(output)

        # Step 2: Queue and collect metadata
        for field, cmd in session.os_metadata_commands:
            try:
                sock.sendall((cmd + "\n").encode())
                sock.settimeout(0.5)
                response = b""

                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break

                result = response.decode(errors="ignore").strip()
                lines = [line for line in result.splitlines() if line.strip() not in ("$", "#", ">")]
                #result_cleaned = "\n".join(lines).strip()
                
                if len(lines) > 1:
                    clean = lines[1] if lines else ""
                    session.metadata[field] = clean

                elif len(lines) == 1:
                    clean = lines[0] if lines else ""
                    session.metadata[field] = clean

                else:
                    print(brightred + f"[!] Failed to execute metadata collecting commands!")

            except Exception as e:
                print(brightred + f"[!] Metadata collection failed for {sid} (field: {field}): {e}")
                session.metadata[field] = "Error"

    except Exception as e:
        print(brightred + f"[!] OS detection failed for {sid}: {e}")
        session.metadata["os"] = "Unknown"

def start_tcp_listener(ip, port, cert_path=None, key_path=None, is_ssl=None):
    if is_ssl:
        if cert_path and key_path:
            if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
                print(brightred + "[-] Specified cert or key file not found. Exiting listener.")
                return

            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            print(brightgreen + f"[*] Loaded TLS cert: {cert_path}, key: {key_path}")

        else:
            context = generate_tls_context(ip)
    else:
        context = None
        #print(brightyellow + f"[*] SSL disabled, running raw TCP on {ip}:{port}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    #server_socket.setsockopt(socket.SOL_SOCKET,  socket.SO_SNDBUF, 1 << 20)  # 1 MiB send buffer
    #server_socket.setsockopt(socket.SOL_SOCKET,  socket.SO_RCVBUF, 1 << 20)  # 1 MiB recv buffer

    try:
        server_socket.bind((ip, port))

    except OverflowError:
        print(brightred + f"[!] Must pick a port between 0-65535")
        return None

    except OSError:
        print(brightred + f"[!] Specified port is already in use")
        return None

    server_socket.listen(5)
    if is_ssl:
        utils.tls_listener_sockets[f"tls-{ip}:{port}"] = server_socket

    elif not is_ssl:
        utils.tcp_listener_sockets[f"tcp-{ip}:{port}"] = server_socket

    else:
        print(brightred + f"[!] Unknown listener type detected!")

    if not is_ssl:
        print(brightyellow + f"[+] TCP listener started on {ip}:{port}")

    elif is_ssl:
        print(brightyellow + f"[+] TLS listener started on {ip}:{port}")

    while True:
        raw_client, addr = server_socket.accept()

        # Wrap in SSL if requested, else keep raw socket
        if is_ssl and context:
            # set a timeout so handshake won’t block forever
            raw_client.settimeout(0.5)
            try:
                # wrap without doing handshake immediately
                ssl_sock = context.wrap_socket(
                    raw_client,
                    server_side=True,
                    do_handshake_on_connect=False
                )

                # perform the handshake under the timeout
                ssl_sock.do_handshake()
                client_socket = ssl_sock

            except (ssl.SSLError, socket.timeout) as e:
                print(brightred + f"[-] TLS handshake failed from {addr}: {e}")
                raw_client.close()
                continue
        else:
            client_socket = raw_client

        try:
            test = 1
            #server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            #server_socket.setsockopt(socket.SOL_SOCKET,  socket.SO_SNDBUF, 1 << 20)  # 1 MiB send buffer
            #server_socket.setsockopt(socket.SOL_SOCKET,  socket.SO_RCVBUF, 1 << 20)  # 1 MiB recv buffer

        except Exception as e:
            # if for some reason the wrapped socket doesn’t like it, ignore
            print(brightred + f"[!] Warning: couldn't tune socket: {e}")

        sid = utils.gen_session_id()
        session_manager.register_tcp_session(sid, client_socket, is_ssl)
        session = session_manager.sessions[sid]
        transport = session.transport.upper()

        """if prompt_print == 1:
            utils.async_note(brightgreen + f"[+] New {transport} agent: {sid}", PROMPT)

        elif prompt_print == 0:
            print(brightgreen + f"[+] New {transport} agent: {sid}")

        else:
            print(brightred + f"[!] An unknown error has ocurred!")"""

        print(brightgreen + f"\n[+] New {transport} agent: {sid}")
        prompt_manager.print_prompt()

        # DRAIN BANNER (important!)
        client_socket.settimeout(0.5)
        try:
            while True:
                junk = client_socket.recv(1024)
                if not junk:
                    break
        except:
            pass
        client_socket.settimeout(None)

        collect_tcp_metadata(sid)
