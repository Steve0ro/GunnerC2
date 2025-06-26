import socket
from core import session_manager, utils

def collect_tcp_metadata(sid):
    session = session_manager.sessions[sid]
    sock = session.handler

    try:
        # Step 1: OS Detection via uname -a
        sock.sendall(b"uname\n")
        sock.settimeout(2)
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
                sock.settimeout(2)
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
                result_cleaned = "\n".join(lines).strip()
                session.metadata[field] = result_cleaned

            except Exception as e:
                print(f"[!] Metadata collection failed for {sid} (field: {field}): {e}")
                session.metadata[field] = "Error"

    except Exception as e:
        print(f"[!] OS detection failed for {sid}: {e}")
        session.metadata["os"] = "Unknown"

def start_tcp_listener(ip, port):
    print(f"[+] TCP listener started on {ip}:{port}")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    utils.tcp_listener_sockets[f"tcp-{ip}:{port}"] = server_socket

    while True:
        client_socket, addr = server_socket.accept()

        sid = utils.gen_session_id()
        session_manager.register_tcp_session(sid, client_socket)

        print(f"\n[+] New TCP agent: {sid}")

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
