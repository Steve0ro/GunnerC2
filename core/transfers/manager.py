import logging
logger = logging.getLogger(__name__)

import os, threading, time, uuid, traceback, ntpath, zipfile, tarfile, re, tempfile, shutil
from dataclasses import dataclass
from typing import Optional, Dict, Any, Literal, Iterable
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec
from .state import StateStore, TransferState
from .chunker import human_bytes, chunk_count
from .protocols.shell import ShellProtocol, _linux_shq, _ps_quote
from core.session_handlers import session_manager
from core.utils import echo

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

@dataclass
class TransferOpts:
	chunk_size: int = 1000000   # 256 KiB default
	compress: Optional[str] = None  # reserved; shell protocol uses archive for folders
	encrypt: Optional[str] = None   # reserved; enable in future protocols
	force_proto: Optional[str] = None  # reserved; e.g., "http-binary"
	to_console: bool = True
	to_op: Optional[str] = None
	quiet: bool = True   # <— NEW: suppress start/progress/complete chatter

class TransferManager:
	def __init__(self):
		self.store = StateStore()
		self._threads: Dict[str, threading.Thread] = {}
		self._stop_flags: Dict[str, threading.Event] = {}
		self._lock = threading.RLock()

	# ---------- helpers ----------
	def _protocol(self, op_id: Optional[str]) -> ShellProtocol:
		# For now we only ship the ShellProtocol (works over HTTP/TCP/TLS).
		return ShellProtocol(op_id)

	def _new_tid(self) -> str:
		return uuid.uuid4().hex[:12]

	# ---------- Windows path normalization ----------
	@staticmethod
	def _ensure_win_double_backslashes(path: str) -> str:
		if not path:
			return path
		# Replace any single '\' that is NOT already escaped on either side with '\\'
		# (?<!\\)   - previous char is not a backslash
		# \\        - the backslash we want to double
		# (?!\\)    - next char is not a backslash
		return re.sub(r'(?<!\\)\\(?!\\)', r'\\\\', path)


	def _mk_state(self, direction: Literal["download","upload"], sid: str, remote_path: str, local_path: str, is_folder: bool, opts: TransferOpts) -> TransferState:
		sess = session_manager.sessions[sid]
		os_type = sess.metadata.get("os","").lower()
		if os_type not in ("windows","linux"):
			raise RuntimeError(f"Unsupported OS for transfer: {os_type}")
		chunk = int(opts.chunk_size)
		st = TransferState(
			tid=self._new_tid(),
			sid=sid,
			direction=direction,
			remote_path=remote_path,
			local_path=local_path if direction=="download" else local_path,  # local_path is source for upload
			is_folder=is_folder,
			os_type=os_type, transport=sess.transport.lower(),
			chunk_size=chunk, total_bytes=0, total_chunks=0, tmp_local_path=None,
			options={"compress":opts.compress, "encrypt":opts.encrypt}
		)
		#print(st)
		logger.debug("TransferState: %r", st)
		return st

	def _progress_line(self, st: TransferState) -> str:
		done = st.bytes_done
		total = st.total_bytes or 0
		pct = (done/total*100.0) if total else 0.0
		return f"[{st.tid}] {pct:5.1f}%  {human_bytes(done)}/{human_bytes(total)}"

	def _emit(self, opts: TransferOpts, msg: str, color: Optional[str]=None, override_quiet: bool=False) -> None:
		if opts.quiet:
			if color:
				logger.debug(color + f"{msg}" + reset)

			else:
				logger.debug(f"{msg}")

		else:
			echo(msg, to_console=opts.to_console, to_op=opts.to_op, world_wide=False, color=color)

	def _backfill_is_folder(self, st) -> None:
		"""
		Ensure st.is_folder is a boolean. Prefer persisted hints; fall back to safe heuristics.
		"""
		# If already a bool, keep it
		if isinstance(getattr(st, "is_folder", None), bool):
			return

		opt = getattr(st, "options", {}) or {}

		# Strong signals from our own pipeline
		if opt.get("is_archive_transfer") or opt.get("extract_to"):
			st.is_folder = True
			return

		# Archive extension is also a strong hint
		ext = (opt.get("archive_ext") or "").lower()
		lp  = (st.local_path or "").lower()
		rp  = (st.remote_path or "").lower()
		if ext and (lp.endswith(ext) or rp.endswith(ext)):
			st.is_folder = True
			return

		# Uploads: original local path tells the truth
		if st.direction == "upload":
			olp = opt.get("original_local_path") or st.local_path
			try:
				st.is_folder = bool(olp and os.path.isdir(olp))
				return
			except Exception:
				pass

		# Downloads: original remote path trailing sep is a decent last resort
		orp = opt.get("original_remote_path") or st.remote_path or ""
		if orp.rstrip().endswith("/") or orp.rstrip().endswith("\\"):
			st.is_folder = True
			return

		# Fallback default
		st.is_folder = False

	# ---------- public API ----------
	def start_download(self, sid: str, remote_path: str, local_path: str, folder: Optional[bool]=None, opts: Optional[TransferOpts]=None) -> str:
		opts = opts or TransferOpts()
		# For folder downloads, choose an archive file path and record extraction target
		sess = session_manager.sessions[sid]
		os_type = sess.metadata.get("os","").lower()

		# Normalize Windows remote path slashes if needed
		if os_type == "windows":
			remote_path = self._ensure_win_double_backslashes(remote_path)

		# Auto-detect if we weren't told explicitly
		if folder is None:
			try:
				folder = self._probe_remote_is_dir(sid, remote_path, os_type, to_op=getattr(opts, "to_op", None))
			except Exception as e:
				# Fallback heuristic (very conservative): treat as FILE unless the path ends with a slash/backslash
				self._emit(opts, f"[!] Could not probe remote path type ({e}); guessing from path")
				rp = (remote_path or "").rstrip()
				folder = rp.endswith("/") or rp.endswith("\\")

		if folder:
			base = self._remote_basename(remote_path)
			ext  = ".zip" if os_type=="windows" else ".tar.gz"
			# local_path is the destination directory (as provided by -o)
			# If user passed a specific path that isn't an existing dir, treat it as a directory root.
			try:
				if os.path.isdir(local_path):
					out_dir = local_path
				else:
					# allow user to pass a not-yet-existing directory
					out_dir = local_path
					os.makedirs(out_dir, exist_ok=True)
			except Exception:
				out_dir = local_path
				os.makedirs(out_dir, exist_ok=True)
			archive_dest = os.path.join(out_dir, base + ext)
			extract_to   = os.path.join(out_dir, base)
			st = self._mk_state("download", sid, remote_path, archive_dest, True, opts)
			st.options["extract_to"] = extract_to
		else:
			# Single file download:
			# Resolve the *actual* target path:
			#   - if local_path is an existing directory → join with remote basename
			#   - if local_path looks like a directory (ends with '/' or '\') → create and join
			#   - else treat local_path as the file path
			target_file = self._resolve_file_target(local_path, remote_path)
			st = self._mk_state("download", sid, remote_path, target_file, False, opts)

		proto = self._protocol(opts.to_op)
		st = proto.init_download(st)
		st.total_chunks = chunk_count(st.total_bytes, st.chunk_size)
		self.store.save(st)
		stop = threading.Event()
		self._stop_flags[st.tid] = stop
		t = threading.Thread(target=self._run_download, args=(proto, st, opts, stop), daemon=True)
		t.start()
		self._threads[st.tid] = t
		self._emit(opts, f"[*] Transfer started (download) TID={st.tid} → {st.local_path}")
		return st.tid

	def _run_download(self, proto: ShellProtocol, st: TransferState, opts: TransferOpts, stop: threading.Event):
		try:
			# --- Align state with on-disk .part before we start/resume ---
			try:
				if st.tmp_local_path and os.path.exists(st.tmp_local_path):
					part_sz = os.path.getsize(st.tmp_local_path)
					# Clamp to total_bytes
					if st.total_bytes:
						part_sz = min(part_sz, st.total_bytes)
					full_chunks = part_sz // st.chunk_size
					tail = part_sz - (full_chunks * st.chunk_size)
					# If tail is non-zero, truncate it (it came from an interrupted chunk)
					if tail:
						with open(st.tmp_local_path, "r+b") as f:
							f.truncate(full_chunks * st.chunk_size)
						part_sz = full_chunks * st.chunk_size
					# Reset counters to match the disk
					st.next_index = full_chunks
					st.bytes_done = part_sz
					self.store.save(st)
			except Exception:
				pass
			# --- SAFETY: refuse resume if remote size changed (prevents corruption) ---
			try:
				# Only check when resuming or partially complete
				if st.next_index > 0 or (st.bytes_done and st.bytes_done > 0):
					current_total = 0
					try:
						current_total = proto._remote_size(st)
					except Exception:
						# If we cannot stat the remote now, pause instead of risking corruption
						st.status = "paused"
						self.store.save(st)
						self._emit(opts, f"[{st.tid}] remote not reachable; paused at chunk {st.next_index}", color=brightred, override_quiet=True)
						return

					# If size mismatch, don't continue writing into the old .part
					if st.total_bytes and current_total != st.total_bytes:
						st.status = "paused"
						self.store.save(st)
						self._emit(opts, f"[{st.tid}] remote file changed (was {st.total_bytes} bytes, now {current_total}); paused", color=brightred, override_quiet=True)
						return
			except Exception:
				pass

			last = time.time()
			while not stop.is_set():
				pre_idx = st.next_index
				#print(st)
				try:
					idx = proto.next_download_chunk(st)

				except (ConnectionError, ConnectionResetError, BrokenPipeError, OSError) as neterr:
					# Roll back any partial write from this in-flight chunk (defensive).
					# We want the file to contain only whole, completed chunks.
					try:
						# bytes that SHOULD exist = pre_idx * chunk_size (cap at total_bytes)
						want_bytes = pre_idx * st.chunk_size
						if want_bytes > st.total_bytes:
							want_bytes = st.total_bytes

						if st.tmp_local_path and os.path.exists(st.tmp_local_path):
							with open(st.tmp_local_path, "r+b") as f:
								f.truncate(want_bytes)

						st.bytes_done = want_bytes
					except Exception:
						# best effort; even if truncate fails, we still pause
						pass
					# Ensure we resume from this same chunk
					st.next_index = pre_idx
					st.status = "paused"
					self.store.save(st)
					self._emit(opts, f"[{st.tid}] connection lost ({neterr.__class__.__name__}); paused at chunk {st.next_index}", color=brightred, override_quiet=True)
					return

				"""except Exception:
					print("GOT YOU")
					raise"""

				if idx is None:
					break
				if time.time() - last >= 0.5:
					self.store.save(st)
					#self._emit(opts, self._progress_line(st))
					last = time.time()

				#self._emit(opts, f"[debug] wrote chunk {idx} (resumed_from={pre_idx})")

			if stop.is_set():
				st.status = "paused"
				self.store.save(st)
				self._emit(opts, f"[{st.tid}] paused at chunk {st.next_index}", color=brightred, override_quiet=True)
				return

			# Not all chunks fetched → treat as paused (don’t finalize!)
			if st.next_index < st.total_chunks:
				st.status = "paused"
				self.store.save(st)
				self._emit(opts, f"[{st.tid}] paused at chunk {st.next_index}", color=brightred, override_quiet=True)
				return

			# finalize: move .part -> archive or final file
			self.store.finalize(st)
			st.status = "done"
			self.store.save(st)
			# If this was a folder download, extract locally then remove archive
			final_msg = st.local_path
			if st.is_folder:
				# Quick header sanity check
				try:
					with open(st.local_path, "rb") as f:
						head = f.read(4)
					if st.os_type == "windows":
						# zip: PK 03 04
						if head != b"PK\x03\x04":
							raise ValueError("zip header mismatch")
					else:
						# gzip: 1F 8B
						if not (len(head) >= 2 and head[0] == 0x1F and head[1] == 0x8B):
							raise ValueError("gz header mismatch")
				except Exception as ex:
					st.status = "error"
					st.error = f"Downloaded archive invalid: {ex}"
					self.store.save(st)
					self._emit(opts, f"[!] Downloaded archive invalid; left at {st.local_path}")
					return

				extract_to = st.options.get("extract_to")
				try:
					if st.os_type == "windows" and st.local_path.lower().endswith(".zip"):
						with zipfile.ZipFile(st.local_path, 'r') as zf:
							self._safe_extract_zip(zf, extract_to)

						try:
							os.remove(st.local_path)   

						except Exception:
							pass

						final_msg = extract_to

					elif st.os_type == "linux" and st.local_path.endswith(".tar.gz"):
						with tarfile.open(st.local_path, "r:gz") as tf:
							self._safe_extract_tar(tf, extract_to)

						try:
							os.remove(st.local_path)

						except Exception:
							pass

						final_msg = extract_to

				except Exception as ex:
					self._emit(opts, f"[!] Local extraction failed ({ex}); archive left at {st.local_path}")
				# Clean up remote archive regardless
				proto.cleanup(st)
			else:
				# Non-folder: still perform any remote cleanup protocol recorded
				proto.cleanup(st)
			self._emit(opts, f"[+] Transfer complete: {final_msg}")
		except Exception as e:
			st.status = "error"
			st.error = f"{e}"
			self.store.save(st)
			self._emit(opts, f"[!] Transfer error {st.tid}: {e}", color=brightred, override_quiet=True)

	def start_upload(self, sid: str, local_path: str, remote_path: str, folder: bool, opts: Optional[TransferOpts]=None) -> str:
		opts = opts or TransferOpts()
		# Normalize Windows remote path slashes if needed *before* creating state
		sess = session_manager.sessions[sid]
		os_type = sess.metadata.get("os","").lower()
		if os_type == "windows":
			remote_path = self._ensure_win_double_backslashes(remote_path)


		# Determine local item type (authoritative) and ignore legacy --folder flag.
		local_is_dir = False
		try:
			local_is_dir = os.path.isdir(local_path)
		except Exception:
			local_is_dir = False

		# Probe remote path to see if it is an existing directory, matching download behavior.
		# Fallback heuristic: treat as DIR if it ends with / or \\, else as FILE.
		try:
			remote_is_dir = self._probe_remote_is_dir(sid, remote_path, os_type, to_op=getattr(opts, "to_op", None))
		except Exception:
			rp = (remote_path or "").rstrip()
			remote_is_dir = rp.endswith("/") or rp.endswith("\\")

		st = self._mk_state("upload", sid, remote_path, local_path, local_is_dir, opts)

		# --- Case A: uploading a folder (archive, upload, extract, cleanup) ---
		if local_is_dir:
			local_root  = local_path.rstrip("/\\")
			folder_name = os.path.basename(local_root) or "folder"
			if os_type == "windows":
				# Build zip in temp; preserve top-level folder name.
				archive = os.path.join(tempfile.gettempdir(), f"{folder_name}.zip")
				try:
					os.remove(archive)
				except FileNotFoundError:
					pass

				shutil.make_archive(
					base_name=os.path.splitext(archive)[0],
					format="zip",
					root_dir=os.path.dirname(local_root),
					base_dir=folder_name,
				)
				# Choose remote directory to place archive into
				remote_dir = remote_path.rstrip("\\/") if remote_is_dir else ntpath.dirname(remote_path.rstrip("\\/"))
				if not remote_dir:
					remote_dir = remote_path.rstrip("\\/")
				remote_archive = ntpath.join(remote_dir, f"{folder_name}.zip")
				st.options["extract_dest"] = remote_dir
			else:
				archive = os.path.join("/tmp", f"{folder_name}.tar.gz")
				try: os.remove(archive)
				except FileNotFoundError: pass
				shutil.make_archive(
					base_name=os.path.splitext(archive)[0],
					format="gztar",
					root_dir=os.path.dirname(local_root),
					base_dir=folder_name,
				)
				remote_dir = remote_path.rstrip("/") if remote_is_dir else os.path.dirname(remote_path.rstrip("/"))
				if not remote_dir:
					remote_dir = remote_path.rstrip("/")
				remote_archive = os.path.join(remote_dir, f"{folder_name}.tar.gz")
				st.options["extract_dest"] = remote_dir
			# Switch transfer to the archive
			st.local_path  = archive
			st.remote_path = remote_archive

		# --- Case B: uploading a single file ---
		else:
			# If remote is a directory (or looks like one), drop file inside using local basename.
			if remote_is_dir:
				name = os.path.basename(local_path.rstrip("/\\"))
				if os_type == "windows":
					st.remote_path = ntpath.join(remote_path.rstrip("\\/"), name)
				else:
					st.remote_path = os.path.join(remote_path.rstrip("/"), name)
			else:
				# Treat the given remote path as the final filename.
				st.remote_path = remote_path

		# Ensure parent directory exists on remote before init_upload (both cases).
		if os_type == "windows":
			parent = ntpath.dirname(st.remote_path.rstrip("\\/")) or st.remote_path.rstrip("\\/")
			ps = (
				f"$p = {_ps_quote(parent)};"
				f"if (-not (Test-Path -LiteralPath $p)) "
				f"{{ New-Item -ItemType Directory -Path $p -Force | Out-Null }}"
			)
			tcp_or_http = session_manager.sessions[sid].transport.lower()
			if tcp_or_http in ("http","https"):
				http_exec.run_command_http(sid, ps, op_id=getattr(opts, "to_op", None))
			else:
				tcp_exec.run_command_tcp(sid, ps, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None))
		else:
			parent = os.path.dirname(st.remote_path.rstrip("/")) or st.remote_path.rstrip("/")
			sh = f"bash -lc \"mkdir -p {_linux_shq(parent)}\""
			tcp_or_http = session_manager.sessions[sid].transport.lower()
			if tcp_or_http in ("http","https"):
				http_exec.run_command_http(sid, sh, op_id=getattr(opts, "to_op", None))
			else:
				tcp_exec.run_command_tcp(sid, sh, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None))
		total = os.path.getsize(st.local_path)
		st.total_bytes  = total
		st.total_chunks = chunk_count(total, st.chunk_size)
		proto = self._protocol(opts.to_op)
		st = proto.init_upload(st)
		self.store.save(st)
		stop = threading.Event()
		self._stop_flags[st.tid] = stop
		t = threading.Thread(target=self._run_upload, args=(proto, st, opts, stop), daemon=True)
		t.start()
		self._threads[st.tid] = t
		self._emit(opts, f"[*] Transfer started (upload) TID={st.tid} → {st.remote_path}")
		return st.tid

	def _run_upload(self, proto: ShellProtocol, st: TransferState, opts: TransferOpts, stop: threading.Event):
		try:
			# --- Align remote file to whole-chunk boundary before (re)starting ---
			try:
				# If remote exists, compute how many full chunks it already has
				try:
					rsz = proto._remote_size(st)
				except Exception:
					rsz = 0
				if rsz < 0:
					rsz = 0
				# Cap by our intended total (defensive)
				if st.total_bytes:
					rsz = min(rsz, st.total_bytes)
				full_chunks = rsz // st.chunk_size
				tail = rsz - (full_chunks * st.chunk_size)
				# If there is a tail (partial chunk), truncate remote back to the boundary
				if tail:
					if st.os_type == "windows":
						ps = (
							f"$p={_ps_quote(st.remote_path)};"
							f"$len={full_chunks * st.chunk_size};"
							"$fs=[System.IO.File]::Open($p,'Open','ReadWrite','None');"
							"$fs.SetLength($len);$fs.Close()"
						)
						tcp_or_http = session_manager.sessions[st.sid].transport.lower()
						if tcp_or_http in ("http","https"):
							http_exec.run_command_http(st.sid, ps, op_id=getattr(opts, "to_op", None))
						else:
							tcp_exec.run_command_tcp(st.sid, ps, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None))
					else:
						sh = f"bash -lc \"truncate -s {full_chunks * st.chunk_size} {_linux_shq(st.remote_path)}\""
						tcp_or_http = session_manager.sessions[st.sid].transport.lower()
						if tcp_or_http in ("http","https"):
							http_exec.run_command_http(st.sid, sh, op_id=getattr(opts, "to_op", None))
						else:
							tcp_exec.run_command_tcp(st.sid, sh, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None))
					rsz = full_chunks * st.chunk_size
				# Snap our local counters to match remote
				st.next_index = full_chunks
				st.bytes_done = rsz
				self.store.save(st)
			except Exception:
				pass
			last = time.time()
			while not stop.is_set():
				pre_idx = st.next_index
				try:
					idx = proto.next_upload_chunk(st)

				except (ConnectionResetError, BrokenPipeError, OSError, ConnectionError) as neterr:
					# Roll remote back to last full chunk boundary (pre_idx)
					try:
						safe_bytes = pre_idx * st.chunk_size
						if st.os_type == "windows":
							ps = (
								f"$p={_ps_quote(st.remote_path)};"
								f"$len={safe_bytes};"
								"$fs=[System.IO.File]::Open($p,'Open','ReadWrite','None');"
								"$fs.SetLength($len);$fs.Close()"
							)
							tcp_or_http = session_manager.sessions[st.sid].transport.lower()
							if tcp_or_http in ("http","https"):
								http_exec.run_command_http(st.sid, ps, op_id=getattr(opts, "to_op", None))
							else:
								tcp_exec.run_command_tcp(st.sid, ps, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None))
						else:
							sh = f"bash -lc \"truncate -s {safe_bytes} {_linux_shq(st.remote_path)}\""
							tcp_or_http = session_manager.sessions[st.sid].transport.lower()
							if tcp_or_http in ("http","https"):
								http_exec.run_command_http(st.sid, sh, op_id=getattr(opts, "to_op", None))
							else:
								tcp_exec.run_command_tcp(st.sid, sh, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None))
						st.bytes_done = min(safe_bytes, st.total_bytes)
					finally:
						st.next_index = pre_idx
						st.status = "paused"
						self.store.save(st)
					self._emit(opts, f"[{st.tid}] connection lost ({neterr.__class__.__name__}); paused at chunk {st.next_index}", color=brightred, override_quiet=True)
					return

				if idx is None:
					break
				if time.time() - last >= 0.5:
					self.store.save(st)
					#self._emit(opts, self._progress_line(st))
					last = time.time()
			if stop.is_set():
				st.status = "paused"
				self.store.save(st)
				self._emit(opts, f"[{st.tid}] paused at chunk {st.next_index}", color=brightred, override_quiet=True)
				return

			# Not all chunks sent → treat as paused (don’t extract!)
			if st.next_index < st.total_chunks:
				st.status = "paused"
				self.store.save(st)
				self._emit(opts, f"[{st.tid}] paused at chunk {st.next_index}", color=brightred, override_quiet=True)
				return

			st.status = "done"
			self.store.save(st)
			# If we uploaded an archive of a folder, extract then delete archive
			if st.is_folder:
				from .protocols.shell import _run_cmd

				# Where to extract on the agent
				dest = st.options.get("extract_dest") or (
					ntpath.dirname(st.remote_path) if st.os_type == "windows"
					else os.path.dirname(st.remote_path)
				)

				if st.os_type == "windows":
					# PowerShell literal quoting: single quotes, double single-quotes inside
					def psq(s: str) -> str:
						return "'" + str(s).replace("'", "''") + "'"

					ps = (
						f"$dest = {psq(dest)};"
						f"if (-not (Test-Path -LiteralPath $dest)) "
						f"{{ New-Item -ItemType Directory -Path $dest -Force | Out-Null }};"
						f"Expand-Archive -LiteralPath {psq(st.remote_path)} -DestinationPath $dest -Force;"
						f"Remove-Item -LiteralPath {psq(st.remote_path)} -Force"
					)
					_run_cmd(st.sid, ps, st.transport, opts.to_op)

				else:
					# Bash-safe single-quote: close ' , insert '"'"' , reopen '
					def shq(s: str) -> str:
						return "'" + str(s).replace("'", "'\"'\"'") + "'"

					sh = (
						f"mkdir -p {shq(dest)} && "
						f"tar xzf {shq(st.remote_path)} -C {shq(dest)} && "
						f"rm -f {shq(st.remote_path)}"
					)
					# Wrap the whole thing for bash -lc using double quotes
					_run_cmd(st.sid, f"bash -lc \"{sh}\"", st.transport, opts.to_op)

				# Best-effort: remove local temp archive (created during folder upload)
				try:
					if os.path.exists(st.local_path):
						os.remove(st.local_path)
				except Exception:
					pass

				self._emit(opts, f"\n[+] Folder extracted to: {dest}")
			else:
				self._emit(opts, "\n[+] Upload complete")

		except Exception as e:
			st.status = "error"
			st.error = f"{e}"
			self.store.save(st)
			self._emit(opts, f"[!] Transfer error {st.tid}: {e}", color=brightred, override_quiet=True)

	# control plane
	def resume(self, sid: str, tid: str, opts: Optional[TransferOpts]=None) -> bool:
		opts = opts or TransferOpts()
		st = self.store.load(sid, tid)
		if st.status not in ("paused","error"):
			return False

		# restart appropriate runner
		stop = threading.Event()
		self._stop_flags[tid] = stop
		proto = self._protocol(opts.to_op)
		runner = self._run_download if st.direction == "download" else self._run_upload
		t = threading.Thread(target=runner, args=(proto, st, opts, stop), daemon=True)
		t.start()
		self._threads[tid] = t
		self._emit(opts, f"[*] Resuming TID={tid} at chunk {st.next_index}")
		return True

	def cancel(self, sid: str, tid: str) -> bool:
		if tid not in self._stop_flags:
			self._stop_flags[tid] = threading.Event()
		self._stop_flags[tid].set()
		try:
			st = self.store.load(sid, tid)
			st.status = "cancelled"
			self.store.save(st)
			return True
		except Exception:
			return False

	def status(self, sid: str, tid: str) -> Optional[Dict[str,Any]]:
		try:
			st = self.store.load(sid, tid)
			return st.to_dict()
		except Exception:
			return None

	def list(self, sid: Optional[str]=None) -> Dict[str,Any]:
		out = []
		base = self.store.base
		if sid:
			roots = [os.path.join(base, sid)]
		else:
			roots = [os.path.join(base, d) for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
		for root in roots:
			for tid in (os.listdir(root) if os.path.isdir(root) else []):
				try:
					st = self.store.load(os.path.basename(root), tid)
					out.append(st.to_dict())
				except Exception:
					continue
		return {"transfers": out}

# --- Safe extract helpers -------------------------------------------------
	def _safe_extract_zip(self, zf: zipfile.ZipFile, dest_dir: str) -> None:
		"""
		Extract a ZIP while:
		  - normalizing Windows-style backslashes to the local OS separator
		  - preventing ZipSlip/path traversal
		  - creating intermediate directories
		"""
		os.makedirs(dest_dir, exist_ok=True)
		for info in zf.infolist():
			# Normalize separators (Windows zips often contain '\')
			raw = info.filename
			if not raw or raw.endswith('/') or raw.endswith('\\'):
				# directory entry
				norm = raw.replace('\\', '/').rstrip('/')
				if not norm:
					continue
				target = os.path.join(dest_dir, *norm.split('/'))
				self._ensure_inside(dest_dir, target)
				os.makedirs(target, exist_ok=True)
				continue
			norm = raw.replace('\\', '/')
			target = os.path.join(dest_dir, *norm.split('/'))
			self._ensure_inside(dest_dir, target)
			os.makedirs(os.path.dirname(target), exist_ok=True)
			with zf.open(info, 'r') as src, open(target, 'wb') as dst:
				while True:
					chunk = src.read(1024 * 1024)
					if not chunk:
						break
					dst.write(chunk)

	def _safe_extract_tar(self, tf: tarfile.TarFile, dest_dir: str) -> None:
		"""
		Extract a tar.gz safely with traversal protection.
		"""
		os.makedirs(dest_dir, exist_ok=True)
		for member in tf.getmembers():
			# tarfile already uses '/' separators; still enforce traversal checks
			target = os.path.join(dest_dir, member.name)
			self._ensure_inside(dest_dir, target)
			if member.isdir():
				os.makedirs(target, exist_ok=True)
			elif member.issym() or member.islnk():
				# Skip links in lab/CTF mode for safety; could be made configurable.
				continue
			else:
				os.makedirs(os.path.dirname(target), exist_ok=True)
				with tf.extractfile(member) as src, open(target, 'wb') as dst:
					if src is None:
						continue
					while True:
						chunk = src.read(1024 * 1024)
						if not chunk:
							break
						dst.write(chunk)

	def _ensure_inside(self, root: str, path: str) -> None:
		"""
		Prevents writing outside dest_dir (ZipSlip/.. protection).
		"""
		ab_root = os.path.abspath(root)
		ab_path = os.path.abspath(path)
		if not ab_path.startswith(ab_root + os.sep) and ab_path != ab_root:
			logger.exception(brightred + f"Unsafe path in archive: {path}" + reset)
			raise RuntimeError(f"Unsafe path in archive: {path}")

	# --- Path helpers ---------------------------------------------------------
	def _remote_basename(self, remote_path: str) -> str:
		"""
		Return the final component of a remote path regardless of whether it is Windows- or POSIX-style.
		Examples:
		  'C:\\Users\\leigh\\repos\\' -> 'repos'
		  '\\\\server\\share\\stuff'  -> 'stuff'
		  '/var/www/html/'            -> 'html'
		"""
		if not remote_path:
			return ""
		rp = remote_path.rstrip("/\\")
		# Heuristics: Windows drive ('C:'), UNC (starts with '\\'), or contains backslashes
		if (len(rp) >= 2 and rp[1] == ':') or rp.startswith('\\\\') or ('\\' in rp):
			base = ntpath.basename(rp)
		else:
			base = os.path.basename(rp)
		# Fallback if something odd returns empty
		return base or rp

	# --- Remote probing -------------------------------------------------------
	def _probe_remote_is_dir(self, sid: str, remote_path: str, os_type: str, to_op: Optional[str]=None) -> bool:
		"""
		Returns True if the remote_path is a directory on the agent, False if it's a file.
		Raises on 'missing' or if transport output can't be parsed.
		"""
		sess = session_manager.sessions[sid]
		transport = getattr(sess, "transport", "").lower()

		if os_type == "windows":
			# PS: robust, literal path, no exceptions
			ps = (
				f"$p = Get-Item -LiteralPath {_ps_quote(remote_path)} -ErrorAction SilentlyContinue; "
				"if ($null -eq $p) { 'MISSING' } "
				"elseif ($p.PSIsContainer) { 'DIR' } else { 'FILE' }"
			)
			out = self._run_remote(sid, ps, transport, to_op)
		else:
			# Linux/Unix
			sh = f"bash -lc 'if [ -d {_linux_shq(remote_path)} ]; then echo DIR; " \
				 f"elif [ -f {_linux_shq(remote_path)} ]; then echo FILE; else echo MISSING; fi'"
			out = self._run_remote(sid, sh, transport, to_op)

		out = (out or "").strip().upper()
		if "DIR" in out:
			return True
		if "FILE" in out:
			return False
		if "MISSING" in out:
			logger.exception(brightred + "Remote path does not exist" + reset)
			raise RuntimeError("Remote path does not exist")
		# Unknown – be defensive
		logger.exception(brightred + f"Unrecognized probe result: {out!r}" + reset)
		raise RuntimeError(f"Unrecognized probe result: {out!r}")

	def _run_remote(self, sid: str, cmd: str, transport: str, to_op: Optional[str]) -> str:
		"""
		Execute a short command on the agent via the appropriate transport and return the output.
		"""
		if transport in ("http", "https"):
			# existing adapter: http_exec.run_command_http(sid, cmd, op_id=...)
			return http_exec.run_command_http(sid, cmd, op_id=to_op)

		else:
			# TCP/TLS paths use TCP adapter
			return tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=to_op)

	def _resolve_file_target(self, local_path: str, remote_path: str) -> str:
		"""
		Normalize the destination path for a *file* download.
		- If local_path is an existing directory, write into it using the remote basename.
		- If local_path ends with a path separator, treat it as a directory (create if needed)
		  and write into it using the remote basename.
		- Otherwise, treat local_path as the file name to write to.
		"""
		try:
			if os.path.isdir(local_path):
				return os.path.join(local_path, self._remote_basename(remote_path))
		except Exception:
			# if os.path.isdir throws (weird permissions, etc), fall through to other checks
			pass

		# Ends with local OS separator → treat as a directory string
		if local_path.endswith(os.sep) or local_path.endswith('\\'):
			try:
				os.makedirs(local_path, exist_ok=True)
			except Exception:
				# Best-effort: if we cannot create, we'll still attempt to join and let the failure surface later
				pass
			return os.path.join(local_path, self._remote_basename(remote_path))

		# Otherwise, it's a concrete file path
		return local_path
