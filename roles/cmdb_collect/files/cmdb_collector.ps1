<#
.SYNOPSIS
  cmdb_collector.ps1 - collecteur CMDB pour Windows (Server 2012 R2 et plus, Windows 10 et 11 ; PowerShell 4.0 et plus).
  Lancé par collect.yml (WinRM ou SSH) ou à la main.

.DESCRIPTION
  Lecture seule. Le seul fichier écrit est le résultat : -OutFile, ou <HostLabel>-<RunId>.cmdb
  dans le répertoire courant. À supprimer du serveur une fois transféré.
  Aucune connexion aux bases de données, aucun mot de passe essayé ; les mots de passe
  visibles dans les lignes de commande et les chemins des services sont masqués ici,
  avant que les données ne quittent le serveur. Aucun contenu de clé privée n'est lu :
  pour une clé on ne relève que sa présence, son type et si elle est chiffrée.

  Produit le même format que les collecteurs Linux et AIX : un document JSON compressé
  (gzip), encodé en base64 entre les marqueurs CMDB-B64-BEGIN et CMDB-B64-END.
  Sur le contrôleur : python3 tools/cmdb_unpack.py <fichier> <store/APP/PF/HOTE/RUN.json.gz>

  Ce qui est relevé : système, correctifs (KB), programmes installés, rôles, services,
  matériel, volumes, réseau (adresses, ports d'écoute, connexions), processus, JDK,
  archives Java (manifeste, pom.properties, empreinte SHA-1, archives imbriquées),
  Tomcat (connecteurs, hôtes et contextes de server.xml), IIS (sites et liaisons),
  instances SQL Server (registre), certificats du magasin de l'ordinateur et fichiers
  de clés et certificats.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File cmdb_collector.ps1 `
     -HostLabel srvwin01 -App MONAPPLI -Platform prod -OutFile C:\Temp\srvwin01.cmdb

  -ExecutionPolicy Bypass ne vaut que pour ce lancement et ne modifie pas la configuration.
  Lancé en administrateur, le relevé est plus complet (configuration IIS, chemins et
  propriétaires des processus des autres comptes) ; il reste en lecture seule.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$App,
    [Parameter(Mandatory = $true)][string]$Platform,
    [string]$HostLabel = $env:COMPUTERNAME.ToLower(),
    [string]$RunId = '',
    [string[]]$Tag = @(),
    [string]$OutFile = '',
    [int]$ScanMaxSeconds = 600,
    [int]$ArchiveMaxSeconds = 900,
    [string[]]$ScanPath = @(),
    [string[]]$ExcludePath = @(),
    [switch]$NoScan,
    [switch]$NoHash
)

$ErrorActionPreference = 'Stop'
$CollectorVersion = '1.0.0-ps'
$Started = (Get-Date).ToUniversalTime()
if (-not $RunId) { $RunId = $Started.ToString("yyyyMMdd'T'HHmmss'Z'") + '-win' }
try { [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'BelowNormal' } catch { }

try { Add-Type -AssemblyName System.IO.Compression } catch { }   # ZipArchive : .NET 4.5, présent sur 2012 R2
$Errors = New-Object System.Collections.ArrayList
function Add-CmdbError([string]$Section, $Err) {
    [void]$Errors.Add([ordered]@{ section = $Section; error = ([string]$Err).Substring(0, [Math]::Min(300, ([string]$Err).Length)) })
}
function Write-Step([string]$Msg) { Write-Host ('[{0}] {1}' -f (Get-Date).ToString('HH:mm:ss'), $Msg) }
function Invoke-Section([string]$Name, [scriptblock]$Block) {
    $t0 = Get-Date
    Write-Step "$Name..."
    try { & $Block } catch { Add-CmdbError $Name $_.Exception.Message; Write-Step "$Name : ERREUR $($_.Exception.Message)" }
    $d = ((Get-Date) - $t0).TotalSeconds
    if ($d -ge 5) { Write-Step ("{0} : {1:N0} s" -f $Name, $d) }
}

# --- Étiquettes ---------------------------------------------------------------
$NameRx = '^[A-Za-z0-9._-]+$'
foreach ($v in @($App, $Platform)) {
    if ($v -notmatch $NameRx) { throw "Application ou plate-forme invalide : '$v' (lettres, chiffres, . _ - seulement)" }
}
$Tags = [ordered]@{ app = $App; platform = $Platform }
foreach ($t in $Tag) {
    foreach ($kv in ($t -split ',')) {
        if ($kv -notmatch '^([A-Za-z0-9._-]+)=([A-Za-z0-9._-]+)$') { throw "Étiquette invalide : '$kv' (forme attendue : cle=valeur)" }
        $Tags[$Matches[1]] = $Matches[2]
    }
}

# --- Masquage des secrets (mêmes règles que cmdb_collector.py) ----------------
$SecretWords = '(?:passw(?:or)?d|passwd|pwd|secret|token|api[_-]?key|apikey|credentials?|private[_-]?key|authtok|access[_-]?key)'
$Redactions = @(
    @(('((?:^|[\s;&|,''"(])-{0,2}[\w.\-]*' + $SecretWords + '[\w.\-]*\s*[=:]\s*)("[^"]*"|''[^'']*''|[^\s,;''"]+)'), '$1***'),
    @(('((?:^|\s)--?[\w\-]*' + $SecretWords + '[\w\-]*\s+)(?!-)(\S+)'), '$1***'),
    @(('((?:^|\s)/[\w\-]*' + $SecretWords + '[\w\-]*[:=])(\S+)'), '$1***'),
    @('(\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:)[^@\s/]+(@)', '$1***$2')
)
function Hide-Secret([string]$s) {
    if (-not $s) { return $s }
    foreach ($r in $Redactions) { $s = $s -replace $r[0], $r[1] }
    return $s
}

# --- Utilitaires ----------------------------------------------------------------
function Get-Wmi([string]$Class, [string]$Filter = '') {
    if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
        if ($Filter) { return @(Get-WmiObject -Class $Class -Filter $Filter) }
        return @(Get-WmiObject -Class $Class)
    }
    if ($Filter) { return @(Get-CimInstance -ClassName $Class -Filter $Filter) }
    return @(Get-CimInstance -ClassName $Class)
}
function ConvertTo-Iso($d) {
    if ($null -eq $d -or $d -eq '') { return $null }
    try {
        if ($d -is [string]) { $d = [System.Management.ManagementDateTimeConverter]::ToDateTime($d) }
        return $d.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    } catch { return $null }
}
function Get-RegValues([string]$Path) {
    try { return Get-ItemProperty -Path $Path -ErrorAction Stop } catch { return $null }
}
function To-Slash([string]$p) { if ($p) { return $p.Replace('\', '/') } return $p }
function Parse-Properties([string]$Text) {
    $d = [ordered]@{}
    if (-not $Text) { return $d }
    foreach ($line in ($Text -split "`r?`n")) {
        $l = $line.Trim()
        if (-not $l -or $l[0] -eq '#' -or $l[0] -eq '!') { continue }
        if ($l -match '^([^=:\s]+)\s*[=:]\s*(.*)$') { $d[$Matches[1]] = $Matches[2] }
    }
    return $d
}
function Parse-KvRelease([string]$Text) {
    $d = [ordered]@{}
    foreach ($line in ($Text -split "`r?`n")) {
        $l = $line.Trim()
        if (-not $l -or $l.StartsWith('#') -or -not $l.Contains('=')) { continue }
        $k, $v = $l.Split('=', 2)
        $v = $v.Trim()
        if ($v.Length -ge 2 -and $v[0] -eq $v[$v.Length - 1] -and ($v[0] -eq '"' -or $v[0] -eq "'")) { $v = $v.Substring(1, $v.Length - 2) }
        $d[$k.Trim()] = $v
    }
    return $d
}
$ManifestDrop = @('Class-Path', 'Import-Package', 'Export-Package', 'Private-Package', 'Include-Resource',
    'Require-Capability', 'Provide-Capability', 'DynamicImport-Package', 'Embedded-Artifacts',
    'Embed-Dependency', 'Ignore-Package', 'Sealed', 'Name', 'Bnd-LastModified', 'Tool')
function Parse-Manifest([string]$Text) {
    $attrs = [ordered]@{}
    $last = $null
    foreach ($line in ($Text -split "`r?`n")) {
        if (-not $line.Trim()) { break }
        if ($line.StartsWith(' ') -and $last) { $attrs[$last] += $line.Substring(1); continue }
        $i = $line.IndexOf(':')
        if ($i -gt 0) { $last = $line.Substring(0, $i).Trim(); $attrs[$last] = $line.Substring($i + 1).Trim() }
    }
    $out = [ordered]@{}
    foreach ($k in $attrs.Keys) {
        if ($ManifestDrop -contains $k) { continue }
        $v = [string]$attrs[$k]
        $out[$k] = $v.Substring(0, [Math]::Min(512, $v.Length))
    }
    return $out
}

# --- JSON (sérialiseur maison : identique sous PowerShell 4.0, 5.1 et 7) -----
$NumTypes = @([int16], [int32], [int64], [uint16], [uint32], [uint64], [byte], [sbyte], [single], [double], [decimal])
function Write-JsonString([System.Text.StringBuilder]$sb, [string]$s) {
    [void]$sb.Append('"')
    if ($s -notmatch '[\x00-\x1f"\\]') { [void]$sb.Append($s) }
    else {
        foreach ($c in $s.ToCharArray()) {
            switch ($c) {
                '"' { [void]$sb.Append('\"') }
                '\' { [void]$sb.Append('\\') }
                "`n" { [void]$sb.Append('\n') }
                "`r" { [void]$sb.Append('\r') }
                "`t" { [void]$sb.Append('\t') }
                default {
                    if ([int]$c -lt 32) { [void]$sb.Append(('\u{0:x4}' -f [int]$c)) } else { [void]$sb.Append($c) }
                }
            }
        }
    }
    [void]$sb.Append('"')
}
function Write-Json([System.Text.StringBuilder]$sb, $o) {
    if ($null -eq $o) { [void]$sb.Append('null'); return }
    if ($o -is [System.Management.Automation.PSObject]) { $o = $o.PSObject.BaseObject }
    if ($o -is [string] -or $o -is [char] -or $o -is [enum] -or $o -is [guid]) { Write-JsonString $sb ([string]$o); return }
    if ($o -is [bool]) { [void]$sb.Append($(if ($o) { 'true' } else { 'false' })); return }
    if ($o -is [datetime]) { Write-JsonString $sb (ConvertTo-Iso $o); return }
    foreach ($t in $NumTypes) {
        if ($o -is $t) {
            if (($o -is [double] -or $o -is [single]) -and ([double]::IsNaN($o) -or [double]::IsInfinity($o))) { [void]$sb.Append('null') }
            else { [void]$sb.Append(([System.IConvertible]$o).ToString([System.Globalization.CultureInfo]::InvariantCulture)) }
            return
        }
    }
    if ($o -is [System.Collections.IDictionary]) {
        [void]$sb.Append('{')
        $first = $true
        foreach ($k in $o.Keys) {
            if (-not $first) { [void]$sb.Append(',') }
            $first = $false
            Write-JsonString $sb ([string]$k)
            [void]$sb.Append(':')
            Write-Json $sb $o[$k]
        }
        [void]$sb.Append('}')
        return
    }
    if ($o -is [System.Collections.IEnumerable]) {
        [void]$sb.Append('[')
        $first = $true
        foreach ($x in $o) {
            if (-not $first) { [void]$sb.Append(',') }
            $first = $false
            Write-Json $sb $x
        }
        [void]$sb.Append(']')
        return
    }
    Write-JsonString $sb ([string]$o)
}

# --- Compte de collecte ---------------------------------------------------------
$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$Elevated = (New-Object System.Security.Principal.WindowsPrincipal($Identity)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

$Doc = [ordered]@{ schema = 'cmdb-collector/1' }
$Win = [ordered]@{}
Write-Step "cmdb_collector.ps1 $CollectorVersion : $HostLabel ($App / $Platform), passage $RunId, administrateur : $Elevated"
Write-Step "Durées maximales : exploration des disques $ScanMaxSeconds s, archives Java $ArchiveMaxSeconds s. Ctrl+C interrompt sans rien laisser sur le serveur."

# --- Système --------------------------------------------------------------------
$OsInfo = [ordered]@{}
Invoke-Section 'os' {
    $os = @(Get-Wmi Win32_OperatingSystem)[0]
    $cs = @(Get-Wmi Win32_ComputerSystem)[0]
    $cv = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [string]$os.BuildNumber
    $ubr = if ($cv -and $cv.UBR) { [string]$cv.UBR } else { $null }
    $server = [int]$os.ProductType -ne 1
    $verId = $null
    if ($server) {
        $map = @{ '9200' = '2012'; '9600' = '2012-r2'; '14393' = '2016'; '17763' = '2019'; '20348' = '2022'; '26100' = '2025' }
        if ($map.ContainsKey($build)) { $verId = $map[$build] }
    } else {
        $verId = if ([int]$build -ge 22000) { '11' } elseif ([int]$build -ge 10240) { '10' } else { [string]$os.Version }
    }
    $full = if ($ubr) { "$($os.Version).$ubr" } else { [string]$os.Version }
    $boot = $os.LastBootUpTime
    if ($boot -is [string]) { $boot = [System.Management.ManagementDateTimeConverter]::ToDateTime($boot) }
    $hostname = [string]$cs.Name
    $fqdn = if ($cs.PartOfDomain -and $cs.Domain) { "$hostname.$($cs.Domain)".ToLower() } else { $hostname.ToLower() }
    $mg = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Cryptography'
    $pending = $false
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                     'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
        if (Test-Path $k) { $pending = $true }
    }
    $sm = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    if ($sm -and $sm.PendingFileRenameOperations) { $pending = $true }
    $OsInfo['hostname'] = $hostname.ToLower()
    $OsInfo['fqdn'] = $fqdn
    $OsInfo['machine_id'] = if ($mg) { [string]$mg.MachineGuid } else { $null }
    $OsInfo['os_release'] = [ordered]@{
        ID = $(if ($server) { 'windows-server' } else { 'windows' }); NAME = 'Windows'
        VERSION_ID = $verId; PRETTY_NAME = "$($os.Caption.Trim()) (build $build$(if ($ubr) { ".$ubr" }))"
    }
    $OsInfo['boot_time'] = ConvertTo-Iso $boot
    $OsInfo['uptime_seconds'] = [int64]((Get-Date) - $boot).TotalSeconds
    $OsInfo['reboot_required_file'] = $pending
    $Win['os'] = [ordered]@{
        caption = $os.Caption.Trim(); version = $full; build = $build; ubr = $ubr
        edition = $(if ($cv) { $cv.EditionID }); display_version = $(if ($cv) { $(if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }) })
        install_date = ConvertTo-Iso $os.InstallDate; product_type = [int]$os.ProductType
        architecture = [string]$os.OSArchitecture; domain = [string]$cs.Domain; part_of_domain = [bool]$cs.PartOfDomain
        locale = [string]$os.Locale; time_zone = [System.TimeZoneInfo]::Local.Id
    }
}
$Doc['os'] = $OsInfo

# --- Matériel -------------------------------------------------------------------
$Hw = [ordered]@{}
Invoke-Section 'hardware' {
    $cs = @(Get-Wmi Win32_ComputerSystem)[0]
    $bios = @(Get-Wmi Win32_BIOS)[0]
    $procs = @(Get-Wmi Win32_Processor)
    $board = @(Get-Wmi Win32_BaseBoard)
    $encl = @(Get-Wmi Win32_SystemEnclosure)
    $Hw['dmi'] = [ordered]@{
        sys_vendor = [string]$cs.Manufacturer; product_name = [string]$cs.Model; product_serial = [string]$bios.SerialNumber
        bios_version = [string]$bios.SMBIOSBIOSVersion; bios_date = ConvertTo-Iso $bios.ReleaseDate
        board_vendor = $(if ($board) { [string]$board[0].Manufacturer }); board_name = $(if ($board) { [string]$board[0].Product })
        chassis_type = $(if ($encl -and $encl[0].ChassisTypes) { [string]$encl[0].ChassisTypes[0] })
    }
    $cores = 0; $logical = 0
    foreach ($p in $procs) { $cores += [int]$p.NumberOfCores; $logical += [int]$p.NumberOfLogicalProcessors }
    $Hw['cpu'] = [ordered]@{ 'model name' = ([string]$procs[0].Name).Trim(); count = $logical }
    $Hw['lscpu_kv'] = [ordered]@{
        'Socket(s)' = [string]$procs.Count
        'Core(s) per socket' = [string]([int]($cores / [Math]::Max(1, $procs.Count)))
        'Thread(s) per core' = [string]([int]($logical / [Math]::Max(1, $cores)))
    }
    $Hw['meminfo_kb'] = [ordered]@{ MemTotal = [int64]([double]$cs.TotalPhysicalMemory / 1024) }
    $model = "$($cs.Manufacturer) $($cs.Model)"
    $Hw['virtualization'] = if ($model -match 'VMware') { 'vmware' } elseif ($model -match 'Microsoft.*Virtual') { 'microsoft' } `
        elseif ($model -match 'KVM|QEMU|OpenStack') { 'kvm' } elseif ($model -match 'Xen') { 'xen' } `
        elseif ($model -match 'VirtualBox') { 'oracle' } elseif ($model -match 'Amazon EC2') { 'amazon' } else { 'none' }
    $mounts = New-Object System.Collections.ArrayList
    foreach ($d in (Get-Wmi Win32_LogicalDisk)) {
        if (@(3, 4) -notcontains [int]$d.DriveType -or -not $d.Size) { continue }
        [void]$mounts.Add([ordered]@{
            mountpoint = [string]$d.DeviceID; device = $(if ($d.ProviderName) { [string]$d.ProviderName } else { [string]$d.VolumeName })
            fstype = $(if ([int]$d.DriveType -eq 4) { 'smb' } else { [string]$d.FileSystem })
            size_bytes = [int64]$d.Size; avail_bytes = [int64]$d.FreeSpace; used_bytes = [int64]$d.Size - [int64]$d.FreeSpace
        })
    }
    $Hw['mounts'] = $mounts
    $disks = New-Object System.Collections.ArrayList
    foreach ($d in (Get-Wmi Win32_DiskDrive)) {
        [void]$disks.Add([ordered]@{
            name = [string]$d.DeviceID; model = [string]$d.Model; serial = ([string]$d.SerialNumber).Trim()
            size_bytes = [int64]$d.Size; transport = [string]$d.InterfaceType; vendor = [string]$d.Manufacturer
        })
    }
    $Hw['disks'] = $disks
}
$Doc['hardware'] = $Hw

# --- Processus ------------------------------------------------------------------
$ProcList = New-Object System.Collections.ArrayList
$ProcName = @{}
Invoke-Section 'processes' {
    # Propriétaires en un seul appel (Get-Process -IncludeUserName : administrateur) ; GetOwner() par processus est trop lent
    $owners = @{}
    if ($Elevated) { try { foreach ($gp in (Get-Process -IncludeUserName -ErrorAction Stop)) { $owners[[int]$gp.Id] = $gp.UserName } } catch { } }
    foreach ($p in (Get-Wmi Win32_Process)) {
        $user = $owners[[int]$p.ProcessId]
        $ProcName[[int]$p.ProcessId] = [string]$p.Name
        [void]$ProcList.Add([ordered]@{
            pid = [int]$p.ProcessId; ppid = [int]$p.ParentProcessId; user = $user; comm = [string]$p.Name
            exe = [string]$p.ExecutablePath; cmdline = Hide-Secret ([string]$p.CommandLine)
            start = ConvertTo-Iso $p.CreationDate; rss_bytes = [int64]$p.WorkingSetSize
        })
    }
}
$Doc['processes'] = [ordered]@{ list = $ProcList }

# --- Réseau ---------------------------------------------------------------------
$Net = [ordered]@{}
Invoke-Section 'network' {
    $listen = New-Object System.Collections.ArrayList
    $lports = @{}
    $est = @{}
    $rows = New-Object System.Collections.ArrayList
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
            [void]$rows.Add(@('tcp', [string]$c.LocalAddress, [int]$c.LocalPort, [string]$c.RemoteAddress, [int]$c.RemotePort, [string]$c.State, [int]$c.OwningProcess))
        }
        foreach ($c in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
            [void]$rows.Add(@('udp', [string]$c.LocalAddress, [int]$c.LocalPort, '', 0, 'Listen', [int]$c.OwningProcess))
        }
    } else {
        foreach ($line in (netstat -ano)) {
            $f = ($line.Trim() -split '\s+')
            if ($f.Count -lt 4 -or @('TCP', 'UDP') -notcontains $f[0]) { continue }
            $la = $f[1]; $i = $la.LastIndexOf(':')
            $ra = $f[2]; $j = $ra.LastIndexOf(':')
            $state = if ($f[0] -eq 'UDP') { 'Listen' } else { $f[3] }
            $ownPid = [int]$f[$f.Count - 1]
            $rp = 0; [void][int]::TryParse($ra.Substring($j + 1), [ref]$rp)
            [void]$rows.Add(@($f[0].ToLower(), $la.Substring(0, $i).Trim('[', ']'), [int]$la.Substring($i + 1), $ra.Substring(0, [Math]::Max(0, $j)).Trim('[', ']'), $rp,
                $(if ($state -eq 'LISTENING') { 'Listen' } elseif ($state -eq 'ESTABLISHED') { 'Established' } else { $state }), $ownPid))
        }
    }
    foreach ($r in $rows) {
        if ($r[5] -eq 'Listen') {
            $lports[$r[2]] = $true
            [void]$listen.Add([ordered]@{ proto = $r[0]; address = $r[1]; port = $r[2]; pid = $r[6]; process = $ProcName[$r[6]]; user = $null })
        }
    }
    foreach ($r in $rows) {
        if ($r[0] -ne 'tcp' -or $r[5] -ne 'Established' -or $r[3] -match '^(127\.|::1$)') { continue }
        if ($lports.ContainsKey($r[2])) { $k = "in|$($r[2])|$($r[3])||$($ProcName[$r[6]])" } else { $k = "out||$($r[3])|$($r[4])|$($ProcName[$r[6]])" }
        if ($est.ContainsKey($k)) { $est[$k] += 1 } else { $est[$k] = 1 }
    }
    $conns = New-Object System.Collections.ArrayList
    foreach ($k in $est.Keys) {
        $f = $k.Split('|')
        [void]$conns.Add([ordered]@{
            direction = $f[0]; local_port = $(if ($f[1]) { [int]$f[1] } else { $null }); remote_addr = $f[2]
            remote_port = $(if ($f[3]) { [int]$f[3] } else { $null }); process = $(if ($f[4]) { $f[4] } else { $null }); count = $est[$k]
        })
    }
    $Net['listening'] = $listen
    $Net['established'] = $conns
    $addrs = New-Object System.Collections.ArrayList
    $ifs = New-Object System.Collections.ArrayList
    if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
        foreach ($a in @(Get-NetIPAddress -ErrorAction SilentlyContinue)) {
            $ip = [string]$a.IPAddress
            if ($ip -match '^(127\.|::1$)') { continue }
            $ip = $ip.Split('%')[0]
            [void]$addrs.Add([ordered]@{
                ifname = [string]$a.InterfaceAlias; family = $(if ([string]$a.AddressFamily -eq 'IPv6') { 'inet6' } else { 'inet' })
                cidr = "$ip/$($a.PrefixLength)"; scope = $(if ($ip -match '^(fe80|169\.254\.)') { 'link' } else { 'global' }); label = $null
            })
        }
        foreach ($n in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
            $mtu = $null
            try { $mtu = [int](Get-NetIPInterface -InterfaceIndex $n.ifIndex -AddressFamily IPv4 -ErrorAction Stop).NlMtu } catch { }
            [void]$ifs.Add([ordered]@{
                name = [string]$n.Name; kind = $(if ($n.HardwareInterface) { 'physical' } else { 'virtual' })
                address = ([string]$n.MacAddress).Replace('-', ':').ToLower(); mtu = $mtu
                operstate = $(if ([string]$n.Status -eq 'Up') { 'up' } else { 'down' })
                speed = $(if ($n.ReceiveLinkSpeed) { [int64]([double]$n.ReceiveLinkSpeed / 1000000) } else { $null })
                driver = [string]$n.InterfaceDescription
            })
        }
    } else {
        foreach ($c in (Get-Wmi Win32_NetworkAdapterConfiguration 'IPEnabled = TRUE')) {
            for ($i = 0; $i -lt @($c.IPAddress).Count; $i++) {
                $ip = @($c.IPAddress)[$i]; $mask = @($c.IPSubnet)[$i]
                if ($ip -match ':') { $plen = [int]$mask; $fam = 'inet6' } else {
                    $plen = 0; foreach ($o in $mask.Split('.')) { $plen += ([Convert]::ToString([int]$o, 2) -replace '0', '').Length }; $fam = 'inet' }
                [void]$addrs.Add([ordered]@{ ifname = [string]$c.Description; family = $fam; cidr = "$ip/$plen"
                    scope = $(if ($ip -match '^(fe80|169\.254\.)') { 'link' } else { 'global' }); label = $null })
            }
        }
    }
    $Net['addresses'] = $addrs
    $Net['interfaces'] = $ifs
}
$Doc['network'] = $Net

# --- Services, rôles, programmes, correctifs ------------------------------------
Invoke-Section 'services' {
    $svc = New-Object System.Collections.ArrayList
    foreach ($s in (Get-Wmi Win32_Service)) {
        $desc = [string]$s.Description
        [void]$svc.Add([ordered]@{
            name = [string]$s.Name; display_name = [string]$s.DisplayName; state = [string]$s.State; start_mode = [string]$s.StartMode
            pid = [int]$s.ProcessId; path = Hide-Secret ([string]$s.PathName); account = [string]$s.StartName
            description = $desc.Substring(0, [Math]::Min(200, $desc.Length))
        })
    }
    $Win['services'] = $svc
}
Invoke-Section 'features' {
    # Win32_ServerFeature n'existe que sur Windows Server avec le Gestionnaire de serveur : absence normale ailleurs
    try { $Win['features'] = @(Get-Wmi Win32_ServerFeature | ForEach-Object { [string]$_.Name }) } catch { $Win['features'] = $null }
}
Invoke-Section 'programs' {
    $prog = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path $root)) { continue }
        foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $v = Get-RegValues $k.PSPath
            if (-not $v -or -not $v.DisplayName -or $v.ParentKeyName) { continue }
            $id = "$($v.DisplayName)|$($v.DisplayVersion)"
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            [void]$prog.Add([ordered]@{
                name = [string]$v.DisplayName; version = [string]$v.DisplayVersion; publisher = [string]$v.Publisher
                install_date = [string]$v.InstallDate; location = [string]$v.InstallLocation
                arch = $(if ($root -match 'WOW6432Node') { 'x86' } else { 'x64' }); system_component = [bool]($v.SystemComponent -eq 1)
            })
        }
    }
    $Win['programs'] = $prog
}
Invoke-Section 'hotfixes' {
    $Win['hotfixes'] = @(Get-Wmi Win32_QuickFixEngineering | ForEach-Object {
        [ordered]@{ id = [string]$_.HotFixID; description = [string]$_.Description; installed_on = [string]$_.InstalledOn } })
}

# --- SQL Server (registre seulement, aucune connexion) --------------------------
Invoke-Section 'sqlserver' {
    $inst = New-Object System.Collections.ArrayList
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server')) {
        $names = Get-RegValues "$base\Instance Names\SQL"
        if (-not $names) { continue }
        foreach ($p in $names.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $id = [string]$p.Value
            $setup = Get-RegValues "$base\$id\Setup"
            $tcp = Get-RegValues "$base\$id\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
            $svcName = if ($p.Name -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { "MSSQL`$$($p.Name)" }
            $svc = $Win['services'] | Where-Object { $_.name -eq $svcName } | Select-Object -First 1
            [void]$inst.Add([ordered]@{
                instance = $p.Name; id = $id; service = $svcName; state = $(if ($svc) { $svc.state }); pid = $(if ($svc) { $svc.pid })
                version = $(if ($setup) { [string]$setup.Version }); patch_level = $(if ($setup) { [string]$setup.PatchLevel })
                edition = $(if ($setup) { [string]$setup.Edition }); path = $(if ($setup) { To-Slash ([string]$setup.SQLPath) })
                data_root = $(if ($setup) { To-Slash ([string]$setup.SQLDataRoot) })
                tcp_port = $(if ($tcp) { [string]$tcp.TcpPort }); tcp_dynamic_ports = $(if ($tcp) { [string]$tcp.TcpDynamicPorts })
            })
        }
    }
    $Win['sqlserver'] = $inst
}

# --- Parcours des disques : archives Java, JDK, Tomcat, clés et certificats -----
$Fs = [ordered]@{}
$Archives = New-Object System.Collections.ArrayList
$JdkHomes = New-Object System.Collections.ArrayList
$ServerXml = New-Object System.Collections.ArrayList
$CryptoPaths = New-Object System.Collections.ArrayList
$State = @{ truncated = $false; unreadable = 0 }   # modifié depuis les blocs de Invoke-Section (portée enfant)
$ArchiveExt = @('.jar', '.war', '.ear', '.hpi', '.jpi', '.sar')
$CryptoExt = @('.key', '.pem', '.crt', '.cer', '.der', '.p12', '.pfx', '.jks', '.keystore', '.jceks', '.bcfks', '.kdb',
    '.sth', '.p7b', '.p8', '.pk8', '.ppk', '.truststore', '.sso')
$CryptoNames = @('keystore', 'truststore', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519')
$SkipDirs = @('\Windows', '\$Recycle.Bin', '\System Volume Information', '\Recovery', '\Windows.old', '\ProgramData\Microsoft',
    '\Config.Msi', '\PerfLogs')

# Tomcat installé en service (procrun) : CATALINA_BASE même hors des disques parcourus
$TomcatSvc = New-Object System.Collections.ArrayList
Invoke-Section 'tomcat-services' {
    foreach ($root in @('HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0', 'HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0')) {
        if (-not (Test-Path $root)) { continue }
        foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $j = Get-RegValues "$($k.PSPath)\Parameters\Java"
            if (-not $j) { continue }
            $base = $null; $home_ = $null
            foreach ($o in @($j.Options) + @($j.Options9)) {
                if ($o -match '^-Dcatalina\.base=(.+)$') { $base = $Matches[1] }
                if ($o -match '^-Dcatalina\.home=(.+)$') { $home_ = $Matches[1] }
            }
            $svc = $Win['services'] | Where-Object { $_.name -eq $k.PSChildName } | Select-Object -First 1
            [void]$TomcatSvc.Add([ordered]@{ service = $k.PSChildName; state = $(if ($svc) { $svc.state })
                catalina_base = To-Slash $base; catalina_home = To-Slash $home_; jvm = To-Slash ([string]$j.Jvm) })
        }
    }
    $Win['tomcat_services'] = $TomcatSvc
}

function Test-Skip([string]$dir) {
    $rest = $dir.Substring([Math]::Min(2, $dir.Length))
    foreach ($s in $SkipDirs) { if ($rest -ieq $s) { return $true } }
    foreach ($s in $ExcludePath) { if ($dir -ieq $s.TrimEnd('\')) { return $true } }
    return $false
}
if (-not $NoScan) {
    Invoke-Section 'scan' {
        $roots = @($ScanPath)
        if (-not $roots) { $roots = @(Get-Wmi Win32_LogicalDisk 'DriveType = 3' | ForEach-Object { "$($_.DeviceID)\" }) }
        foreach ($t in $TomcatSvc) { foreach ($p in @($t.catalina_base, $t.catalina_home)) { if ($p) { $roots += $p.Replace('/', '\') } } }
        $Deadline = (Get-Date).AddSeconds($ScanMaxSeconds)
        $nextNote = (Get-Date).AddSeconds(30)
        Write-Step ("  racines : " + ($roots -join ', '))
        $seenDirs = @{}
        $stack = New-Object System.Collections.Stack
        foreach ($r in $roots) { if ($r -and (Test-Path -LiteralPath $r)) { $stack.Push($r.TrimEnd('\')) } }
        while ($stack.Count -gt 0) {
            $now = Get-Date
            if ($now -gt $Deadline) { $State.truncated = $true; Write-Step "  durée maximale atteinte : exploration arrêtée (-ScanMaxSeconds, -ScanPath)"; break }
            if ($now -gt $nextNote) { Write-Step ("  {0} répertoires, {1} archives Java, en cours : {2}" -f $seenDirs.Count, $Archives.Count, $dir); $nextNote = $now.AddSeconds(30) }
            $dir = $stack.Pop()
            $key = $dir.ToLower()
            if ($seenDirs.ContainsKey($key)) { continue }
            $seenDirs[$key] = $true
            $di = New-Object System.IO.DirectoryInfo(($dir + '\'))
            try {
                foreach ($sub in $di.GetDirectories()) {
                    if ($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                    if (-not (Test-Skip $sub.FullName)) { $stack.Push($sub.FullName) }
                }
                $files = $di.GetFiles()
            } catch { $State.unreadable++; continue }
            foreach ($f in $files) {
                $ln = $f.Name.ToLower()
                $ext = $f.Extension.ToLower()
                if ($ArchiveExt -contains $ext) { [void]$Archives.Add($f) }
                elseif ($ln -eq 'release' -and (Test-Path -LiteralPath (Join-Path $dir 'bin\java.exe'))) {
                    try { [void]$JdkHomes.Add([ordered]@{ path = To-Slash $dir; release = Parse-KvRelease ([System.IO.File]::ReadAllText($f.FullName)) }) } catch { }
                }
                elseif ($ln -eq 'server.xml' -and $dir -match '\\conf$') { [void]$ServerXml.Add($f.FullName) }
                elseif (($CryptoExt -contains $ext -or $CryptoNames -contains $ln) -and $dir -notmatch '\\lib\\security$') { [void]$CryptoPaths.Add($f) }
            }
        }
    }
}
foreach ($t in $TomcatSvc) {
    if ($t.catalina_base) {
        $p = Join-Path $t.catalina_base.Replace('/', '\') 'conf\server.xml'
        if ((Test-Path -LiteralPath $p) -and -not ($ServerXml -contains $p)) { [void]$ServerXml.Add($p) }
    }
}

# --- Archives Java ---------------------------------------------------------------
$Markers = [ordered]@{
    'org/apache/logging/log4j/core/lookup/JndiLookup.class' = 'log4j2-core:JndiLookup'
    'org/apache/logging/log4j/core/LoggerContext.class' = 'log4j2-core'
    'org/apache/log4j/net/JMSAppender.class' = 'log4j1:JMSAppender'
    'org/apache/log4j/net/SocketServer.class' = 'log4j1:SocketServer'
    'org/apache/log4j/Logger.class' = 'log4j1'
    'org/apache/commons/text/lookup/ScriptStringLookup.class' = 'commons-text:ScriptStringLookup'
    'org/springframework/core/SpringVersion.class' = 'spring-core'
    'org/springframework/boot/SpringApplication.class' = 'spring-boot'
    'org/apache/struts2/dispatcher/Dispatcher.class' = 'struts2'
    'org/yaml/snakeyaml/Yaml.class' = 'snakeyaml'
    'com/fasterxml/jackson/databind/ObjectMapper.class' = 'jackson-databind'
    'org/codehaus/jackson/map/ObjectMapper.class' = 'jackson1-mapper'
    'org/apache/commons/collections/functors/InvokerTransformer.class' = 'commons-collections3:InvokerTransformer'
    'org/apache/commons/collections4/functors/InvokerTransformer.class' = 'commons-collections4:InvokerTransformer'
    'com/thoughtworks/xstream/XStream.class' = 'xstream'
    'org/apache/shiro/SecurityUtils.class' = 'shiro'
    'com/alibaba/fastjson/JSON.class' = 'fastjson'
    'org/h2/Driver.class' = 'h2'
    'org/apache/catalina/startup/Catalina.class' = 'tomcat-catalina'
    'org/eclipse/jetty/server/Server.class' = 'jetty-server'
    'io/netty/handler/codec/http/HttpObjectDecoder.class' = 'netty-codec-http'
    'org/apache/xmlrpc/XmlRpcRequest.class' = 'xmlrpc'
    'org/apache/axis2/engine/AxisServer.class' = 'axis2'
    'org/apache/axis/client/Service.class' = 'axis1'
}
$MarkerBase = @{}
foreach ($k in $Markers.Keys) {
    $b = $k.Substring($k.LastIndexOf('/') + 1)
    if (-not $MarkerBase.ContainsKey($b)) { $MarkerBase[$b] = New-Object System.Collections.ArrayList }
    [void]$MarkerBase[$b].Add($k)
}
$NestedMax = 100MB
$MaxDepth = 3
$Sha1 = [System.Security.Cryptography.SHA1]::Create()
function Get-Sha1Hex([byte[]]$b) { return ([System.BitConverter]::ToString($Sha1.ComputeHash($b))).Replace('-', '').ToLower() }
function Read-EntryText($e, [int]$Max) {
    $s = $e.Open()
    try {
        $buf = New-Object byte[] $Max
        $n = 0
        while ($n -lt $Max) { $r = $s.Read($buf, $n, $Max - $n); if ($r -le 0) { break }; $n += $r }
        return [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
    } finally { $s.Dispose() }
}
function Inspect-Zip($zip, [string]$display, [int]$depth) {
    $res = [ordered]@{ path = $display; entries = $zip.Entries.Count }
    $maven = New-Object System.Collections.ArrayList
    $found = New-Object System.Collections.ArrayList
    $nested = New-Object System.Collections.ArrayList
    $special = [ordered]@{}
    foreach ($e in $zip.Entries) {
        $name = $e.FullName.Replace('\', '/')
        if ($name.EndsWith('/')) { continue }
        try {
            if ($name -ceq 'META-INF/MANIFEST.MF') { $res['manifest'] = Parse-Manifest (Read-EntryText $e 262144); continue }
            if ($name.StartsWith('META-INF/maven/') -and $name.EndsWith('/pom.properties')) {
                $pp = Parse-Properties (Read-EntryText $e 65536)
                [void]$maven.Add([ordered]@{ groupId = $pp['groupId']; artifactId = $pp['artifactId']; version = $pp['version'] })
                continue
            }
            $base = $name.Substring($name.LastIndexOf('/') + 1)
            if ($MarkerBase.ContainsKey($base)) {
                foreach ($k in $MarkerBase[$base]) {
                    if ($name.EndsWith($k)) {
                        $label = $Markers[$k]
                        if ($name -cne $k) { $label += ' (shaded:' + $name.Substring(0, $name.Length - $k.Length).TrimEnd('/') + ')' }
                        if (-not $found.Contains($label)) { [void]$found.Add($label) }
                    }
                }
            }
            if ($name -ceq 'org/apache/catalina/util/ServerInfo.properties') { $special['tomcat_serverinfo'] = Parse-Properties (Read-EntryText $e 65536) }
            $lname = $name.ToLower()
            $isArch = $false
            foreach ($x in $ArchiveExt) { if ($lname.EndsWith($x)) { $isArch = $true } }
            if ($isArch -and $depth -lt $MaxDepth) {
                if ($nested.Count -ge 3000) { $res['nested_truncated'] = $true; continue }
                if ($e.Length -gt $NestedMax) { [void]$nested.Add([ordered]@{ path = "$display!/$name"; skipped = 'too_large'; size = [int64]$e.Length }); continue }
                $ms = New-Object System.IO.MemoryStream
                $s = $e.Open()
                try { $s.CopyTo($ms) } finally { $s.Dispose() }
                $bytes = $ms.ToArray()
                try {
                    $ms.Position = 0
                    $z2 = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                    try { $sub = Inspect-Zip $z2 "$display!/$name" ($depth + 1) } finally { $z2.Dispose() }
                } catch { $sub = [ordered]@{ path = "$display!/$name"; error = $_.Exception.Message } }
                $sub['size'] = $bytes.Length
                $sub['sha1'] = Get-Sha1Hex $bytes
                [void]$nested.Add($sub)
                $ms.Dispose()
            }
        } catch { if (-not $res.Contains('error')) { $res['error'] = "$name : $($_.Exception.Message)" } }
    }
    if ($maven.Count) { $res['maven'] = $maven }
    if ($found.Count) { $res['markers'] = @($found | Sort-Object) }
    if ($special.Count) { $res['special'] = $special }
    if ($nested.Count) { $res['nested'] = $nested }
    return $res
}
$JavaArchives = New-Object System.Collections.ArrayList
Invoke-Section 'java-archives' {
    $Deadline = (Get-Date).AddSeconds($ArchiveMaxSeconds)
    $nextNote = (Get-Date).AddSeconds(30)
    $n = 0
    Write-Step "  $($Archives.Count) archives à inspecter"
    foreach ($f in $Archives) {
        $n++
        $now = Get-Date
        if ($now -gt $Deadline) { $State.truncated = $true; Write-Step "  durée maximale atteinte : $($n - 1) archives inspectées sur $($Archives.Count) (-ArchiveMaxSeconds)"; break }
        if ($now -gt $nextNote) { Write-Step ("  {0}/{1} archives" -f $n, $Archives.Count); $nextNote = $now.AddSeconds(30) }
        $disp = To-Slash $f.FullName
        $st = $null
        try {
            $st = [System.IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
            $sha = $null
            if (-not $NoHash) { $sha = ([System.BitConverter]::ToString($Sha1.ComputeHash($st))).Replace('-', '').ToLower(); $st.Position = 0 }
            $z = New-Object System.IO.Compression.ZipArchive($st, [System.IO.Compression.ZipArchiveMode]::Read, $true)
            try { $info = Inspect-Zip $z $disp 0 } finally { $z.Dispose() }
            $info['size'] = $f.Length
            if ($sha) { $info['sha1'] = $sha }
            [void]$JavaArchives.Add($info)
        } catch {
            [void]$JavaArchives.Add([ordered]@{ path = $disp; error = $_.Exception.Message.Substring(0, [Math]::Min(200, $_.Exception.Message.Length)) })
        } finally { if ($st) { $st.Dispose() } }
    }
}
$Fs['java_archives'] = $JavaArchives
$Fs['jdk_homes'] = $JdkHomes

# --- Tomcat : server.xml (seuls les attributs utiles sont relevés, jamais les mots de passe)
$Endpoints = New-Object System.Collections.ArrayList
function Resolve-TomcatPath([string]$store, [string]$serverXml) {
    $base = Split-Path (Split-Path $serverXml -Parent) -Parent
    $store = $store -replace '^\$\{catalina\.(base|home)\}[/\\]?', ''
    if ($store -match '^([A-Za-z]:|[/\\])') { return To-Slash $store }
    return To-Slash (Join-Path $base $store)
}
function New-XmlDoc([string]$Path) {
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Ignore
    $settings.XmlResolver = $null
    $r = [System.Xml.XmlReader]::Create($Path, $settings)
    try { $x = New-Object System.Xml.XmlDocument; $x.XmlResolver = $null; $x.Load($r); return $x } finally { $r.Close() }
}
foreach ($sx in $ServerXml) {
    Invoke-Section "tomcat:$sx" {
        $x = New-XmlDoc $sx
        foreach ($c in $x.SelectNodes('//Connector')) {
            $store = $c.GetAttribute('keystoreFile')
            if (-not $store) { $store = $c.GetAttribute('certificateKeystoreFile') }
            if (-not $store) { $store = $c.GetAttribute('certificateFile') }
            if (-not $store) {
                $cert = $c.SelectSingleNode('.//Certificate')
                if ($cert) { $store = $cert.GetAttribute('certificateKeystoreFile'); if (-not $store) { $store = $cert.GetAttribute('certificateFile') } }
            }
            $port = $c.GetAttribute('port')
            [void]$Endpoints.Add([ordered]@{
                product = 'tomcat'; kind = 'connector'; port = $(if ($port -match '^\d+$') { [int]$port } else { $null })
                address = $(if ($c.GetAttribute('address')) { $c.GetAttribute('address') } else { $null })
                protocol = $(if ($c.GetAttribute('protocol')) { $c.GetAttribute('protocol') } else { $null })
                tls = ($c.GetAttribute('SSLEnabled') -eq 'true' -or $c.GetAttribute('scheme') -eq 'https')
                cert = $(if ($store) { Resolve-TomcatPath $store $sx } else { $null }); path = To-Slash $sx
            })
        }
        foreach ($h in $x.SelectNodes('//Host')) {
            $aliases = @($h.SelectNodes('Alias') | ForEach-Object { $_.InnerText.Trim() })
            [void]$Endpoints.Add([ordered]@{ product = 'tomcat'; kind = 'vhost'; server_name = $h.GetAttribute('name')
                root = $h.GetAttribute('appBase'); aliases = $aliases; path = To-Slash $sx })
            foreach ($ctx in $h.SelectNodes('Context')) {
                [void]$Endpoints.Add([ordered]@{ product = 'tomcat'; kind = 'context'; server_name = $h.GetAttribute('name')
                    location = $ctx.GetAttribute('path'); root = $ctx.GetAttribute('docBase'); path = To-Slash $sx })
            }
        }
    }
}

# --- IIS (configuration lisible en administrateur) -------------------------------
Invoke-Section 'iis' {
    $stp = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\InetStp'
    if (-not $stp) { return }
    $iis = [ordered]@{ version = "$($stp.MajorVersion).$($stp.MinorVersion)"; path = To-Slash ([string]$stp.InstallPath); sites = @() }
    $cfg = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    try { $x = New-XmlDoc $cfg } catch { $iis['note'] = "applicationHost.config illisible : $($_.Exception.Message)"; $Win['iis'] = $iis; return }
    $sites = New-Object System.Collections.ArrayList
    foreach ($s in $x.SelectNodes('/configuration/system.applicationHost/sites/site')) {
        $root = $null
        $apps = New-Object System.Collections.ArrayList
        foreach ($a in $s.SelectNodes('application')) {
            $vd = $a.SelectSingleNode("virtualDirectory[@path='/']")
            $phys = if ($vd) { [System.Environment]::ExpandEnvironmentVariables($vd.GetAttribute('physicalPath')) } else { $null }
            if ($a.GetAttribute('path') -eq '/') { $root = $phys }
            [void]$apps.Add([ordered]@{ path = $a.GetAttribute('path'); pool = $a.GetAttribute('applicationPool'); root = To-Slash $phys })
        }
        $bind = New-Object System.Collections.ArrayList
        foreach ($b in $s.SelectNodes('bindings/binding')) {
            $proto = $b.GetAttribute('protocol'); $info = $b.GetAttribute('bindingInformation')
            [void]$bind.Add([ordered]@{ protocol = $proto; information = $info })
            if (@('http', 'https') -notcontains $proto) { continue }
            $parts = $info.Split(':')
            $addr = if ($parts[0] -and $parts[0] -ne '*') { $parts[0] } else { $null }
            $port = if ($parts.Count -gt 1 -and $parts[1] -match '^\d+$') { [int]$parts[1] } else { $null }
            $hn = if ($parts.Count -gt 2 -and $parts[2]) { $parts[2] } else { $null }
            [void]$Endpoints.Add([ordered]@{ product = 'iis'; kind = 'vhost'; address = $addr; port = $port
                server_name = $(if ($hn) { $hn } else { $s.GetAttribute('name') }); root = To-Slash $root
                tls = ($proto -eq 'https'); protocol = $proto; path = To-Slash $cfg })
        }
        foreach ($a in $apps) {
            if ($a.path -ne '/') {
                [void]$Endpoints.Add([ordered]@{ product = 'iis'; kind = 'context'; server_name = $s.GetAttribute('name')
                    location = $a.path; root = $a.root; path = To-Slash $cfg })
            }
        }
        [void]$sites.Add([ordered]@{ name = $s.GetAttribute('name'); id = $s.GetAttribute('id'); bindings = $bind; applications = $apps })
    }
    $iis['sites'] = $sites
    $Win['iis'] = $iis
}
$Fs['endpoints'] = $Endpoints

# --- Clés et certificats ---------------------------------------------------------
# Fichiers : on ne transmet que les certificats (publics) et, pour une clé, son type.
# Les PKCS#12 et magasins Java ne sont pas ouverts (pas d'essai de mot de passe).
function Get-CertFacts($c, [string]$alias) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $sans = New-Object System.Collections.ArrayList
    $isCa = $false
    foreach ($ext in $c.Extensions) {
        if ($ext.Oid.Value -eq '2.5.29.17') {
            foreach ($part in ($ext.Format($false) -split ',\s*')) {
                if ($part -match '^(DNS Name|Nom DNS)=(.+)$') { [void]$sans.Add($Matches[2]) }
                elseif ($part -match '^(IP Address|Adresse IP)=(.+)$') { [void]$sans.Add($Matches[2]) }
            }
        }
        if ($ext.Oid.Value -eq '2.5.29.19') { $isCa = [bool]$ext.CertificateAuthority }
    }
    $cn = $c.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $keyAlg = switch ($c.PublicKey.Oid.Value) { '1.2.840.113549.1.1.1' { 'RSA' } '1.2.840.10045.2.1' { 'EC' } default { $c.PublicKey.Oid.FriendlyName } }
    $bits = $null
    try { if ($keyAlg -eq 'RSA') { $bits = $c.PublicKey.Key.KeySize } } catch { }
    return [ordered]@{
        alias = $alias; subject = $c.Subject; cn = $cn; issuer = $c.Issuer
        not_before = ConvertTo-Iso $c.NotBefore; not_after = ConvertTo-Iso $c.NotAfter; serial = $c.SerialNumber.ToLower()
        sans = $sans; sig_alg = $c.SignatureAlgorithm.FriendlyName; key_alg = $keyAlg; key_bits = $bits
        self_signed = ($c.Subject -eq $c.Issuer); is_ca = $isCa
        sha256 = ([System.BitConverter]::ToString($sha256.ComputeHash($c.RawData))).Replace('-', '').ToLower()
    }
}
$Crypto = New-Object System.Collections.ArrayList
Invoke-Section 'cert-store' {
    foreach ($store in @('My', 'WebHosting')) {
        $path = "Cert:\LocalMachine\$store"
        if (-not (Test-Path $path)) { continue }
        foreach ($c in (Get-ChildItem $path)) {
            [void]$Crypto.Add([ordered]@{
                path = "cert:/LocalMachine/$store/$($c.Thumbprint)"; kind = 'windows-store'; has_private_key = [bool]$c.HasPrivateKey
                encrypted = $null; key_type = $null; owner = $null; mode = $null; size = $null; mtime = $null
                note = $(if ($c.FriendlyName) { "nom : $($c.FriendlyName)" } else { $null })
                certs = @(Get-CertFacts $c $c.Thumbprint); cert_count = 1
            })
        }
    }
}
Invoke-Section 'crypto-files' {
    foreach ($f in ($CryptoPaths | Select-Object -First 20000)) {
        $e = [ordered]@{ path = To-Slash $f.FullName; kind = 'inconnu'; has_private_key = $null; encrypted = $null; key_type = $null
            size = $f.Length; mtime = ConvertTo-Iso $f.LastWriteTime; owner = $null; mode = $null; note = $null; certs = @() }
        try {
            $ext = $f.Extension.ToLower()
            if ($f.Length -gt 2MB) { $e['note'] = 'trop volumineux : non lu' }
            elseif (@('.p12', '.pfx') -contains $ext) { $e['kind'] = 'pkcs12'; $e['note'] = 'non ouvert (pas d''essai de mot de passe)' }
            elseif (@('.jks', '.keystore', '.jceks', '.truststore', '.bcfks') -contains $ext -or $CryptoNames -contains $f.Name.ToLower()) {
                $e['kind'] = 'java-keystore'; $e['note'] = 'non ouvert (pas d''essai de mot de passe)'
            } else {
                $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                $text = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
                if ($text.Contains('-----BEGIN ')) {
                    $e['kind'] = 'pem'
                    $keys = [regex]::Matches($text, '-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----')
                    $e['has_private_key'] = $keys.Count -gt 0
                    if ($keys.Count) {
                        $kt = ($keys[0].Groups[1].Value -replace ' ?PRIVATE KEY', '').Trim()
                        $e['key_type'] = $(if ($kt) { $kt } else { 'PKCS8' })
                        $e['encrypted'] = ($keys[0].Groups[1].Value -match 'ENCRYPTED') -or $text.Contains('Proc-Type: 4,ENCRYPTED')
                    }
                    $certs = New-Object System.Collections.ArrayList
                    foreach ($m in [regex]::Matches($text, '-----BEGIN (?:TRUSTED |X509 )?CERTIFICATE-----([\s\S]*?)-----END')) {
                        try {
                            $der = [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', ''))
                            $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $der)
                            if ($certs.Count -lt 20) { [void]$certs.Add((Get-CertFacts $c $null)) }
                        } catch { }
                    }
                    $e['certs'] = $certs
                } elseif ($bytes.Length -gt 0 -and $bytes[0] -eq 0x30 -and @('.cer', '.crt', '.der') -contains $ext) {
                    try {
                        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $bytes)
                        $e['kind'] = 'der'; $e['has_private_key'] = $false; $e['certs'] = @(Get-CertFacts $c $null)
                    } catch { $e['kind'] = 'der-inconnu' }
                } elseif ($text.StartsWith('PuTTY-User-Key-File-')) {
                    $e['kind'] = 'ppk'; $e['has_private_key'] = $true; $e['encrypted'] = -not ($text -match 'Encryption: none')
                }
                $bytes = $null; $text = $null
            }
        } catch { $e['kind'] = 'illisible'; $e['note'] = 'illisible pour le compte de collecte' }
        $e['cert_count'] = @($e['certs']).Count
        [void]$Crypto.Add($e)
    }
}
$Fs['crypto_files'] = $Crypto
$Fs['stats'] = [ordered]@{ truncated = $State.truncated; unreadable_dirs = $State.unreadable; archives = $JavaArchives.Count; scan_max_seconds = $ScanMaxSeconds; archive_max_seconds = $ArchiveMaxSeconds }
$Doc['filesystem'] = $Fs
$Doc['windows'] = $Win

# --- En-tête ---------------------------------------------------------------------
$Doc['meta'] = [ordered]@{
    collector = 'powershell'; collector_version = $CollectorVersion; schema = 1
    host_label = $HostLabel; run_id = $RunId; tags = $Tags
    started_at = $Started.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"); finished_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    os = 'Windows'; user = $Identity.Name; uid = $null; elevated = $Elevated
    powershell = $PSVersionTable.PSVersion.ToString(); clr = [string]$PSVersionTable.CLRVersion
    visibility = [ordered]@{ processes = $(if ($Elevated) { 'all' } else { 'partial' }); fs_unreadable_dirs = $State.unreadable }
    errors = $Errors
}

# --- Sortie : JSON -> gzip -> base64 entre marqueurs -----------------------------
Write-Step 'Mise en forme du résultat...'
$sb = New-Object System.Text.StringBuilder (1MB)
Write-Json $sb $Doc
$raw = [System.Text.Encoding]::UTF8.GetBytes($sb.ToString())
$sb = $null
$ms = New-Object System.IO.MemoryStream
$gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$gz.Write($raw, 0, $raw.Length)
$gz.Dispose()
$b64 = [Convert]::ToBase64String($ms.ToArray(), [System.Base64FormattingOptions]::InsertLineBreaks)
$out = "CMDB-B64-BEGIN`n" + ($b64 -replace "`r", '') + "`nCMDB-B64-END`n"
$summary = '{{"collector": "powershell", "version": "{0}", "bytes_json": {1}, "archives": {2}, "programs": {3}, "errors": {4}, "truncated": {5}}}' -f `
    $CollectorVersion, $raw.Length, $JavaArchives.Count, @($Win['programs']).Count, $Errors.Count, $State.truncated.ToString().ToLower()
if (-not $OutFile) { $OutFile = "$HostLabel-$RunId.cmdb" }
if (-not [System.IO.Path]::IsPathRooted($OutFile)) { $OutFile = Join-Path (Get-Location).Path $OutFile }
[System.IO.File]::WriteAllText($OutFile, $out, (New-Object System.Text.ASCIIEncoding))
Write-Host "Collecte écrite dans $OutFile"
Write-Host $summary
Write-Host "Sur le contrôleur, après transfert du fichier :"
Write-Host "  mkdir -p store/$App/$Platform/$HostLabel"
Write-Host "  python3 tools/cmdb_unpack.py $(Split-Path $OutFile -Leaf) store/$App/$Platform/$HostLabel/$RunId.json.gz"
Write-Host "  cp store/$App/$Platform/$HostLabel/$RunId.json.gz store/$App/$Platform/$HostLabel/latest.json.gz"
