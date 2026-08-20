<#
.SYNOPSIS
    Read-only host sweep for the three Aug-2026 GitHub/VPN campaigns.

.DESCRIPTION
    Hunts for host artifacts from:
      A. BoryptGrab-lineage infostealer   (fake GitHub repos, WinGUP + trojanized libcurl.dll)
      B. QuickFox VPN supply chain        (FDMTP implant, Mustang Panda lineage)
      C. "Free VPN for PC" GitHub repo    (Lumma Stealer dropper)

    STRICTLY READ-ONLY. This script does not delete, quarantine, modify, or kill anything.
    It only reads the filesystem, registry, DNS cache, and process list.

    A clean result is not proof of safety. BoryptGrab installs no persistence and the
    QuickFox implant only proceeds on endpoints running a specific application set, so
    absence of artifacts is weaker evidence here than it usually is. Read the negative
    ledger in the README before treating a clean sweep as an all-clear.

.PARAMETER Deep
    Widens the filesystem walk from depth 3 to depth 6 and hashes more candidates. Slower.

.PARAMETER JsonOut
    Where to write the full JSON result. Defaults to sweep-results.json beside the script.

.NOTES
    Author : Cristian Ruvalcaba and the Saluca Agentic AI Research Team
    Date   : 2026-08-10
    Part of: saluca-labs/borrowed-trust-detections

.EXAMPLE
    .\Invoke-BorrowedTrustSweep.ps1

.EXAMPLE
    .\Invoke-BorrowedTrustSweep.ps1 -Deep -JsonOut .\results.json
#>

[CmdletBinding()]
param(
    [switch]$Deep,
    [string]$JsonOut
)

# $PSScriptRoot is not reliably populated inside a param() default, so resolve it here.
if (-not $JsonOut) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    if (-not $root) { $root = (Get-Location).Path }
    $JsonOut = Join-Path $root 'sweep-results.json'
}

$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO','CLEAR')][string]$Severity,
        [Parameter(Mandatory)][ValidateSet('A-BoryptGrab','B-QuickFox','C-LummaVPN','X-Adjacent')][string]$Campaign,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Evidence = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Campaign = $Campaign
        Check    = $Check
        Detail   = $Detail
        Evidence = $Evidence
    })
}

function Write-Section { param([string]$Text) Write-Host "`n=== $Text ===" -ForegroundColor Cyan }

# ---------------------------------------------------------------------------
# IOC tables
# ---------------------------------------------------------------------------

# A - BoryptGrab
$A_Hashes = @(
    '1c854a6aa415f4be964e8a4be49c06e092156bf66d71f9c79995b3e6b156e778'  # Arctic-Wolf-6.86.5.zip
    '6db05c4473760c44fa572ffac4c5911b35caf2467a37726c21c5f87e25cb2ea8'  # libcurl.dll A
    'fd01262bd56510088b9ddfe58ca101abb98575f3c0259b480a31b917aa73bc56'  # libcurl.dll B
    '07dcc12197490bf3292619273ba8b11a960273a34265bca3b7d6d40e8c47dc82'  # decrypted implant
    '8e1ea6d9a8ccb303be9a2aad3524a529d0d99b1b24a136d8422276e942c4c4b8'  # nested stealer PE
    'e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2'  # GrabPure_Dump.bin
    '52825dbf3fc28b9f7c3a24adf78d3425ac714e975769f4d70e8c718ddcbb9856'  # reference BoryptGrab
)

# A - stealer output artifacts. Note the operator misspelling "Filegraber".
$A_ArtifactNames = @(
    'Filegraber','browser_decryption.log','sends.log','UserInformation.txt',
    'credentials_data.txt','Discord_tokens.txt','steam_accounts.txt',
    'installed_applications.txt','browsers.txt','decrypt_browser'
)

# B - QuickFox / FDMTP
$B_Hashes = @(
    '2B6CDAFDFE427A3DE1A94A8A2CA1F09FC4C8F90E4F59089FD9B35B73185ED01C'  # Gen1 loader
    '795594AD5E6F2868CC4D8ED12DABF4F3999A1477C6B250527C5EDE9A98528FB9'  # Gen2 loader
) | ForEach-Object { $_.ToLower() }

$B_FirstBadVersion = [version]'3.0.51.0'
$B_FixedVersion    = [version]'3.59.6'

# C - Lumma "Free VPN for PC"
$C_Hashes = @(
    'acbaa6041286f9e3c815cd1712771a490530f52c90ce64da20f28cfa0955a5ca'  # Launch.exe dropper
    '15b644b42edce646e8ba69a677edcb09ec752e6e7920fd982979c714aece3925'  # msvcp110.dll payload
)

# Domains across all campaigns, checked against DNS cache and the hosts file.
$AllDomains = @(
    # A - distribution / TDS
    'targetroyena.com','furiesniffer.com','fleecykobird.com','balafohoaxee.com',
    'yontzarpzenu.com','eggcupmadras.com','lafferdingar.com','palchknosp.com',
    'brakerhotdog.com','sellietuskar.com','logic-prox.com','hamletlunoid.com',
    'parnelmentha.com','refonttaught.com','bentleyvazquezpvey.github.io',
    # B - QuickFox / FDMTP
    'cdns3.51quickfox.cn','www.icloud-cdn.net','icloud-cdn.net','www.google-apis.net',
    'google-apis.net','www.yahoo-cdn.it.com','yahoo-cdn.it.com','www.wangmeng.xyz',
    'wangmeng.xyz','www.wangmengsb.com','wangmengsb.com','www.wangmeng66.top',
    'wangmeng66.top','www.techcheck1.com','techcheck1.com',
    # C - Lumma C2
    'explorationmsn.store','snailyeductyi.sbs','ferrycheatyk.sbs','deepymouthi.sbs',
    'wrigglesight.sbs','captaitwik.sbs','sidercotay.sbs','heroicmint.sbs','monstourtu.sbs'
)

$AllIPs = @(
    # A
    '193.143.1.131','45.93.20.61','2.27.5.63','77.91.96.188','185.100.157.222',
    '193.221.201.165','217.145.226.0','217.145.227.254',
    # B - FDMTP cluster
    '47.238.64.56','47.239.93.49','47.239.4.179','47.88.21.252','47.238.240.219',
    '154.223.75.206','154.223.58.64','45.158.180.250','154.223.58.142','38.60.142.56'
)

$SearchRoots = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    $env:TEMP,
    "$env:LOCALAPPDATA\Temp",
    "$env:APPDATA",
    "$env:LOCALAPPDATA"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

Write-Host "GH/VPN campaign sweep - read-only" -ForegroundColor White
Write-Host "Host: $env:COMPUTERNAME  User: $env:USERNAME  Started: $(Get-Date -Format o)"
Write-Host "Deep mode: $Deep"

# ---------------------------------------------------------------------------
# A1 - BoryptGrab staging directories and output artifacts
# ---------------------------------------------------------------------------
Write-Section 'A1. BoryptGrab staging + output artifacts'

$a1hits = 0
foreach ($root in $SearchRoots) {
    foreach ($name in $A_ArtifactNames) {
        Get-ChildItem -LiteralPath $root -Filter $name -Recurse -Force -Depth 4 |
            ForEach-Object {
                $a1hits++
                Add-Finding -Severity CRITICAL -Campaign 'A-BoryptGrab' `
                    -Check 'Stealer output artifact' `
                    -Detail "Found stealer staging artifact '$name'" `
                    -Evidence $_.FullName
                Write-Host "  [!] $($_.FullName)" -ForegroundColor Red
            }
    }
}

# %TEMP%\XX_<geo>_<time>_GUID_... staging folder pattern
foreach ($root in $SearchRoots) {
    Get-ChildItem -LiteralPath $root -Directory -Force |
        Where-Object { $_.Name -match '^XX_.*_.*_.*' } |
        ForEach-Object {
            $a1hits++
            Add-Finding -Severity CRITICAL -Campaign 'A-BoryptGrab' `
                -Check 'Staging directory pattern' `
                -Detail 'Directory matches XX_<geo>_<time>_GUID_ stealer staging pattern' `
                -Evidence $_.FullName
            Write-Host "  [!] $($_.FullName)" -ForegroundColor Red
        }
}
if ($a1hits -eq 0) { Write-Host '  clean' -ForegroundColor Green; Add-Finding -Severity CLEAR -Campaign 'A-BoryptGrab' -Check 'Stealer output artifact' -Detail 'No staging dirs or output artifacts found' }

# ---------------------------------------------------------------------------
# A2 - Loose libcurl.dll next to an EXE in a user-writable path (sideload pair)
# ---------------------------------------------------------------------------
Write-Section 'A2. libcurl.dll sideload pairs in user-writable paths'

$a2hits = 0
foreach ($root in $SearchRoots) {
    Get-ChildItem -LiteralPath $root -Filter 'libcurl.dll' -Recurse -Force -Depth 4 |
        ForEach-Object {
            $dll = $_
            $siblingExe = Get-ChildItem -LiteralPath $dll.DirectoryName -Filter '*.exe' -Force |
                          Select-Object -First 5
            $hash = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256).Hash.ToLower()
            $known = $A_Hashes -contains $hash
            $sev = if ($known) { 'CRITICAL' } elseif ($siblingExe) { 'HIGH' } else { 'MEDIUM' }
            $a2hits++
            Add-Finding -Severity $sev -Campaign 'A-BoryptGrab' `
                -Check 'libcurl.dll in user-writable path' `
                -Detail ("SHA256=$hash knownIOC=$known siblingExe=" + (($siblingExe | Select-Object -ExpandProperty Name) -join ',')) `
                -Evidence $dll.FullName
            $color = if ($known) { 'Red' } else { 'Yellow' }
            Write-Host "  [$sev] $($dll.FullName)  sha256=$hash" -ForegroundColor $color
        }
}
if ($a2hits -eq 0) { Write-Host '  clean' -ForegroundColor Green; Add-Finding -Severity CLEAR -Campaign 'A-BoryptGrab' -Check 'libcurl.dll sideload pair' -Detail 'No loose libcurl.dll in user-writable paths' }

# ---------------------------------------------------------------------------
# A3 - Known-bad hashes across archives and executables in download paths
# ---------------------------------------------------------------------------
Write-Section 'A3. Known-bad hash match (archives + PEs in user paths)'

$a3hits = 0
$hashTargets = foreach ($root in $SearchRoots) {
    Get-ChildItem -LiteralPath $root -Recurse -Force -Depth $(if ($Deep) { 6 } else { 3 }) -File |
        Where-Object { $_.Extension -in '.zip','.exe','.dll','.7z','.rar','.bin','.dmp' -and $_.Length -lt 400MB }
}
foreach ($f in $hashTargets) {
    $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
    if ($A_Hashes -contains $h) {
        $a3hits++
        Add-Finding -Severity CRITICAL -Campaign 'A-BoryptGrab' -Check 'Known-bad SHA256' `
            -Detail "File matches published BoryptGrab IOC hash $h" -Evidence $f.FullName
        Write-Host "  [!] IOC HASH $($f.FullName)" -ForegroundColor Red
    }
    elseif ($B_Hashes -contains $h) {
        $a3hits++
        Add-Finding -Severity CRITICAL -Campaign 'B-QuickFox' -Check 'Known-bad SHA256' `
            -Detail "File matches published FDMTP loader hash $h" -Evidence $f.FullName
        Write-Host "  [!] IOC HASH $($f.FullName)" -ForegroundColor Red
    }
    elseif ($C_Hashes -contains $h) {
        $a3hits++
        Add-Finding -Severity CRITICAL -Campaign 'C-LummaVPN' -Check 'Known-bad SHA256' `
            -Detail "File matches published Lumma 'Free VPN for PC' hash $h" -Evidence $f.FullName
        Write-Host "  [!] IOC HASH $($f.FullName)" -ForegroundColor Red
    }
}
Write-Host "  hashed $($hashTargets.Count) files, $a3hits IOC matches"
if ($a3hits -eq 0) { Add-Finding -Severity CLEAR -Campaign 'A-BoryptGrab' -Check 'Known-bad SHA256' -Detail "Hashed $($hashTargets.Count) candidate files, no IOC matches" }

# ---------------------------------------------------------------------------
# B1 - QuickFox installed? Which version?
# ---------------------------------------------------------------------------
Write-Section 'B1. QuickFox VPN presence and version'

$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$qf = Get-ItemProperty $uninstallRoots |
      Where-Object { $_.DisplayName -match 'quickfox|51quickfox|å¿«è¿ž|é—ªç”µ' }

if ($qf) {
    foreach ($app in $qf) {
        $ver = $null; [void][version]::TryParse($app.DisplayVersion, [ref]$ver)
        $vulnerable = $ver -and $ver -ge $B_FirstBadVersion -and $ver -lt $B_FixedVersion
        $sev = if ($vulnerable) { 'CRITICAL' } else { 'HIGH' }
        Add-Finding -Severity $sev -Campaign 'B-QuickFox' -Check 'QuickFox installed' `
            -Detail "DisplayName=$($app.DisplayName) Version=$($app.DisplayVersion) inTrojanizedRange=$vulnerable (bad: >=3.0.51.0 and <3.59.6)" `
            -Evidence $app.InstallLocation
        Write-Host "  [$sev] $($app.DisplayName) $($app.DisplayVersion)  trojanized-range=$vulnerable" -ForegroundColor Red
    }
} else {
    Write-Host '  QuickFox not installed' -ForegroundColor Green
    Add-Finding -Severity CLEAR -Campaign 'B-QuickFox' -Check 'QuickFox installed' -Detail 'No QuickFox product found in uninstall registry'
}

# Directory-level check in case it was installed without registering
foreach ($p in @("$env:LOCALAPPDATA\Programs\quickfox","$env:APPDATA\quickfox","${env:ProgramFiles}\quickfox","${env:ProgramFiles(x86)}\quickfox")) {
    if (Test-Path $p) {
        Add-Finding -Severity HIGH -Campaign 'B-QuickFox' -Check 'QuickFox directory' -Detail 'QuickFox install directory present' -Evidence $p
        Write-Host "  [HIGH] dir present: $p" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# B2 - FDMTP implant artifacts
# ---------------------------------------------------------------------------
Write-Section 'B2. FDMTP implant artifacts (mutex, sideload dir, registry persistence)'

$b2hits = 0

# File-based mutex
$mutexPath = "$env:TEMP\quickfox\data.dat"
if (Test-Path $mutexPath) {
    $b2hits++
    $len = (Get-Item $mutexPath).Length
    Add-Finding -Severity CRITICAL -Campaign 'B-QuickFox' -Check 'FDMTP file mutex' `
        -Detail "FDMTP re-infection guard present (expected 1 byte, actual $len)" -Evidence $mutexPath
    Write-Host "  [!] $mutexPath ($len bytes)" -ForegroundColor Red
}

# Sideload staging dir + the specific sideload pair
$sideloadDir = "$env:LOCALAPPDATA\Temp\quickfox\updated"
foreach ($d in @($sideloadDir, "$env:TEMP\quickfox\updated")) {
    if (Test-Path $d) {
        $b2hits++
        Add-Finding -Severity CRITICAL -Campaign 'B-QuickFox' -Check 'FDMTP sideload staging dir' `
            -Detail 'quickfox\updated staging directory present' -Evidence $d
        Write-Host "  [!] $d" -ForegroundColor Red
        Get-ChildItem -LiteralPath $d -Force | ForEach-Object { Write-Host "        - $($_.Name)" }
    }
}

# csmonitor.exe + Microsoft.ServiceHosting.Tools.dll sideload pair anywhere user-writable
foreach ($root in $SearchRoots) {
    # NOTE: -Include is silently ignored when combined with -LiteralPath, so filter explicitly.
    Get-ChildItem -LiteralPath $root -Recurse -Force -Depth 4 -File |
        Where-Object { $_.Name -in @('csmonitor.exe','Microsoft.ServiceHosting.Tools.dll','update.bin') } |
        ForEach-Object {
            $b2hits++
            Add-Finding -Severity CRITICAL -Campaign 'B-QuickFox' -Check 'FDMTP sideload component' `
                -Detail "FDMTP sideload component '$($_.Name)' in a user-writable path" -Evidence $_.FullName
            Write-Host "  [!] $($_.FullName)" -ForegroundColor Red
        }
}

# Registry persistence: HKCU\SOFTWARE\Microsoft\IME\{HWID}
$imeKey = 'HKCU:\SOFTWARE\Microsoft\Microsoft\IME'
$imeKeyReal = 'HKCU:\SOFTWARE\Microsoft\IME'
if (Test-Path $imeKeyReal) {
    Get-ChildItem $imeKeyReal | ForEach-Object {
        # Legit IME subkeys are named things like IMEJP, IMEKR, IMETC, IMESC.
        # FDMTP writes a subkey named after the host HWID - long, GUID-ish or hex-ish.
        if ($_.PSChildName -notmatch '^(IME[A-Z]{2}|IMEJP\d*|Cache|Zhuyin|Wubi)$' -and $_.PSChildName.Length -ge 12) {
            $b2hits++
            $vals = (Get-ItemProperty $_.PSPath | Select-Object -Property * -ExcludeProperty PS* | Out-String).Trim()
            Add-Finding -Severity HIGH -Campaign 'B-QuickFox' -Check 'FDMTP registry persistence candidate' `
                -Detail "Anomalous subkey under HKCU\SOFTWARE\Microsoft\IME - FDMTP persists as {HWID} here" `
                -Evidence "$($_.PSChildName) :: $vals"
            Write-Host "  [HIGH] anomalous IME subkey: $($_.PSChildName)" -ForegroundColor Yellow
        }
    }
}
if ($b2hits -eq 0) { Write-Host '  clean' -ForegroundColor Green; Add-Finding -Severity CLEAR -Campaign 'B-QuickFox' -Check 'FDMTP implant artifacts' -Detail 'No mutex, staging dir, sideload components, or anomalous IME subkeys' }

# ---------------------------------------------------------------------------
# C1 - Lumma "Free VPN for PC" dropper artifacts
# ---------------------------------------------------------------------------
Write-Section 'C1. "Free VPN for PC" / Lumma dropper artifacts'

$c1hits = 0
foreach ($root in $SearchRoots) {
    Get-ChildItem -LiteralPath $root -Recurse -Force -Depth 4 -File |
        Where-Object { $_.Name -match '^(Launch\.exe)$' -or $_.Name -match 'Free.?VPN.?for.?PC|Minecraft.?Skin.?Changer' } |
        ForEach-Object {
            $c1hits++
            Add-Finding -Severity HIGH -Campaign 'C-LummaVPN' -Check 'Lumma lure filename' `
                -Detail "Filename matches the CYFIRMA 'Free VPN for PC' campaign lure or dropper" -Evidence $_.FullName
            Write-Host "  [HIGH] $($_.FullName)" -ForegroundColor Yellow
        }
}

# The dropper stages msvcp110.dqq then renames to msvcp110.dll directly in %APPDATA% (Roaming
# root, not a subfolder). A legitimate msvcp110.dll never lives there.
foreach ($n in @('msvcp110.dll','msvcp110.dqq')) {
    $p = Join-Path $env:APPDATA $n
    if (Test-Path $p) {
        $c1hits++
        $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()
        Add-Finding -Severity CRITICAL -Campaign 'C-LummaVPN' -Check 'Lumma payload in %APPDATA% root' `
            -Detail "$n staged in Roaming root - the CYFIRMA-documented Lumma drop location. SHA256=$h knownIOC=$($C_Hashes -contains $h)" `
            -Evidence $p
        Write-Host "  [!] $p  sha256=$h" -ForegroundColor Red
    }
}
if ($c1hits -eq 0) { Write-Host '  clean' -ForegroundColor Green; Add-Finding -Severity CLEAR -Campaign 'C-LummaVPN' -Check 'Lumma dropper artifacts' -Detail 'No lure filenames and no msvcp110 staging in %APPDATA% root' }

# ---------------------------------------------------------------------------
# N1 - Network: DNS cache and hosts file
# ---------------------------------------------------------------------------
Write-Section 'N1. DNS resolver cache + hosts file'

$n1hits = 0
$dns = Get-DnsClientCache
foreach ($d in $AllDomains) {
    $m = $dns | Where-Object { $_.Entry -like "*$d*" -or $_.Name -like "*$d*" }
    if ($m) {
        $n1hits++
        Add-Finding -Severity CRITICAL -Campaign 'X-Adjacent' -Check 'DNS cache hit' `
            -Detail "Resolver cache contains campaign domain $d" -Evidence ($m | Out-String).Trim()
        Write-Host "  [!] DNS cache: $d" -ForegroundColor Red
    }
}
foreach ($ip in $AllIPs) {
    $m = $dns | Where-Object { $_.Data -eq $ip }
    if ($m) {
        $n1hits++
        Add-Finding -Severity CRITICAL -Campaign 'X-Adjacent' -Check 'DNS cache resolves to IOC IP' `
            -Detail "A cached record resolves to campaign IP $ip" -Evidence ($m | Out-String).Trim()
        Write-Host "  [!] DNS cache -> $ip" -ForegroundColor Red
    }
}

$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsTxt = Get-Content $hostsFile -Raw
foreach ($d in $AllDomains) {
    if ($hostsTxt -match [regex]::Escape($d)) {
        $n1hits++
        Add-Finding -Severity HIGH -Campaign 'X-Adjacent' -Check 'hosts file entry' `
            -Detail "hosts file references campaign domain $d" -Evidence $hostsFile
        Write-Host "  [HIGH] hosts: $d" -ForegroundColor Yellow
    }
}
Write-Host "  checked $($AllDomains.Count) domains / $($AllIPs.Count) IPs against $($dns.Count) cache entries"
if ($n1hits -eq 0) { Add-Finding -Severity CLEAR -Campaign 'X-Adjacent' -Check 'DNS cache + hosts' -Detail "No campaign domains or IPs in DNS cache ($($dns.Count) entries) or hosts file" }

# ---------------------------------------------------------------------------
# N2 - Live connections to IOC IPs
# ---------------------------------------------------------------------------
Write-Section 'N2. Active TCP connections to IOC infrastructure'

$n2hits = 0
$conns = Get-NetTCPConnection -State Established,SynSent
foreach ($c in $conns) {
    if ($AllIPs -contains $c.RemoteAddress) {
        $n2hits++
        $proc = (Get-Process -Id $c.OwningProcess).Path
        Add-Finding -Severity CRITICAL -Campaign 'X-Adjacent' -Check 'Live C2 connection' `
            -Detail "Established connection to IOC IP $($c.RemoteAddress):$($c.RemotePort)" -Evidence $proc
        Write-Host "  [!] $($c.RemoteAddress):$($c.RemotePort) <- $proc" -ForegroundColor Red
    }
    # FDMTP cluster port range 20800-20816 to any host is worth surfacing
    if ($c.RemotePort -ge 20800 -and $c.RemotePort -le 20816) {
        $n2hits++
        $proc = (Get-Process -Id $c.OwningProcess).Path
        Add-Finding -Severity HIGH -Campaign 'B-QuickFox' -Check 'FDMTP port range' `
            -Detail "Connection on FDMTP cluster port range 20800-20816 to $($c.RemoteAddress):$($c.RemotePort)" -Evidence $proc
        Write-Host "  [HIGH] port $($c.RemotePort) -> $($c.RemoteAddress) <- $proc" -ForegroundColor Yellow
    }
}
Write-Host "  checked $($conns.Count) connections"
if ($n2hits -eq 0) { Add-Finding -Severity CLEAR -Campaign 'X-Adjacent' -Check 'Live C2 connection' -Detail "No connections to IOC IPs or FDMTP port range across $($conns.Count) sockets" }

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Section 'SUMMARY'

$order = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3; INFO=4; CLEAR=5 }
$sorted = $script:Findings | Sort-Object { $order[$_.Severity] }
$bad = $sorted | Where-Object { $_.Severity -in 'CRITICAL','HIGH','MEDIUM' }

if ($bad) {
    Write-Host "$($bad.Count) finding(s) needing attention:" -ForegroundColor Red
    $bad | Format-Table Severity,Campaign,Check,Evidence -AutoSize -Wrap
} else {
    Write-Host 'No campaign artifacts found. Host is clean against all checked IOCs.' -ForegroundColor Green
}

$sorted | ConvertTo-Json -Depth 4 | Out-File -FilePath $JsonOut -Encoding utf8
Write-Host "`nFull results written to: $JsonOut"
