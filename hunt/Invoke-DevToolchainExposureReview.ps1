<#
.SYNOPSIS
    Read-only review for the adjacent Aug-2026 developer-machine attack: npm install
    scripts and editor "run on open" hooks that execute code without the developer
    doing anything but cloning or opening a project.

.DESCRIPTION
    The npm worm reported the same week as the GH/VPN campaigns used a package
    preinstall script to harvest GitHub, npm, cloud, Vault, Kubernetes, and private-key
    material from developer machines and CI runners. The compromised repository ALSO
    carried Claude Code and VS Code hooks wired to run the payload when a developer
    merely opened the project.

    That is the part worth reviewing, because it turns "I cloned a repo to look at it"
    into code execution.

    This script inventories, it does not judge. Every hit needs a human read. A
    postinstall script is not evidence of compromise; most of them are legitimate build
    steps. What the output gives you is the list of places where cloning or installing
    runs somebody else's code, so you can decide which of those you actually accept.

    STRICTLY READ-ONLY. Nothing is deleted, quarantined, modified, or killed.

.PARAMETER Roots
    One or more directories to walk. Required - there is deliberately no default, so the
    script never silently inventories a tree you did not name.

.PARAMETER JsonOut
    Where to write the full JSON result. Defaults to dev-toolchain-exposure.json beside
    the script.

.NOTES
    Author : Cristian Ruvalcaba and the Saluca Agentic AI Research Team
    Date   : 2026-08-10
    Part of: saluca-labs/borrowed-trust-detections

.EXAMPLE
    .\Invoke-DevToolchainExposureReview.ps1 -Roots C:\src

.EXAMPLE
    .\Invoke-DevToolchainExposureReview.ps1 -Roots C:\src,D:\work -JsonOut .\exposure.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Roots,
    [string]$JsonOut
)

$ErrorActionPreference = 'SilentlyContinue'

if (-not $JsonOut) {
    $r = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    if (-not $r) { $r = (Get-Location).Path }
    $JsonOut = Join-Path $r 'dev-toolchain-exposure.json'
}

$results = New-Object System.Collections.Generic.List[object]
function Add-Row {
    param($Kind,$Severity,$Path,$Detail)
    $results.Add([pscustomobject]@{ Kind=$Kind; Severity=$Severity; Path=$Path; Detail=$Detail })
}

Write-Host "Fleet exposure review - npm install scripts + editor auto-run hooks" -ForegroundColor White
Write-Host "Roots: $($Roots -join ', ')"

# ---------------------------------------------------------------------------
# 1. npm lifecycle scripts that run on install
# ---------------------------------------------------------------------------
Write-Host "`n=== 1. npm preinstall / postinstall / prepare scripts ===" -ForegroundColor Cyan

$pkgFiles = foreach ($root in $Roots) {
    Get-ChildItem -LiteralPath $root -Filter 'package.json' -Recurse -Force -File -Depth 6 |
        Where-Object { $_.FullName -notmatch '\\node_modules\\' }
}
Write-Host "  scanned $($pkgFiles.Count) package.json files (node_modules excluded)"

$lifecycle = @('preinstall','install','postinstall','prepare','prepublish','prepack')
foreach ($pf in $pkgFiles) {
    $json = Get-Content -LiteralPath $pf.FullName -Raw | ConvertFrom-Json
    if (-not $json.scripts) { continue }
    foreach ($hook in $lifecycle) {
        $cmd = $json.scripts.$hook
        if ($cmd) {
            # Flag the shapes that actually matter: network fetch, piped execution,
            # encoded blobs, or a raw interpreter invocation.
            $dangerous = $cmd -match 'curl|wget|Invoke-WebRequest|iwr|fetch\(|https?://|base64|atob|\|\s*(sh|bash|node|python)|child_process|eval\('
            $sev = if ($dangerous) { 'HIGH' } elseif ($hook -in 'preinstall','postinstall') { 'REVIEW' } else { 'INFO' }
            Add-Row -Kind "npm:$hook" -Severity $sev -Path $pf.FullName -Detail $cmd
            $color = switch ($sev) { 'HIGH' {'Red'} 'REVIEW' {'Yellow'} default {'Gray'} }
            Write-Host "  [$sev] $hook :: $($pf.FullName)" -ForegroundColor $color
            Write-Host "         $cmd" -ForegroundColor $color
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Claude Code hooks in project-scoped settings
# ---------------------------------------------------------------------------
Write-Host "`n=== 2. Claude Code project hooks ===" -ForegroundColor Cyan

$claudeSettings = foreach ($root in $Roots) {
    Get-ChildItem -LiteralPath $root -Recurse -Force -File -Depth 6 |
        Where-Object { $_.Name -in @('settings.json','settings.local.json') -and $_.DirectoryName -match '\\\.claude$' }
}
Write-Host "  found $($claudeSettings.Count) .claude settings files"

foreach ($cs in $claudeSettings) {
    $raw = Get-Content -LiteralPath $cs.FullName -Raw
    $json = $raw | ConvertFrom-Json
    if ($json.hooks) {
        $hookText = ($json.hooks | ConvertTo-Json -Depth 10 -Compress)
        $dangerous = $hookText -match 'curl|wget|Invoke-WebRequest|iwr|https?://|base64|atob|\|\s*(sh|bash|node|python)'
        $sev = if ($dangerous) { 'HIGH' } else { 'REVIEW' }
        Add-Row -Kind 'claude:hooks' -Severity $sev -Path $cs.FullName -Detail $hookText
        $color = if ($dangerous) { 'Red' } else { 'Yellow' }
        Write-Host "  [$sev] $($cs.FullName)" -ForegroundColor $color
        Write-Host "         $hookText" -ForegroundColor $color
    }
}

# ---------------------------------------------------------------------------
# 3. VS Code tasks that auto-run on folder open
# ---------------------------------------------------------------------------
Write-Host "`n=== 3. VS Code tasks with runOn folderOpen ===" -ForegroundColor Cyan

$vscodeFiles = foreach ($root in $Roots) {
    Get-ChildItem -LiteralPath $root -Recurse -Force -File -Depth 6 |
        Where-Object { $_.Name -in @('tasks.json','launch.json','settings.json') -and $_.DirectoryName -match '\\\.vscode$' }
}
Write-Host "  found $($vscodeFiles.Count) .vscode config files"

foreach ($vf in $vscodeFiles) {
    $raw = Get-Content -LiteralPath $vf.FullName -Raw
    if ($raw -match 'folderOpen') {
        Add-Row -Kind 'vscode:folderOpen' -Severity 'HIGH' -Path $vf.FullName `
            -Detail 'Task configured to run automatically when the folder is opened'
        Write-Host "  [HIGH] $($vf.FullName)" -ForegroundColor Red
        ($raw -split "`n" | Select-String -Pattern 'folderOpen' -Context 4,4) | ForEach-Object { Write-Host "         $_" -ForegroundColor Red }
    }
    elseif ($raw -match '"command"\s*:\s*".*(curl|wget|Invoke-WebRequest|https?://|base64)') {
        Add-Row -Kind 'vscode:task' -Severity 'REVIEW' -Path $vf.FullName -Detail 'Task command performs a network fetch'
        Write-Host "  [REVIEW] $($vf.FullName)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 4. Git hooks that are not the stock samples
# ---------------------------------------------------------------------------
Write-Host "`n=== 4. Non-sample git hooks ===" -ForegroundColor Cyan

$hookCount = 0
foreach ($root in $Roots) {
    Get-ChildItem -LiteralPath $root -Directory -Force -Recurse -Depth 4 |
        Where-Object { $_.Name -eq 'hooks' -and $_.Parent.Name -eq '.git' } |
        ForEach-Object {
            Get-ChildItem -LiteralPath $_.FullName -File -Force |
                Where-Object { $_.Extension -ne '.sample' } |
                ForEach-Object {
                    $hookCount++
                    $body = Get-Content -LiteralPath $_.FullName -Raw
                    $dangerous = $body -match 'curl|wget|Invoke-WebRequest|https?://|base64|atob'
                    $sev = if ($dangerous) { 'HIGH' } else { 'REVIEW' }
                    Add-Row -Kind 'git:hook' -Severity $sev -Path $_.FullName -Detail ($body.Substring(0, [Math]::Min(400, $body.Length)))
                    $color = if ($dangerous) { 'Red' } else { 'Yellow' }
                    Write-Host "  [$sev] $($_.FullName)" -ForegroundColor $color
                }
        }
}
Write-Host "  $hookCount non-sample git hooks found"

# ---------------------------------------------------------------------------
# 5. Global npm config that would disable the one protection that matters
# ---------------------------------------------------------------------------
Write-Host "`n=== 5. npm ignore-scripts posture ===" -ForegroundColor Cyan

# NOTE: a foreach *statement* is not legal inside ( ) in PS 5.1, it needs $( ).
$npmrcPaths = @("$env:USERPROFILE\.npmrc") + $(foreach ($root in $Roots) {
    Get-ChildItem -LiteralPath $root -Filter '.npmrc' -Recurse -Force -File -Depth 4 |
        Where-Object { $_.FullName -notmatch '\\node_modules\\' } | Select-Object -ExpandProperty FullName
})
foreach ($n in ($npmrcPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
    $body = Get-Content -LiteralPath $n -Raw
    if ($body -match 'ignore-scripts\s*=\s*true') {
        Add-Row -Kind 'npm:ignore-scripts' -Severity 'GOOD' -Path $n -Detail 'ignore-scripts=true is set'
        Write-Host "  [GOOD] ignore-scripts=true in $n" -ForegroundColor Green
    } else {
        Add-Row -Kind 'npm:ignore-scripts' -Severity 'REVIEW' -Path $n -Detail 'ignore-scripts is not enabled'
        Write-Host "  [REVIEW] ignore-scripts NOT set in $n" -ForegroundColor Yellow
    }
}
if (-not ($npmrcPaths | Where-Object { $_ -and (Test-Path $_) })) {
    Add-Row -Kind 'npm:ignore-scripts' -Severity 'REVIEW' -Path '(none)' -Detail 'No .npmrc found; install scripts run by default'
    Write-Host "  [REVIEW] no .npmrc found - npm install scripts run by default" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
$high = $results | Where-Object Severity -eq 'HIGH'
$rev  = $results | Where-Object Severity -eq 'REVIEW'
Write-Host "HIGH: $($high.Count)   REVIEW: $($rev.Count)   total rows: $($results.Count)"
if ($high) { $high | Format-Table Kind,Path -AutoSize -Wrap }

$results | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonOut -Encoding utf8
Write-Host "Full results: $JsonOut"
