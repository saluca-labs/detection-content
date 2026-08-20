<#
.SYNOPSIS
    Read-only sweep: where can an LLM take actions on this host, and is one doing so now.

.DESCRIPTION
    Written after the July 2026 campaign in which up to eight LLM agents, built on the
    open-source Hermes and OpenClaw frameworks, worked 21 Taiwanese government systems over
    four days.

    This script does NOT hunt for that operator. No indicators were published, so any script
    claiming to would be guessing. It answers a question most organisations cannot currently
    answer at all:

        Where in this estate can a language model take an action, and what can it reach?

    That inventory is the prerequisite for every other control. You cannot gate what you have
    not enumerated.

    STRICTLY READ-ONLY. It reads files, registry, processes and network state. It starts
    nothing, stops nothing, quarantines nothing, and sends nothing anywhere.

.PARAMETER OutputPath
    Directory for the JSON and CSV report. Defaults to the current directory.

.PARAMETER IncludeUserProfiles
    Also sweep every user profile on the box, not just the current one. Slower.

.EXAMPLE
    .\Invoke-AgenticExposureSweep.ps1 -OutputPath C:\hunt -IncludeUserProfiles

.NOTES
    Author : Cristian Ruvalcaba and the Saluca Agentic AI Research Team, 2026-08-20
    Ref    : https://securityaffairs.com/197079/apt/china-linked-hackers-use-ai-agents-in-autonomous-attack-on-taiwan.html
    License: Apache-2.0
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [switch]$IncludeUserProfiles
)

$ErrorActionPreference = 'SilentlyContinue'
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param($Category, $Severity, $Item, $Detail, $Why)
    $findings.Add([pscustomobject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Host      = $env:COMPUTERNAME
        Category  = $Category
        Severity  = $Severity
        Item      = $Item
        Detail    = $Detail
        Why       = $Why
    })
}

Write-Host "Agentic exposure sweep on $env:COMPUTERNAME  (read-only)" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 0. Is this a server? Everything below is judged against that.
# ---------------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$isServer = $os.ProductType -ne 1        # 1 = workstation
$roleNote = if ($isServer) { "SERVER - agent capability here is high severity" }
            else { "workstation - agent capability here is expected" }
Write-Host "[*] Role: $roleNote"
Add-Finding 'context' 'info' 'host-role' $os.Caption $roleNote

# ---------------------------------------------------------------------------
# 1. Agent frameworks installed
# ---------------------------------------------------------------------------
Write-Host "[*] Agent frameworks..."
$profiles = if ($IncludeUserProfiles) {
    Get-ChildItem 'C:\Users' -Directory | ForEach-Object { $_.FullName }
} else { @($env:USERPROFILE) }

$frameworkPaths = @(
    @{ Name = 'Hermes (NousResearch)'; Rel = 'AppData\Local\hermes' },
    @{ Name = 'Hermes (dotdir)';       Rel = '.hermes' },
    @{ Name = 'OpenClaw';              Rel = '.openclaw' },
    @{ Name = 'OpenClaw (local)';      Rel = 'AppData\Local\openclaw' }
)
foreach ($p in $profiles) {
    foreach ($f in $frameworkPaths) {
        $full = Join-Path $p $f.Rel
        if (Test-Path $full) {
            $sz = (Get-ChildItem $full -Recurse -File | Measure-Object Length -Sum).Sum
            $sev = if ($isServer) { 'high' } else { 'info' }
            Add-Finding 'framework' $sev $f.Name $full `
                ("{0:N1} MB. Legitimate software; severity is about WHERE it is." -f ($sz/1MB))
        }
    }
}

# ---------------------------------------------------------------------------
# 2. MCP tool servers - the blast radius question
# ---------------------------------------------------------------------------
# An agent with no tools is a chatbot. An MCP server is how it gets hands. This is the
# most valuable section: it enumerates what a model on this host is permitted to touch.
Write-Host "[*] MCP tool server configuration..."
$mcpConfigs = @()
foreach ($p in $profiles) {
    $mcpConfigs += Get-ChildItem -Path $p -Recurse -Depth 4 -File `
        -Include 'mcp.json','claude_desktop_config.json','mcp_servers.json','.mcp.json' 2>$null
}
# High-risk tool classes: anything that reaches storage, credentials, or other machines.
$reaching = 'filesystem|postgres|mysql|sqlite|mongo|ssh|kubernetes|k8s|aws|azure|gcloud|gcp|shell|exec|terminal|browser|puppeteer|playwright|docker|git|slack|email|smtp'
foreach ($cfg in $mcpConfigs) {
    $text = Get-Content $cfg.FullName -Raw
    $servers = @()
    try { $servers = ($text | ConvertFrom-Json).mcpServers.PSObject.Properties.Name } catch {}
    $risky = [regex]::Matches($text, $reaching, 'IgnoreCase') |
             ForEach-Object { $_.Value.ToLower() } | Select-Object -Unique
    $sev = if ($risky.Count -gt 0) { if ($isServer) { 'high' } else { 'medium' } } else { 'info' }
    Add-Finding 'mcp-config' $sev $cfg.FullName `
        ("servers: {0}" -f ($(if ($servers) { $servers -join ', ' } else { 'unparsed' }))) `
        ("Tool classes granted: {0}" -f ($(if ($risky) { $risky -join ', ' } else { 'none matched' })))
}
if (-not $mcpConfigs) { Write-Host "    none found" }

# ---------------------------------------------------------------------------
# 3. Agent processes running right now
# ---------------------------------------------------------------------------
Write-Host "[*] Running agent and tool-server processes..."
$procs = Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -match 'hermes|openclaw|mcp|uvx|langchain|autogen|crewai' }
foreach ($pr in $procs) {
    $sev = if ($isServer) { 'high' } else { 'info' }
    Add-Finding 'process' $sev $pr.Name `
        ($pr.CommandLine.Substring(0, [Math]::Min(240, $pr.CommandLine.Length))) `
        "Agent or tool-server process active"
}
if (-not $procs) { Write-Host "    none running" }

# ---------------------------------------------------------------------------
# 4. Evidence this host talks to inference providers
# ---------------------------------------------------------------------------
# DNS cache is a cheap, non-invasive look at recent resolution.
Write-Host "[*] Inference endpoint resolution (DNS cache)..."
$inference = 'anthropic|openai|openrouter|generativelanguage|mistral|groq|deepseek|together\.xyz|api\.x\.ai'
$dns = Get-DnsClientCache | Where-Object { $_.Entry -match $inference }
foreach ($d in $dns) {
    $sev = if ($isServer) { 'high' } else { 'info' }
    Add-Finding 'egress' $sev $d.Entry $d.Data `
        "Inference provider resolved from this host. On a server this is the finding."
}
if (-not $dns) { Write-Host "    no inference endpoints in DNS cache" }

# Environment variables holding provider credentials. NAMES ONLY, never values.
Write-Host "[*] Inference credentials present in environment (names only)..."
$keyNames = Get-ChildItem Env: | Where-Object {
    $_.Name -match 'ANTHROPIC|OPENAI|OPENROUTER|GEMINI|GOOGLE_API|MISTRAL|GROQ|DEEPSEEK|TOGETHER|XAI' -and
    $_.Name -match 'KEY|TOKEN|SECRET'
}
foreach ($k in $keyNames) {
    Add-Finding 'credential' $(if ($isServer) { 'high' } else { 'medium' }) $k.Name `
        "(value not read)" `
        "A model credential is present in this process environment, so anything running here can call a model."
}
if (-not $keyNames) { Write-Host "    none in the current environment" }

# ---------------------------------------------------------------------------
# 5. Report
# ---------------------------------------------------------------------------
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$json  = Join-Path $OutputPath "agentic-exposure-$env:COMPUTERNAME-$stamp.json"
$csv   = Join-Path $OutputPath "agentic-exposure-$env:COMPUTERNAME-$stamp.csv"
$findings | ConvertTo-Json -Depth 5 | Out-File $json -Encoding utf8
$findings | Export-Csv $csv -NoTypeInformation -Encoding utf8

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
$findings | Group-Object Severity | Sort-Object Name |
    ForEach-Object { Write-Host ("  {0,-8} {1}" -f $_.Name, $_.Count) }
Write-Host ""
Write-Host "  JSON: $json"
Write-Host "  CSV : $csv"
Write-Host ""
Write-Host "Reminder: a 'high' here means an LLM has the ability to act on a server." -ForegroundColor Yellow
Write-Host "That is an exposure finding, not evidence of compromise. Read the repo README." -ForegroundColor Yellow
