<#
.SYNOPSIS
Fetches known malicious IPs from a live threat intelligence feed and compares them to the system's active TCP connections.

.DESCRIPTION
This PowerShell script retrieves a threat feed from URLhaus (abuse.ch), extracts all IP addresses using regex, and compares them to currently active TCP connections on the machine using netstat. If any matches are found, they are saved to a timestamped report on the user's Desktop.

.SAFE TO RUN
- No data is sent to malicious hosts
- No payloads are downloaded
- This is a passive detection tool only

.AUTHOR
Athanasios Oikonomopoulos
#>

# ---------- Config ----------
$OutputPath       = Join-Path $env:USERPROFILE "Desktop\ThreatIntelMatches.txt"
$ObserveSeconds   = 8        # sampling window; raise to 12 if needed
$SampleIntervalMs = 300
$TxtFeedUrl       = "https://urlhaus.abuse.ch/downloads/text/"
$CsvFeedUrl       = "https://urlhaus.abuse.ch/downloads/csv/"
$Headers          = @{
  "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0"
  "Accept"          = "text/plain, text/csv, */*"
  "Cache-Control"   = "no-cache"
}

function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)  { Write-Host "[OK] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Err($m) { Write-Host "[X] $m" -ForegroundColor Red }

# Ensure TLS 1.2+ (older PS on Win sometimes defaults to TLS1.0)
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch { }

# ---------- Helpers ----------
function Invoke-HttpWithRetry {
  param(
    [Parameter(Mandatory)][string]$Url,
    [int]$MaxAttempts = 3,
    [int]$InitialDelayMs = 500
  )
  $attempt = 0
  $delay = $InitialDelayMs
  do {
    $attempt++
    try {
      return Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -TimeoutSec 30
    } catch {
      if ($attempt -ge $MaxAttempts) { throw }
      Start-Sleep -Milliseconds $delay
      $delay = [Math]::Min($delay * 2, 4000)
    }
  } while ($true)
}

# Extract IPv4 from any text
function Extract-IPv4 {
  param([string]$Text)
  if (-not $Text) { return @() }
  $rx = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
  [regex]::Matches($Text, $rx) | ForEach-Object { $_.Value }
}

# ---------- Feeds ----------
function Get-UrlhausIPsFromTxt {
  Info "Fetching URLhaus TXT feed..."
  try {
    $resp = Invoke-HttpWithRetry -Url $TxtFeedUrl
  } catch {
    Err "TXT feed failed: $($_.Exception.Message)"
    return @()
  }
  $ips = Extract-IPv4 -Text $resp.Content | Sort-Object -Unique
  return $ips
}

function Get-UrlhausIPsFromCsvOnline {
  Info "Fetching URLhaus CSV feed (online-only fallback)..."
  try {
    $resp = Invoke-HttpWithRetry -Url $CsvFeedUrl
  } catch {
    Err "CSV feed failed: $($_.Exception.Message)"
    return @()
  }
  # Strip comment banner lines that start with '#'
  $lines = ($resp.Content -split "`n") | Where-Object { $_ -and ($_ -notmatch '^\s*#') }
  if (-not $lines) { return @() }

  # Keep only lines where the status column indicates 'online'
  # (CSV header varies; simplest reliable: require 'online' somewhere and extract any IPv4 in the line)
  $onlineLines = $lines | Where-Object { $_ -match '\bonline\b' }
  $ips = @()
  foreach ($ln in $onlineLines) { $ips += Extract-IPv4 -Text $ln }
  $ips | Sort-Object -Unique
}

# ---------- Active connections ----------
function Get-ActiveRemoteIPv4 {
  try {
    # Get all, filter in PS to avoid noisy "no such State" messages
    $valid = @('Established','SynSent','SynReceived','TimeWait','CloseWait')
    $list = Get-NetTCPConnection -ErrorAction SilentlyContinue |
      Where-Object { $valid -contains $_.State } |
      Select-Object -ExpandProperty RemoteAddress |
      Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }
    if ($list) { return $list }
  } catch { }
  # Fallback to netstat if cmdlet unavailable
  (netstat -n) |
    Select-String "TCP" |
    ForEach-Object {
      $parts = ($_ -split '\s+') | Where-Object { $_ -ne '' }
      if ($parts.Count -ge 3) { ($parts[-2] -replace ':\d+$','') }
    } |
    Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }
}

# ---------- MAIN ----------
$timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# 1) TXT feed first
$ipList = Get-UrlhausIPsFromTxt

# 2) Fallback to CSV online-only if TXT returned nothing
if (-not $ipList -or $ipList.Count -eq 0) {
  Warn "TXT feed returned 0 IPs. Trying CSV online-only fallback..."
  $ipList = Get-UrlhausIPsFromCsvOnline
}

# 3) Bail out if still nothing (but don’t crash)
if (-not $ipList -or $ipList.Count -eq 0) {
  Err "Could not retrieve any IPs from URLhaus (TXT or CSV). Try again later."
  return
}

Ok "Loaded $($ipList.Count) IPs from URLhaus."

# Make membership tests fast (HashSet)
$ipSet = New-Object System.Collections.Generic.HashSet[string]
foreach ($ip in $ipList) { [void]$ipSet.Add($ip) }

Info "Observing active TCP connections for $ObserveSeconds second(s)..."
$collected = @()
$end = (Get-Date).AddSeconds($ObserveSeconds)
while ((Get-Date) -lt $end) {
  $collected += Get-ActiveRemoteIPv4
  Start-Sleep -Milliseconds $SampleIntervalMs
}
$activeIPs = $collected | Sort-Object -Unique

# Compare
$matches = $activeIPs | Where-Object { $ipSet.Contains($_) } | Sort-Object -Unique

if ($matches.Count -gt 0) {
  Warn "Found $($matches.Count) suspicious connection(s):"
  foreach ($m in $matches) {
    Write-Host (" -> {0}" -f $m) -ForegroundColor Red
    Add-Content -Path $OutputPath -Value "$timeStamp - Suspicious IP Detected: $m"
  }
  Ok "Report saved to: $OutputPath"
} else {
  Ok "No suspicious connections found."
}
