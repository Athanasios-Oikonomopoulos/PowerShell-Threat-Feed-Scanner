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

# Geolocation settings
$EnableGeo        = $true
$GeoDelayMs       = 1500   # ms delay to stay under ip-api free tier (~45 req/min)

# ---------- Helpers ----------
function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)  { Write-Host "[OK] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Err($m) { Write-Host "[X] $m" -ForegroundColor Red }

# Ensure TLS 1.2+
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch { }

# ---------- HTTP with retry ----------
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

# ---------- Extract IPv4 ----------
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
  $lines = ($resp.Content -split "`n") | Where-Object { $_ -and ($_ -notmatch '^\s*#') }
  if (-not $lines) { return @() }
  $onlineLines = $lines | Where-Object { $_ -match '\bonline\b' }
  $ips = @()
  foreach ($ln in $onlineLines) { $ips += Extract-IPv4 -Text $ln }
  $ips | Sort-Object -Unique
}

# ---------- Active connections ----------
function Get-ActiveRemoteIPv4 {
  try {
    $valid = @('Established','SynSent','SynReceived','TimeWait','CloseWait')
    $list = Get-NetTCPConnection -ErrorAction SilentlyContinue |
      Where-Object { $valid -contains $_.State } |
      Select-Object -ExpandProperty RemoteAddress |
      Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }
    if ($list) { return $list }
  } catch { }
  (netstat -n) |
    Select-String "TCP" |
    ForEach-Object {
      $parts = ($_ -split '\s+') | Where-Object { $_ -ne '' }
      if ($parts.Count -ge 3) { ($parts[-2] -replace ':\d+$','') }
    } |
    Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }
}

# ---------- Geolocation ----------
function Get-IPGeoInfo {
  param([string]$Ip)
  if (-not $Ip) { return $null }

  try {
    $url = "http://ip-api.com/json/$Ip"
    $resp = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 15 -ErrorAction Stop
    if ($resp.status -ne 'success') {
      return @{ Error = "Lookup failed: $($resp.message)" }
    }
    return @{
      IP      = $resp.query
      Country = $resp.country
      Region  = $resp.regionName
      City    = $resp.city
      ISP     = $resp.isp
      Org     = $resp.org
      ASN     = $resp.as
    }
  } catch {
    return @{ Error = "API error: $($_.Exception.Message)" }
  }
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

# 3) Bail if still nothing
if (-not $ipList -or $ipList.Count -eq 0) {
  Err "Could not retrieve any IPs from URLhaus (TXT or CSV). Try again later."
  return
}

Ok "Loaded $($ipList.Count) IPs from URLhaus."

# Build HashSet
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
    $geoString = ""
    if ($EnableGeo) {
      $geo = Get-IPGeoInfo -Ip $m
      if ($geo -and $geo.Error) {
        $geoString = "GEO_ERR: $($geo.Error)"
      } elseif ($geo) {
        $geoParts = @()
        if ($geo.Country) { $geoParts += $geo.Country }
        if ($geo.Region)  { $geoParts += $geo.Region }
        if ($geo.City)    { $geoParts += $geo.City }
        $loc = ($geoParts -join ", ")
        $isp = $geo.ISP
        $asn = $geo.ASN
        $geoString = if ($loc) { "$loc" } else { "Unknown location" }
        if ($isp) { $geoString += " | ISP: $isp" }
        if ($asn) { $geoString += " | ASN: $asn" }
      } else {
        $geoString = "GEO_ERR: unknown"
      }
      Start-Sleep -Milliseconds $GeoDelayMs
    }

    $msg = if ($geoString) {
      "$timeStamp - Suspicious IP Detected: $m - $geoString"
    } else {
      "$timeStamp - Suspicious IP Detected: $m"
    }

    Write-Host (" -> {0}" -f $msg) -ForegroundColor Red
    Add-Content -Path $OutputPath -Value $msg
  }
  Ok "Report saved to: $OutputPath"
} else {
  Ok "No suspicious connections found."
}
