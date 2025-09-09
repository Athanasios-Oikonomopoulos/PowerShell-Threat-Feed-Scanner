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

# Define output file path
$outputPath = "$env:USERPROFILE\Desktop\ThreatIntelMatches.txt"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "[*] Fetching threat intel feed from abuse.ch..." -ForegroundColor Cyan

# Spoof user-agent to bypass 403 Forbidden error
$headers = @{
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

try {
    $feed = Invoke-WebRequest -Uri "https://urlhaus.abuse.ch/downloads/text/" -Headers $headers -UseBasicParsing
} catch {
    Write-Host "[!] Failed to download threat feed. Check internet connection or proxy settings." -ForegroundColor Red
    exit 1
}

# Extract IPs using regex from all lines
$ipList = @()

foreach ($line in $feed.Content -split "`n") {
    if ($line -match '\b(?:\d{1,3}\.){3}\d{1,3}\b') {
        $matches = [regex]::Matches($line, '\b(?:\d{1,3}\.){3}\d{1,3}\b')
        foreach ($match in $matches) {
            $ipList += $match.Value
        }
    }
}

$ipList = $ipList | Sort-Object -Unique
Write-Host "[*] Extracted $($ipList.Count) IPs from feed." -ForegroundColor Green

# Get netstat connections
Write-Host "[*] Getting current active TCP connections..." -ForegroundColor Cyan
$netstatOutput = netstat -n | Select-String "TCP"

# Extract remote IPs from netstat output
$activeIPs = $netstatOutput | ForEach-Object {
    ($_ -split '\s+')[-2] -replace ':\d+$',''
} | Sort-Object -Unique

# Compare and match
Write-Host "[*] Comparing connections against threat feed..." -ForegroundColor Cyan
$matches = $activeIPs | Where-Object { $ipList -contains $_ }

# Display and save results
if ($matches.Count -gt 0) {
    Write-Host "[!] Found $($matches.Count) suspicious connection(s):" -ForegroundColor Yellow
    $matches | ForEach-Object {
        Write-Host " → $_" -ForegroundColor Red
        Add-Content -Path $outputPath -Value "$timestamp - Suspicious IP Detected: $_"
    }
    Write-Host "`n[+] Report saved to: $outputPath" -ForegroundColor Green
} else {
    Write-Host "[✓] No suspicious connections found." -ForegroundColor Green
}
