$report = "investigation_report.txt"

"===== SECURITY INVESTIGATION REPORT =====" | Out-File $report

#########################################
# 1. SSH Brute Force Detection
#########################################

"`n[Checking SSH brute force attempts]" | Out-File $report -Append

$threshold = 3

$failed = Select-String "Failed password" auth.log

$ips = $failed | ForEach-Object {
    ($_ -split " ")[-4]
}

$grouped = $ips | Group-Object | Sort-Object Count -Descending

foreach ($g in $grouped) {
    if ($g.Count -ge $threshold) {
        "[ALERT] Brute force attack from $($g.Name) ($($g.Count) attempts)" | Out-File $report -Append
    }
}

#########################################
# 2. Web Scanning Detection (404 errors)
#########################################

"`n[Checking web scanning activity]" | Out-File $report -Append

$scanThreshold = 10

$logs = Get-Content access.log

$errors = $logs | Where-Object { $_ -match " 404 " }

$ips = $errors | ForEach-Object {
    ($_ -split " ")[0]
}

$grouped = $ips | Group-Object | Sort-Object Count -Descending

foreach ($g in $grouped) {
    if ($g.Count -ge $scanThreshold) {
        "[ALERT] Possible web scanning from $($g.Name) ($($g.Count) 404 errors)" | Out-File $report -Append
    }
}

#########################################
# 3. PowerShell Attack Detection
#########################################

"`n[Checking PowerShell activity]" | Out-File $report -Append

$psLogs = Get-Content powershell_log.txt

$suspicious = $psLogs | Select-String "EncodedCommand|ExecutionPolicy Bypass|Invoke-WebRequest|Upload"

if ($suspicious) {
    "[ALERT] Suspicious PowerShell activity detected" | Out-File $report -Append
    $suspicious | Out-File $report -Append
}

#########################################
# 4. IOC Matching
#########################################

"`n[Checking IOC matches]" | Out-File $report -Append

$iocs = Get-Content ioc.txt | Where-Object { $_ -and $_ -notmatch "^#" }

foreach ($ioc in $iocs) {
    if (
        (Select-String $ioc access.log -Quiet) -or
        (Select-String $ioc auth.log -Quiet) -or
        (Select-String $ioc powershell_log.txt -Quiet)
    ) {
        "[ALERT] IOC match found: $ioc" | Out-File $report -Append
    }
}

#########################################
# 5. Summary
#########################################

"`n===== SUMMARY =====" | Out-File $report -Append

$totalAlerts = (Get-Content $report | Select-String "\[ALERT\]").Count

"Total alerts detected: $totalAlerts" | Out-File $report -Append

if ($totalAlerts -ge 20) {
    $risk = "HIGH"
}
elseif ($totalAlerts -ge 5) {
    $risk = "MEDIUM"
}
else {
    $risk = "LOW"
}

"Overall Risk Level: $risk" | Out-File $report -Append

#########################################
# END
#########################################

"`n===== END OF REPORT =====" | Out-File $report -Append

Write-Host "Investigation complete. Report saved to $report"