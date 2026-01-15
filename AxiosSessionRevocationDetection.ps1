<#
.SYNOPSIS
    Real-time PowerShell monitor for axios-based Entra ID sign-ins using Microsoft Graph, with guided response actions for new events.

.DESCRIPTION
    This script continuously queries EntraIdSignInEvents via the Microsoft Graph Security API (runHuntingQuery) to detect
    axios-driven sign-ins targeting OfficeHome—an activity pattern commonly observed in phishing-based Adversary-in-the-Middle
    (AiTM) intrusions where attackers validate access using automated sign-in attempts after capturing credentials or tokens.

    The goal is early detection and fast operator response. When new matching events are found, the script surfaces them
    immediately in the console, triggers a popup alert, and initiates a follow-on workflow that supports rapid containment,
    including reviewing the user session context and prompting for session revocation actions as part of the response.

    These indicators reflect repeated, real-world observations over the last year and represent common early-stage attacker
    behavior prior to accessing additional Microsoft 365 / Entra ID resources.

    Detection logic focuses on:
        - Axios user-agent sign-ins
        - OfficeHome resource access
        - Conditional Access outcomes of interest (non-zero CA status excluding invalid credentials, plus explicit successful sign-ins)

    The console auto-refreshes with:
        - Static monitoring header
        - Live timestamp
        - Colored output for NEW vs PREVIOUS results

    NEW sign-in events:
        - Trigger a popup alert
        - Launch a follow-on user session review workflow for each unique UPN detected
        - Provide operators an explicit prompt/opportunity to revoke sessions during triage (containment step)

    Results are deduplicated in-memory to prevent repeated alerts and repeated NEW listings across refresh cycles.

.PARAMETER appId
    The Entra ID application (client) ID used to authenticate to Microsoft Graph.

.PARAMETER tenantId
    The Azure AD tenant ID used for Graph authentication.

.PARAMETER userSessionReviewScriptPath
    Path to the follow-on UserSessionReview script used during NEW event triage (session context + revocation workflow).

.PARAMETER intervalSeconds
    How frequently the script runs the query and refreshes the UI.

.NOTES
    Requirements:
        - Microsoft.Graph PowerShell module
        - Permissions to call /security/runHuntingQuery
        - Windows PowerShell (for popup message compatibility)

    Intended audience:
        Security analysts who need high-visibility, near real-time detection of suspicious axios automation and a built-in
        containment-oriented workflow (session review / revocation) when new activity is observed.
#>


# ============================
# Settings
# ============================
# appId and tenantId are required for authenticated Graph API calls.
# intervalSeconds controls the monitoring refresh rate.
$appId = ""
$tenantId = ""
$intervalSeconds = 60   # how often to run the query

# Path to the follow-on script you want to launch for NEW users
$userSessionReviewScriptPath = ""
$defaultAppNameToPass = "OfficeHome"

# ============================
# Popup Message Support
# ============================
Add-Type -AssemblyName PresentationFramework

# ============================
# Connect to Microsoft Graph
# ============================
Write-Output "Connecting to Microsoft Graph..."
Connect-MgGraph -TenantId $tenantId -ClientId $appId
Write-Output "Connected to Microsoft Graph."

# ============================
# KQL Query — Last 24 hours
# ============================
$query = @"
EntraIdSignInEvents
| where Timestamp >= ago(24h)
| where UserAgent has "axios" 
  and ResourceDisplayName has "OfficeHome"
| where 
    (
        ConditionalAccessStatus != "0"
        and ErrorCode != "50126"
    )
    or
    (
        ConditionalAccessStatus == "0"
        and ErrorCode == "0"
    )
| project
    Timestamp,
    AccountUpn,
    IPAddress,
    ConditionalAccessStatus,
    ErrorCode,
    ResourceDisplayName
| sort by Timestamp desc
"@

# ============================
# Track previously seen events
# ============================
$seenEvents = [System.Collections.Generic.HashSet[string]]::new()

# ============================
# Helper: Clean formatter
# ============================
function Format-Clean {
    param($r)
    [PSCustomObject]@{
        Username = $r.AccountUpn
        IP       = $r.IPAddress
        CST      = ([datetime]$r.Timestamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        CAStatus = $r.ConditionalAccessStatus
        Resource = $r.ResourceDisplayName
    }
}

# ============================
# Monitoring Loop
# ============================
Write-Output "Starting monitoring loop (every $intervalSeconds seconds)..."

while ($true) {

    Clear-Host

    # ============================
    # Static Header + Live Clock
    # ============================
    $currentTime = (Get-Date).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")

    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "              AXIOS SIGN-IN MONITORING DASHBOARD            " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Last Refresh: $currentTime (CST/CDT)" -ForegroundColor Yellow
    Write-Host " Refresh Interval: $intervalSeconds seconds"
    Write-Host "============================================================`n"

    try {
        $body = @{ Query = $query } | ConvertTo-Json

        $result = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
            -Body $body

        $rows = $result.results

        if ($rows -and $rows.Count -gt 0) {

            $newRows      = @()
            $previousRows = @()

            foreach ($row in $rows) {
                # Signature to track uniqueness across refreshes
                $sig = "$($row.Timestamp)|$($row.AccountUpn)|$($row.IPAddress)"

                if (-not $seenEvents.Contains($sig)) {
                    $seenEvents.Add($sig) | Out-Null
                    $newRows += $row
                }
                else {
                    $previousRows += $row
                }
            }

            # ============================
            # DISPLAY NEW RESULTS (GREEN)
            # ============================
            if ($newRows.Count -gt 0) {
                Write-Host "---- NEW RESULTS ----" -ForegroundColor Green
                $formattedNew = $newRows | ForEach-Object { Format-Clean $_ }
                $formattedNew | Format-Table -AutoSize
                Write-Host ""
            }
            else {
                Write-Host "No NEW results this run.`n" -ForegroundColor DarkGreen
            }

            # ============================
            # DISPLAY PREVIOUS RESULTS (GRAY)
            # ============================
            if ($previousRows.Count -gt 0) {
                Write-Host "---- PREVIOUS RESULTS ----" -ForegroundColor DarkGray
                $formattedPrev = $previousRows | ForEach-Object { Format-Clean $_ } | Sort-Object CST -Descending
                $formattedPrev | Format-Table -AutoSize
                Write-Host ""
            }
            else {
                Write-Host "No PREVIOUS results.`n" -ForegroundColor DarkGray
            }

            # ============================
            # POPUP FOR NEW ONLY
            # ============================
            if ($newRows.Count -gt 0) {
                $latestNew = $newRows[-1]
                $cst = ([datetime]$latestNew.Timestamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")

                $msg = @"
New axios sign-in detected:

User     : $($latestNew.AccountUpn)
IP       : $($latestNew.IPAddress)
Time     : $cst
CAStatus : $($latestNew.ConditionalAccessStatus)
Resource : $($latestNew.ResourceDisplayName)
"@

                [System.Windows.MessageBox]::Show(
                    $msg,
                    "Axios Sign-in Alert (NEW Events)",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Warning
                ) | Out-Null
            }

if ($newRows.Count -gt 0) {

                if (-not (Test-Path $userSessionReviewScriptPath)) {
                    Write-Host "WARNING: UserSessionReview script not found at: $userSessionReviewScriptPath" -ForegroundColor Yellow
                }
                else {

                    # Hashtable-safe extraction of unique NEW user UPNs
                    $newUserUPNs = $newRows |
                        ForEach-Object {
                            if ($null -ne $_.AccountUpn) { $_.AccountUpn }
                            elseif ($_ -is [System.Collections.IDictionary] -and $_.Contains("AccountUpn")) { $_["AccountUpn"] }
                            else { $null }
                        } |
                        Where-Object { $_ -and $_.ToString().Trim() -ne "" } |
                        Sort-Object -Unique

                    foreach ($upn in $newUserUPNs) {

                        # Pick the most recent NEW event for this user (in case multiple)
                        $userEvent = $newRows |
                            Where-Object {
                                ($_.AccountUpn -eq $upn) -or (($_ -is [System.Collections.IDictionary]) -and $_["AccountUpn"] -eq $upn)
                            } |
                            Select-Object -Last 1

                        # Hashtable-safe getters
                        $evtUser     = if ($userEvent.AccountUpn) { $userEvent.AccountUpn } elseif ($userEvent -is [System.Collections.IDictionary]) { $userEvent["AccountUpn"] } else { $upn }
                        $evtIP       = if ($userEvent.IPAddress)  { $userEvent.IPAddress  } elseif ($userEvent -is [System.Collections.IDictionary]) { $userEvent["IPAddress"] } else { "" }
                        $evtTSRaw    = if ($userEvent.Timestamp)  { $userEvent.Timestamp  } elseif ($userEvent -is [System.Collections.IDictionary]) { $userEvent["Timestamp"] } else { "" }
                        $evtCA       = if ($userEvent.ConditionalAccessStatus) { $userEvent.ConditionalAccessStatus } elseif ($userEvent -is [System.Collections.IDictionary]) { $userEvent["ConditionalAccessStatus"] } else { "" }
                        $evtResource = if ($userEvent.ResourceDisplayName) { $userEvent.ResourceDisplayName } elseif ($userEvent -is [System.Collections.IDictionary]) { $userEvent["ResourceDisplayName"] } else { "" }

                        # Format timestamp into local CST/CDT string if possible
                        $evtCST = $evtTSRaw
                        try {
                            if ($evtTSRaw) {
                                $evtCST = ([datetime]$evtTSRaw).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                            }
                        } catch { }

                        Start-Process powershell.exe -ArgumentList @(
                            "-NoProfile",
                            "-ExecutionPolicy", "Bypass",
                            "-File", "`"$userSessionReviewScriptPath`"",
                            "-UserPrincipalName", "`"$evtUser`"",
                            "-IPAddress", "`"$evtIP`"",
                            "-Timestamp", "`"$evtCST`"",
                            "-ConditionalAccessStatus", "`"$evtCA`"",
                            "-ResourceDisplayName", "`"$evtResource`""
                        )
                    }
                }
            }
        }
        else {
            Write-Host "No matching results in the last 24 hours." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }

    Start-Sleep -Seconds $intervalSeconds
}
