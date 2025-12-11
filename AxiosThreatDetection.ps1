<#
.SYNOPSIS
    Real-time PowerShell monitor for axios-based Entra ID sign-ins using Microsoft Graph. The KQL query searches on known attac

.DESCRIPTION
    This script continuously queries EntraIdSignInEvents through the
    Microsoft Graph Security API runHuntingQuery.

    OfficeHome has consistently been the initial application accessed by threat
    actors after they obtain compromised credentials through phishing campaigns
    that lead to Adversary in the Middle style attacks. After harvesting user
    credentials or session tokens, attackers often validate access by
    initiating an OfficeHome authentication request using axios based
    automation tools.

    This script is designed to identify that activity early, often before the
    full sign in lifecycle appears in Azure logs. The rapid alerting allows
    defenders to respond quickly and interrupt the intrusion sequence before
    the threat actor moves deeper into the environment or reaches additional
    Microsoft 365 or Entra ID applications.

    These indicators reflect activity that has been repeatedly observed over the
    last year and represent a common early stage behavior in real world attacks.

    
   It highlights:
        - Axios user-agent sign-ins
        - CA status not equal to 0
        - OfficeHome resource access

    The console auto-refreshes with:
        - Static monitoring header
        - Live timestamp
        - Colored output for NEW and PREVIOUS results

    NEW sign-in events trigger a popup alert.

    Results are deduplicated using an in-memory hash table
    to prevent repeated popups and repeated NEW listings.

.PARAMETER appId
    The Entra ID application (client) ID used to authenticate
    to Microsoft Graph.

.PARAMETER tenantId
    The Azure AD tenant ID used for Graph authentication.

.PARAMETER intervalSeconds
    How frequently the script runs the query and refreshes the UI.

.NOTES
    Requirements:
        - Microsoft.Graph PowerShell module
        - Permissions to call /security/runHuntingQuery
        - Windows PowerShell (for popup message compatibility)

    This script is intended for security analysts who need
    high-visibility and real-time detection of suspicious axios activity.
#>

# ============================
# Settings
# ============================
# appId and tenantId are required for authenticated Graph API calls.
# intervalSeconds controls the monitoring refresh rate.
$appId = ""
$tenantId = ""
$intervalSeconds = 60   # how often to run the query

# ============================
# Popup Message Support
# ============================
# Loads WPF PresentationFramework to enable graphical popups.
Add-Type -AssemblyName PresentationFramework

# ============================
# Connect to Microsoft Graph
# ============================
# Authenticates the session using the supplied tenant and app ID.
Write-Output "Connecting to Microsoft Graph..."
Connect-MgGraph -TenantId $tenantId -ClientId $appId
Write-Output "Connected to Microsoft Graph."

# ============================
# KQL Query — Last 12 hours
# ============================
# Defines the hunting query submitted to Microsoft Graph Security.
# Filters:
#   - Timestamp window
#   - axios UserAgent
#   - OfficeHome access
#   - CA applied/not applied
#   - Excludes bad password error 50126
$query = @"
EntraIdSignInEvents
| where Timestamp >= ago(12h)
| where UserAgent has 'axios' and ResourceDisplayName has 'OfficeHome'
| where ConditionalAccessStatus != '0' and ErrorCode != '50126'
| project
    Timestamp,
    AccountUpn,
    IPAddress,
    ConditionalAccessStatus,
    ResourceDisplayName
| sort by Timestamp
"@

# ============================
# Track previously seen events
# ============================
# HashSet prevents duplicate alerts and helps separate NEW vs PREVIOUS.
$seenEvents = [System.Collections.Generic.HashSet[string]]::new()

# ============================
# Monitoring Loop
# ============================
Write-Output "Starting monitoring loop (every $intervalSeconds seconds)..."

while ($true) {

    # Clears the console window to maintain a dashboard feel.
    Clear-Host

    # ============================
    # Static Header + Live Clock
    # ============================
    # Displays a fixed banner and live timestamp for visual clarity.
    $currentTime = (Get-Date).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")

    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "              AXIOS SIGN-IN MONITORING DASHBOARD            " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Last Refresh: $currentTime (CST/CDT)" -ForegroundColor Yellow #change the timezone if needed
    Write-Host " Refresh Interval: $intervalSeconds seconds"
    Write-Host "============================================================`n"

    try {
        # Prepares JSON body for Graph API query submission.
        $body = @{ Query = $query } | ConvertTo-Json

        # Executes the hunting query and retrieves rows of results.
        $result = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
            -Body $body

        # Extracts the result set.
        $rows = $result.results

        if ($rows -and $rows.Count -gt 0) {

            # Arrays for separating new vs previously seen events.
            $newRows      = @()
            $previousRows = @()

            foreach ($row in $rows) {

                # Signature uniquely identifies an event instance.
                $sig = "$($row.Timestamp)|$($row.AccountUpn)|$($row.IPAddress)"

                # NEW event
                if (-not $seenEvents.Contains($sig)) {
                    $seenEvents.Add($sig) | Out-Null
                    $newRows += $row
                }
                # PREVIOUS event
                else {
                    $previousRows += $row
                }
            }

            # ============================
            # CLEAN FORMATTER
            # ============================
            # Converts raw API output into consistently formatted objects.
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
                $formattedPrev = $previousRows | ForEach-Object { Format-Clean $_ }
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

                # Popup alert notification for immediate visibility.
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

        }
        else {
            Write-Host "No matching results in the last 12 hours." -ForegroundColor Red
        }

    }
    catch {
        # Centralized error handler for API or formatting issues.
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Wait before refreshing again.
    Start-Sleep -Seconds $intervalSeconds
}
