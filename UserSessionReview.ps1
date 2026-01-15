<#
.SYNOPSIS
    Interactive triage helper for axios-based Entra ID sign-in alerts that displays event context and optionally revokes user sessions.

.DESCRIPTION
    This script is designed to be launched by the axios sign-in monitoring script when NEW matching sign-in activity is detected.
    It receives key event fields (UPN, IP, timestamp, Conditional Access status, and resource) as parameters, prints the event in a
    readable format, and then prompts the analyst to take an immediate containment action: revoking the user’s active sign-in sessions.

    The intent is to reduce time-to-containment during suspected credential theft / token replay activity (e.g., AiTM-style attacks)
    by placing the containment decision directly in the analyst workflow as soon as suspicious activity is surfaced.

    Workflow:
        1) Accepts sign-in event details passed from the monitoring script.
        2) Ensures a Microsoft Graph session is available (connects if needed).
        3) Displays the received sign-in event details in a single formatted view.
        4) Prompts the analyst to revoke sessions for the identified user.
        5) If approved, calls Revoke-MgUserSignInSession for the provided user.
        6) Displays error detail (if any) and pauses before exit for analyst review.

    Notes on session revocation:
        - Revoke-MgUserSignInSession invalidates refresh tokens and forces re-authentication, helping to interrupt active token-based access.
        - This is a containment step and should be paired with follow-on actions per your runbook (account investigation, sign-in review,
          password reset, MFA checks, Conditional Access review, etc.).

.PARAMETER UserPrincipalName
    (Required) The user UPN being evaluated. Used for display and as the target for session revocation.

.PARAMETER IPAddress
    (Optional) Source IP address associated with the sign-in event passed in.

.PARAMETER Timestamp
    (Optional) Local time string passed from the monitoring script (e.g., CST/CDT formatted) for operator readability.

.PARAMETER ConditionalAccessStatus
    (Optional) Conditional Access status value passed from the monitoring script for quick triage context.

.PARAMETER ResourceDisplayName
    (Optional) Resource/app name tied to the event (e.g., OfficeHome).

.NOTES
    Requirements:
        - Microsoft.Graph PowerShell module
        - Permissions sufficient to revoke sign-in sessions in your tenant (commonly User.ReadWrite.All, but org requirements may vary)
        - This script is intended to be executed interactively by an analyst (it uses Read-Host prompts)

    Security considerations:
        - Keep Graph scopes minimal and align to least privilege.
        - Consider logging analyst decisions (revoked vs skipped) if you need auditability outside of console history.
        - If UPN-to-ObjectId resolution is required in your environment, add a lookup step (Get-MgUser) before revocation.
#>



param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$IPAddress,

    [Parameter(Mandatory = $false)]
    [string]$Timestamp,

    [Parameter(Mandatory = $false)]
    [string]$ConditionalAccessStatus,

    [Parameter(Mandatory = $false)]
    [string]$ResourceDisplayName
)

Write-Host "Received event for: $UserPrincipalName" -ForegroundColor Cyan

# Connect to Microsoft Graph if not already connected
if (-not (Get-MgContext)) {
    # Revoke requires at least User.ReadWrite.All or Directory.AccessAsUser.All depending on your org setup.
    # Keep scopes minimal; add others only if your script uses them elsewhere.
    Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome
}

# Display the single sign-in event passed from the axios script
Write-Host "`n=== Axios Sign-in Event ===" -ForegroundColor Cyan

$eventObj = [PSCustomObject]@{
    "User"      = $UserPrincipalName
    "IP"        = $IPAddress
    "Time (CST)"= $Timestamp
    "CAStatus"  = $ConditionalAccessStatus
    "Resource"  = $ResourceDisplayName
}

$eventObj | Format-List

# Ask about revoking sessions
$decision = Read-Host "`nDo you want to revoke sessions for $UserPrincipalName? (y/n)"
if ($decision -eq "y") {
    Write-Host "`n>> [ACTION] Revoking sessions for $UserPrincipalName..." -ForegroundColor Red
    Revoke-MgUserSignInSession -UserId $UserPrincipalName
}
else {
    Write-Host "Skipping session revocation for $UserPrincipalName." -ForegroundColor Gray
}

# Final pause and error output if needed
if ($Error.Count -gt 0) {
    Write-Host "`n--- ERROR ---" -ForegroundColor Red
    $Error[0] | Format-List * -Force
}
Read-Host -Prompt "`nPress Enter to exit"
