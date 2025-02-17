# Connect to Microsoft 365 Exchange Online
Connect-ExchangeOnline -ShowProgress $true

function Get-AllQuarantineMessages {
    $allMessages = @()
    $page = 1

    do {
        $messages = Get-QuarantineMessage -PageSize 1000 -Page $page
        $allMessages += $messages
        $page++
    } while ($messages.Count -eq 1000)  # Continue fetching until less than 1000 results are returned

    return $allMessages
}

function Display-TopTen {
    $allMessages = Get-AllQuarantineMessages
    $totalCount = $allMessages.Count

    $top10Subjects = $allMessages | Group-Object -Property Subject | Sort-Object Count -Descending | Select-Object -First 10 -Property Count, Name
    $top10SenderAddresses = $allMessages | Group-Object -Property SenderAddress | Sort-Object Count -Descending | Select-Object -First 10 -Property Count, Name


    Write-Output "`nTop 10 Subjects:"
    $top10Subjects | Format-Table -AutoSize
    Write-Output "`nTop 10 Senders:"
    $top10SenderAddresses | Format-Table -AutoSize
    Write-Output "Total Quarantined Messages: $totalCount"`n`n
}
`n`n
`n`n
# Main Loop
$enterScript = $true
while ($enterScript) {
    Clear-Host
    Display-TopTen
    $choice = Read-Host "Press Enter or '0' to refresh"

    if ($choice -eq "0") {
        Display-TopTen
    }
}
