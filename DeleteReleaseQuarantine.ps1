if (Get-Command Get-QuarantineMessage -ErrorAction SilentlyContinue) {
    Write-Host "Connected to Exchange Online Powershell."
} else {
    Connect-ExchangeOnline
}
$continue = $true

do {
    Clear-Host
    $SenderFilter = ""
    $SubjectFilter = ""
    $SelectedMessages = ""
    $SelectedMessagesCount = ""
    $PageNumber = 1
    Write-Host "`n`n
    =========================================
               QUARANTINE SEARCH 
    =========================================`n`n"
    Write-Host "Actions:`n"
    Write-Host "  1.) Delete Quarantine Messages`n"
    Write-Host "  2.) Release Quarantine Messages`n`n"
    $option = Read-Host "Select an option (1 or 2)"
    
    if ($option -eq "1") {
        Clear-Host
        Write-Host "`n`n
    =========================================
            Delete Quarantine Messages
    =========================================`n`n"
        $SenderFilter = Read-Host "   Input Sender Email Address"
        $SubjectFilter = Read-Host "`n   Input Email Subject"

        do {
            if (($SenderFilter -ne "") -and ($SubjectFilter -ne "")) {
                Write-Host "`n----------------------------`nSearching by Sender and Subject on page $PageNumber......`n----------------------------`n"
                $SelectedMessages = Get-QuarantineMessage -SenderAddress $SenderFilter -Subject $SubjectFilter -PageSize 1000 -Page $PageNumber
                $SelectedMessagesCount = ($SelectedMessages | Measure-Object).Count
                Write-Host "The search returned $SelectedMessagesCount results on page $PageNumber."

            } elseif (($SenderFilter -ne "") -and ($SubjectFilter -eq "")) {
                Write-Host "`n----------------------------`nSearching by Sender on page $PageNumber.....`n----------------------------`n"
                $SelectedMessages = Get-QuarantineMessage -SenderAddress $SenderFilter -PageSize 1000 -Page $PageNumber
                $SelectedMessagesCount = ($SelectedMessages | Measure-Object).Count
                Write-Host "The search returned $SelectedMessagesCount results on page $PageNumber.`n"

            } elseif (($SenderFilter -eq "") -and ($SubjectFilter -ne "")) {
                Write-Host "`n----------------------------`nSearching by Subject on page $PageNumber.....`n----------------------------`n"
                $SelectedMessages = Get-QuarantineMessage -Subject $SubjectFilter -PageSize 1000 -Page $PageNumber
                $SelectedMessagesCount = ($SelectedMessages | Measure-Object).Count
                Write-Host "The search returned $SelectedMessagesCount results on page $PageNumber.`n"
            } else {
                Write-Host "`n`n   ***************************`n   Error: No filters provided.`n   ***************************`n" -ForegroundColor red
                break
            }

            if ($SelectedMessagesCount -gt 0) {
                $deleteConfirmation = Read-Host "Are you sure you want to delete these messages? (Y/N)"

                if ($deleteConfirmation -eq "Y" -or $deleteConfirmation -eq "y") {
                    $SelectedMessages | Delete-QuarantineMessage -Confirm:$false
                    Write-Host "`nDeletion completed for page $PageNumber.`n" -ForegroundColor darkgreen
                } else {
                    Write-Host "`nDeletion aborted for page $PageNumber.`n" -ForegroundColor red
                }
            }
            
            $PageNumber++
        } while ($SelectedMessagesCount -gt 0)

    } elseif ($option -eq "2") {
        Clear-Host
        Write-Host "`n`n
    =========================================
           RELEASE QUARANTINE MESSAGES
    =========================================`n`n"
        $SenderFilter = Read-Host "   Input Sender Email Address"
        $SubjectFilter = Read-Host "`n   Input Email Subject"

        do {
            if (($SenderFilter -ne "") -and ($SubjectFilter -ne "")) {
                Write-Host "`n----------------------------`nSearching by Sender and Subject on page $PageNumber......`n----------------------------`n"
                $SelectedMessages = Get-QuarantineMessage -SenderAddress $SenderFilter -Subject $SubjectFilter -PageSize 1000 -Page $PageNumber
                $SelectedMessagesCount = ($SelectedMessages | Measure-Object).Count
                Write-Host "The search returned $SelectedMessagesCount results on page $PageNumber."

            } elseif (($SenderFilter -ne "") -and ($SubjectFilter -eq "")) {
                Write-Host "`n----------------------------`nSearching by Sender on page $PageNumber.....`n----------------------------`n"
                $SelectedMessages = Get-QuarantineMessage -SenderAddress $SenderFilter -PageSize 1000 -Page $PageNumber
                $SelectedMessagesCount = ($SelectedMessages | Measure-Object).Count
                Write-Host "The search returned $SelectedMessagesCount results on page $PageNumber.`n"

            } elseif (($SenderFilter -eq "") -and ($SubjectFilter -ne "")) {
                Write-Host "`n----------------------------`nSearching by Subject on page $PageNumber.....`n----------------------------`n"
                $SelectedMessages = Get-QuarantineMessage -Subject $SubjectFilter -PageSize 1000 -Page $PageNumber
                $SelectedMessagesCount = ($SelectedMessages | Measure-Object).Count
                Write-Host "The search returned $SelectedMessagesCount results on page $PageNumber.`n"
            } else {
                Write-Host "`n`n   ***************************`n   Error: No filters provided.`n   ***************************`n" -ForegroundColor red
                break
            }

            if ($SelectedMessagesCount -gt 0) {
                $releaseConfirmation = Read-Host "Are you sure you want to release these messages from quarantine? (Y/N)"

                if ($releaseConfirmation -eq "Y" -or $releaseConfirmation -eq "y") {
                    $SelectedMessages | Release-QuarantineMessage -ReleaseToAll -Confirm:$false
                    $SelectedMessages | Delete-QuarantineMessage -Confirm:$false
                    Write-Host "`nRelease and Deletion completed for page $PageNumber.`n" -ForegroundColor darkgreen
                } else {
                    Write-Host "`nRelease and Deletion aborted for page $PageNumber.`n" -ForegroundColor red
                }
            }

            $PageNumber++
        } while ($SelectedMessagesCount -gt 0)

    } else {
        Write-Host "`n`n   ***************************`n   Invalid option selected.`n   ***************************`n" -ForegroundColor red
    }

    $continueResponse = Read-Host "     Do you want to continue? (Y/N)"
    if ($continueResponse -ne "Y") {
        $continue = $false
    }
} while ($continue)
