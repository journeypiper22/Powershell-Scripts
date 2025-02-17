# Define file paths
$resultsFilePath = "C:\Users\$env:USERNAME\PATH\$(Get-Date -Format 'yyyyMMdd').DeviceInformationDedup.csv"
$patchFilePath = "C:\Users\$env:USERNAME\PATH\Patch & Date Information.csv"
$outputFilePath = "C:\Users\$env:USERNAME\PATH\$((Get-Date).ToString('yyyyMMdd')).NotUpToDateDevicesDedup.csv"
$unmatchedOutputFilePath = "C:\Users\$env:USERNAME\PATH\$((Get-Date).ToString('yyyyMMdd')).UpToDateDevicesDedup.csv"

Write-Output "Loading results and patch data..."

# Load the results from the existing CSV file
if (-Not (Test-Path $resultsFilePath)) {
    Write-Error "Results file not found: $resultsFilePath"
    return
}
$resultsData = Import-Csv -Path $resultsFilePath

# Load the patch data
if (-Not (Test-Path $patchFilePath)) {
    Write-Error "Patch file not found: $patchFilePath"
    return
}
$patchData = Import-Csv -Path $patchFilePath


# Determine the last date in the patch file
$excludedDates = @('') # Add specific dates to exclude as needed
$lastPatchDate = $patchData | Where-Object { 
    $excludedDates -notcontains $_.'OS Patch Release Date' -and $_.'OS Patch Release Date' -ne $null 
} |
    Sort-Object -Property {[datetime]$_.'OS Patch Release Date'} | Select-Object -Last 1 | Select-Object -ExpandProperty 'OS Patch Release Date'

if ($lastPatchDate) {
    Write-Output "The last patch release date added to the file is: $lastPatchDate"
} else {
    Write-Output "No valid patch release dates found in the patch file."
}

# Prompt user to continue or exit
$response = Read-Host "Would you like to continue? (Yes/No)"
if ($response -ne "Yes") {
    Write-Output "Exiting script as per user input."
    return
}


Write-Output "Comparing patch data with results..."

# Compare the data and find matches
$matchedData = @()
$unmatchedData = @()

foreach ($result in $resultsData) {
    $matchedPatch = $patchData | Where-Object {
        $_.'OS Patch Number' -eq $result.'OS Patch Number'
    }

    if ($matchedPatch) {
        $matchedData += [PSCustomObject]@{
            'Device Name'       = $result.'Device Name'
            'OS Platform'       = $result.'OS Platform'
            'OS Version'        = $result.'OS Version'
            'OS Version Info'   = $result.'OS Version Info'
            'OS Build'          = $result.'OS Build'
            'OS Patch Number'   = $result.'OS Patch Number'
            'Patch Release Date' = if ($result.'Patch Release Date') { $result.'Patch Release Date' } else { $matchedPatch.'OS Patch Release Date' }
        }
    } else {
        $unmatchedData += [PSCustomObject]@{
            'Device Name'       = $result.'Device Name'
            'OS Platform'       = $result.'OS Platform'
            'OS Version'        = $result.'OS Version'
            'OS Version Info'   = $result.'OS Version Info'
            'OS Build'          = $result.'OS Build'
            'OS Patch Number'   = $result.'OS Patch Number'
            'Patch Release Date' = if ($result.'Patch Release Date') { $result.'Patch Release Date' } else { $null }
        }
    }
}

if ($matchedData) {
    Write-Output "Saving matched data to new file: $outputFilePath"

    # Save matched data to a new CSV file
    $matchedData | Export-Csv -Path $outputFilePath -NoTypeInformation

    Write-Output "Matched data saved successfully to $outputFilePath"
} else {
    Write-Output "No matching patches found."
}

if ($unmatchedData) {
    Write-Output "Saving unmatched data to new file: $unmatchedOutputFilePath"

    # Save unmatched data to a new CSV file
    $unmatchedData | Export-Csv -Path $unmatchedOutputFilePath -NoTypeInformation

    Write-Output "Unmatched data saved successfully to $unmatchedOutputFilePath"
} else {
    Write-Output "All patches matched; no unmatched data to save."
}

Write-Output "Script execution completed."
