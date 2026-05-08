param(
    [Parameter(Mandatory=$true)]
    [string]$ComputersCsv
)

# Import the lookup table
$companyLookup = @{}
Import-Csv -Path "Companies.csv" | ForEach-Object {
    $companyLookup[$_.Company] = $_.Tag
}

$deviceLookup = @{}

# Import the original CSV and enrich it
$results = Import-Csv -Path $ComputersCsv | ForEach-Object {
    $device = $_
    $division = "OIT"  # Default value
    if ($device.Type -in @("Desktops","Keyboards","Laptops","Laptops (by adapter)","Personal Computers","Printers","Projectors","Workstations", "Tablets")) {
        if ($device.'Data Sources' -and "Microsoft Intune" -in $device.'Data Sources'.split(", ")) { # don't include personal machines from guest wifi in reports to team
            $device.Boundaries = "Desktop Team"
            if($deviceLookup.ContainsKey($device.Name)) {
                $division = $deviceLookup[$device.Name]
            }
            else {
                try {
                    # Get the computer's ManagedBy property
                    $computerName = $device.Name.Split('.')[0]
                    $managedByDN = (Get-ADComputer -Identity $computerName -Property ManagedBy).ManagedBy

                    if ($managedByDN) {
                        # Get the Company from the ManagedBy user
                        $company = (Get-ADUser -Identity $managedByDN -Property Company).Company
                        if ($company -and $companyLookup.ContainsKey($company)) {
                            $division = $companyLookup[$company]
                        }
                    }
                }
                catch {
                    Write-Warning "Could not process computer: $($device.Name) - $($_.Exception.Message)"
                    $division = "None"
                } finally {
                    $deviceLookup[$device.Name] = $division
                }
            }
        } else {
            $device.Boundaries = $device.Boundaries.replace("Desktop Team", "")
            $division = "None"
            $deviceLookup[$device.Name] = $division
        }
    } elseif(($device.Type -in @("Servers","Storage Server","Virtual Machines","Hypervisor") -or $device.Brand -eq "F5 Networks")) {
        $hostname = $device.Name.Split('.')[0].toLower()
        if (-not ($hostname -in @("dfsrmdvintp01","dfsrmdvintp02","dfsrmdvintp03","dfsrmdvintp04","dfsrmdvintp05","dfsrmdvintt01","dfsrmdvintt02","dfsrmdvintt03","dfsrmdvintt04","dfsrmdvintt05","dfssblsintp1","dfsscavextp01"))) {
            $device.Boundaries = "Infrastructure Team"
            if ($hostname -like "rl*" -and (-not ($hostname -in @("rlqappvintd01","rlqappvextt01","rlqappvextt02","rlqappvextp01","rlqappvextp02","dfstmpvintd01","rlxenvintp01")))) {
                $division = "RL"
            }
        }
    } elseif ($device.Category -eq "Handhelds" -and $device.'Data Sources' -and "Microsoft Intune" -in $device.'Data Sources'.split(", ")) {
        $device.Boundaries = "Mobile Devices Team"
    } else {
        $device.Boundaries = "Network Team"
    }
    $report = ""
    if ($device.Boundaries -eq "Desktop Team") {
        if      ($division -eq "OIT") { $report = "OIT Desktop" }
        elseif  ($division -eq "CID") { $report = "CID Desktop" }
        elseif  ($division -eq "RL")  { $report = "RL Desktop"  }
    } elseif ($device.Boundaries -eq "Infrastructure Team") {
        if      ($division -eq "OIT") { $report = "OIT Infrastructure" }
        elseif  ($division -eq "RL")  { $report = "RL Infrastructure"  }
    } elseif ($device.Boundaries -eq "Mobile Devices Team") {
        $report = "OIT Mobile Devices"
    } elseif ($device.Boundaries -eq "Network Team") {
        $report = "OIT Network"
    }
    $device |
        Add-Member -NotePropertyName "Division" -NotePropertyValue $division -PassThru |
        Add-Member -NotePropertyName "Report"   -NotePropertyValue $report   -PassThru
}

# Export the enriched CSV
$dir = [System.IO.Path]::GetDirectoryName($ComputersCsv)
$name = [System.IO.Path]::GetFileNameWithoutExtension($ComputersCsv) + "_Enriched.csv"
$outputPath = if ($dir) { Join-Path $dir $name } else { $name }
# Strip embedded newlines from all fields before export
$results | ForEach-Object {
    foreach ($prop in $_.PSObject.Properties) {
        if ($prop.Value -is [string]) {
            $prop.Value = $prop.Value -replace '\r?\n', ' '
        }
    }
    $_
} | Export-Csv -Path $outputPath -NoTypeInformation

Write-Host "Output saved to: $outputPath"