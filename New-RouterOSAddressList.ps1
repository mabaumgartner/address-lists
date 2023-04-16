# Download threat intel sources
$drop = (Invoke-WebRequest -Uri 'https://www.spamhaus.org/drop/drop.txt'-UseBasicParsing ).Content
$drop = $drop.Split("`n")
$edrop = (Invoke-WebRequest -Uri 'https://www.spamhaus.org/drop/edrop.txt' -UseBasicParsing ).Content
$edrop = $edrop.Split("`n")
$spamhaus = $drop + $edrop | Where-Object {$_}
$feodotracker = (Invoke-WebRequest -Uri 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json' -UseBasicParsing).Content | ConvertFrom-Json
$EtOpen_Blocklist = (Invoke-WebRequest -Uri 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt' -UseBasicParsing ).Content
$EtOpen_Blocklist = $EtOpen_Blocklist.Split("`n")
$EtOpen_Blocklist = $EtOpen_Blocklist | Where-Object {$_}

# Normalize Spamhaus Ipv4 Indicators
$Spamhaus_BlockList = @()
foreach ($r in $spamhaus) {
    if ($r[0] -eq ';') {
        # ignore comments
    }
    elseif ($r -eq "") {
        # ignore blank lines
    }
    else {
        $lineSplit = $r.Split(" ; ")
        $Spamhaus_BlockList += $lineSplit[0].Trim()
    }
}

# Select AbuseCH Ipv4 Indicators
$AbuseCh_BlockList = @()
foreach ($r in $feodotracker) {
    $AbuseCh_BlockList += $r.ip_address
}

# Remove any duplicate values
$Spamhaus_BlockList = $Spamhaus_BlockList | Select-Object -Unique
$AbuseCh_BlockList = $AbuseCh_BlockList | Select-Object -Unique
$EtOpen_Blocklist = $EtOpen_Blocklist | Select-Object -Unique

# Generate RouterOS Script to generate the address list
$outfile = '.\RouterOS\blocklist.rsc'
$date = Get-Date -Format FileDateTimeUniversal
Write-Output "# Generated on $($date)" | Out-File -FilePath $outfile
Write-Output '/ip firewall address-list remove [/ip firewall address-list find list="spamhaus"]' | Out-File -FilePath $outfile -Append
Write-Output '/ip firewall address-list remove [/ip firewall address-list find list="abusech"]' | Out-File -FilePath $outfile -Append
Write-Output '/ip firewall address-list remove [/ip firewall address-list find list="etopen"]' | Out-File -FilePath $outfile -Append
Write-Output ":delay 2000ms" | Out-File -FilePath $outfile -Append
Write-Output "/ip firewall address-list" | Out-File -FilePath $outfile -Append

foreach ($network in $Spamhaus_BlockList) {
    Write-Output "add list=spamhaus address=$($network)" | Out-File -FilePath $outfile -Append
}
foreach ($network in $AbuseCh_BlockList) {
    Write-Output "add list=abusech address=$($network)" | Out-File -FilePath $outfile -Append
}
foreach ($network in $EtOpen_Blocklist) {
    Write-Output "add list=etopen address=$($network)" | Out-File -FilePath $outfile -Append
}
