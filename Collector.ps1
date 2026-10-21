$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$issues = [System.Collections.Generic.List[object]]::new()
function Read-Section([string]$Name, [scriptblock]$Body) {
    try { & $Body } catch { $issues.Add([ordered]@{ area = $Name; message = $_.Exception.Message }) }
}
function Read-Events($Filter, [int]$Maximum) {
    try {
        @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Maximum -ErrorAction Stop | ForEach-Object {
            [ordered]@{ timeUtc = $_.TimeCreated.ToUniversalTime().ToString('o'); id = $_.Id; provider = $_.ProviderName; message = $_.Message }
        })
    } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
}
$targetName=$env:WD_TARGET
$system=@{success=$false;addresses=@();error=''}
try { $system.addresses=@([Net.Dns]::GetHostAddresses($targetName)|ForEach-Object{$_.ToString()});$system.success=$system.addresses.Count -gt 0 } catch {$system.error=$_.Exception.Message}
$adapters=@(Read-Section 'dns-configuration' {
    $active=@(Get-NetAdapter -IncludeHidden | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {$_.ifIndex})
    Get-DnsClientServerAddress | Where-Object {$_.InterfaceIndex -in $active -and $_.ServerAddresses.Count -gt 0} | ForEach-Object { @{name=$_.InterfaceAlias;index=$_.InterfaceIndex;servers=@($_.ServerAddresses)} }
})
$hostsEntries=@(Read-Section 'hosts-file' {
    $hostsPath=Join-Path ([Environment]::SystemDirectory) 'drivers\etc\hosts'
    if ((Get-Item -LiteralPath $hostsPath).Length -gt 1048576) {throw 'Hosts file exceeds the 1 MiB read limit.'}
    Get-Content -LiteralPath $hostsPath | ForEach-Object {
        $parts=($_ -split '#',2)[0].Trim() -split '\s+'
        if ($parts.Count -gt 1) { foreach($alias in $parts[1..($parts.Count-1)]) { if($alias.TrimEnd('.') -eq $targetName.TrimEnd('.')) { @{address=$parts[0];name=$alias} } } }
    } | Select-Object -First 100
})
$servers=@($adapters | ForEach-Object {$_.servers} | Sort-Object -Unique)
$queries=@();$skip=$env:WD_SYSTEM_ONLY -eq '1'
if(-not $skip) {
    foreach($dnsServer in ($servers|Select-Object -First 8)) { foreach($recordType in @('A','AAAA')) {
        $query=@{server=$dnsServer;type=$recordType;success=$false;addresses=@();error=''}
        try {$query.addresses=@(Resolve-DnsName -Name $targetName -Server $dnsServer -Type $recordType -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Where-Object {$_.IPAddress} | ForEach-Object {$_.IPAddress});$query.success=$true} catch {$query.error=$_.Exception.Message}
        $queries+=,$query
    } }
}
@{evidence=@{host=$targetName;system=$system;adapters=$adapters;hostsEntries=$hostsEntries;queries=$queries;directQueriesSkipped=$skip;serversCapped=($servers.Count -gt 8 -and -not $skip)};issues=@($issues.ToArray())}|ConvertTo-Json -Depth 10 -Compress
