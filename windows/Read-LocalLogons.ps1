#Requires -Version 5.1
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
function Read-Clear {
    try { return (Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 1 -ErrorAction Stop).TimeCreated.ToUniversalTime().ToString('o') }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return '' }; throw }
}
try {
    $state=[Console]::In.ReadToEnd() | ConvertFrom-Json
    $latest=Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    $oldest=(Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop).RecordId
    $clear=Read-Clear
    $start=[long]$state.last_record
    $epoch=[string]$state.epoch
    $gap=''
    if ($start -gt [long]$latest.RecordId -or ($null -ne $state.last_clear -and $state.last_clear -ne $clear)) {
        $start=0; $epoch=[Guid]::NewGuid().ToString(); $gap='log_cleared'
    }
    if ($start -gt 0 -and $oldest -gt ($start+1)) { $gap='checkpoint_evicted' }
    $upper=[long]$latest.RecordId
    $cutoff=[DateTime]::UtcNow.AddDays(-90).ToString('o')
    $filter="((System[(EventID=4624 or EventID=4634)] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']) or System[(EventID=4625 or EventID=4778 or EventID=4779)])"
    $xpath="*[System[EventRecordID > $start and EventRecordID <= $upper and TimeCreated[@SystemTime >= '$cutoff']] and $filter]"
    try { $items=@(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 500 -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $items=@() } else { throw } }
    $events=@()
    foreach ($event in $items) {
        [xml]$xml=$event.ToXml(); $fields=@{}
        foreach ($entry in $xml.Event.EventData.Data) { $fields[[string]$entry.Name]=[string]$entry.'#text' }
        $type=if ($fields.LogonType) {[int]$fields.LogonType} else {0}
        $username=if ($fields.TargetUserName) {$fields.TargetUserName} else {$fields.AccountName}
        $domain=if ($fields.TargetDomainName) {$fields.TargetDomainName} else {$fields.AccountDomain}
        $logon=if ($fields.TargetLogonId) {$fields.TargetLogonId} else {$fields.LogonID}
        $ip=if ($fields.IpAddress) {$fields.IpAddress} else {$fields.ClientAddress}
        $events+=@{record_id=[long]$event.RecordId;event_id=[int]$event.Id;at=$event.TimeCreated.ToUniversalTime().ToString('o');username=[string]$username;domain=[string]$domain;ip=[string]$ip;logon_type=$type;logon_id=[string]$logon;session_name=[string]$fields.SessionName;status=[string]$fields.Status;substatus=[string]$fields.SubStatus}
    }
    if ((Read-Clear) -ne $clear) { throw 'El registro cambió durante la lectura.' }
    $cursor=if ($items.Count -eq 500) {[long]$items[-1].RecordId} else {$upper}
    @{ok=$true;epoch=$epoch;events=@($events);last_record=$cursor;last_clear=$clear;gap=$gap;backlog=($items.Count -eq 500)} | ConvertTo-Json -Depth 6 -Compress
} catch {
    @{ok=$false;error='No se pudo leer el registro Security local. Revisa permisos y política de auditoría.'} | ConvertTo-Json -Compress
    exit 1
}
