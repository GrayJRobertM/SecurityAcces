#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [switch]$Continuous,
    [int]$IntervalSeconds=60
)
$ErrorActionPreference='Stop'
if ($IntervalSeconds -lt 15) { throw 'El intervalo mínimo es 15 segundos.' }
$config=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if (([Uri]$config.portal).Scheme -ne 'https') { throw 'El recolector requiere HTTPS con certificado válido.' }
$base=Split-Path -Parent (Resolve-Path $ConfigPath)
$stateFile=Join-Path $base 'collector-state.json'
$tokenFile=Join-Path $base 'collector-token.dpapi'
$tokenSecure=(Get-Content -LiteralPath $tokenFile -Raw).Trim() | ConvertTo-SecureString
$pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenSecure)
$token=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
$tokenSecure.Dispose()
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
function Save-State($state) {
    $temp=$stateFile+'.tmp'
    $state | ConvertTo-Json -Compress | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $stateFile -Force
}
function Read-LatestClear {
    try { return (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102 } -MaxEvents 1 -ErrorAction Stop).TimeCreated.ToUniversalTime().ToString('o') }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return '' }; throw }
}
function Send-Batch($epoch,$events,$gap) {
    $body=@{ epoch=$epoch; events=@($events); gap_reason=$gap } | ConvertTo-Json -Depth 6 -Compress
    $reply=Invoke-RestMethod -Uri ($config.portal.TrimEnd('/')+'/api/telemetry/events') -Method Post -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -Headers @{ Authorization=('Bearer '+$token) } -MaximumRedirection 0 -TimeoutSec 45
    if ($reply.server -ne $config.server.ToLowerInvariant() -or [int]$reply.received -ne @($events).Count) { throw 'Confirmación de lote incompatible. No se avanza el cursor.' }
}
# Prevent overlapping invocations from advancing the same checkpoint independently.
$lock=$null
try {
    $lock=[IO.File]::Open((Join-Path $base 'collector.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    do {
        $hasBacklog=$false
        try {
            $latest=Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
            $oldest=(Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop).RecordId
            $clear=Read-LatestClear
            $gap=''
            if (Test-Path $stateFile) { $state=Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json }
            else { $state=@{ epoch=[Guid]::NewGuid().ToString(); last_record=0; last_clear=$clear; pending_gap='' }; Save-State $state }
            if ([long]$state.last_record -gt [long]$latest.RecordId -or $state.last_clear -ne $clear) {
                $state=@{ epoch=[Guid]::NewGuid().ToString(); last_record=0; last_clear=$clear; pending_gap='log_cleared' }
                Save-State $state # Persist new generation before network I/O: retries stay idempotent.
            }
            $gap=[string]$state.pending_gap
            if ([long]$state.last_record -gt 0 -and [long]$oldest -gt ([long]$state.last_record+1)) { $gap='checkpoint_evicted' }
            $cutoff=[DateTime]::UtcNow.AddHours(-24).ToString('o')
            $start=[long]$state.last_record
            $upper=[long]$latest.RecordId
            $eventFilter="((System[(EventID=4624 or EventID=4634)] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']) or System[(EventID=4625 or EventID=4778 or EventID=4779)])"
            $timeFilter=if ($start -eq 0) { " and TimeCreated[@SystemTime >= '$cutoff']" } else { '' }
            $xpath="*[System[EventRecordID > $start and EventRecordID <= $upper$timeFilter] and $eventFilter]"
            try { $items=@(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 100 -ErrorAction Stop) }
            catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $items=@() } else { throw } }
            $batch=@()
            foreach ($event in $items) {
                [xml]$xml=$event.ToXml()
                $fields=@{}
                foreach ($entry in $xml.Event.EventData.Data) { $fields[[string]$entry.Name]=[string]$entry.'#text' }
                $type=if ($fields.LogonType) { [int]$fields.LogonType } else { 0 }
                # Successful network/service logons do not represent human interactive usage.
                if ($event.Id -in 4624,4634 -and $type -notin 2,7,10,11) { continue }
                $username=if ($fields.TargetUserName) { $fields.TargetUserName } else { $fields.AccountName }
                $domain=if ($fields.TargetDomainName) { $fields.TargetDomainName } else { $fields.AccountDomain }
                $logon=if ($fields.TargetLogonId) { $fields.TargetLogonId } else { $fields.LogonID }
                $ip=if ($fields.IpAddress) { $fields.IpAddress } else { $fields.ClientAddress }
                $batch+=@{ record_id=[long]$event.RecordId; event_id=[int]$event.Id; at=$event.TimeCreated.ToUniversalTime().ToString('o'); username=[string]$username; domain=[string]$domain; ip=[string]$ip; logon_type=$type; logon_id=[string]$logon; session_name=[string]$fields.SessionName; status=[string]$fields.Status; substatus=[string]$fields.SubStatus }
            }
            if ((Read-LatestClear) -ne $clear) { throw 'El registro cambió durante la lectura; reintentar antes de entregar.' }
            Send-Batch $state.epoch $batch $gap
            $last=if ($items.Count -eq 100) { [long]$items[-1].RecordId } else { $upper }
            $state=@{ epoch=$state.epoch; last_record=$last; last_clear=$clear; pending_gap='' }
            Save-State $state # A failed POST/ack never advances the cursor.
            $hasBacklog=$items.Count -eq 100
            Write-Host ('Recolector: '+$batch.Count+' eventos procesados; cursor '+$last+'.')
        } catch {
            # Do not print request bodies, authorization headers, tokens or full exception objects.
            Write-Warning 'No se completó la lectura o entrega. Revisa permisos, HTTPS y registro del recolector; se conserva el cursor para reintentar.'
            if (-not $Continuous) { exit 1 }
        }
        if ($Continuous) { if ($hasBacklog) { Start-Sleep -Seconds 1 } else { Start-Sleep -Seconds $IntervalSeconds } }
    } while ($Continuous)
} finally {
    $token=$null
    if ($lock) { $lock.Dispose() }
}
