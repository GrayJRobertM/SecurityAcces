#Requires -Version 5.1
# Own exact-IP rules only. Token is read locally and never returned/logged.
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
try {
    $p=[Console]::In.ReadToEnd() | ConvertFrom-Json
    if($p.action -in @('monitor','alert')) {
        $root=Join-Path $env:ProgramData 'FreshkampoTelegramMonitor'
        $config=Get-Content -LiteralPath (Join-Path $root 'config.json') -Raw | ConvertFrom-Json
        $tokenPath=Join-Path $root 'token.dpapi'
        if(-not (Test-Path -LiteralPath $tokenPath) -or [string]$config.ChatId -notmatch '^-?[0-9]{1,20}$') { throw 'Monitor incompleto.' }
        Add-Type -AssemblyName System.Security
        $bytes=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($tokenPath),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
        try {$token=[Text.Encoding]::UTF8.GetString($bytes)} finally {[Array]::Clear($bytes,0,$bytes.Length)}
        if($token -notmatch '^[0-9]+:[A-Za-z0-9_-]+$'){throw 'Token inválido.'}
        if($p.action -eq 'monitor') {
            @{ok=$true;available=$true;message='Monitor existente y token protegido disponibles. No se ha enviado mensaje de prueba.'} | ConvertTo-Json -Compress
            exit 0
        }
        $ip=[Net.IPAddress]::Parse([string]$p.ip).ToString()
        $id=[Guid]::ParseExact([string]$p.event_id,'N').ToString('N')
        $at=[DateTimeOffset]::FromUnixTimeSeconds([long]$p.at).UtcDateTime.ToString('u')
        $expires=[DateTimeOffset]::FromUnixTimeSeconds([long]$p.expires).UtcDateTime.ToString('u')
        $count=[int]$p.failures
        if($count -lt 0 -or $count -gt 100000000){throw 'Conteo inválido.'}
        $text="METAKAMPO | IP BLOQUEADA`nServidor: $env:COMPUTERNAME`nIP: $ip`nIntentos fallidos: $count`nBloqueada desde (UTC): $at`nVence (UTC): $expires`nRegla: entrada de todos los protocolos`nReferencia: $id"
        $body=@{chat_id=[string]$config.ChatId;text=$text;protect_content=$true}
        if($config.TemaId){$body.message_thread_id=[long]$config.TemaId}
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        # Sending only: never getUpdates, so existing restart/command receiver keeps its offset.
        $r=Invoke-RestMethod -Uri ('https://api.telegram.org/bot{0}/sendMessage' -f $token) -Method Post -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Compress))) -TimeoutSec 12 -MaximumRedirection 0
        if(-not $r.ok){throw 'Telegram sin confirmar.'}
        $token=$null
        @{ok=$true} | ConvertTo-Json -Compress
        exit 0
    }
    Import-Module NetSecurity -ErrorAction Stop
    if($p.action -eq 'list') {
        if([string]$p.instance -notmatch '^[a-f0-9]{32}$'){throw 'Instancia inválida.'}
        $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name ('Metakampo-IP-'+$p.instance+'-*') -ErrorAction SilentlyContinue)
        $items=@()
        foreach($r in $rules){
            if($r.Group -ne 'Metakampo Access - IP Protection v1'){continue}
            $f=@($r | Get-NetFirewallAddressFilter)
            $items+=@{rule=[string]$r.Name;ip=[string]@($f[0].RemoteAddress)[0];enabled=([string]$r.Enabled -eq 'True');block=([string]$r.Action -eq 'Block');inbound=([string]$r.Direction -eq 'Inbound')}
        }
        @{ok=$true;rules=@($items)} | ConvertTo-Json -Depth 4 -Compress
        exit 0
    }
    if($p.action -notin @('add','remove')){throw 'Acción inválida.'}
    $name=[string]$p.rule
    if($name -notmatch '^Metakampo-IP-[a-f0-9]{32}-[a-f0-9]{32}$'){throw 'Regla ajena.'}
    $ip=[Net.IPAddress]::Parse([string]$p.ip).ToString()
    if($ip -ne [string]$p.ip){throw 'IP no canónica.'}
    $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
    foreach($r in $rules){
        if($r.Group -ne 'Metakampo Access - IP Protection v1'){throw 'Conflicto de regla.'}
        $addresses=@(($r|Get-NetFirewallAddressFilter).RemoteAddress)
        if($addresses.Count -ne 1 -or [Net.IPAddress]::Parse([string]$addresses[0]).ToString() -ne $ip){throw 'Dirección de regla inesperada.'}
    }
    if($p.action -eq 'remove') {
        foreach($r in $rules){$r|Remove-NetFirewallRule -ErrorAction Stop}
        if(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue){throw 'Retirada sin confirmar.'}
    } else {
        if($rules.Count -eq 0){
            $null=New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName ('Metakampo - Bloquear '+$ip) -Group 'Metakampo Access - IP Protection v1' -Direction Inbound -Action Block -RemoteAddress $ip -Protocol Any -Profile Any -Enabled True
        } else {
            foreach($r in $rules){$r|Set-NetFirewallRule -Direction Inbound -Action Block -Protocol Any -Profile Any -Enabled True}
        }
        # Do not claim enforcement when firewall profiles or local rule merging are disabled.
        foreach($profile in @(Get-NetFirewallProfile -PolicyStore ActiveStore)) {
            if([string]$profile.Enabled -eq 'False' -or [string]$profile.AllowLocalFirewallRules -eq 'False'){throw 'Perfil o política no aplica reglas locales.'}
        }
        $active=Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop
        if([string]$active.Enabled -ne 'True' -or [string]$active.Action -ne 'Block' -or [string]$active.Direction -ne 'Inbound'){throw 'Regla activa sin confirmar.'}
    }
    @{ok=$true} | ConvertTo-Json -Compress
} catch {
    # HTTP/DPAPI errors can contain secrets; never return exception contents.
    @{ok=$false;error='No se confirmó la operación. Revisa permisos, Firewall de Windows/políticas o monitor Telegram existente según la acción.'} | ConvertTo-Json -Compress
    exit 1
}
