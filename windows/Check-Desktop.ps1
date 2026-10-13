#Requires -Version 5.1
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
try {
    $config=[Console]::In.ReadToEnd() | ConvertFrom-Json
    if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 1) { throw 'Windows Server requerido.' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $null=Get-ADOrganizationalUnit -Identity $config.ou -Server $config.server -ErrorAction Stop
    @{ok=$true;ad=$true} | ConvertTo-Json -Compress
} catch {
    @{ok=$false;error='Verifica Windows Server, RSAT Active Directory, controlador de dominio, OU y permisos de la cuenta Windows.'} | ConvertTo-Json -Compress
    exit 1
}
