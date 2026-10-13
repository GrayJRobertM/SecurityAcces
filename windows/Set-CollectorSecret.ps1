#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path $Directory -Force | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $Directory -AclObject $acl
$secure=Read-Host 'Token del recolector generado por Freshkampo Access' -AsSecureString
try { $secure | ConvertFrom-SecureString | Set-Content -LiteralPath (Join-Path $Directory 'collector-token.dpapi') -Encoding UTF8 }
finally { $secure.Dispose() }
Write-Host 'Token protegido con DPAPI del usuario Windows actual. Ejecuta el recolector bajo esta misma identidad.'
