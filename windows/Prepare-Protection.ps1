#Requires -Version 5.1
# Private machine policy; installed code may be read, never modified, by ordinary sessions.
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
function New-DirectoryAcl([bool]$ReadUsers=$false){
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $owner=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');$acl.SetOwner($owner)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){
        $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)
    }
    if($ReadUsers){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))}
    return $acl
}
try{
    $p=[Console]::In.ReadToEnd()|ConvertFrom-Json
    if($p.action -eq 'data'){
        $parent=$env:ProgramData
        foreach($part in @('Metakampo','Access','Protection')){
            $parent=Join-Path $parent $part
            if(-not [IO.Directory]::Exists($parent)){[void][IO.Directory]::CreateDirectory($parent,(New-DirectoryAcl))}
            if([IO.Directory]::Exists($parent)){
                if(([IO.File]::GetAttributes($parent) -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse rejected'}
                $sid=[IO.Directory]::GetAccessControl($parent).GetOwner([Security.Principal.SecurityIdentifier]).Value
                if($sid -notin @('S-1-5-18','S-1-5-32-544')){throw 'Untrusted existing data directory'}
            }
            [IO.Directory]::SetAccessControl($parent,(New-DirectoryAcl))
        }
    } elseif($p.action -eq 'code'){
        $root=[IO.Path]::GetFullPath([string]$p.root)
        foreach($item in @(Get-Item -LiteralPath $root -Force)+@(Get-ChildItem -LiteralPath $root -Recurse -Force)){
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse rejected'}
        }
        [IO.Directory]::SetAccessControl($root,(New-DirectoryAcl $true))
        & "$env:SystemRoot\System32\icacls.exe" (Join-Path $root '*') /reset /T /Q | Out-Null
        if($LASTEXITCODE -ne 0){throw 'Code ACL reset refused'}
        & "$env:SystemRoot\System32\icacls.exe" $root /setowner '*S-1-5-32-544' /T /Q | Out-Null
        if($LASTEXITCODE -ne 0){throw 'Code owner refused'}
        $cache=Join-Path $root '.metakampo-updates'
        if([IO.Directory]::Exists($cache)){
            [IO.Directory]::SetAccessControl($cache,(New-DirectoryAcl))
            if(@(Get-ChildItem -LiteralPath $cache -Force).Count){
                & "$env:SystemRoot\System32\icacls.exe" (Join-Path $cache '*') /reset /T /Q | Out-Null
                if($LASTEXITCODE -ne 0){throw 'Update ACL refused'}
            }
        }
    } else {throw 'Invalid action'}
    @{ok=$true}|ConvertTo-Json -Compress
} catch {
    @{ok=$false;error='No se confirmaron permisos privados de la protección. Revisa propietario, enlaces y permisos de instalación.'}|ConvertTo-Json -Compress
    exit 1
}
