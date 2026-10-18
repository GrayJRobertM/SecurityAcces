# Resolve the configured base without broadening to the domain root.
function Get-MetakampoADBase([string]$Identity,[string]$Server) {
    if ($Identity -notmatch '^(?i:OU|CN)=.+,DC=.+' -or $Identity.Contains(';')) {throw 'Invalid directory base DN'}
    $base=Get-ADObject -Identity $Identity -Server $Server -ErrorAction Stop
    if ($base.ObjectClass -notin @('organizationalUnit','container')) {throw 'Directory base must be an OU or container'}
    return $base
}
