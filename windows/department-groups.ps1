# Shared naming contract; never adopt an existing unmarked Windows/AD group.
function Department-Spec([string]$department) {
    $department=$department.Trim()
    if (-not $department) {return $null}
    if ($department.Length -gt 256 -or $department -match '[\x00-\x1f]') {throw 'Invalid department'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($department)))).Replace('-','').ToLowerInvariant().Substring(0,8)} finally {$sha.Dispose()}
    $slug=[regex]::Replace($department,'[^A-Za-z0-9]','').ToUpperInvariant()
    if (-not $slug) {$slug='DEP'}
    $slug=$slug.Substring(0,[Math]::Min(7,$slug.Length))
    return @{Name=('MKD-'+$slug+'-'+$hash);Description=('Metakampo Department v1: '+$department);Department=$department}
}
function Department-Group([string]$department,[bool]$create=$true) {
    $spec=Department-Spec $department
    if (-not $spec) {return $null}
    if ($request.server) {
        $groups=@(Get-ADGroup -Filter "SamAccountName -eq '$($spec.Name)'" -Properties Description,adminCount,member @common)
        $group=$groups | Select-Object -First 1
        if ($group -and ($group.Description -cne $spec.Description -or $group.adminCount -eq 1 -or -not $group.DistinguishedName.EndsWith(','+$base.DistinguishedName,[StringComparison]::OrdinalIgnoreCase))) {throw 'Department group conflict or outside scope'}
        if (-not $group -and $create) {$group=New-ADGroup -Name $spec.Name -SamAccountName $spec.Name -DisplayName $spec.Department -Description $spec.Description -GroupCategory Security -GroupScope Global -Path $base.DistinguishedName -PassThru @common}
    } else {
        $group=Get-LocalGroup -Name $spec.Name -ErrorAction SilentlyContinue
        if ($group -and $group.Description -cne $spec.Description) {throw 'Department group conflict'}
        if (-not $group -and $create) {$group=New-LocalGroup -Name $spec.Name -Description $spec.Description -ErrorAction Stop}
    }
    return $group
}
function Set-DepartmentMembership($user,[string]$previous,[string]$department) {
    $target=Department-Group $department
    if ($target) {
        if ($request.server) {
            $target=Get-ADGroup -Identity $target -Properties member @common
            if (@($target.member) -notcontains $user.DistinguishedName) {Add-ADGroupMember -Identity $target -Members $user @common}
        } elseif (@([MetakampoLocalSam]::MemberSids($target.Name)) -notcontains $user.SID.Value) {Add-LocalGroupMember -SID $target.SID -Member $user -ErrorAction Stop}
    }
    if ($previous -and $previous -cne $department) {
        $old=Department-Group $previous $false
        if ($old) {
            if ($request.server) {
                if (@($old.member) -contains $user.DistinguishedName) {Remove-ADGroupMember -Identity $old -Members $user -Confirm:$false @common}
            } elseif (@([MetakampoLocalSam]::MemberSids($old.Name)) -contains $user.SID.Value) {Remove-LocalGroupMember -SID $old.SID -Member $user -ErrorAction Stop}
        }
    }
    if ($target) {return [string]$target.Name}
    return ''
}
