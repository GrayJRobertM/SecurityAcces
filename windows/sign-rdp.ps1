# JSON stdin contains only paths and public certificate identifiers, never credentials.
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
function Find-Certificate($hash, $store) {
    foreach ($cert in Get-ChildItem "Cert:\$store\My") {
        $digest = [Security.Cryptography.SHA256]::Create()
        try { $sha256 = ([BitConverter]::ToString($digest.ComputeHash($cert.RawData))).Replace('-','') }
        finally { $digest.Dispose() }
        if ($cert.Thumbprint -eq $hash -or $sha256 -eq $hash) {
            if (-not $cert.HasPrivateKey -or $cert.NotBefore -gt (Get-Date) -or $cert.NotAfter -le (Get-Date)) { throw 'Certificate unavailable' }
            return @{ Cert=$cert; SHA256=$sha256 }
        }
    }
    throw 'Certificate not found'
}
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    if ($request.store -notin 'CurrentUser','LocalMachine') { throw 'Invalid store' }
    $rdp = Find-Certificate $request.rdpHash $request.store
    $script = Find-Certificate $request.scriptHash $request.store
    $usage = @($script.Cert.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } | ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
    if ($usage -notcontains '1.3.6.1.5.5.7.3.3') { throw 'Code signing EKU required' }
    $profile = Join-Path $request.folder 'Conexion.rdp'
    if ($request.step -eq 'rdp') {
        $tool = Join-Path $env:SystemRoot 'System32\rdpsign.exe'
        if (Test-Path (Join-Path $env:SystemRoot 'Sysnative\rdpsign.exe')) { $tool = Join-Path $env:SystemRoot 'Sysnative\rdpsign.exe' }
        & $tool /sha256 $request.rdpHash $profile *> $null
        if ($LASTEXITCODE -ne 0) { throw 'RDP signing failed' }
    } elseif ($request.step -eq 'script') {
        $arguments = @{ FilePath=(Join-Path $request.folder 'Conectar.ps1'); Certificate=$script.Cert; HashAlgorithm='SHA256' }
        if ($request.timestamp) {
            $uri = [Uri]$request.timestamp
            if ($uri.Scheme -ne 'https') { throw 'HTTPS timestamp required' }
            $arguments.TimestampServer = $request.timestamp
        }
        $signature = Set-AuthenticodeSignature @arguments
        if ($signature.Status -ne 'Valid') { throw 'Script signature invalid' }
    } else { throw 'Unsupported operation' }
    @{ ok=$true; scriptSignerSha256=$script.SHA256 } | ConvertTo-Json -Compress
} catch {
    @{ ok=$false; error='RDP_SIGNING_FAILED' } | ConvertTo-Json -Compress
    exit 1
}
