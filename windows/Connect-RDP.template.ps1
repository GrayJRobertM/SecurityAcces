#Requires -Version 5.1
# This template is populated and signed by Freshkampo Access before distribution.
$ErrorActionPreference = 'Stop'
$config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG_BASE64__')) | ConvertFrom-Json
if (-not $PSCommandPath) { throw 'Ejecuta el archivo firmado desde Windows PowerShell.' }
$signature = Get-AuthenticodeSignature -FilePath $PSCommandPath
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw 'La firma del lanzador no es válida o su editor no es de confianza.' }
$digest = [Security.Cryptography.SHA256]::Create()
try { $signer = ([BitConverter]::ToString($digest.ComputeHash($signature.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant() }
finally { $digest.Dispose() }
if ($signer -ne $config.signerSha256.ToLowerInvariant()) { throw 'El editor no coincide con el certificado configurado.' }
$profile = Join-Path $PSScriptRoot 'Conexion.rdp'
if ((Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $config.rdpSha256.ToLowerInvariant()) { throw 'El archivo RDP ha sido modificado.' }
if (([Uri]$config.portal).Scheme -ne 'https') { throw 'La activación requiere HTTPS.' }

# Use the Windows Credential API, not cmdkey /pass: (which exposes the secret in process arguments).
if (-not ('FreshkampoRdpCredential' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class FreshkampoRdpCredential {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct Credential {
        public uint Flags, Type;
        public string TargetName, Comment;
        public FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist, AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias, UserName;
    }
    [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CredWrite(ref Credential credential, uint flags);
    [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);
    [DllImport("advapi32.dll")] private static extern void CredFree(IntPtr credential);
    public static bool Exists(string target, string user, string marker) {
        IntPtr ptr;
        if (!CredRead(target, 1, 0, out ptr)) return false;
        try {
            var c=(Credential)Marshal.PtrToStructure(ptr, typeof(Credential));
            return String.Equals(c.UserName,user,StringComparison.OrdinalIgnoreCase) && c.Comment==marker;
        } finally { CredFree(ptr); }
    }
    public static void Store(string target, string user, string password, string marker) {
        IntPtr secret=Marshal.StringToCoTaskMemUni(password);
        try {
            Credential c=new Credential();
            c.Type=1; c.TargetName=target; c.UserName=user; c.Comment=marker;
            c.CredentialBlob=secret; c.CredentialBlobSize=(uint)(password.Length*2); c.Persist=2;
            if (!CredWrite(ref c,0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { Marshal.ZeroFreeCoTaskMemUnicode(secret); }
    }
}
'@
}
$target = 'TERMSRV/' + $config.host
$marker = 'Freshkampo Access: ' + $config.id
if (-not [FreshkampoRdpCredential]::Exists($target, $config.username, $marker)) {
    Write-Host "Preparar conexión a $($config.host) con $($config.username)."
    Write-Host 'La credencial quedará guardada en el perfil de Windows actual, solo en este equipo.'
    $code = Read-Host 'Código de activación entregado por TI' -AsSecureString
    $plainCode = $null
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($code)
    try {
        $plainCode = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $body = @{ id=$config.id; code=$plainCode } | ConvertTo-Json -Compress
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            $response = Invoke-RestMethod -Uri ($config.portal + '/api/rdp/redeem') -Method Post -ContentType 'application/json' -Body $body -MaximumRedirection 0 -TimeoutSec 30
        } catch {
            throw 'No se pudo activar. El código puede ser inválido, estar usado o caducado; verifica HTTPS y acceso al gestor. Solicita un nuevo paquete si el intento quedó incompleto.'
        }
        if ($response.host -ne $config.host -or $response.username -ne $config.username -or -not $response.password) { throw 'Respuesta de activación incompatible.' }
        [FreshkampoRdpCredential]::Store($target, $response.username, $response.password, $marker)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        $code.Dispose()
        $plainCode=$null; $body=$null; $response=$null
    }
}
# Run only the pinned, signed profile. NLA, certificates and domain policies remain enforced.
& (Join-Path $env:SystemRoot 'System32\mstsc.exe') $profile
