"""RDP profiles and signed launchers. Credentials never enter exported archives."""
import base64
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from zipfile import ZipFile, ZIP_DEFLATED

BASE=Path(__file__).parent
class RDPError(Exception): pass

def validate_connection(host, username, port=3389):
    if not isinstance(host,str) or not 1<=len(host)<=253:
        raise ValueError('Indica un nombre DNS o IPv4 del servidor.')
    host=host.lower()
    labels=host.split('.')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in labels):
        raise ValueError('El servidor debe ser un nombre DNS o IPv4 sin rutas, espacios ni instrucciones RDP.')
    if type(port) is not int or not 1<=port<=65535:
        raise ValueError('El puerto debe estar entre 1 y 65535.')
    if not isinstance(username,str) or len(username)>253 or not re.fullmatch(r'[A-Za-z0-9._-]+(?:\\[A-Za-z0-9._-]+|@[A-Za-z0-9.-]+)',username):
        raise ValueError('Usa el formato DOMINIO\\usuario o usuario@dominio.')
    return host, username, port

def portal_url():
    url=os.environ.get('FK_RDP_PORTAL_URL','').rstrip('/')
    parts=urlsplit(url)
    if parts.scheme!='https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path:
        raise RDPError('Configura FK_RDP_PORTAL_URL con el origen HTTPS del gestor, sin rutas ni credenciales.')
    return url

def configured():
    return os.name=='nt' and bool(os.environ.get('FK_RDP_CERT_HASH')) and bool(os.environ.get('FK_RDP_PORTAL_URL'))

def profile_bytes(host,username,port=3389):
    host,username,port=validate_connection(host,username,port)
    address=host if port==3389 else f'{host}:{port}'
    # Explicitly preserve server authentication and NLA; redirection is minimized.
    lines=[f'full address:s:{address}',f'username:s:{username}','screen mode id:i:2','use multimon:i:0',
           'authentication level:i:1','enablecredsspsupport:i:1','prompt for credentials:i:0',
           'redirectclipboard:i:0','redirectprinters:i:0','redirectcomports:i:0','redirectsmartcards:i:0',
           'drivestoredirect:s:','audiomode:i:2','autoreconnection enabled:i:1']
    return ('\r\n'.join(lines)+'\r\n').encode('utf-16')

def signed_files(profile, configuration):
    if os.name!='nt':
        raise RDPError('La firma de clientes RDP requiere Windows y rdpsign.exe.')
    rdp_hash=os.environ.get('FK_RDP_CERT_HASH','').replace(' ','').upper()
    script_hash=(os.environ.get('FK_RDP_SCRIPT_CERT_HASH') or rdp_hash).replace(' ','').upper()
    if not all(re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})',x) for x in (rdp_hash,script_hash)):
        raise RDPError('Configura la huella del certificado RDP y un certificado de firma de código para el lanzador.')
    store=os.environ.get('FK_RDP_CERT_STORE','CurrentUser')
    if store not in ('CurrentUser','LocalMachine'):
        raise RDPError('El almacén de certificados debe ser CurrentUser o LocalMachine.')
    with tempfile.TemporaryDirectory(prefix='fk-rdp-sign-') as folder:
        root=Path(folder)
        rdp_file=root/'Conexion.rdp'
        launcher=root/'Conectar.ps1'
        rdp_file.write_bytes(profile)
        data=dict(folder=str(root),rdpHash=rdp_hash,scriptHash=script_hash,store=store,
                  timestamp=os.environ.get('FK_RDP_TIMESTAMP_URL',''))
        def run(step):
            try:
                result=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-File',str(BASE/'windows'/'sign-rdp.ps1')],
                                      input=json.dumps(dict(data,step=step)),capture_output=True,text=True,encoding='utf-8',timeout=60,
                                      creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                result_data=json.loads(result.stdout.lstrip('\ufeff'))
                if result.returncode or not result_data.get('ok'):
                    raise RDPError('No se pudo firmar. Revisa el certificado, su clave privada, su vigencia y permisos de la cuenta de servicio.')
                return result_data
            except (OSError,subprocess.TimeoutExpired,json.JSONDecodeError) as exc:
                raise RDPError('No se pudo completar la firma del cliente RDP.') from exc
        result=run('rdp')
        signed=rdp_file.read_bytes()
        content=signed.decode('utf-16')
        if not re.search(r'^signature:s:\S+',content,re.M) or not re.search(r'^signscope:s:',content,re.M):
            raise RDPError('rdpsign no produjo una firma RDP verificable.')
        config=dict(configuration,rdpSha256=hashlib.sha256(signed).hexdigest(),signerSha256=result['scriptSignerSha256'])
        encoded=base64.b64encode(json.dumps(config).encode()).decode()
        template_name='Connect-LocalRDP.template.ps1' if configuration.get('local') else 'Connect-RDP.template.ps1'
        template=(BASE/'windows'/template_name).read_text(encoding='utf-8')
        launcher.write_text(template.replace('__CONFIG_BASE64__',encoded),encoding='utf-8-sig')
        run('script')
        return signed,launcher.read_bytes()

def make_package(host,username,port,configuration=None,demo=False):
    profile=profile_bytes(host,username,port)
    if demo:
        files={'Vista-previa-SIN-FIRMA.rdp':profile,
               'LEEME.txt':'VISTA PREVIA SIN FIRMA Y SIN CONTRASEÑA.\r\nEste perfil no incluye credenciales ni activación.\r\nPara generar un paquete firmado configura Windows, los certificados y el portal HTTPS.\r\n'.encode()}
    else:
        signed,launcher=signed_files(profile,configuration)
        files={'Conexion.rdp':signed,'Conectar.ps1':launcher,
               'LEEME.txt':('Freshkampo Access · Cliente RDP firmado\r\n\r\nExtrae el ZIP en una carpeta privada. Verifica el editor de Conectar.ps1.\r\nEjecuta en Windows PowerShell: .\\Conectar.ps1\r\nNo uses ExecutionPolicy Bypass ni alteres el RDP firmado.\r\nLa primera vez pide el código de activación entregado por separado.\r\nRequiere acceso HTTPS al gestor antes de la caducidad indicada por TI.\r\nLa activación se utiliza una sola vez; guarda la contraseña en el Administrador de credenciales de Windows de tu usuario, para este equipo y servidor.\r\nLos siguientes accesos usan esa credencial local, hasta que cambie la contraseña o la borres.\r\nPara retirarla, usa el Administrador de credenciales de Windows.\r\nLa firma no garantiza permisos RDP ni validez de la contraseña. Se respetan NLA, certificados y políticas de Windows.\r\n').encode('utf-8')}
        if configuration and configuration.get('local'):
            files['LEEME.txt']=('Freshkampo Access · Cliente RDP local firmado\r\nExtrae el ZIP en una carpeta privada y ejecuta .\\Conectar.ps1 en Windows PowerShell.\r\nFunciona solo en el servidor y con la cuenta Windows que lo generó. No requiere portal ni código de activación.\r\nLa contraseña está protegida con DPAPI, nunca en texto claro. Windows guarda la credencial para TERMSRV/destino.\r\nNo uses ExecutionPolicy Bypass. Requiere confianza válida en el certificado de firma de código.\r\nSe respetan NLA, certificados y políticas Windows. La firma no valida la contraseña ni habilita MFA.\r\nPara retirar el acceso, elimina la credencial en el Administrador de credenciales de Windows y cambia la contraseña de la cuenta si corresponde.\r\n').encode('utf-8')
    output=io.BytesIO()
    with ZipFile(output,'w',ZIP_DEFLATED) as archive:
        for name,content in files.items():archive.writestr(name,content)
    return output.getvalue()
