import json
import ntpath
import os
import subprocess
from pathlib import Path

class DirectoryError(Exception):
    pass

def call_ad(action, **values):
    if os.name != 'nt':
        raise DirectoryError('La conexión real requiere Windows Server y el módulo ActiveDirectory.')
    server, ou = os.environ.get('FK_AD_SERVER'), os.environ.get('FK_AD_OU')
    if not server or not ou:
        raise DirectoryError('Configura el controlador de dominio y la OU autorizada.')
    data = dict(action=action, server=server, ou=ou, upnSuffix=os.environ.get('FK_AD_UPN_SUFFIX', ''), **values)
    script = Path(__file__).parent / 'windows' / 'directory.ps1'
    try:
        result = subprocess.run(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script)],
                                input=json.dumps(data), capture_output=True, text=True, encoding='utf-8', timeout=45,
                                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        response = json.loads(result.stdout.lstrip('\ufeff'))
        if result.returncode or not response.get('ok'):
            raise DirectoryError('Active Directory rechazó la operación. Revisa permisos, política y registros de Windows.')
        return response.get('data')
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
        raise DirectoryError('No se pudo completar la operación con Active Directory. Verifica el resultado antes de reintentar.') from exc


def local_powershell_path():
    # Never resolve powershell.exe through PATH or use 32-bit LocalAccounts.
    root=os.environ.get('SystemRoot',r'C:\Windows')
    system='Sysnative' if os.environ.get('PROCESSOR_ARCHITEW6432') else 'System32'
    return ntpath.join(root,system,'WindowsPowerShell','v1.0','powershell.exe')


def local_response(result):
    try:
        response=json.loads(result.stdout.lstrip('\ufeff'))
        if not isinstance(response,dict):raise ValueError()
    except (ValueError,TypeError,AttributeError):
        # Inspect known startup signatures, never expose stderr or submitted values.
        diagnostic=(str(result.stderr)+' '+str(result.stdout)).lower()
        if any(value in diagnostic for value in ('pssecurityexception','about_execution_policies','running scripts is disabled','digitally signed')):
            raise DirectoryError('La política de PowerShell bloqueó el script local. Solicita a TI validar su firma y la política de ejecución del servidor. [PS_POLICY]') from None
        if any(value in diagnostic for value in ('microsoft.powershell.localaccounts','microsoft.powershell.utility','cimcmdlets','couldnotautoloadmatchingmodule','modules_module')):
            raise DirectoryError('No se pudieron cargar los módulos de Windows PowerShell de 64 bits. Revisa la instalación de Windows PowerShell y LocalAccounts. [PS_MODULES]') from None
        raise DirectoryError('Windows PowerShell no devolvió un inventario válido. Verifica que el antivirus no haya bloqueado el script y que Windows PowerShell funcione en este servidor. [PS_RESPONSE]') from None
    if result.returncode or not response.get('ok'):
        stage=response.get('stage','');category=response.get('category','');exception=response.get('exception','')
        diagnostics=' ['+','.join(str(value) for value in (stage,category,exception,response.get('line','')) if value)+']'
        raise DirectoryError('Windows rechazó la operación local. Abre Metakampo como administrador para realizar cambios; revisa cuentas protegidas, políticas y el estado real antes de reintentar. El modo local no admite controladores de dominio.'+diagnostics)
    return response.get('data')


def call_local(action, **values):
    if os.name != 'nt':
        raise DirectoryError('Los usuarios locales requieren Windows Server con experiencia de escritorio.')
    script = Path(__file__).parent / 'windows' / 'local-directory.ps1'
    try:
        result = subprocess.run([local_powershell_path(), '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script)],
                                input=json.dumps(dict(action=action, **values)), capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=45,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except subprocess.TimeoutExpired:
        raise DirectoryError('La consulta local excedió 45 segundos. Comprueba el estado de Windows antes de repetir una operación. [PS_TIMEOUT]') from None
    except OSError:
        raise DirectoryError('No se pudo iniciar Windows PowerShell de 64 bits. Revisa que esté instalado y permitido por la protección del servidor. [PS_LAUNCH]') from None
    return local_response(result)
