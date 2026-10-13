import json
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


def call_local(action, **values):
    if os.name != 'nt':
        raise DirectoryError('Los usuarios locales requieren Windows Server con experiencia de escritorio.')
    script = Path(__file__).parent / 'windows' / 'local-directory.ps1'
    try:
        result = subprocess.run(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script)],
                                input=json.dumps(dict(action=action, **values)), capture_output=True,
                                text=True, encoding='utf-8', timeout=45,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        response = json.loads(result.stdout.lstrip('\ufeff'))
        if result.returncode or not response.get('ok'):
            stage=response.get('stage','');category=response.get('category','');exception=response.get('exception','')
            diagnostics=' ['+','.join(str(value) for value in (stage,category,exception,response.get('line','')) if value)+']'
            raise DirectoryError('Windows rechazó la operación local. Abre Metakampo como administrador; revisa cuentas protegidas, políticas y el estado real antes de reintentar. El modo local no admite controladores de dominio.'+diagnostics)
        return response.get('data')
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
        raise DirectoryError('No se pudo completar la operación local. Verifica el estado de Windows antes de reintentar.') from exc
