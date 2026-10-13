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
                                input=json.dumps(data), capture_output=True, text=True, encoding='utf-8', timeout=45)
        response = json.loads(result.stdout.lstrip('\ufeff'))
        if result.returncode or not response.get('ok'):
            raise DirectoryError('Active Directory rechazó la operación. Revisa permisos, política y registros de Windows.')
        return response.get('data')
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
        raise DirectoryError('No se pudo completar la operación con Active Directory. Verifica el resultado antes de reintentar.') from exc
