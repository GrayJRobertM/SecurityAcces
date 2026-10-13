"""Windows account + machine binding. No secret travels through process arguments."""
import csv
import ctypes
import os
import subprocess
from ctypes import wintypes

ENTROPY = b'Freshkampo.Access.Desktop.v1'


def machine_identity():
    if os.name != 'nt':
        raise OSError('La aplicación de escritorio requiere Windows.')
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography',
                       0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        machine = winreg.QueryValueEx(key, 'MachineGuid')[0]
    result = subprocess.run(['whoami.exe', '/user', '/fo', 'csv', '/nh'],
                            capture_output=True, text=True, check=True,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    sid = list(csv.reader(result.stdout.strip().splitlines()))[0][-1]
    if not sid.startswith('S-1-'):
        raise OSError('No se pudo identificar la cuenta Windows.')
    return dict(machine=machine, sid=sid)


def dpapi(value, decrypt=False):
    if os.name != 'nt':
        raise OSError('DPAPI requiere Windows.')
    class Blob(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
    def blob(raw):
        buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        return Blob(len(raw), buffer), buffer
    incoming, buffer = blob(value)
    entropy, entropy_buffer = blob(ENTROPY)
    outgoing = Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    free = ctypes.WinDLL('kernel32').LocalFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_void_p
    fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fn.restype = wintypes.BOOL
    # CurrentUser scope, UI forbidden. MachineGuid is checked separately at load.
    if not fn(ctypes.byref(incoming), None, ctypes.byref(entropy), None, None, 1, ctypes.byref(outgoing)):
        raise OSError('Windows no pudo proteger o abrir los datos para esta cuenta y equipo.')
    try:
        return ctypes.string_at(outgoing.data, outgoing.size)
    finally:
        ctypes.memset(outgoing.data, 0, outgoing.size)
        free(outgoing.data)
        ctypes.memset(buffer, 0, len(value))


def restrict_folder(folder, sid):
    subprocess.run(['icacls.exe', str(folder), '/inheritance:r', '/grant:r',
                    '*' + sid + ':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'],
                   check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)


def powershell(script, payload, timeout=60):
    import json
    result = subprocess.run(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
                             '-File', str(script)], input=json.dumps(payload),
                            capture_output=True, text=True, encoding='utf-8', timeout=timeout,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    try:
        data = json.loads(result.stdout.lstrip('\ufeff'))
    except ValueError:
        raise OSError('Windows no completó la operación solicitada.') from None
    if result.returncode or not data.get('ok'):
        raise OSError(data.get('error', 'No se pudo completar la operación Windows.'))
    return data
