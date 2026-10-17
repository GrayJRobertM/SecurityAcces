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
    sid=current_sid()
    return dict(machine=machine, sid=sid)


def current_sid():
    k=ctypes.WinDLL('kernel32',use_last_error=True);a=ctypes.WinDLL('advapi32',use_last_error=True)
    k.GetCurrentThread.restype=wintypes.HANDLE;k.GetCurrentProcess.restype=wintypes.HANDLE
    k.CloseHandle.argtypes=[wintypes.HANDLE];k.LocalFree.argtypes=[ctypes.c_void_p]
    a.OpenThreadToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.BOOL,ctypes.POINTER(wintypes.HANDLE)]
    a.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    a.GetTokenInformation.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    a.ConvertSidToStringSidW.argtypes=[ctypes.c_void_p,ctypes.POINTER(wintypes.LPWSTR)]
    token=wintypes.HANDLE()
    if not a.OpenThreadToken(k.GetCurrentThread(),8,True,ctypes.byref(token)):
        if ctypes.get_last_error()!=1008 or not a.OpenProcessToken(k.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        length=wintypes.DWORD();a.GetTokenInformation(token,1,None,0,ctypes.byref(length))
        buffer=ctypes.create_string_buffer(length.value)
        if not a.GetTokenInformation(token,1,buffer,length,ctypes.byref(length)):raise ctypes.WinError(ctypes.get_last_error())
        sid=ctypes.cast(buffer,ctypes.POINTER(ctypes.c_void_p))[0];text=wintypes.LPWSTR()
        if not a.ConvertSidToStringSidW(sid,ctypes.byref(text)):raise ctypes.WinError(ctypes.get_last_error())
        try:return text.value
        finally:k.LocalFree(ctypes.cast(text,ctypes.c_void_p))
    finally:k.CloseHandle(token)


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
