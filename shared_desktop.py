"""Local-only Windows named-pipe transport between RDP desktop sessions.

Only the elevated owner opens the database/DPAPI store. A standard-user client
verifies the pipe server executable before sending any application credentials.
"""
import base64
import ctypes
import json
import os
from pathlib import Path
import struct
import threading
from contextlib import contextmanager
from ctypes import wintypes as W
from werkzeug.test import Client
from werkzeug.wrappers import Response

PIPE_NAME=r'\\.\pipe\Metakampo.Access.Shared.v1'
MAX_FRAME=16*1024*1024
CLIENT_RIGHTS=0x00120183  # data R/W + attributes + synchronize, NEVER create-instance (0x4).
PIPE_SDDL='D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00120183;;;IU)'


def _native():
    if os.name!='nt':raise OSError('Las sesiones compartidas requieren Windows Server.')
    k=ctypes.WinDLL('kernel32',use_last_error=True);a=ctypes.WinDLL('advapi32',use_last_error=True)
    signatures={
        'CreateNamedPipeW':([W.LPCWSTR,W.DWORD,W.DWORD,W.DWORD,W.DWORD,W.DWORD,W.DWORD,W.LPVOID],W.HANDLE),
        'CreateFileW':([W.LPCWSTR,W.DWORD,W.DWORD,W.LPVOID,W.DWORD,W.DWORD,W.HANDLE],W.HANDLE),
        'ConnectNamedPipe':([W.HANDLE,W.LPVOID],W.BOOL),
        'FlushFileBuffers':([W.HANDLE],W.BOOL),
        'DisconnectNamedPipe':([W.HANDLE],W.BOOL),'CloseHandle':([W.HANDLE],W.BOOL),
        'ReadFile':([W.HANDLE,W.LPVOID,W.DWORD,ctypes.POINTER(W.DWORD),W.LPVOID],W.BOOL),
        'WriteFile':([W.HANDLE,W.LPVOID,W.DWORD,ctypes.POINTER(W.DWORD),W.LPVOID],W.BOOL),
        'GetNamedPipeServerProcessId':([W.HANDLE,ctypes.POINTER(W.ULONG)],W.BOOL),
        'OpenProcess':([W.DWORD,W.BOOL,W.DWORD],W.HANDLE),
        'QueryFullProcessImageNameW':([W.HANDLE,W.DWORD,W.LPWSTR,ctypes.POINTER(W.DWORD)],W.BOOL),
        'WaitNamedPipeW':([W.LPCWSTR,W.DWORD],W.BOOL),
        'OpenThread':([W.DWORD,W.BOOL,W.DWORD],W.HANDLE),
        'CancelSynchronousIo':([W.HANDLE],W.BOOL),'LocalFree':([W.LPVOID],W.LPVOID),
    }
    for name,(args,result) in signatures.items():fn=getattr(k,name);fn.argtypes=args;fn.restype=result
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[W.LPCWSTR,W.DWORD,ctypes.POINTER(W.LPVOID),W.LPVOID]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=W.BOOL
    a.ImpersonateNamedPipeClient.argtypes=[W.HANDLE];a.ImpersonateNamedPipeClient.restype=W.BOOL
    a.RevertToSelf.argtypes=[];a.RevertToSelf.restype=W.BOOL
    return k,a


def _check(value):
    if not value:raise ctypes.WinError(ctypes.get_last_error())
    return value


def _read(k,pipe,count):
    chunks=[]
    while count:
        buffer=ctypes.create_string_buffer(min(count,65536));read=W.DWORD()
        _check(k.ReadFile(pipe,buffer,len(buffer),ctypes.byref(read),None))
        if not read.value:raise OSError('Canal local cerrado.')
        chunks.append(buffer.raw[:read.value]);count-=read.value
    return b''.join(chunks)


def read_message(k,pipe):
    length=struct.unpack('<I',_read(k,pipe,4))[0]
    if length>MAX_FRAME:raise ValueError('Mensaje local demasiado grande.')
    data=json.loads(_read(k,pipe,length))
    if not isinstance(data,dict):raise ValueError('Mensaje local inválido.')
    return data


def write_message(k,pipe,data):
    raw=json.dumps(data,separators=(',',':')).encode('utf-8')
    if len(raw)>MAX_FRAME:raise ValueError('Respuesta local demasiado grande.')
    raw=struct.pack('<I',len(raw))+raw;offset=0
    while offset<len(raw):
        chunk=raw[offset:offset+65536];written=W.DWORD();buffer=ctypes.create_string_buffer(chunk)
        _check(k.WriteFile(pipe,buffer,len(chunk),ctypes.byref(written),None))
        if not written.value:raise OSError('Canal local cerrado.')
        offset+=written.value


@contextmanager
def impersonation(pipe):
    _,a=_native();_check(a.ImpersonateNamedPipeClient(pipe))
    try:yield
    finally:
        # Continuing under another identity would endanger the owner store.
        if not a.RevertToSelf():os._exit(70)


def bridge_request(application,data,scope=None):
    method=data.get('method');path=data.get('path','')
    if method not in ('GET','POST') or not isinstance(path,str) or len(path)>8192 or not path.startswith('/') or path.startswith('//') or '\\' in path or any(ord(c)<32 for c in path):raise ValueError('Solicitud no permitida.')
    clean=path.split('?',1)[0]
    if clean!='/' and not clean.startswith(('/api/','/static/')):raise ValueError('Ruta no disponible para sesiones compartidas.')
    # Configuration and local collection infrastructure remain with the owner.
    if clean.startswith(('/api/telemetry/events','/api/collectors','/api/rdp/redeem')):return dict(status=403,headers=[['Content-Type','application/json']],body=base64.b64encode(b'{"error":"Operacion reservada al propietario del servidor."}').decode())
    headers=data.get('headers',{})
    if not isinstance(headers,dict) or len(headers)>64:raise ValueError('Cabeceras inválidas.')
    headers={key:value for key,value in headers.items() if key.lower() in ('content-type','cookie','x-csrf-token','range','if-none-match')}
    raw=base64.b64decode(data.get('body',''),validate=True)
    if len(raw)>2*1048576:raise ValueError('Solicitud demasiado grande.')
    env={'REMOTE_ADDR':'127.0.0.1','metakampo.shared_client':True}
    if scope:env['metakampo.impersonate']=scope
    with Client(application,Response,use_cookies=False).open(path,method=method,base_url='http://127.0.0.1',headers=headers,data=raw,environ_overrides=env) as response:
        body=response.get_data()
        if len(body)>10*1048576:raise ValueError('Respuesta demasiado grande.')
        return dict(status=response.status_code,headers=list(response.headers),body=base64.b64encode(body).decode())


def allow_host_identity_query():
    """Let interactive clients verify this process path, without reading its memory."""
    k,a=_native();k.GetCurrentProcess.restype=W.HANDLE
    a.ConvertStringSidToSidW.argtypes=[W.LPCWSTR,ctypes.POINTER(W.LPVOID)];a.ConvertStringSidToSidW.restype=W.BOOL
    a.GetSecurityInfo.argtypes=[W.HANDLE,ctypes.c_int,W.DWORD,W.LPVOID,W.LPVOID,ctypes.POINTER(W.LPVOID),W.LPVOID,ctypes.POINTER(W.LPVOID)];a.GetSecurityInfo.restype=W.DWORD
    a.SetSecurityInfo.argtypes=[W.HANDLE,ctypes.c_int,W.DWORD,W.LPVOID,W.LPVOID,W.LPVOID,W.LPVOID];a.SetSecurityInfo.restype=W.DWORD
    class Trustee(ctypes.Structure):_fields_=[('multiple',W.LPVOID),('operation',ctypes.c_int),('form',ctypes.c_int),('kind',ctypes.c_int),('name',W.LPVOID)]
    class Access(ctypes.Structure):_fields_=[('permissions',W.DWORD),('mode',ctypes.c_int),('inheritance',W.DWORD),('trustee',Trustee)]
    a.SetEntriesInAclW.argtypes=[W.ULONG,ctypes.POINTER(Access),W.LPVOID,ctypes.POINTER(W.LPVOID)];a.SetEntriesInAclW.restype=W.DWORD
    descriptor=W.LPVOID();old=W.LPVOID();new=W.LPVOID();sid=W.LPVOID()
    try:
        _check(a.ConvertStringSidToSidW('S-1-5-4',ctypes.byref(sid)))
        error=a.GetSecurityInfo(k.GetCurrentProcess(),6,4,None,None,ctypes.byref(old),None,ctypes.byref(descriptor))
        if error:raise ctypes.WinError(error)
        entry=Access(0x1000,1,0,Trustee(None,0,0,2,sid))
        error=a.SetEntriesInAclW(1,ctypes.byref(entry),old,ctypes.byref(new))
        if error:raise ctypes.WinError(error)
        error=a.SetSecurityInfo(k.GetCurrentProcess(),6,4,None,None,new,None)
        if error:raise ctypes.WinError(error)
    finally:
        for pointer in (descriptor,new,sid):
            if pointer:k.LocalFree(pointer)


class PipeServer:
    def __init__(self,application,name=PIPE_NAME):
        self.application=application;self.name=name;self.k,self.a=_native();self.stopped=threading.Event();self.slots=threading.BoundedSemaphore(16)
        allow_host_identity_query()
        self.first=self._create(True)
        self.thread=threading.Thread(target=self._run,daemon=True)
    def _create(self,first=False):
        class Attributes(ctypes.Structure):_fields_=[('length',W.DWORD),('descriptor',W.LPVOID),('inherit',W.BOOL)]
        descriptor=W.LPVOID();_check(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(PIPE_SDDL,1,ctypes.byref(descriptor),None))
        try:
            attr=Attributes(ctypes.sizeof(Attributes),descriptor,False)
            handle=self.k.CreateNamedPipeW(self.name,3|(0x80000 if first else 0),8,32,65536,65536,5000,ctypes.byref(attr))
            if handle==ctypes.c_void_p(-1).value:raise OSError('Ya existe un servidor compartido o Windows rechazó el canal local.')
            return handle
        finally:self.k.LocalFree(descriptor)
    def start(self):self.thread.start()
    def _run(self):
        pipe=self.first
        while not self.stopped.is_set():
            connected=self.k.ConnectNamedPipe(pipe,None)
            if connected or ctypes.get_last_error()==535:
                if self.slots.acquire(blocking=False):threading.Thread(target=self._serve,args=(pipe,),daemon=True).start()
                else:self.k.CloseHandle(pipe)
            else:self.k.CloseHandle(pipe)
            if self.stopped.is_set():break
            try:pipe=self._create()
            except OSError:break
    def _serve(self,pipe):
        thread_handle=self.k.OpenThread(1,False,threading.get_native_id())
        timer=threading.Timer(90,lambda:self.k.CancelSynchronousIo(thread_handle))
        timer.daemon=True;timer.start()
        try:
            data=read_message(self.k,pipe)
            app=self.application()
            if app is None:raise ValueError('El propietario debe configurar primero Metakampo.')
            response=bridge_request(app,data,scope=lambda:impersonation(pipe))
            write_message(self.k,pipe,response)
            self.k.FlushFileBuffers(pipe)
        except Exception:
            try:write_message(self.k,pipe,dict(status=503,headers=[['Content-Type','application/json']],body=base64.b64encode(b'{"error":"El servidor local no pudo completar la operacion. Verifica el resultado antes de reintentar."}').decode()))
            except Exception:pass
        finally:
            timer.cancel();self.k.CloseHandle(thread_handle);self.k.DisconnectNamedPipe(pipe);self.k.CloseHandle(pipe);self.slots.release()
    def stop(self):
        self.stopped.set()
        try:
            handle=self.k.CreateFileW(self.name,CLIENT_RIGHTS,0,None,3,0x120000,None)
            if handle!=ctypes.c_void_p(-1).value:self.k.CloseHandle(handle)
        except Exception:pass
        self.thread.join(2)


class PipeClient:
    def __init__(self,expected_executable,name=PIPE_NAME):self.expected=Path(expected_executable);self.name=name
    def request(self,data):
        k,_=_native()
        # LOCAL pipe name is fixed by installed code, never accepted from a server/config file.
        if not self.name.startswith('\\\\.\\pipe\\'):raise OSError('Solo se permite comunicación en este servidor.')
        k.WaitNamedPipeW(self.name,3000)
        pipe=k.CreateFileW(self.name,CLIENT_RIGHTS,0,None,3,0x120000,None) # SQOS present + SecurityImpersonation.
        if pipe==ctypes.c_void_p(-1).value:raise OSError('No se pudo conectar con el servicio local Metakampo. Código Windows '+str(ctypes.get_last_error())+'. Revisa el estado del servicio y sus credenciales.')
        thread_handle=k.OpenThread(1,False,threading.get_native_id());timer=threading.Timer(90,lambda:k.CancelSynchronousIo(thread_handle));timer.daemon=True;timer.start()
        try:
            pid=W.ULONG();_check(k.GetNamedPipeServerProcessId(pipe,ctypes.byref(pid)))
            process=k.OpenProcess(0x1000,False,pid.value);_check(process)
            try:
                text=ctypes.create_unicode_buffer(32768);size=W.DWORD(len(text));_check(k.QueryFullProcessImageNameW(process,0,text,ctypes.byref(size)))
                if os.path.normcase(os.path.realpath(text.value))!=os.path.normcase(os.path.realpath(str(self.expected))):raise OSError('El canal no pertenece al ejecutable instalado de Metakampo.')
            finally:k.CloseHandle(process)
            write_message(k,pipe,data);return read_message(k,pipe)
        finally:timer.cancel();k.CloseHandle(thread_handle);k.CloseHandle(pipe)


class LocalProxy:
    def __init__(self,client):self.client=client
    def __call__(self,env,start):
        try:
            count=int(env.get('CONTENT_LENGTH') or 0)
            if not 0<=count<=2*1048576:raise ValueError('Archivo demasiado grande.')
            path=env.get('PATH_INFO','/')
            if env.get('QUERY_STRING'):path+='?'+env['QUERY_STRING']
            headers={key[5:].replace('_','-'):value for key,value in env.items() if key.startswith('HTTP_')}
            if env.get('CONTENT_TYPE'):headers['Content-Type']=env['CONTENT_TYPE']
            result=self.client.request(dict(method=env.get('REQUEST_METHOD'),path=path,headers=headers,body=base64.b64encode(env['wsgi.input'].read(count)).decode()))
            body=base64.b64decode(result['body'],validate=True)
            response=Response(body,status=int(result['status']),headers=result['headers'])
        except Exception:
            response=Response('El servidor compartido no está disponible. Solicita al propietario abrir Administrar servidor Metakampo. No repitas una operación de cambio sin comprobar su resultado.',status=503,content_type='text/plain; charset=utf-8')
        return response(env,start)
