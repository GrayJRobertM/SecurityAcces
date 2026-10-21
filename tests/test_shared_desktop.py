import base64
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch
from flask import Flask,jsonify,request
from werkzeug.test import Client
from werkzeug.wrappers import Response
from shared_desktop import bridge_request,LocalProxy,PipeServer,PipeClient,PIPE_SDDL,CLIENT_RIGHTS,connect_pipe

class BridgeTests(unittest.TestCase):
    def test_busy_pipe_open_is_retried_but_access_denied_is_not(self):
        import ctypes
        invalid=ctypes.c_void_p(-1).value
        kernel=Mock();kernel.CreateFileW.side_effect=[invalid,invalid,42]
        with patch('shared_desktop.ctypes.get_last_error',return_value=231,create=True):
            self.assertEqual(connect_pipe(kernel,'local-test'),42)
        self.assertEqual(kernel.WaitNamedPipeW.call_count,2)
        kernel=Mock();kernel.CreateFileW.return_value=invalid
        with patch('shared_desktop.ctypes.get_last_error',return_value=5,create=True):
            with self.assertRaisesRegex(OSError,'Código Windows 5'):
                connect_pipe(kernel,'local-test')
        kernel.WaitNamedPipeW.assert_not_called()
        kernel=Mock();kernel.CreateFileW.return_value=invalid
        with patch('shared_desktop.ctypes.get_last_error',return_value=231,create=True), patch('shared_desktop.time.monotonic',side_effect=[0,4]):
            with self.assertRaisesRegex(OSError,'Código Windows 231'):
                connect_pipe(kernel,'local-test')
        kernel.WaitNamedPipeW.assert_not_called()
    def setUp(self):
        self.app=Flask(__name__)
        @self.app.route('/api/check',methods=['GET','POST'])
        def check():
            result=jsonify(body=request.get_data().decode(),cookie=request.cookies.get('session'),shared=request.environ['metakampo.shared_client'])
            result.set_cookie('session','returned',httponly=True,samesite='Strict');return result
    def test_proxy_preserves_body_session_cookie_and_csrf_headers(self):
        class Fake:
            def request(inner,data):return bridge_request(self.app,data)
        proxy=Client(LocalProxy(Fake()),Response,use_cookies=False)
        result=proxy.post('/api/check',data='payload',headers={'Cookie':'session=original','X-CSRF-Token':'token'},content_type='text/plain')
        self.assertEqual(result.status_code,200);self.assertEqual(result.json,dict(body='payload',cookie='original',shared=True));self.assertIn('HttpOnly',result.headers['Set-Cookie'])
    def test_owner_configuration_remote_broker_and_non_http_payloads_rejected(self):
        for path in ('/desktop/settings','//other/api/check','/api/check\n','/api\\check'):
            with self.assertRaises(ValueError):bridge_request(self.app,dict(method='GET',path=path,headers={},body=''))
        result=bridge_request(self.app,dict(method='POST',path='/api/rdp/redeem',headers={},body=''));self.assertEqual(result['status'],403)
        with self.assertRaises(ValueError):bridge_request(self.app,dict(method='PUT',path='/api/check',headers={},body=''))
        self.assertEqual(CLIENT_RIGHTS&4,0);self.assertNotIn(';;;WD',PIPE_SDDL)

@unittest.skipUnless(os.name=='nt' and os.environ.get('FK_NATIVE_SHARED_TESTS')=='1','Explicit Windows local IPC integration only')
class NativeSharedTests(unittest.TestCase):
    def setUp(self):
        self.app=Flask(__name__)
        @self.app.get('/api/check')
        def check():
            from windows_native import current_sid
            with request.environ['metakampo.impersonate']():sid=current_sid()
            return jsonify(ok=True,sid=sid)
        self.name=r'\\.\pipe\Metakampo.CI.'+uuid.uuid4().hex
        self.server=PipeServer(lambda:self.app,name=self.name);self.server.start();self.addCleanup(self.server.stop)
    def test_parallel_browser_requests_all_reach_verified_pipe(self):
        import time
        create=self.server._create
        def slow_listener(*args,**kwargs):
            time.sleep(.01)
            return create(*args,**kwargs)
        self.server._create=slow_listener
        def query(_):
            return PipeClient(sys.executable,name=self.name).request(dict(method='GET',path='/api/check',headers={},body=''))
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(query,range(64)))
        self.assertEqual(len(results),64)
        self.assertTrue(all(r['status']==200 and json.loads(base64.b64decode(r['body']))['ok'] for r in results))
    def test_real_pipe_roundtrip_and_wrong_server_executable_rejected(self):
        from windows_native import current_sid
        result=PipeClient(sys.executable,name=self.name).request(dict(method='GET',path='/api/check',headers={},body=''))
        self.assertEqual(json.loads(base64.b64decode(result['body']))['sid'],current_sid())
        with self.assertRaises(OSError):PipeClient(Path(sys.executable).with_name('wrong.exe'),name=self.name).request(dict(method='GET',path='/api/check',headers={},body=''))
        with self.assertRaises(OSError):PipeClient(sys.executable,name=r'\\remote\pipe\Metakampo').request({})
    def test_standard_windows_identity_can_connect_without_local_administrator_membership(self):
        import ctypes,subprocess
        from ctypes import wintypes as W
        from security import generate_password
        username='mkipc'+uuid.uuid4().hex[:12];password=generate_password(24);sid=None;token=W.HANDLE();a=ctypes.WinDLL('advapi32',use_last_error=True);k=ctypes.WinDLL('kernel32',use_last_error=True)
        a.LogonUserW.argtypes=[W.LPCWSTR,W.LPCWSTR,W.LPCWSTR,W.DWORD,W.DWORD,ctypes.POINTER(W.HANDLE)];a.LogonUserW.restype=W.BOOL
        a.ImpersonateLoggedOnUser.argtypes=[W.HANDLE];a.ImpersonateLoggedOnUser.restype=W.BOOL;a.RevertToSelf.restype=W.BOOL;k.CloseHandle.argtypes=[W.HANDLE]
        script="$ErrorActionPreference='Stop';$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')+';'+$env:PSModulePath;Import-Module Microsoft.PowerShell.LocalAccounts;$r=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
        def run(command):
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script+command],input=json.dumps(dict(username=username,password=password,sid=sid)),text=True,capture_output=True)
            self.assertEqual(result.returncode,0,'CI local account setup/cleanup failed');return result.stdout.strip()
        try:
            sid=run("$p=[Security.SecureString]::new();foreach($c in $r.password.ToCharArray()){$p.AppendChar($c)};$u=New-LocalUser -Name $r.username -Password $p;Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-545') -Member $u;[Console]::Write($u.SID.Value)")
            self.assertTrue(a.LogonUserW(username,'.',password,2,0,ctypes.byref(token)),ctypes.get_last_error())
            self.assertTrue(a.ImpersonateLoggedOnUser(token))
            try:
                from shared_desktop import _native
                limited,_=_native()
                self.assertFalse(limited.OpenProcess(0x10,False,os.getpid()),'Standard users must not read host process memory')
                rogue=limited.CreateNamedPipeW(self.name,3,8,32,65536,65536,5000,None)
                if rogue!=ctypes.c_void_p(-1).value:limited.CloseHandle(rogue)
                self.assertEqual(rogue,ctypes.c_void_p(-1).value,'Clients must not create server instances')
                result=PipeClient(sys.executable,name=self.name).request(dict(method='GET',path='/api/check',headers={},body=''))
            finally:self.assertTrue(a.RevertToSelf())
            self.assertEqual(json.loads(base64.b64decode(result['body']))['sid'],sid)
        finally:
            if token:k.CloseHandle(token)
            if sid:run('Remove-LocalUser -SID ([Security.Principal.SecurityIdentifier]$r.sid)')
