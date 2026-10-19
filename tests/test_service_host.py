import base64
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from app import create_app
from storage import connection
from updater import UpdateManager
from service_host import wait_for_pipe

class ServiceClientTests(unittest.TestCase):
    def test_ready_probe_requires_healthy_application(self):
        class Client:
            def request(self,data):return dict(status=200)
        wait_for_pipe(Client(),timeout=.1)
        class Unready:
            def request(self,data):return dict(status=503)
        with self.assertRaisesRegex(OSError,'servicio'):wait_for_pipe(Unready(),timeout=0)

class ServiceUpdatesTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.manager=UpdateManager(self.folder.name);self.manager.service_host=True;self.manager.owner_sid='S-owner'
        self.app=create_app(dict(MODE='demo',DATA_DIR=self.folder.name,TESTING=True,DESKTOP=True,UPDATE_MANAGER=self.manager))
        with connection(self.app.db_path) as db:db.execute('INSERT INTO admin VALUES(1,?)',(generate_password_hash('test',method='pbkdf2:sha256:1000000'),))
        self.client=self.app.test_client();csrf=self.client.get('/api/session').json['csrf']
        self.csrf=self.client.post('/api/login',json=dict(username='admin',password='test'),headers={'X-CSRF-Token':csrf}).json['csrf']
    @contextmanager
    def scope(self):yield
    def test_shared_owner_sid_can_update_without_owner_window_but_other_sessions_cannot(self):
        for sid,allowed in [('S-owner',True),('S-other',False)]:
            with patch('windows_native.current_sid',return_value=sid),patch.object(self.manager,'check') as check:
                env={'metakampo.shared_client':True,'metakampo.impersonate':self.scope}
                self.assertEqual(self.client.get('/api/updates/status',environ_overrides=env).json['owner'],allowed)
                response=self.client.post('/api/updates/check',headers={'X-CSRF-Token':self.csrf},environ_overrides=env,json={})
                self.assertEqual(response.status_code,202 if allowed else 403)
                self.assertEqual(check.called,allowed)
    def test_shared_claim_without_native_impersonation_is_not_owner(self):
        self.assertFalse(self.client.get('/api/updates/status',environ_overrides={'metakampo.shared_client':True}).json['owner'])

import os
@unittest.skipUnless(os.name=='nt','Windows service API availability')
class WindowsServiceAPITests(unittest.TestCase):
    def test_installed_scm_security_and_profile_apis_exist(self):
        import win32security,win32service,win32profile,servicemanager
        for module,names in [(win32security,['LsaOpenPolicy','LsaAddAccountRights','LsaClose','LogonUser']),(win32service,['CreateService','ChangeServiceConfig','QueryServiceStatusEx']),(win32profile,['LoadUserProfile','UnloadUserProfile']),(servicemanager,['Initialize','PrepareToHostSingle','StartServiceCtrlDispatcher'])]:
            for name in names:self.assertTrue(callable(getattr(module,name)))
