import base64
import io
import os
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from app import create_app
from desktop import Store,DesktopGate,setup_application,validate_settings
from directory import call_local,DirectoryError,DirectoryConflict
from security import generate_password
from storage import connection
from user_sync import encrypt_package,decrypt_package


class LocalModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password=generate_password(24)
        cls.admin_hash=generate_password_hash(cls.password,method='pbkdf2:sha256:1000000')
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        with patch.dict(os.environ,dict(FK_MASTER_KEY=base64.b64encode(os.urandom(32)).decode())):
            self.app=create_app(dict(MODE='local',DATA_DIR=self.folder.name,TESTING=True,DESKTOP=True))
        self.addCleanup(lambda:[thread.join(10) for thread in self.app.sync_threads])
        with connection(self.app.db_path) as db:db.execute('INSERT INTO admin VALUES(1,?)',(self.admin_hash,))
        self.client=self.app.test_client();csrf=self.client.get('/api/session').json['csrf']
        self.csrf=self.client.post('/api/login',json=dict(username='admin',password=self.password),headers={'X-CSRF-Token':csrf}).json['csrf']
        self.identifier='S-1-5-21-123-456-789-1001';self.scope='local:'+str(uuid.uuid4());self.stamp='10000000'
        self.users=[dict(id=self.identifier,username='local.user',name='Local user',department='TI',enabled=True,protected=False,upn='PILOT\\local.user')]
        self.mock=patch('app.call_local',side_effect=self.native);self.native_mock=self.mock.start();self.addCleanup(self.mock.stop)
    def native(self,action,**kwargs):
        if action=='list':return self.users
        if action=='inventory':return dict(users=self.users,source='windows-local',computer='PILOT',read_only=False,warnings=[])
        if action=='stamps':return dict(domain_guid=self.scope,users=[dict(id=u,stamp=self.stamp) for u in kwargs['identifiers']])
        if action in ('create','reset'):return dict(id=self.identifier,username='local.user',domain_guid=self.scope,stamp=self.stamp)
        return dict(id=self.identifier)
    def post(self,path,data):return self.client.post('/api/'+path,json=data,headers={'X-CSRF-Token':self.csrf})
    def test_local_mode_has_no_demo_users_and_routes_sid_to_local_adapter(self):
        self.assertEqual(self.client.get('/api/session').json['mode'],'local')
        self.assertEqual(self.client.get('/api/users').json['users'][0]['upn'],'PILOT\\local.user')
        with connection(self.app.db_path) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM users').fetchone()[0],0)
        result=self.post('users/'+self.identifier+'/reset',{})
        self.assertEqual(result.status_code,200)
        self.assertEqual(self.post('users/'+str(uuid.uuid4())+'/disable',{}).status_code,400)
        self.assertEqual(self.post('users',dict(name='Local user',username='local.user',department='TI')).status_code,201)
    def test_local_mode_is_desktop_only_and_requires_master_key(self):
        with self.assertRaises(ValueError):create_app(dict(MODE='local',DATA_DIR=self.folder.name))
        self.assertEqual(validate_settings(dict(mode='local',store='CurrentUser',server='ignored',ou='ignored',suffix='ignored'))['server'],'')
    def test_changed_password_is_never_exported_or_revealed(self):
        self.post('users/'+self.identifier+'/reset',{})
        key=generate_password(32)
        result=self.post('user-sync/export',dict(admin_password=self.password,transfer_password=key,include_passwords=True))
        self.assertEqual(result.status_code,200)
        self.assertEqual(decrypt_package(result.data,key)['users'][0]['source_id'],self.identifier)
        self.stamp='20000000'
        self.assertEqual(self.post('user-sync/export',dict(admin_password=self.password,transfer_password=key,include_passwords=True)).status_code,409)
        self.assertEqual(self.post('user-sync/password/'+self.identifier,dict(admin_password=self.password)).status_code,409)
    def test_protected_accounts_cannot_be_imported_and_are_excluded_from_csv(self):
        self.users[0]['protected']=True
        result=self.post('user-sync/export',dict(admin_password=self.password,include_passwords=False))
        self.assertNotIn(b'local.user',result.data)
        raw=b'username,name,department,enabled\nlocal.user,Local user,TI,true\n'
        result=self.client.post('/api/user-sync/preview',data=dict(file=(io.BytesIO(raw),'users.csv'),admin_password=self.password),headers={'X-CSRF-Token':self.csrf})
        self.assertEqual(result.status_code,400)
        self.assertIn('protegida',result.json['error'])
    def test_import_between_local_machines_restores_password_after_explicit_preview(self):
        key=generate_password(32);secret=generate_password(24)
        raw=encrypt_package(dict(version=1,includes_passwords=True,users=[dict(username='local.user',name='Local user',department='TI',enabled=True,password=secret,source_id='S-1-5-21-1-2-3-1001',domain_guid='local:other',stamp='old')]),key)
        result=self.client.post('/api/user-sync/preview',data=dict(file=(io.BytesIO(raw),'users.fksync'),admin_password=self.password,transfer_password=key),headers={'X-CSRF-Token':self.csrf})
        self.assertEqual(result.status_code,200);self.assertEqual(result.json['resets'],1)
        self.assertNotIn(secret,result.get_data(as_text=True))
        applied=self.post('user-sync/apply',dict(plan=result.json['plan'],admin_password=self.password))
        self.assertEqual(applied.status_code,202)
        for thread in self.app.sync_threads:thread.join(10)
        self.assertEqual(self.client.get('/api/user-sync/jobs/'+applied.json['job']).json['status'],'completado')
        self.assertTrue(any(call.args[0]=='reset' for call in self.native_mock.call_args_list))
        self.assertEqual(self.post('user-sync/password/'+self.identifier,dict(admin_password=self.password)).json['password'],secret)


class ModeSwitchTests(unittest.TestCase):
    def test_authenticated_switch_preserves_old_database_and_master_key(self):
        with tempfile.TemporaryDirectory() as folder,patch('desktop.machine_identity',return_value=dict(machine='test',sid='S-1-5-21-1')),patch('desktop.restrict_folder'),patch('desktop.dpapi',side_effect=lambda value,decrypt=False:value):
            store=Store(folder);gate=DesktopGate(None);setup=setup_application(store,gate,lambda app:None);setup.config['SERVER_NAME']='127.0.0.1';client=setup.test_client()
            csrf=client.get('/desktop/settings').json['csrf'];password=generate_password(24)
            headers={'X-CSRF-Token':csrf};body=dict(mode='demo',store='CurrentUser',password=password,confirmation=password)
            self.assertEqual(client.post('/desktop/settings',json=body,headers=headers).status_code,200)
            key=store.values['key'];old_db=gate.application.db_path
            with connection(old_db) as db:db.execute("INSERT INTO vault(id,title,username,secret) VALUES('old','Keep','test',X'00')")
            with patch('directory.call_local',return_value=dict(local=True)):
                self.assertEqual(client.post('/desktop/settings',json=dict(body,mode='local',password='wrong'),headers=headers).status_code,403)
                self.assertEqual(client.post('/desktop/settings',json=dict(body,mode='local'),headers=headers).status_code,200)
            self.assertEqual(store.values['key'],key);self.assertNotEqual(old_db,gate.application.db_path)
            self.assertEqual(client.post('/desktop/settings',json=body,headers=headers).status_code,200)
            with connection(gate.application.db_path) as db:self.assertEqual(db.execute('SELECT title FROM vault').fetchone()[0],'Keep')


@unittest.skipUnless(os.name=='nt' and os.environ.get('FK_NATIVE_LOCAL_TESTS')=='1','Native SAM tests run only in explicitly enabled Windows CI')
class NativeLocalTests(unittest.TestCase):
    def test_create_reset_disable_stamp_and_admin_protection_on_windows(self):
        import subprocess,json
        username='mkci'+uuid.uuid4().hex[:12];identifier=None
        try:
            check=call_local('check');self.assertTrue(check['local'])
            before=call_local('inventory');self.assertTrue(before['users']);self.assertEqual(before['source'],'windows-local')
            created=call_local('create',username=username,name='Metakampo CI test',department='Disposable CI account',password=generate_password(24))
            identifier=created['id'];self.assertTrue(identifier.startswith('S-1-5-21-'));self.assertTrue(created['stamp'])
            with self.assertRaises(DirectoryConflict):call_local('create',username=username,name='Duplicate',department='CI',password=generate_password(24))
            stamps=call_local('stamps',identifiers=[identifier]);self.assertEqual(stamps['users'][0]['stamp'],created['stamp'])
            time.sleep(1.1)
            changed=call_local('reset',identifier=identifier,password=generate_password(24));self.assertNotEqual(created['stamp'],changed['stamp'])
            call_local('disable',identifier=identifier)
            inventory=call_local('inventory');users=inventory['users']
            self.assertTrue({user['id'] for user in before['users']}.issubset({user['id'] for user in users}))
            user=next(user for user in users if user['id']==identifier)
            self.assertFalse(user['enabled']);self.assertFalse(user['protected']);self.assertTrue(user['upn'].endswith('\\'+username))
            protected=next(user for user in users if user['protected'])
            with self.assertRaises(DirectoryError):call_local('disable',identifier=protected['id'])
        finally:
            if identifier:
                # Cleanup only this newly created CI account, never existing accounts.
                command="$request=[Console]::In.ReadToEnd()|ConvertFrom-Json;Remove-LocalUser -SID ([Security.Principal.SecurityIdentifier]$request.sid) -ErrorAction Stop"
                result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],input=json.dumps(dict(sid=identifier)),text=True,capture_output=True)
                self.assertEqual(result.returncode,0,'CI account cleanup failed')

    def test_existing_inventory_survives_unresolvable_administrator_members(self):
        import subprocess,json
        from pathlib import Path
        script=Path(__file__).resolve().parents[1]/'windows'/'local-directory.ps1'
        with tempfile.TemporaryDirectory() as folder:
            wrapper=Path(folder)/'inventory-test.ps1'
            wrapper.write_text("param([string]$Script)\nfunction global:Get-LocalGroup {throw 'CI simulated local group access failure'}\n& $Script\n")
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(wrapper),'-Script',str(script)],input=json.dumps(dict(action='inventory')),text=True,encoding='utf-8',capture_output=True)
            self.assertEqual(result.returncode,0,'Inventory must not fail when group lookup fails')
            data=json.loads(result.stdout.lstrip('\ufeff'))['data']
            self.assertTrue(data['users']);self.assertTrue(data['read_only']);self.assertTrue(data['warnings'])
            self.assertTrue(all(user['protected'] for user in data['users']))

    def test_inventory_avoids_wmi_and_account_name_resolution(self):
        import subprocess,json
        from pathlib import Path
        script=Path(__file__).resolve().parents[1]/'windows'/'local-directory.ps1'
        with tempfile.TemporaryDirectory() as folder:
            wrapper=Path(folder)/'fast-inventory.ps1'
            wrapper.write_text("param([string]$Script)\nfunction global:Get-CimInstance {throw 'WMI must not be called'}\nfunction global:Get-LocalGroupMember {throw 'Name resolution must not be called'}\n& $Script\n")
            started=time.monotonic()
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(wrapper),'-Script',str(script)],input=json.dumps(dict(action='inventory')),text=True,encoding='utf-8',capture_output=True,timeout=30)
            self.assertLess(time.monotonic()-started,30)
            data=json.loads(result.stdout.lstrip('\ufeff'))
            self.assertTrue(data['ok']);self.assertTrue(data['data']['users']);self.assertFalse(data['data']['read_only'])
            self.assertTrue(all(user['lock_state_known'] is False for user in data['data']['users']))


class LocalTransportTests(unittest.TestCase):
    def test_known_startup_errors_are_specific_and_never_echo_sensitive_output(self):
        from directory import local_response
        from types import SimpleNamespace
        secret='synthetic-sensitive-value'
        for stderr,code in [('PSSecurityException about_Execution_Policies','PS_POLICY'),('Microsoft.PowerShell.LocalAccounts failed module load','PS_MODULES'),('Unexpected startup failure','PS_RESPONSE')]:
            with self.assertRaises(DirectoryError) as caught:local_response(SimpleNamespace(stdout='',stderr=stderr+' '+secret,returncode=1))
            self.assertIn(code,str(caught.exception));self.assertNotIn(secret,str(caught.exception))
        with self.assertRaises(DirectoryConflict):local_response(SimpleNamespace(stdout='{"ok":false,"exception":"Microsoft.PowerShell.Commands.UserExistsException"}',stderr='',returncode=1))
        self.assertEqual(local_response(SimpleNamespace(stdout='\ufeff{"ok":true,"data":[{"username":"existing"}]}',stderr='',returncode=0))[0]['username'],'existing')
    def test_local_powershell_uses_system_64_bit_location_not_path(self):
        from directory import local_powershell_path
        with patch.dict(os.environ,dict(SystemRoot='C:\\Windows'),clear=True):
            self.assertTrue(local_powershell_path().endswith('System32\\WindowsPowerShell\\v1.0\\powershell.exe'))
        with patch.dict(os.environ,dict(SystemRoot='C:\\Windows',PROCESSOR_ARCHITEW6432='AMD64'),clear=True):
            self.assertIn('Sysnative',local_powershell_path())
