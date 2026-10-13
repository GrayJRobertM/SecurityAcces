import io
import json
import sqlite3
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from app import create_app
from security import generate_password
from storage import connection
from user_sync import encrypt_package,decrypt_package,read_csv,csv_bytes


class SyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin=generate_password(24);cls.hash=generate_password_hash(cls.admin,method='pbkdf2:sha256:1000000')
    def setUp(self):
        self.folders=[];self.apps=[]
        self.app,self.client,self.csrf=self.instance()
        self.transfer=generate_password(32)
    def tearDown(self):
        for app in self.apps:
            for worker in app.sync_threads:worker.join(timeout=10)
        for folder in self.folders:folder.cleanup()
    def instance(self):
        folder=tempfile.TemporaryDirectory();self.folders.append(folder)
        app=create_app(dict(MODE='demo',DATA_DIR=folder.name,TESTING=True));self.apps.append(app)
        with connection(app.db_path) as db:db.execute('INSERT INTO admin VALUES(1,?)',(self.hash,))
        client=app.test_client();csrf=client.get('/api/session').json['csrf']
        login=client.post('/api/login',json=dict(username='admin',password=self.admin),headers={'X-CSRF-Token':csrf})
        return app,client,login.json['csrf']
    def post(self,path,data,client=None,csrf=None):
        return (client or self.client).post('/api/'+path,json=data,headers={'X-CSRF-Token':csrf or self.csrf})
    def create(self):
        reply=self.post('users',dict(name='Cuenta sincronizada',username='sync.user',department='TI'))
        self.assertEqual(reply.status_code,201)
        return reply.json['password']
    def export(self):
        reply=self.post('user-sync/export',dict(admin_password=self.admin,transfer_password=self.transfer,include_passwords=True))
        self.assertEqual(reply.status_code,200,reply.json)
        return reply.data
    def preview(self,raw,client=None,csrf=None,filename='users.fksync',transfer=None):
        return (client or self.client).post('/api/user-sync/preview',data=dict(file=(io.BytesIO(raw),filename),admin_password=self.admin,transfer_password=transfer or self.transfer),headers={'X-CSRF-Token':csrf or self.csrf})
    def wait(self,identifier,client=None):
        client=client or self.client
        for _ in range(100):
            result=client.get('/api/user-sync/jobs/'+identifier).json
            if result['status']!='aplicando':
                for app in self.apps:
                    for worker in app.sync_threads:worker.join(timeout=10)
                return result
            time.sleep(.02)
        self.fail('Import did not complete')

    def test_export_and_import_require_session_csrf_and_admin_password(self):
        self.create()
        self.assertEqual(self.app.test_client().post('/api/user-sync/export',json={}).status_code,403)
        self.assertEqual(self.post('user-sync/export',dict(admin_password='wrong',include_passwords=False)).status_code,403)
        self.assertEqual(self.client.post('/api/user-sync/preview',data=dict(admin_password='wrong'),headers={'X-CSRF-Token':self.csrf}).status_code,403)

    def test_encrypted_export_contains_only_available_passwords_and_no_plaintext(self):
        password=self.create();raw=self.export()
        self.assertNotIn(password.encode(),raw);self.assertNotIn(self.admin.encode(),raw);self.assertNotIn(self.transfer.encode(),raw)
        payload=decrypt_package(raw,self.transfer)
        self.assertEqual(len(payload['users']),1)
        self.assertEqual(payload['users'][0]['password'],password)
        with self.assertRaises(ValueError):decrypt_package(raw,generate_password(32))
        package=json.loads(raw);package['ciphertext']=package['ciphertext'][:-4]+'AAAA'
        with self.assertRaises(ValueError):decrypt_package(json.dumps(package).encode(),self.transfer)
        self.assertNotIn(password,self.client.get('/api/users').get_data(as_text=True))
        self.assertNotIn(password,self.client.get('/api/audit').get_data(as_text=True))
        self.assertNotIn(password.encode(),self.app.db_path.read_bytes())

    def test_cross_installation_import_keeps_the_password_without_copying_master_key(self):
        password=self.create();raw=self.export();target,client,csrf=self.instance()
        self.assertNotEqual(self.app.config['VAULT_KEY'],target.config['VAULT_KEY'])
        preview=self.preview(raw,client,csrf)
        self.assertEqual(preview.status_code,200,preview.json)
        self.assertNotIn(password,preview.get_data(as_text=True))
        self.assertEqual(preview.json['creates'],1)
        applied=self.post('user-sync/apply',dict(plan=preview.json['plan'],admin_password=self.admin),client,csrf)
        self.assertEqual(applied.status_code,202,applied.json)
        result=self.wait(applied.json['job'],client);self.assertEqual(result['status'],'completado')
        user=next(u for u in client.get('/api/users').json['users'] if u['username']=='sync.user')
        revealed=self.post('user-sync/password/'+user['id'],dict(admin_password=self.admin),client,csrf)
        self.assertEqual(revealed.json['password'],password)
        self.assertNotIn(password.encode(),target.db_path.read_bytes())
        self.assertEqual(self.post('user-sync/apply',dict(plan=preview.json['plan'],admin_password=self.admin),client,csrf).status_code,409)

    def test_preview_does_not_mutate_and_rechecks_admin_at_apply(self):
        self.create();raw=self.export();target,client,csrf=self.instance()
        preview=self.preview(raw,client,csrf)
        self.assertEqual(len(client.get('/api/users').json['users']),6)
        response=self.post('user-sync/apply',dict(plan=preview.json['plan'],admin_password='wrong'),client,csrf)
        self.assertEqual(response.status_code,403)
        self.assertEqual(len(client.get('/api/users').json['users']),6)

    def test_changed_directory_invalidates_preview(self):
        self.create();preview=self.preview(self.export())
        self.post('users',dict(name='Otra cuenta',username='otra',department='TI'))
        response=self.post('user-sync/apply',dict(plan=preview.json['plan'],admin_password=self.admin))
        self.assertEqual(response.status_code,409)

    def test_csv_roundtrip_and_spreadsheet_formula_escaping(self):
        users=[dict(username='-test',name='=SUM(1,2)',department="'TI",enabled=False)]
        raw=csv_bytes(users);self.assertIn(b"'=SUM",raw)
        parsed=read_csv(raw)
        self.assertEqual({field:parsed[0][field] for field in users[0]},users[0])
        with self.assertRaises(ValueError):read_csv(b'username,name,department,enabled,password\na,b,c,true,p\n')
        with self.assertRaises(ValueError):read_csv(b'username,name,department,enabled,username\na,b,c,true,d\n')

    def test_duplicate_accounts_and_duplicate_passwords_are_rejected(self):
        password=self.create();payload=decrypt_package(self.export(),self.transfer)
        payload['users'].append(dict(payload['users'][0],username='SYNC.USER'))
        self.assertEqual(self.preview(encrypt_package(payload,self.transfer)).status_code,400)
        payload['users'][-1]['username']='another'
        self.assertEqual(self.preview(encrypt_package(payload,self.transfer)).status_code,400)

    def test_missing_passwords_are_explicit_and_not_invented(self):
        response=self.post('user-sync/export',dict(admin_password=self.admin,transfer_password=self.transfer,include_passwords=True))
        self.assertEqual(response.status_code,409)
        response=self.post('user-sync/export',dict(admin_password=self.admin,include_passwords=False))
        self.assertEqual(response.status_code,200)
        self.assertNotIn(b'password',response.data)

    def test_shared_ad_stamp_imports_local_secret_without_resetting_domain_password(self):
        identifier=str(uuid.uuid4());domain=str(uuid.uuid4());password=generate_password(24)
        item=dict(username='sync.user',name='Cuenta',department='TI',enabled=True,password=password,source_id=identifier,domain_guid=domain,stamp='2:100:origin')
        raw=encrypt_package(dict(version=1,includes_passwords=True,users=[item]),self.transfer)
        self.app.config['MODE']='ad';calls=[]
        def ad(action,**kwargs):
            calls.append(action)
            if action=='list':return [dict(id=identifier,username='sync.user',name='Cuenta',department='TI',enabled=True)]
            if action=='stamps':return dict(domain_guid=domain,users=[dict(id=identifier,stamp='2:100:origin')])
            raise AssertionError('Shared AD credentials must not be reset')
        with patch('user_sync.call_ad',side_effect=ad):
            preview=self.preview(raw);self.assertEqual(preview.json['resets'],0)
            applied=self.post('user-sync/apply',dict(plan=preview.json['plan'],admin_password=self.admin));self.assertEqual(applied.status_code,202,applied.json)
            self.assertEqual(self.wait(applied.json['job'])['status'],'completado')
            self.assertEqual(self.post('user-sync/password/'+identifier,dict(admin_password=self.admin)).json['password'],password)
        self.assertNotIn('reset',calls)

    def test_password_version_changed_outside_app_is_not_exported(self):
        identifier=str(uuid.uuid4());domain=str(uuid.uuid4());password=generate_password(24)
        from user_sync import remember
        with connection(self.app.db_path) as db:remember(db,self.app.config['VAULT_KEY'],identifier,'external',password,domain,'old-version')
        self.app.config['MODE']='ad'
        def ad(action,**kwargs):
            if action=='list':return [dict(id=identifier,username='external',name='Cuenta',department='TI',enabled=True)]
            return dict(domain_guid=domain,users=[dict(id=identifier,stamp='new-version')])
        with patch('user_sync.call_ad',side_effect=ad):
            result=self.post('user-sync/export',dict(admin_password=self.admin,transfer_password=self.transfer,include_passwords=True))
        self.assertEqual(result.status_code,409)

    def test_stale_file_for_same_ad_is_rejected_without_reset(self):
        identifier=str(uuid.uuid4());domain=str(uuid.uuid4())
        item=dict(username='sync.user',name='Cuenta',department='TI',enabled=True,password=generate_password(24),source_id=identifier,domain_guid=domain,stamp='old')
        raw=encrypt_package(dict(version=1,includes_passwords=True,users=[item]),self.transfer)
        self.app.config['MODE']='ad'
        def ad(action,**kwargs):
            if action=='list':return [dict(id=identifier,username='sync.user',name='Cuenta',department='TI',enabled=True)]
            if action=='stamps':return dict(domain_guid=domain,users=[dict(id=identifier,stamp='new')])
            self.fail('Stale preview must not mutate AD')
        with patch('user_sync.call_ad',side_effect=ad):
            self.assertEqual(self.preview(raw).status_code,400)

    def test_password_reset_after_preview_requires_new_preview(self):
        self.create();raw=self.export();preview=self.preview(raw)
        user=next(user for user in self.client.get('/api/users').json['users'] if user['username']=='sync.user')
        self.post('users/'+user['id']+'/reset',{})
        result=self.post('user-sync/apply',dict(plan=preview.json['plan'],admin_password=self.admin))
        self.assertEqual(result.status_code,409)

    def test_csv_updates_attributes_and_disabled_state_without_changing_known_password(self):
        password=self.create()
        raw=csv_bytes([dict(username='sync.user',name='Nombre actualizado',department='',enabled=False)])
        preview=self.preview(raw,filename='users.csv')
        self.assertEqual(preview.status_code,200,preview.json)
        self.assertEqual(preview.json['resets'],0)
        applied=self.post('user-sync/apply',dict(plan=preview.json['plan'],admin_password=self.admin))
        self.assertEqual(self.wait(applied.json['job'])['status'],'completado')
        user=next(user for user in self.client.get('/api/users').json['users'] if user['username']=='sync.user')
        self.assertEqual(user['name'],'Nombre actualizado');self.assertFalse(user['enabled'])
        self.assertEqual(self.post('user-sync/password/'+user['id'],dict(admin_password=self.admin)).json['password'],password)


if __name__=='__main__':unittest.main()
