import tempfile
import unittest
from werkzeug.security import generate_password_hash
from app import create_app
from storage import connection

class OperatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.password='Initial-Admin-Password-91!';cls.hash=generate_password_hash(cls.password,method='pbkdf2:sha256:1000000')
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.app=create_app(dict(MODE='demo',DATA_DIR=self.folder.name,TESTING=True))
        with connection(self.app.db_path) as db:db.execute('INSERT INTO admin VALUES(1,?)',(self.hash,))
        self.client=self.app.test_client();self.login(self.client,'admin',self.password)
    def login(self,client,user,password):
        csrf=client.get('/api/session').json['csrf'];result=client.post('/api/login',json=dict(username=user,password=password),headers={'X-CSRF-Token':csrf})
        self.assertEqual(result.status_code,200,result.json);return result
    def post(self,client,path,data):
        csrf=client.get('/api/session').json['csrf'];return client.post('/api/'+path,json=data,headers={'X-CSRF-Token':csrf})
    def add(self):
        result=self.post(self.client,'operators',dict(username='soporte',name='Soporte',admin_password=self.password))
        self.assertEqual(result.status_code,201,result.json);return result.json['password']
    def test_individual_login_own_reauthentication_and_attributed_audit(self):
        password=self.add();other=self.app.test_client();self.login(other,'SOPORTE',password)
        self.assertEqual(other.get('/api/session').json['username'],'soporte')
        value=self.post(other,'vault',dict(title='Test',username='service')).json
        self.assertEqual(self.post(other,'vault/'+value['id']+'/reveal',dict(password=self.password)).status_code,403)
        self.assertEqual(self.post(other,'vault/'+value['id']+'/reveal',dict(password=password)).json['password'],value['password'])
        events=other.get('/api/audit').json['events'];self.assertTrue(any(e['actor']=='soporte' and e['action']=='crear credencial' for e in events))
        self.assertNotIn(password,str(events))
        exported=self.post(other,'user-sync/export',dict(admin_password=password,include_passwords=False));self.assertEqual(exported.status_code,200)
        self.assertEqual(self.post(other,'operators',dict(username='tercero',name='Otro',admin_password=password)).status_code,201)
    def test_disable_and_reset_revoke_all_existing_sessions(self):
        password=self.add();other=self.app.test_client();self.login(other,'soporte',password)
        result=self.post(self.client,'operators/soporte/status',dict(enabled=False,admin_password=self.password));self.assertEqual(result.status_code,200)
        self.assertEqual(other.get('/api/users').status_code,401);self.assertFalse(other.get('/api/session').json['authenticated'])
        self.post(self.client,'operators/soporte/status',dict(enabled=True,admin_password=self.password));self.login(other,'soporte',password)
        result=self.post(self.client,'operators/soporte/reset',dict(admin_password=self.password));self.assertEqual(result.status_code,200)
        self.assertEqual(other.get('/api/users').status_code,401)
        self.login(other,'soporte',result.json['password'])
    def test_operator_creation_and_reserved_accounts_are_guarded(self):
        self.assertEqual(self.post(self.client,'operators',dict(username='soporte',name='Soporte',admin_password='wrong')).status_code,403)
        self.assertEqual(self.post(self.client,'operators',dict(username='admin',name='Admin',admin_password=self.password)).status_code,400)
        password=self.add();other=self.app.test_client();self.login(other,'soporte',password)
        self.assertEqual(self.post(other,'operators/soporte/status',dict(enabled=False,admin_password=password)).status_code,400)
        self.assertEqual(self.post(other,'operators/admin/reset',dict(admin_password=password)).status_code,400)
        self.assertEqual(self.app.test_client().get('/api/operators').status_code,401)
