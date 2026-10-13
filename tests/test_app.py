import json
import sqlite3
from storage import connection
import tempfile
import unittest
from unittest.mock import patch
from cryptography.exceptions import InvalidTag
from werkzeug.security import generate_password_hash
from app import create_app
from security import generate_password, seal, unseal, CATEGORIES

class AccessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({'TESTING':True,'DATA_DIR':self.temp.name,'MODE':'demo'})
        self.password=generate_password(24)
        with connection(self.app.db_path) as db:
            db.execute('INSERT INTO admin VALUES (1,?)',(generate_password_hash(self.password, method="pbkdf2:sha256:1000000"),))
        self.client=self.app.test_client()
        self.csrf=self.client.get('/api/session').json['csrf']
    def tearDown(self): self.temp.cleanup()
    def post(self,path,data=None):
        return self.client.post('/api/'+path,json=data or {},headers={'X-CSRF-Token':self.csrf})
    def login(self):
        response=self.post('login',{'username':'admin','password':self.password})
        self.assertEqual(response.status_code,200)
        self.csrf=response.json['csrf']
    def test_authentication_csrf_and_logout(self):
        self.assertEqual(self.client.get('/api/vault').status_code,401)
        self.assertEqual(self.client.post('/api/login',json={}).status_code,403)
        self.login()
        self.assertEqual(self.client.get('/api/users').status_code,200)
        self.post('logout')
        self.assertEqual(self.client.get('/api/users').status_code,401)
    def test_login_rate_limit(self):
        for _ in range(5): self.assertEqual(self.post('login',{'username':'admin','password':'wrong'}).status_code,401)
        self.assertEqual(self.post('login',{'username':'admin','password':self.password}).status_code,429)
    def test_random_password_quality(self):
        values=[generate_password() for _ in range(2000)]
        self.assertEqual(len(set(values)),len(values))
        for value in values:
            self.assertEqual(len(value),15)
            self.assertTrue(all(any(c in group for c in value) for group in CATEGORIES))
    def test_collision_is_rejected(self):
        self.login()
        first=generate_password()
        second=generate_password()
        with patch('app.generate_password',side_effect=[first,first,second]):
            self.assertEqual(self.post('generate').json['password'],first)
            self.assertEqual(self.post('generate').json['password'],second)
        with connection(self.app.db_path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM issued').fetchone()[0],2)
    def test_vault_is_encrypted_and_reauthenticated(self):
        self.login()
        response=self.post('vault',{'title':'Servicio de prueba','username':'servicio'})
        self.assertEqual(response.status_code,201)
        identifier,password=response.json['id'],response.json['password']
        self.assertNotIn(password,json.dumps(self.client.get('/api/vault').json))
        self.assertEqual(self.post('vault/'+identifier+'/reveal',{'password':'invalid'}).status_code,403)
        self.assertEqual(self.post('vault/'+identifier+'/reveal',{'password':self.password}).json['password'],password)
        self.assertNotIn(password,json.dumps(self.client.get('/api/audit').json))
        self.assertNotIn(password.encode(),self.app.db_path.read_bytes())
        key=self.app.config['VAULT_KEY']
        encrypted=seal(key,'id',password)
        with self.assertRaises(InvalidTag): unseal(key,'different-id',encrypted)
        with self.assertRaises(InvalidTag): unseal(key,'id',encrypted[:-1]+bytes([encrypted[-1]^1]))
    def test_create_and_disable_demo_user(self):
        self.login()
        response=self.post('users',{'name':'Prueba','username':'prueba','department':'TI'})
        self.assertEqual(response.status_code,201)
        self.assertEqual(len(response.json['password']),15)
        users=self.client.get('/api/users').json['users']
        identifier=next(u['id'] for u in users if u['username']=='prueba')
        self.assertEqual(self.post('users/'+identifier+'/disable').status_code,200)
        user=next(u for u in self.client.get('/api/users').json['users'] if u['id']==identifier)
        self.assertFalse(user['enabled'])
        self.assertEqual(self.post('users',{'name':'Prueba','username':'prueba','department':'TI'}).status_code,409)
    def test_policy_limits_and_persistence(self):
        self.login()
        for invalid in (14,65,'15',True):self.assertEqual(self.post('policy',{'length':invalid}).status_code,400)
        self.assertEqual(self.post('policy',{'length':20}).status_code,200)
        self.assertEqual(len(self.post('generate').json['password']),20)
        app2=create_app({'TESTING':True,'DATA_DIR':self.temp.name,'MODE':'demo'})
        self.assertEqual(app2.config['VAULT_KEY'],self.app.config['VAULT_KEY'])
    def test_headers_and_host_check(self):
        response=self.client.get('/')
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])
        response.close()
        self.assertEqual(self.client.get('/api/session',headers={'Host':'evil.example'}).status_code,400)
    def test_forms_do_not_submit_secrets_in_urls(self):
        from html.parser import HTMLParser
        from pathlib import Path
        class Forms(HTMLParser):
            methods=[]
            def handle_starttag(self, tag, attrs):
                if tag=='form':self.methods.append(dict(attrs).get('method','get'))
        parser=Forms()
        parser.feed((Path(__file__).parents[1]/'static'/'index.html').read_text(encoding='utf-8'))
        self.assertTrue(parser.methods)
        self.assertTrue(all(m=='post' for m in parser.methods))

    def test_non_windows_ad_fails_closed(self):
        from directory import call_ad,DirectoryError
        with patch('directory.os.name','posix'):
            with self.assertRaises(DirectoryError):call_ad('reset',identifier='test')
    def test_ad_adapter_contract_without_domain_mutations(self):
        self.login()
        self.app.config['MODE']='ad'
        identifier='c53a72bc-6ed2-4eb9-9a2a-cc5882874ad9'
        with patch('app.call_ad',return_value={}) as adapter:
            response=self.post('users/'+identifier+'/reset')
            self.assertEqual(response.status_code,200)
            adapter.assert_called_once_with('reset',identifier=identifier,password=response.json['password'])
        with patch('app.call_ad') as adapter:
            self.assertEqual(self.post('users/not-a-guid/reset').status_code,400)
            adapter.assert_not_called()

if __name__=='__main__': unittest.main()
