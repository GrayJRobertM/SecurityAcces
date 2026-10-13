import io
import json
import os
import sqlite3
from storage import connection
import tempfile
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from zipfile import ZipFile
from werkzeug.security import generate_password_hash
from app import create_app
from rdp import make_package, profile_bytes, validate_connection, portal_url, RDPError, signed_files
from security import generate_password, unseal

class RDPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin=generate_password(24)
        cls.admin_hash=generate_password_hash(cls.admin,method='pbkdf2:sha256:1000000')
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({'DATA_DIR':self.temp.name,'MODE':'demo','TESTING':True})
        with connection(self.app.db_path) as db:db.execute('INSERT INTO admin VALUES(1,?)',(self.admin_hash,))
        self.client=self.app.test_client()
        csrf=self.client.get('/api/session').json['csrf']
        result=self.client.post('/api/login',json={'username':'admin','password':self.admin},headers={'X-CSRF-Token':csrf})
        self.csrf=result.json['csrf']
        self.code=generate_password(24)
        self.rdp_password=generate_password(20)
        self.payload={'host':'srv-rdp.example.test','username':'EMPRESA\\usuario','port':3389,
                      'admin_password':self.admin,'activation_code':self.code,'account_password':self.rdp_password}
    def tearDown(self):self.temp.cleanup()
    def post(self,path,data=None,https=False):
        return self.client.post('/api/'+path,json=data or {},headers={'X-CSRF-Token':self.csrf},environ_overrides={'wsgi.url_scheme':'https' if https else 'http'})
    def provision(self):
        self.app.config['MODE']='ad'
        captured={}
        def builder(host,username,port,configuration):
            captured.update(configuration)
            self.assertNotIn('password',configuration)
            self.assertNotIn('code',configuration)
            with patch('rdp.signed_files',return_value=(profile_bytes(host,username,port),b'# signing mocked for unit test')):
                return make_package(host,username,port,configuration=configuration)
        with patch.dict(os.environ,{'FK_RDP_PORTAL_URL':'https://access.example.test'}),patch('app.make_package',side_effect=builder):
            result=self.post('rdp/package',self.payload,https=True)
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.headers['X-RDP-Signed'],'true')
        return captured['id'],result.data
    def redeem(self,identifier,code=None,https=True,client=None):
        return (client or self.app.test_client()).post('/api/rdp/redeem',json={'id':identifier,'code':code or self.code},environ_overrides={'wsgi.url_scheme':'https' if https else 'http'})
    def test_profile_preserves_nla_and_authentication(self):
        text=profile_bytes('SRV.EXAMPLE.TEST','EMPRESA\\user',3390).decode('utf-16')
        self.assertIn('full address:s:srv.example.test:3390',text)
        self.assertIn('authentication level:i:1',text)
        self.assertIn('enablecredsspsupport:i:1',text)
        self.assertNotIn('password 51',text)
        self.assertEqual(text.count('full address:'),1)
    def test_connection_injection_and_invalid_fields_rejected(self):
        for host in ('host\r\nfull address:s:evil','evil/path','host:3389',' host','$(whoami)','foo..bar'):
            with self.assertRaises(ValueError):validate_connection(host,'EMPRESA\\user')
        for username in ('user','DOM\\u\r\nredirectclipboard:i:1','DOMAIN\\a\\b','a@b x'):
            with self.assertRaises(ValueError):validate_connection('host',username)
        for port in (-1,65536,True,'3389'):
            with self.assertRaises(ValueError):validate_connection('host','DOMAIN\\user',port)
    def test_demo_package_never_claims_signature_or_embeds_secrets(self):
        response=self.post('rdp/package',self.payload)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.headers['X-RDP-Signed'],'false')
        with ZipFile(io.BytesIO(response.data)) as z:
            self.assertNotIn('Conectar.ps1',z.namelist())
            for name in z.namelist():
                data=z.read(name)
                self.assertNotIn(self.rdp_password.encode(),data)
                self.assertNotIn(self.code.encode(),data)
                self.assertNotIn(self.rdp_password.encode('utf-16-le'),data)
        with connection(self.app.db_path) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM rdp_clients').fetchone()[0],0)
    def test_package_requires_authentication_csrf_and_https(self):
        anonymous=self.app.test_client()
        self.assertEqual(anonymous.get('/api/rdp/clients').status_code,401)
        self.assertEqual(self.client.post('/api/rdp/package',json=self.payload).status_code,403)
        self.app.config['MODE']='ad'
        self.assertEqual(self.post('rdp/package',self.payload).status_code,403)
        bad=dict(self.payload,admin_password='wrong')
        self.assertEqual(self.post('rdp/package',bad,https=True).status_code,403)
    def test_signing_failure_leaves_no_delivery_credential(self):
        self.app.config['MODE']='ad'
        with patch.dict(os.environ,{'FK_RDP_PORTAL_URL':'https://access.example.test'}),patch('app.make_package',side_effect=RDPError('Firma no disponible')):
            response=self.post('rdp/package',self.payload,https=True)
        self.assertEqual(response.status_code,503)
        with connection(self.app.db_path) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM rdp_clients').fetchone()[0],0)
    def test_activation_is_encrypted_and_one_use_without_admin_session(self):
        identifier,archive=self.provision()
        with ZipFile(io.BytesIO(archive)) as z:
            for name in z.namelist():
                self.assertNotIn(self.rdp_password.encode(),z.read(name))
                self.assertNotIn(self.code.encode(),z.read(name))
        with connection(self.app.db_path) as db:
            secret,code_hash=db.execute('SELECT secret,code_hash FROM rdp_clients WHERE id=?',(identifier,)).fetchone()
        self.assertNotIn(self.rdp_password.encode(),secret)
        self.assertNotIn(self.code,code_hash)
        self.assertEqual(json.loads(unseal(self.app.config['VAULT_KEY'],identifier,secret))['password'],self.rdp_password)
        self.assertEqual(self.redeem(identifier,generate_password(24)).status_code,403)
        response=self.redeem(identifier)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['password'],self.rdp_password)
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.assertEqual(self.redeem(identifier).status_code,403)
        with connection(self.app.db_path) as db:self.assertIsNone(db.execute('SELECT secret FROM rdp_clients WHERE id=?',(identifier,)).fetchone()[0])
        listing=self.client.get('/api/rdp/clients').json
        self.assertNotIn(self.rdp_password,json.dumps(listing))
        self.assertNotIn(self.code,json.dumps(self.client.get('/api/audit').json))
    def test_activation_https_origin_and_expiration(self):
        identifier,_=self.provision()
        self.assertEqual(self.redeem(identifier,https=False).status_code,403)
        browser=self.app.test_client()
        self.assertEqual(browser.post('/api/rdp/redeem',json={'id':identifier,'code':self.code},headers={'Origin':'https://evil.example'},environ_overrides={'wsgi.url_scheme':'https'}).status_code,403)
        with connection(self.app.db_path) as db:db.execute('UPDATE rdp_clients SET expires=? WHERE id=?',(time.time()-1,identifier))
        self.assertEqual(self.redeem(identifier).status_code,403)
        with connection(self.app.db_path) as db:self.assertIsNone(db.execute('SELECT secret FROM rdp_clients WHERE id=?',(identifier,)).fetchone()[0])
    def test_activation_can_be_revoked(self):
        identifier,_=self.provision()
        self.assertEqual(self.post('rdp/clients/'+identifier+'/revoke').status_code,200)
        self.assertEqual(self.redeem(identifier).status_code,403)
        self.assertEqual(self.client.get('/api/rdp/clients').json['clients'][0]['status'],'revocado')
    def test_concurrent_redemption_cannot_return_two_credentials(self):
        identifier,_=self.provision()
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses=list(pool.map(lambda _:self.redeem(identifier).status_code,range(2)))
        self.assertEqual(sorted(statuses),[200,403])
    def test_activation_attempts_limited(self):
        identifier,_=self.provision()
        for _ in range(5):self.assertEqual(self.redeem(identifier,generate_password(24)).status_code,403)
        self.assertEqual(self.redeem(identifier).status_code,429)
    def test_portal_must_be_a_trusted_https_origin(self):
        for value in ('http://example.test','https://user:secret@example.test','https://example.test/path','https://example.test?query=1'):
            with patch.dict(os.environ,{'FK_RDP_PORTAL_URL':value}):
                with self.assertRaises(RDPError):portal_url()
    def test_native_signer_fails_closed_on_non_windows(self):
        with patch('rdp.os.name','posix'):
            with self.assertRaises(RDPError):signed_files(profile_bytes('host','DOMAIN\\user'),{})

if __name__=='__main__':unittest.main()
