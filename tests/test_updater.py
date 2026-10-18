import base64
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch,Mock
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from werkzeug.security import generate_password_hash
from app import create_app
from storage import connection
import updater as u

class SignatureTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
  cls.public=cls.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
 def manifest(self,**extra):
  value=dict(schema=1,version='1.9.0',tag='metakampo-v1.9.0',platform='windows-x64',asset=u.ASSET,size=6,sha256=hashlib.sha256(b'MZtest').hexdigest(),published_at=int(time.time()));value.update(extra);return value
 def signed(self,value):
  payload=json.dumps(value).encode();return json.dumps(dict(payload=base64.b64encode(payload).decode(),signature=base64.b64encode(self.key.sign(payload,padding.PKCS1v15(),hashes.SHA256())).decode())).encode()
 def test_signature_tamper_foreign_key_and_strict_fields(self):
  raw=self.signed(self.manifest());self.assertEqual(u.verified_manifest(raw,self.public)['version'],'1.9.0')
  for data in [raw.replace(b'payload',b'payloae'),raw+b'x',b'x'*32769,self.signed(self.manifest(size=True)),self.signed(self.manifest(version='1.09.0')),self.signed(self.manifest(asset='other.exe')),self.signed(self.manifest(tag='other')),self.signed(self.manifest(platform='other')),self.signed(self.manifest(extra='injected')),self.signed(self.manifest(published_at=int(time.time())+90000))]:
   with self.assertRaises(u.UpdateError):u.verified_manifest(data,self.public)
  with self.assertRaises(u.UpdateError):u.verified_manifest(raw) # foreign key never trusted
  envelope=json.loads(raw);payload=json.loads(base64.b64decode(envelope['payload']));payload['version']='9.0.0';envelope['payload']=base64.b64encode(json.dumps(payload).encode()).decode()
  with self.assertRaises(u.UpdateError):u.verified_manifest(json.dumps(envelope).encode(),self.public)
 def test_package_rejects_truncated_modified_non_pe_and_excess(self):
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/'setup.exe'
   for value in [b'MZtest',b'MZtes',b'MZtess',b'XXtest',b'MZtestx']:
    path.write_bytes(value)
    if value==b'MZtest':u.verify_package(path,self.manifest())
    else:
     with self.assertRaises(u.UpdateError):u.verify_package(path,self.manifest())
 def test_sources_are_https_and_pinned(self):
  for url in ['http://github.com/a','https://evil.test/a','https://github.com@evil.test/a','https://github.com:444/a','file:///tmp/a']:
   with self.assertRaises(u.UpdateError):u.check_url(url)
  with self.assertRaises(u.UpdateError):u.asset_url('../../other','setup.exe')
  u.check_url(u.asset_url('metakampo-v1.9.0',u.ASSET))
 def test_check_download_and_no_version_rollback(self):
  with tempfile.TemporaryDirectory() as folder:
   manifest=self.manifest();raw=self.signed(manifest)
   manager=u.UpdateManager(folder,root=folder,current='1.8.0',reader=lambda url,limit:json.dumps(dict(draft=False,prerelease=False,tag_name=manifest['tag'])).encode() if url==u.API else raw,opener=lambda url:io.BytesIO(b'MZtest'))
   verify=lambda raw:u.verified_manifest_original(raw,self.public)
   with patch.object(u,'verified_manifest_original',u.verified_manifest,create=True),patch.object(u,'verified_manifest',side_effect=verify),patch.object(u,'secure_stage',return_value=Path(folder)):
    manager.check();manager.thread.join(5);self.assertEqual(manager.phase,'available')
    manager.download();manager.thread.join(5);self.assertEqual(manager.phase,'ready',manager.message)
    with self.assertRaises(u.UpdateError):manager.check()
    self.assertNotIn('@@PUBLIC_XML@@',(Path(folder)/'Apply-Update.ps1').read_text(encoding='utf-8-sig'))
    manager.current='1.9.0'
    with self.assertRaises(u.UpdateError):manager._download()
 def test_failed_preparation_resumes_without_executing(self):
  with tempfile.TemporaryDirectory() as folder:
   stage=Path(folder);manifest=self.manifest();(stage/u.ASSET).write_bytes(b'MZtest');(stage/u.ENVELOPE).write_bytes(self.signed(manifest))
   manager=u.UpdateManager(folder,root=folder);manager.latest=manifest;manager.stage=stage;manager.phase='ready';manager.prepare=Mock(side_effect=u.UpdateError('Importación activa'));manager.resume=Mock();manager.close=Mock()
   original=u.verified_manifest
   with patch.object(u,'verified_manifest',side_effect=lambda raw:original(raw,self.public)),patch.object(u.subprocess,'Popen') as execute:
    manager.apply('1.9.0');manager.thread.join(5);self.assertEqual(manager.phase,'error');self.assertFalse(manager.draining);manager.resume.assert_called_once();execute.assert_not_called();manager.close.assert_not_called()
 def test_busy_request_and_backup_preserve_sqlite_and_cipher_bytes(self):
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder).resolve();(root/'demo').mkdir();(root/'installation.dpapi').write_bytes(b'ciphertext-only')
   with sqlite3.connect(root/'demo/access.sqlite3') as db:db.execute('CREATE TABLE sample(value BLOB)');db.execute('INSERT INTO sample VALUES(?)',(b'encrypted-secret',))
   target=u.backup_store(root);second=u.backup_store(root);self.assertNotEqual(target,second)
   self.assertEqual((target/'installation.dpapi').read_bytes(),b'ciphertext-only')
   with sqlite3.connect(target/'demo/access.sqlite3') as db:self.assertEqual(db.execute('SELECT value FROM sample').fetchone()[0],b'encrypted-secret')
   manager=u.UpdateManager(root);self.assertTrue(manager.enter());manager.draining=True;self.assertFalse(manager.enter());manager.leave();self.assertEqual(manager.active,0)

class UpdateAPITests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.hash=generate_password_hash('test',method='pbkdf2:sha256:1000000')
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.manager=u.UpdateManager(self.tmp.name)
  self.app=create_app(dict(MODE='demo',DATA_DIR=self.tmp.name,TESTING=True,DESKTOP=True,UPDATE_MANAGER=self.manager));self.client=self.app.test_client()
  with connection(self.app.db_path) as db:db.execute('INSERT INTO admin VALUES(1,?)',(self.hash,))
 def login(self,client,username='admin',password='test'):
  token=client.get('/api/session').json['csrf'];r=client.post('/api/login',json=dict(username=username,password=password),headers={'X-CSRF-Token':token});self.assertEqual(r.status_code,200);return r.json['csrf']
 def test_auth_csrf_owner_shared_and_password_guards(self):
  self.assertEqual(self.client.get('/api/updates/status').status_code,401);csrf=self.login(self.client)
  self.assertTrue(self.client.get('/api/updates/status').json['owner'])
  with patch.object(self.manager,'check') as check,patch.object(self.manager,'apply') as apply:
   self.assertEqual(self.client.post('/api/updates/check',json={}).status_code,403)
   self.assertEqual(self.client.post('/api/updates/check',json={},headers={'X-CSRF-Token':csrf},environ_overrides={'metakampo.shared_client':True}).status_code,403)
   self.assertEqual(self.client.post('/api/updates/check',json={},headers={'X-CSRF-Token':csrf}).status_code,202);check.assert_called_once()
   self.assertEqual(self.client.post('/api/updates/apply',json=dict(admin_password='wrong',version='1.9.0'),headers={'X-CSRF-Token':csrf}).status_code,403);apply.assert_not_called()
   self.assertEqual(self.client.post('/api/updates/apply',json=dict(admin_password='test',version='1.9.0'),headers={'X-CSRF-Token':csrf}).status_code,202);apply.assert_called_once_with('1.9.0')
 def test_other_administrator_cannot_launch_installer(self):
  csrf=self.login(self.client)
  r=self.client.post('/api/operators',json=dict(username='support',name='Support',password='a',admin_password='test'),headers={'X-CSRF-Token':csrf});self.assertEqual(r.status_code,201)
  other=self.app.test_client();token=self.login(other,'support','a')
  self.assertFalse(other.get('/api/updates/status').json['owner']);self.assertEqual(other.post('/api/updates/check',json={},headers={'X-CSRF-Token':token}).status_code,403)
 def test_draining_exposes_state_to_clients_but_refuses_new_work(self):
  self.login(self.client);self.assertEqual(self.client.get('/api/users').status_code,200);self.assertEqual(self.manager.active,0)
  self.manager.draining=True
  self.assertTrue(self.client.get('/api/session').json['updating']);self.assertEqual(self.client.get('/api/users').status_code,503);self.assertEqual(self.manager.active,0)
  self.assertEqual(self.client.get('/api/updates/status').status_code,200)

@unittest.skipUnless(os.name=='nt' and os.environ.get('FK_NATIVE_UPDATE_TESTS')=='1','Native elevated Windows pilot only')
class NativeUpdateTests(unittest.TestCase):
 def test_private_stage_and_untrusted_helper_fails_without_running_installer(self):
  import subprocess
  from directory import local_powershell_path
  with tempfile.TemporaryDirectory(prefix='mk-update-test-') as folder:
   root=Path(folder);stage=u.secure_stage(root)
   command="([IO.Directory]::GetAccessControl('"+str(stage)+"')).Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }"
   acl=subprocess.check_output([local_powershell_path(),'-NoProfile','-NonInteractive','-Command',command],text=True)
   self.assertEqual(set(acl.split()),{'S-1-5-18','S-1-5-32-544'})
   (stage/'plan.json').write_text(json.dumps(dict(schema=1,version='1.9.0',owner_pid=os.getpid(),interactive=False)))
   (stage/u.ENVELOPE).write_text('{}');(stage/u.ASSET).write_bytes(b'MZ-not-executable')
   (stage/'Apply-Update.ps1').write_text((u.BASE/'windows/Apply-Update.ps1').read_text().replace('@@PUBLIC_XML@@',u.PUBLIC_XML),encoding='utf-8-sig')
   r=subprocess.run([local_powershell_path(),'-NoProfile','-NonInteractive','-File',str(stage/'Apply-Update.ps1'),'-Plan',str(stage/'plan.json')],timeout=30,capture_output=True)
   self.assertNotEqual(r.returncode,0);self.assertFalse((stage/'ready.json').exists())
   self.assertEqual(json.loads((stage.parent/'result.json').read_text(encoding='utf-8-sig'))['status'],'error')
