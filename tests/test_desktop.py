import json
import os
import sqlite3
from storage import connection
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from werkzeug.test import Client
from werkzeug.wrappers import Response
from werkzeug.security import generate_password_hash
from app import create_app
from desktop import DesktopGate, Store, validate_settings, setup_application
from local_telemetry import commit_batch
from security import generate_password
from windows_native import dpapi


class GateTests(unittest.TestCase):
    def setUp(self):
        self.gate = DesktopGate(lambda env, start: (start('200 OK', []), [b'window'])[1])
        self.gate.host = '127.0.0.1:8768'
        self.client = Client(self.gate, Response)
        self.base = dict(base_url='http://127.0.0.1:8768', environ_overrides={'REMOTE_ADDR': '127.0.0.1'})

    def open(self):
        return self.client.get('/desktop-open?token=' + self.gate.bootstrap, **self.base)

    def test_browser_and_remote_clients_are_denied(self):
        self.assertEqual(self.client.get('/', **self.base).status_code, 403)
        self.assertEqual(self.client.get('/api/session', **self.base).status_code, 403)
        token = self.gate.bootstrap
        self.assertEqual(self.client.get('/desktop-open?token='+token, base_url='http://127.0.0.1:8768',
                                        environ_overrides={'REMOTE_ADDR':'192.0.2.5'}).status_code,403)
        self.assertEqual(self.client.get('/desktop-open?token='+token, base_url='http://evil.example:8768',
                                        environ_overrides={'REMOTE_ADDR':'127.0.0.1'}).status_code,403)

    def test_window_bootstrap_is_one_use_and_cross_origin_is_denied(self):
        token=self.gate.bootstrap
        opened=self.open()
        self.assertEqual(opened.status_code,303)
        self.assertIn('HttpOnly', opened.headers['Set-Cookie'])
        self.assertEqual(self.client.get('/', **self.base).status_code,200)
        self.assertEqual(self.client.get('/desktop-open?token='+token, **self.base).status_code,403)
        self.assertEqual(self.client.post('/', headers={'Origin':'https://evil.example'}, **self.base).status_code,403)

    def test_network_collectors_and_credential_broker_remain_disabled(self):
        self.open()
        for path in ('/api/collectors','/api/telemetry/events','/api/rdp/redeem'):
            self.assertEqual(self.client.post(path, **self.base).status_code,403)


class DesktopDataTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.identity=dict(machine='pilot-machine',sid='S-1-5-21-123')
        self.native=patch('desktop.machine_identity',return_value=self.identity)
        self.acl=patch('desktop.restrict_folder')
        self.protection=patch('desktop.dpapi',side_effect=lambda value,decrypt=False:value)
        for mock in (self.native,self.acl,self.protection):mock.start()
        self.addCleanup(lambda:[mock.stop() for mock in (self.native,self.acl,self.protection)])
        self.addCleanup(self.temp.cleanup)

    def test_settings_validate_domain_ou_and_certificates(self):
        settings=validate_settings(dict(mode='ad',server='dc.empresa.local',suffix='empresa.local',
                                       ou='OU=Pruebas,DC=empresa,DC=local',store='CurrentUser'))
        self.assertEqual(settings['mode'],'ad')
        for change in (dict(server='dc/path'),dict(ou='DC=empresa'),dict(rdp_cert='bogus'),dict(mode='bad')):
            with self.assertRaises(ValueError):validate_settings(dict(settings,**change))

    def test_existing_key_survives_settings_update_and_copies_fail(self):
        store=Store(self.temp.name)
        settings=validate_settings(dict(mode='demo',store='CurrentUser'))
        store.save(settings)
        key=store.values['key']
        store.save(dict(settings,rdp_cert='A'*40))
        self.assertEqual(Store(self.temp.name).values['key'],key)
        with patch('desktop.machine_identity',return_value=dict(machine='other',sid=self.identity['sid'])):
            with self.assertRaises(OSError):Store(self.temp.name)
        with patch('desktop.machine_identity',return_value=dict(machine=self.identity['machine'],sid='S-1-5-21-999')):
            with self.assertRaises(OSError):Store(self.temp.name)

    def test_first_run_requires_csrf_and_strong_password(self):
        store=Store(self.temp.name)
        gate=DesktopGate(None)
        app=setup_application(store,gate,lambda app:None)
        app.config['SERVER_NAME']='127.0.0.1'
        client=app.test_client()
        csrf=client.get('/desktop/settings').json['csrf']
        self.assertEqual(client.post('/desktop/settings',json={}).status_code,403)
        body=dict(mode='demo',store='CurrentUser',password='weak',confirmation='weak')
        self.assertEqual(client.post('/desktop/settings',json=body,headers={'X-CSRF-Token':csrf}).status_code,400)
        password=generate_password(24)
        body.update(password=password,confirmation=password)
        with patch.dict(os.environ,{},clear=False):
            response=client.post('/desktop/settings',json=body,headers={'X-CSRF-Token':csrf})
        self.assertEqual(response.status_code,200,response.json)
        self.assertTrue(gate.application.config['DESKTOP'])
        self.assertFalse(gate.application.config['SESSION_COOKIE_SECURE'])
        with connection(gate.application.db_path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM admin').fetchone()[0],1)
        self.assertNotIn(password,store.file.read_text(encoding='utf-8'))


class LocalEventTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        with patch.dict(os.environ,{},clear=False):
            self.app=create_app(dict(DATA_DIR=self.temp.name,MODE='demo',TESTING=True,DESKTOP=True))
        with connection(self.app.db_path) as db:
            db.execute('CREATE TABLE local_collector_state(id INTEGER PRIMARY KEY,state TEXT NOT NULL)')
            db.execute('INSERT INTO collectors(id,name,server,token_hash) VALUES(?,?,?,?)',
                       ('local-desktop','Local','pilot.example.test','no-network-token'))
        from datetime import datetime,timezone
        self.event=dict(record_id=1,event_id=4624,at=datetime.now(timezone.utc).isoformat(),
                        username='pilot',domain='TEST',logon_type=10)
        self.batch=dict(epoch=str(uuid.uuid4()),last_record=1,last_clear='',gap='',events=[self.event])

    def test_checkpoint_and_events_commit_together_and_deduplicate(self):
        self.assertEqual(commit_batch(self.app.db_path,'pilot.example.test',self.batch),1)
        self.assertEqual(commit_batch(self.app.db_path,'pilot.example.test',self.batch),0)
        with connection(self.app.db_path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM windows_events WHERE source='windows'").fetchone()[0],1)
            self.assertEqual(json.loads(db.execute('SELECT state FROM local_collector_state').fetchone()[0])['last_record'],1)
        invalid=dict(self.batch,events=[dict(self.event,password='not admitted')],last_record=2)
        with self.assertRaises(ValueError):commit_batch(self.app.db_path,'pilot.example.test',invalid)
        with connection(self.app.db_path) as db:
            self.assertEqual(json.loads(db.execute('SELECT state FROM local_collector_state').fetchone()[0])['last_record'],1)

    def test_desktop_disables_remote_receivers_even_without_gate(self):
        client=self.app.test_client()
        for path in ('/api/collectors','/api/telemetry/events','/api/rdp/redeem'):
            self.assertEqual(client.post(path,json={}).status_code,403)

    def test_local_rdp_requires_reauth_and_uses_dpapi_without_broker(self):
        password=generate_password(24)
        with connection(self.app.db_path) as db:
            db.execute('INSERT INTO admin VALUES(1,?)',(generate_password_hash(password,method='pbkdf2:sha256:1000000'),))
        client=self.app.test_client()
        csrf=client.get('/api/session').json['csrf']
        response=client.post('/api/login',json=dict(username='admin',password=password),headers={'X-CSRF-Token':csrf})
        csrf=response.json['csrf']; self.app.config['MODE']='ad'
        body=dict(host='destination.example.test',username='TEST\\pilot',account_password=generate_password(24),admin_password='bad')
        self.assertEqual(client.post('/api/rdp/package',json=body,headers={'X-CSRF-Token':csrf}).status_code,403)
        body['admin_password']=password
        with patch('windows_native.machine_identity',return_value=dict(machine='server',sid='S-1-5-21-123')),patch('windows_native.dpapi',return_value=b'protected'),patch('app.make_package',return_value=b'zip') as builder:
            result=client.post('/api/rdp/package',json=body,headers={'X-CSRF-Token':csrf})
        self.assertEqual(result.status_code,200)
        configuration=builder.call_args.kwargs['configuration']
        self.assertTrue(configuration['local'])
        self.assertNotIn(body['account_password'],json.dumps(configuration))
        self.assertNotIn('portal',configuration)
        with connection(self.app.db_path) as db:
            self.assertEqual(db.execute('SELECT secret,consumed FROM rdp_clients').fetchone(),(None,1))
        self.assertNotIn(body['account_password'].encode(),self.app.db_path.read_bytes())


@unittest.skipUnless(os.name=='nt','Native Windows DPAPI integration')
class NativeTests(unittest.TestCase):
    def test_real_dpapi_roundtrip_and_tamper_rejection(self):
        raw=os.urandom(32)
        encrypted=dpapi(raw)
        self.assertNotIn(raw,encrypted)
        self.assertEqual(dpapi(encrypted,decrypt=True),raw)
        with self.assertRaises(OSError):dpapi(encrypted[:-1],decrypt=True)


if __name__=='__main__':unittest.main()
