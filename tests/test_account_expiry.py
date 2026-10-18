import tempfile
import base64
import os
import unittest
from pathlib import Path
from datetime import datetime,timezone
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from app import create_app
from account_expiry import AccountExpiry, instant
from storage import connection

class ExpiryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.app=create_app(dict(TESTING=True,MODE='demo',DATA_DIR=self.tmp.name))
        self.now=1800000000;self.user=dict(username='temporary.user',enabled=True,expires_at=None)
        self.calls=[];self.messages=[];self.fail=False;self.notify_fail=False
        def directory(action,**values):
            self.calls.append((action,values))
            if self.fail:raise OSError('Synthetic refusal')
            if values.get('identifier')=='protected':raise ValueError('Protected')
            if action=='expiry-set':self.user['expires_at']=int(datetime.fromisoformat(values['expires_at']).timestamp()) if values['expires_at'] else None
            if action=='expiry-disable':
                if self.user['expires_at']!=values['expected_at']:return dict(conflict=True)
                if self.now<values['expected_at']:raise OSError('Not due')
                changed=self.user['enabled'];self.user['enabled']=False
                return dict(self.user,changed=changed)
            return dict(self.user)
        def notify(action,**values):
            if self.notify_fail:raise OSError('No confirmation')
            self.messages.append((action,values))
        self.directory=directory;self.notify=notify
        self.engine=AccountExpiry(self.app.db_path,directory,notify,clock=lambda:self.now)
    def iso(self,offset=60):return datetime.fromtimestamp(self.now+offset,timezone.utc).isoformat()
    def state(self):
        with self.engine.db() as db:return dict(db.execute('SELECT * FROM account_expiry').fetchone())
    def test_native_expiry_then_confirmed_disable_and_single_alert(self):
        self.engine.save('id',self.iso(),'operator');deadline=self.now+60
        self.assertEqual(self.user['expires_at'],deadline);self.assertTrue(self.user['enabled'])
        self.engine.tick();self.assertEqual(self.messages,[])
        self.now+=61;self.engine.tick();self.engine.tick()
        self.assertFalse(self.user['enabled']);self.assertEqual(self.state()['state'],'done');self.assertEqual(len(self.messages),1)
        self.assertEqual(self.messages[0][0],'user-alert');self.assertTrue(self.messages[0][1]['changed'])
        with self.engine.db() as db:self.assertEqual(db.execute("SELECT actor FROM audit WHERE action='programar vencimiento'").fetchone()[0],'operator')
    def test_no_false_disable_alert_on_native_failure_and_retry_after_restart(self):
        self.engine.save('id',self.iso(),'admin');self.now+=61;self.fail=True;self.engine.tick()
        self.assertEqual(self.messages,[]);self.assertTrue(self.user['enabled']);self.assertEqual(self.state()['state'],'armed');self.assertTrue(self.state()['error'])
        self.fail=False;self.engine=AccountExpiry(self.app.db_path,self.directory,self.notify,clock=lambda:self.now);self.engine.tick()
        self.assertFalse(self.user['enabled']);self.assertEqual(len(self.messages),1)
    def test_external_date_change_stops_automatic_disable(self):
        self.engine.save('id',self.iso(),'admin');self.user['expires_at']+=300;self.now+=61;self.engine.tick()
        self.assertTrue(self.user['enabled']);self.assertEqual(self.messages,[]);self.assertEqual(self.state()['state'],'conflict')
        self.engine.ensure_enable('id') # External change is left for review, not overwritten.
    def test_extend_or_remove_does_not_reactivate_and_enable_requires_future_date(self):
        self.engine.save('id',self.iso(),'admin');self.now+=61;self.engine.tick()
        with self.assertRaises(ValueError):self.engine.ensure_enable('id')
        self.engine.save('id',self.iso(600),'admin');self.engine.ensure_enable('id');self.assertFalse(self.user['enabled'])
        self.engine.save('id',None,'admin');self.assertIsNone(self.user['expires_at']);self.assertFalse(self.user['enabled']);self.assertEqual(self.state()['state'],'cancelled')
    def test_delivery_retry_does_not_repeat_disable(self):
        self.engine.save('id',self.iso(),'admin');self.now+=61;self.notify_fail=True;self.engine.tick()
        self.assertEqual(self.engine.history()['alerts'][0]['status'],'pending');before=len([a for a,v in self.calls if a=='expiry-disable'])
        self.notify_fail=False;self.now+=31;self.engine.tick()
        self.assertEqual(len([a for a,v in self.calls if a=='expiry-disable']),before);self.assertEqual(self.engine.history()['alerts'][0]['status'],'sent')
    def test_pending_intent_reconciles_without_overwriting_external_change(self):
        self.engine.save('id',self.iso(),'admin')
        with self.engine.db() as db:db.execute("UPDATE account_expiry SET state='pending',previous_at=NULL")
        before=len([a for a,v in self.calls if a=='expiry-set']);self.engine.tick()
        self.assertEqual(len([a for a,v in self.calls if a=='expiry-set']),before);self.assertEqual(self.state()['state'],'armed')
        with self.engine.db() as db:db.execute("UPDATE account_expiry SET state='pending',previous_at=NULL")
        self.user['expires_at']+=400;self.engine.tick();self.assertEqual(self.state()['state'],'conflict')
    def test_already_disabled_account_is_reported_honestly(self):
        self.user['enabled']=False;self.engine.save('id',self.iso(),'admin');self.now+=61;self.engine.tick()
        self.assertFalse(self.messages[0][1]['changed']);self.assertEqual(self.state()['state'],'done')
    def test_protected_account_and_invalid_or_ambiguous_dates(self):
        with self.assertRaises(ValueError):self.engine.save('protected',self.iso(),'admin')
        for value in ['2026-10-18T12:00','bad','2001-01-01T00:00:00Z',True,{},'2101-01-01T00:00:00Z']:
            with self.assertRaises(ValueError):instant(value,self.now)
        self.assertEqual(instant('2027-01-15T12:00:00-06:00',0),instant('2027-01-15T18:00:00Z',0))

class ExpiryAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.hash=generate_password_hash('test',method='pbkdf2:sha256:1000000')
    def test_background_ad_scope_does_not_follow_another_environments_configuration(self):
        env=dict(FK_MASTER_KEY=base64.b64encode(b'x'*32).decode(),FK_AD_SERVER='dc-original.example.test',FK_AD_OU='OU=Original,DC=example,DC=test')
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,env),patch('app.call_ad',return_value={}) as native:
            app=create_app(dict(MODE='ad',DATA_DIR=folder,DESKTOP=True,TESTING=True))
            os.environ['FK_AD_SERVER']='dc-other.example.test'
            app.account_expiry.directory('expiry-info',identifier='test-guid')
            self.assertEqual(native.call_args.kwargs['_configuration']['server'],'dc-original.example.test')
            self.assertEqual(native.call_args.kwargs['_configuration']['ou'],env['FK_AD_OU'])
    def test_auth_csrf_confirmation_and_demo_isolation(self):
        with tempfile.TemporaryDirectory() as folder,patch('ip_protection.native',side_effect=AssertionError('No Windows/Telegram calls')):
            app=create_app(dict(MODE='demo',DATA_DIR=folder,TESTING=True));client=app.test_client()
            with connection(app.db_path) as db:db.execute('INSERT INTO admin VALUES(1,?)',(self.hash,))
            self.assertEqual(client.get('/api/account-expiry').status_code,401)
            csrf=client.get('/api/session').json['csrf'];r=client.post('/api/login',json=dict(username='admin',password='test'),headers={'X-CSRF-Token':csrf});csrf=r.json['csrf']
            identifier=client.get('/api/users').json['users'][0]['id'];path='/api/users/'+identifier+'/expiration'
            self.assertEqual(client.post(path,json={}).status_code,403)
            self.assertEqual(client.post(path,json=dict(expires_at=None,admin_password='wrong'),headers={'X-CSRF-Token':csrf}).status_code,403)
            future=datetime(2030,1,1,tzinfo=timezone.utc).isoformat()
            self.assertEqual(client.post(path,json=dict(expires_at=future,admin_password='test'),headers={'X-CSRF-Token':csrf}).status_code,200)
            user=next(u for u in client.get('/api/users').json['users'] if u['id']==identifier);self.assertEqual(user['expiration']['state'],'armed')
            app.account_expiry.clock=lambda:2000000000;app.account_expiry.tick()
            self.assertEqual(client.post('/api/users/'+identifier+'/enable',json={},headers={'X-CSRF-Token':csrf}).status_code,400)
            self.assertEqual(client.get('/api/account-expiry').json['alerts'][0]['status'],'simulated')
