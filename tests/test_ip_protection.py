import os
import tempfile
import time
import subprocess
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from datetime import datetime,timezone
from ip_protection import IPProtection, address, network, native
from storage import connection
from telemetry import install, INSERT, normalize
from app import create_app
from werkzeug.security import generate_password_hash

class ProtectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.events=self.root/'events.sqlite3';install(self.events,'local')
        self.now=time.time();self.calls=[];self.rules={};self.fail=False
        def backend(action,**data):
            self.calls.append((action,data))
            if self.fail:raise OSError('synthetic failure')
            if action=='add':self.rules[data['rule']]=dict(rule=data['rule'],ip=data['ip'],enabled=True,block=True,inbound=True)
            if action=='remove':self.rules.pop(data['rule'],None)
            if action=='list':return dict(rules=list(self.rules.values()))
            return dict(ok=True)
        self.guard=IPProtection(self.root/'guard.sqlite3',self.events,b'x'*32,backend=backend,clock=lambda:self.now)
        self.epoch=str(uuid.uuid4());self.record=0
        self.policy=dict(enabled=True,threshold=3,window_minutes=10,duration_minutes=1,network_failures=True,alerts=True)
        self.guard.settings(self.policy,'admin')
        self.now+=1
    def tearDown(self):self.tmp.cleanup()
    def events_add(self,count=3,ip='198.51.100.20',typ=10,server=None,at=None,source='windows'):
        with connection(self.events) as db:
            for _ in range(count):
                self.record+=1
                e=dict(record_id=self.record,event_id=4625,at=datetime.fromtimestamp(at or self.now-0.001,timezone.utc).isoformat(),ip=ip,username='attempted',logon_type=typ)
                db.execute(INSERT,(source,)+normalize(e,server or self.guard.server,self.epoch,self.now))
    def test_threshold_deduplication_expiry_and_reset(self):
        self.events_add(2);self.guard.tick();self.assertEqual(self.guard.state()['blocks'],[])
        self.events_add(1);self.guard.tick();self.guard.tick()
        state=self.guard.state();self.assertEqual(state['blocks'][0]['status'],'blocked');self.assertEqual(len(state['alerts']),1)
        self.assertEqual(sum(a=='alert' for a,d in self.calls),1)
        self.now+=61;self.guard.tick();self.assertEqual(self.guard.state()['blocks'][0]['status'],'released')
        self.assertFalse(self.rules)
        self.guard.tick();self.assertEqual(len(self.guard.state()['blocks']),1)
        self.now+=1;self.events_add();self.guard.tick();self.assertEqual(len(self.guard.state()['blocks']),2)
    def test_whitelist_precedes_manual_and_automatic_and_removes_existing(self):
        self.events_add();self.guard.tick()
        self.guard.white_add('198.51.100.0/24','VPN','operator')
        self.assertFalse(self.rules)
        self.assertEqual(self.guard.state()['blocks'][0]['status'],'released')
        with self.assertRaises(ValueError):self.guard.manual('198.51.100.20','admin')
        self.events_add(8);self.guard.tick();self.assertFalse(self.rules)
        self.assertEqual(len(self.guard.state()['blocks']),1)
    def test_white_removal_failure_is_visible_and_retried(self):
        self.events_add();self.guard.tick();self.fail=True
        with self.assertRaises(OSError):self.guard.white_add('198.51.100.20','VPN','admin')
        self.assertEqual(len(self.guard.state()['whitelist']),1)
        self.fail=False;self.guard.tick();self.assertFalse(self.rules)
    def test_no_historical_remote_demo_or_non_network_events(self):
        self.events_add(at=self.now-500);self.events_add(server='remote.example.test');self.events_add(source='demo');self.events_add(typ=2)
        self.events_add(ip='127.0.0.1');self.events_add(ip='::1');self.events_add(ip='-')
        self.guard.tick();self.assertFalse(self.rules)
        self.events_add(typ=3);self.guard.tick();self.assertTrue(self.rules)
    def test_mapped_ipv4_cannot_bypass_whitelist_and_threshold(self):
        self.events_add(1);self.events_add(2,ip='::ffff:198.51.100.20');self.guard.tick();self.assertEqual(len(self.rules),1)
        self.guard.white_add('198.51.100.20','VPN','admin');self.assertFalse(self.rules)
        self.events_add(10,ip='::ffff:198.51.100.20');self.guard.tick();self.assertFalse(self.rules)
    def test_disable_removes_automatic_but_manual_still_expires(self):
        self.events_add();self.guard.tick();self.guard.manual('198.51.100.21','operator')
        self.guard.settings(dict(self.policy,enabled=False),'admin');self.assertEqual(len(self.rules),1)
        self.now+=61;self.guard.tick();self.assertFalse(self.rules)
    def test_failure_is_not_claimed_blocked_and_alerts_retry_without_reblocking(self):
        self.fail=True;self.events_add();self.guard.tick();self.assertEqual(self.guard.state()['blocks'][0]['status'],'error')
        self.assertEqual(self.guard.state()['alerts'],[])
        self.fail=False;self.guard.tick();self.assertEqual(self.guard.state()['blocks'][0]['status'],'blocked')
        with self.guard.db() as db:db.execute("UPDATE notifications SET status='pending',next_try=0")
        self.fail=True;self.guard.tick();self.assertEqual(self.guard.state()['alerts'][0]['status'],'pending')
        self.fail=False;self.now+=61;self.guard.tick();self.assertEqual(self.guard.state()['alerts'][0]['status'],'sent')
    def test_restart_reconciles_pending_and_missing_rule_without_duplicate_alert(self):
        self.events_add();self.guard.tick();self.rules.clear();self.guard.tick();self.assertEqual(len(self.rules),1)
        self.assertEqual(len(self.guard.state()['alerts']),1)
        self.assertEqual(sum(a=='alert' for a,d in self.calls),1)
    def test_no_nla_when_excluded_and_no_old_events_after_whitelist_removal(self):
        self.guard.settings(dict(self.policy,network_failures=False),'admin')
        self.events_add(typ=3);self.guard.tick();self.assertFalse(self.rules)
        self.guard.white_add('198.51.100.20','','admin');self.events_add()
        self.now+=1;self.guard.white_remove(self.guard.state()['whitelist'][0]['id'],'admin');self.guard.tick();self.assertFalse(self.rules)
    def test_validation_and_manual_release_confirmation(self):
        for bad in ['192.0.2.1;whoami','example.com','fe80::1%7','1.1.1.1:3389']:
            with self.assertRaises(ValueError):address(bad)
        with self.assertRaises(ValueError):network('198.51.100.1/24')
        self.guard.manual('198.51.100.20','operator');self.fail=True
        with self.assertRaises(OSError):self.guard.release(self.guard.state()['blocks'][0]['id'],'operator')
        self.fail=False;self.guard.tick();self.assertFalse(self.rules)

class ProtectionAPITests(unittest.TestCase):
    def test_native_transport_uses_fixed_powershell_and_sanitizes_errors(self):
        with patch('ip_protection.subprocess.run',return_value=subprocess.CompletedProcess([],1,'invalid','https://secret.example/token')) as run:
            with self.assertRaises(OSError) as error:native('monitor')
            self.assertNotIn('secret',str(error.exception))
            self.assertTrue(run.call_args.args[0][0].lower().endswith('windowspowershell\\v1.0\\powershell.exe'))
            self.assertNotEqual(run.call_args.args[0][0],'powershell.exe')

    def test_auth_csrf_reauth_and_demo_never_operates_windows(self):
        with tempfile.TemporaryDirectory() as folder,patch('ip_protection.native',side_effect=AssertionError('No OS calls')):
            app=create_app(dict(TESTING=True,MODE='demo',DATA_DIR=folder));client=app.test_client()
            self.assertEqual(client.get('/api/ip-protection').status_code,401)
            with connection(app.db_path) as db:db.execute('INSERT INTO admin VALUES(1,?)',(generate_password_hash('x',method='pbkdf2:sha256:1000000'),))
            csrf=client.get('/api/session').json['csrf'];r=client.post('/api/login',json=dict(username='admin',password='x'),headers={'X-CSRF-Token':csrf});csrf=r.json['csrf']
            self.assertEqual(client.post('/api/ip-protection/block',json=dict(ip='198.51.100.1',admin_password='x')).status_code,403)
            self.assertEqual(client.post('/api/ip-protection/block',json=dict(ip='198.51.100.1',admin_password='wrong'),headers={'X-CSRF-Token':csrf}).status_code,400)
            r=client.post('/api/ip-protection/block',json=dict(ip='198.51.100.1',admin_password='x'),headers={'X-CSRF-Token':csrf})
            self.assertEqual(r.status_code,200);self.assertTrue(r.json['demo']);self.assertEqual(r.json['blocks'][0]['status'],'blocked')

@unittest.skipUnless(os.name=='nt' and os.environ.get('FK_NATIVE_IP_TESTS')=='1','Opt-in native Windows firewall test')
class NativeIPTests(unittest.TestCase):
    def test_owned_documentation_ip_rule_roundtrip(self):
        for ip in ('198.51.100.254','2001:db8::254'):
            instance=uuid.uuid4().hex;rule='Metakampo-IP-'+instance+'-'+uuid.uuid4().hex
            try:
                native('add',rule=rule,ip=ip)
                result=native('list',instance=instance)
                self.assertEqual(len(result['rules']),1);self.assertEqual(result['rules'][0]['ip'],ip)
                with self.assertRaises(OSError):native('remove',rule='Other-Application-Rule',ip=ip)
            finally:native('remove',rule=rule,ip=ip)
            self.assertEqual(native('list',instance=instance)['rules'],[])
