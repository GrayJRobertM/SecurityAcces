import json
import sqlite3
from storage import connection
import tempfile
import time
import unittest
import uuid
from datetime import datetime,timezone,timedelta
from werkzeug.security import generate_password_hash
from app import create_app
from security import generate_password
from telemetry import metrics

class TelemetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password=generate_password(24)
        cls.password_hash=generate_password_hash(cls.password,method='pbkdf2:sha256:1000000')
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({'TESTING':True,'DATA_DIR':self.temp.name,'MODE':'demo'})
        with connection(self.app.db_path) as db:db.execute('INSERT INTO admin VALUES(1,?)',(self.password_hash,))
        self.client=self.app.test_client()
        csrf=self.client.get('/api/session').json['csrf']
        result=self.client.post('/api/login',json={'username':'admin','password':self.password},headers={'X-CSRF-Token':csrf})
        self.csrf=result.json['csrf']
        self.server='srv01.example.test'
        reply=self.client.post('/api/collectors',json={'server':self.server,'name':'Recolector prueba','admin_password':self.password},headers={'X-CSRF-Token':self.csrf})
        self.assertEqual(reply.status_code,201)
        self.token=reply.json['token'];self.collector_id=reply.json['id']
        self.epoch=str(uuid.uuid4())
    def tearDown(self):self.temp.cleanup()
    def event(self,record=1,event=4624,typ=10,user='alice',at=None):
        return dict(record_id=record,event_id=event,at=at or datetime.now(timezone.utc).isoformat(),username=user,domain='EXAMPLE',ip='192.0.2.10',logon_type=typ,logon_id='0x10')
    def send(self,items,token=None,https=True,extra=None):
        data=dict(epoch=self.epoch,events=items);data.update(extra or {})
        return self.app.test_client().post('/api/telemetry/events',json=data,headers={'Authorization':'Bearer '+(token or self.token)},environ_overrides={'wsgi.url_scheme':'https' if https else 'http'})
    def real(self):self.app.config['MODE']='ad'
    def dashboard(self,query=''):
        return self.client.get('/api/dashboard'+query)
    def test_demo_is_explicit_and_never_ingests_real_events(self):
        reply=self.dashboard()
        self.assertTrue(reply.json['demo']);self.assertGreater(reply.json['totals']['success'],0)
        self.assertEqual(self.send([self.event()]).status_code,403)
        self.real();self.assertEqual(self.dashboard().json['totals']['success'],0)
    def test_authentication_https_and_scope(self):
        self.real()
        self.assertEqual(self.app.test_client().get('/api/dashboard').status_code,401)
        self.assertEqual(self.send([self.event()],token='a'*43).status_code,401)
        self.assertEqual(self.send([self.event()],https=False).status_code,403)
        self.assertEqual(self.send([dict(self.event(),server='other.example.test')]).status_code,400)
        self.assertEqual(self.send([self.event()]).status_code,200)
        with connection(self.app.db_path) as db:
            self.assertEqual(db.execute("SELECT server FROM windows_events WHERE source='windows'").fetchone()[0],self.server)
    def test_idempotency_and_log_generations(self):
        self.real()
        item=self.event()
        self.assertEqual(self.send([item]).json['accepted'],1)
        self.assertEqual(self.send([item]).json['duplicates'],1)
        self.assertEqual(self.dashboard().json['totals']['success'],1)
        self.epoch=str(uuid.uuid4())
        self.assertEqual(self.send([item]).json['accepted'],1)
        self.assertEqual(self.dashboard().json['totals']['success'],2)
    def test_atomic_validation_and_secret_rejection(self):
        self.real()
        self.assertEqual(self.send([self.event(),dict(self.event(2),message='not accepted')]).status_code,400)
        self.assertEqual(self.dashboard().json['totals']['success'],0)
        self.assertEqual(self.send([dict(self.event(),password='not accepted')]).status_code,400)
        self.assertEqual(self.send([dict(self.event(),at='2026-01-01T00:00:00')]).status_code,400)
        self.assertEqual(self.send([dict(self.event(),at=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())]).status_code,400)
    def test_metrics_do_not_confuse_nla_network_failures_with_rdp(self):
        self.real()
        items=[self.event(1,user='Alice'),self.event(2,user='alice'),self.event(3,event=4625),self.event(4,event=4625,typ=3),self.event(5,typ=2,user='bob'),self.event(6,event=4778,typ=0),self.event(7,event=4779,typ=0)]
        items[-2]['session_name']='RDP-Tcp#1';items[-1]['session_name']='RDP-Tcp#1'
        self.assertEqual(self.send(items).json['accepted'],7)
        data=self.dashboard().json
        self.assertEqual(data['totals'],dict(success=2,failure=1,users=1,servers=1,network_failures=1))
        self.assertEqual(data['event_count'],5)
        self.assertEqual(sum(r['success'] for r in data['daily']),2)
        self.assertEqual(self.dashboard('?scope=interactive').json['totals']['success'],3)
    def test_revocation_and_empty_heartbeat(self):
        self.real()
        self.assertEqual(self.send([]).status_code,200)
        self.assertEqual(self.dashboard().json['collectors'][0]['health'],'reportando')
        reply=self.client.post('/api/collectors/'+self.collector_id+'/revoke',json={'admin_password':self.password},headers={'X-CSRF-Token':self.csrf},environ_overrides={'wsgi.url_scheme':'https'})
        self.assertEqual(reply.status_code,200)
        self.assertEqual(self.send([self.event()]).status_code,401)
    def test_gap_and_retention(self):
        self.real()
        old=(datetime.now(timezone.utc)-timedelta(days=100)).isoformat()
        self.send([self.event(at=old)],extra={'gap_reason':'log_cleared'})
        data=self.dashboard('?days=90').json
        self.assertEqual(data['totals']['success'],0)
        self.assertIsNotNone(data['collectors'][0]['last_gap'])
        with connection(self.app.db_path) as db:self.assertEqual(db.execute("SELECT COUNT(*) FROM windows_events WHERE source='windows'").fetchone()[0],0)
    def test_filters_batch_limits_and_key_privacy(self):
        self.real();self.send([self.event()])
        self.assertEqual(self.dashboard('?server=other.example.test').json['totals']['success'],0)
        self.assertEqual(self.dashboard('?days=999').status_code,400)
        self.assertEqual(self.send([self.event(i+1) for i in range(501)]).status_code,400)
        self.assertNotIn(self.token,json.dumps(self.dashboard().json))
        self.assertNotIn(self.token,self.app.db_path.read_bytes().decode('latin1'))
    def test_large_valid_batch_and_display_limit(self):
        self.real()
        reply=self.send([self.event(i+1) for i in range(100)])
        self.assertEqual(reply.status_code,200)
        self.assertEqual(reply.json['accepted'],100)
        data=self.dashboard().json
        self.assertEqual(data['totals']['success'],100)
        self.assertEqual(len(data['events']),50)
    def test_local_calendar_bucket(self):
        self.real()
        self.send([self.event()])
        with connection(self.app.db_path) as db:
            db.row_factory=sqlite3.Row
            data=metrics(db,{'days':'7','offset':'-360'},'ad')
        self.assertEqual(sum(r['success'] for r in data['daily']),1)

if __name__=='__main__':unittest.main()
