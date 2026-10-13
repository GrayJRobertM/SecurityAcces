import sqlite3
import tempfile
import time
import unittest
import uuid
from datetime import datetime,timezone
from pathlib import Path
from werkzeug.security import generate_password_hash
from app import create_app
from access_map import Locator,model,filters
from security import generate_password
from storage import connection
from telemetry import INSERT,normalize


class MapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password=generate_password(24)
        cls.password_hash=generate_password_hash(cls.password,method='pbkdf2:sha256:1000000')

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app(dict(DATA_DIR=self.temp.name,MODE='demo',TESTING=True))
        with connection(self.app.db_path) as db:
            db.execute('INSERT INTO admin VALUES(1,?)',(self.password_hash,))
            db.execute("DELETE FROM windows_events WHERE source='demo'")
        self.client=self.app.test_client()
        self.addCleanup(self.temp.cleanup)
        self.epoch=str(uuid.uuid4())

    def login(self):
        csrf=self.client.get('/api/session').json['csrf']
        response=self.client.post('/api/login',json=dict(username='admin',password=self.password),headers={'X-CSRF-Token':csrf})
        self.assertEqual(response.status_code,200)

    def event(self,record,user='ana',ip='192.0.2.10',event=4624,typ=10,at=None):
        item=dict(record_id=record,event_id=event,at=datetime.fromtimestamp(at or time.time(),timezone.utc).isoformat(),
                  username=user,domain='DEMO',ip=ip,logon_type=typ)
        with connection(self.app.db_path) as db:
            db.execute(INSERT,('demo',)+normalize(item,'pilot.example.test',self.epoch))

    def test_requires_administrative_session(self):
        for path in ('/api/map','/api/map/events?point=unknown'):
            self.assertEqual(self.client.get(path).status_code,401)

    def test_point_shows_every_account_and_separates_attempts(self):
        self.event(1);self.event(2,user='daniel',event=4625);self.event(3,user='sofia')
        self.login();data=self.client.get('/api/map').json
        self.assertTrue(data['demo']);point=data['points'][0]
        self.assertEqual((point['success'],point['failure'],point['events']),(2,1,3))
        events=self.client.get('/api/map/events',query_string=dict(point=point['id'])).json['events']
        self.assertEqual({event['username'] for event in events},{'DEMO\\ana','DEMO\\daniel','DEMO\\sofia'})
        self.assertEqual(sum(e['event_id']==4625 for e in events),1)

    def test_private_absent_invalid_and_unmapped_ips_are_not_located(self):
        locator=Locator()
        for ip in ('10.0.0.1','192.168.1.2','127.0.0.1','100.64.0.1','192.0.2.5','::1','fd00::10','', '-', 'bad'):
            self.assertFalse(locator.lookup(ip)['located'],ip)
        self.assertFalse(locator.lookup('8.8.8.8')['located'])
        self.event(1,ip='10.0.0.1');self.login()
        data=self.client.get('/api/map').json
        self.assertEqual(data['points'],[])
        self.assertEqual(data['unlocated'][0]['ip'],'10.0.0.1')
        events=self.client.get('/api/map/events',query_string=dict(point=data['unlocated'][0]['id'])).json['events']
        self.assertEqual(len(events),1)

    def test_network_failure_is_separate_from_success_and_filters_work(self):
        self.event(1);self.event(2,user='daniel',event=4625,typ=3)
        self.login();data=self.client.get('/api/map?outcome=failure&user=daniel').json
        self.assertEqual(data['totals']['events'],1)
        details=self.client.get('/api/map/events',query_string=dict(point=data['points'][0]['id'],outcome='failure',user='daniel')).json
        self.assertEqual(details['events'][0]['kind'],'network_failure')
        self.assertEqual(self.client.get('/api/map?days=1').status_code,400)
        self.assertEqual(self.client.get('/api/map?outcome=sql').status_code,400)

    def test_literals_in_user_filter_and_time_window(self):
        self.event(1,user='a_b');self.event(2,user='axb');self.event(3,user='a_b',at=time.time()-91*86400)
        self.login()
        self.assertEqual(self.client.get('/api/map?user=a_b&days=90').json['totals']['events'],1)
        self.assertEqual(self.client.get('/api/map?user=%25').json['totals']['events'],0)

    def test_event_pagination_does_not_drop_other_accounts(self):
        for index in range(205):self.event(index+1,user='user'+str(index))
        self.login();point=self.client.get('/api/map').json['points'][0]['id']
        first=self.client.get('/api/map/events',query_string=dict(point=point)).json
        second=self.client.get('/api/map/events',query_string=dict(point=point,before=first['next_cursor'])).json
        third=self.client.get('/api/map/events',query_string=dict(point=point,before=second['next_cursor'])).json
        records=first['events']+second['events']+third['events']
        self.assertEqual(len(records),205)
        self.assertEqual(len({e['id'] for e in records}),205)
        self.assertIsNone(third['next_cursor'])

    def test_groups_shared_location_across_ips_without_exposing_secrets(self):
        self.event(1,ip='192.0.2.10');self.event(2,user='daniel',ip='192.0.2.15')
        self.login();data=self.client.get('/api/map').json
        self.assertEqual(len(data['points']),1)
        self.assertEqual(data['points'][0]['origins'],2)
        self.assertNotIn('password',str(data))
        self.assertEqual(self.client.get('/api/map/events?point=not-a-point').status_code,404)

    def test_bundled_database_resolves_public_ipv4_and_ipv6_offline(self):
        path=Path(__file__).parents[1]/'geodata'/'city.mmdb'
        self.assertTrue(path.is_file(),'Build requires the pinned offline dataset')
        locator=Locator(path)
        try:
            self.assertTrue(locator.info['available'])
            self.assertTrue(locator.lookup('8.8.8.8')['located'])
            self.assertTrue(locator.lookup('2001:4860:4860::8888')['located'])
            self.assertEqual(locator.lookup('8.8.8.8'),locator.lookup('::ffff:8.8.8.8'))
            self.assertFalse(locator.lookup('192.168.1.1')['located'])
        finally:locator.close()


if __name__=='__main__':unittest.main()
