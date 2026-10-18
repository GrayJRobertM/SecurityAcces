import tempfile
from pathlib import Path
import unittest
from ip_protection import IPProtection
from background_protection import migrate_legacy

class MigrationTests(unittest.TestCase):
 def test_first_owner_migrates_policy_whitelist_rule_identity_and_queue_once(self):
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder);old=IPProtection(root/'old.sqlite3',root/'events.sqlite3',b'',demo=True);new=IPProtection(root/'new.sqlite3',root/'events.sqlite3',b'',demo=True)
   with old.db() as db:
    db.execute("UPDATE config SET enabled=1,threshold=7,since=100,alerts=1")
    identity=db.execute('SELECT instance FROM config').fetchone()[0]
   old.white_add('198.51.100.1','VPN','admin');old.manual('198.51.100.2','admin')
   migrate_legacy(new,old.path);state=new.state();self.assertEqual(state['config']['threshold'],7);self.assertEqual(state['whitelist'][0]['cidr'],'198.51.100.1/32');self.assertEqual(len(state['alerts']),1)
   with new.db() as db:self.assertEqual(db.execute('SELECT instance FROM config').fetchone()[0],identity)
   with old.db() as db:db.execute('UPDATE config SET threshold=10')
   migrate_legacy(new,old.path);self.assertEqual(new.state()['config']['threshold'],7)
 def test_preconfigured_shared_policy_is_never_overwritten_by_other_profile(self):
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder);old=IPProtection(root/'old.sqlite3',root/'e.sqlite3',b'',demo=True);new=IPProtection(root/'new.sqlite3',root/'e.sqlite3',b'',demo=True)
   with new.db() as db:db.execute('UPDATE config SET since=10,threshold=20')
   migrate_legacy(new,old.path);self.assertEqual(new.state()['config']['threshold'],20)
