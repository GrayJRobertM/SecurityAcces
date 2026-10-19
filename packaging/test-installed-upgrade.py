"""Disposable GitHub Windows runner only: actual signed upgrade of an installed pilot."""
import base64,json,os,subprocess,sys,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from updater import UpdateManager,verified_manifest,backup_store,ASSET,ENVELOPE
from desktop import Store,validate_settings
from directory import local_powershell_path
from shared_desktop import PipeClient
from security import seal,unseal,generate_password
from storage import connection
from werkzeug.security import generate_password_hash

if os.name!='nt' or os.environ.get('GITHUB_ACTIONS')!='true':raise SystemExit('This integration harness is restricted to the disposable CI runner')
previous=Path(sys.argv[1]).resolve();release=Path(sys.argv[2]).resolve();root=Path(r'C:\MetakampoUpgradePilot')
folder=Path(os.environ['LOCALAPPDATA'])/'Freshkampo'/'Access'
if (folder/'installation.dpapi').exists():raise SystemExit('Refusing to overwrite an existing owner profile')
manifest=verified_manifest((release/ENVELOPE).read_bytes());owner=None;restarted=None;helper=None
try:
 result=subprocess.run([str(previous),'/VERYSILENT','/SUPPRESSMSGBOXES','/SP-','/NORESTART','/DIR='+str(root)],timeout=180)
 if result.returncode:raise RuntimeError('Previous installer failed')
 store=Store(folder);store.save(validate_settings(dict(mode='demo',store='CurrentUser')));app=store.application()
 key=base64.b64decode(store.values['key']);identity=store.identity
 password=generate_password(24);admin=generate_password_hash(password,method='pbkdf2:sha256:1000000');identifier=str(uuid.uuid4());secret=generate_password(24)
 with connection(app.db_path) as db:
  db.execute('INSERT OR REPLACE INTO admin VALUES(1,?)',(admin,))
  db.execute('INSERT INTO vault(id,title,username,secret) VALUES(?,?,?,?)',(identifier,'Synthetic upgrade pilot','ci-user',seal(key,identifier,secret)))
 installation=(folder/'installation.dpapi').read_bytes()
 exe=root/'MetakampoAccess.exe'
 old_version=subprocess.check_output([local_powershell_path(),'-NoProfile','-NonInteractive','-Command',"(Get-Item -LiteralPath 'C:\MetakampoUpgradePilot\MetakampoAccess.exe').VersionInfo.ProductVersion"],text=True).strip()
 owner=subprocess.Popen([str(exe),'--legacy-host' if tuple(map(int,old_version.split('.')[:3]))>=(1,10,0) else '--shared-host'])
 def ready(timeout=60):
  until=time.monotonic()+timeout
  while time.monotonic()<until:
   try:
    r=PipeClient(exe).request(dict(method='GET',path='/api/session',headers={},body=''))
    if r['status']==200:return
   except Exception:pass
   time.sleep(.5)
  raise RuntimeError('Installed owner did not open')
 ready()
 manager=UpdateManager(folder,root=root,current=old_version,opener=lambda url:(release/ASSET).open('rb'))
 manager.latest=manifest;manager.envelope=(release/ENVELOPE).read_bytes();manager.download();manager.thread.join(90)
 if manager.phase!='ready':raise RuntimeError('Signed staging failed: '+manager.message)
 backup=backup_store(folder)
 if (Path(os.environ['ProgramData'])/'Metakampo/Access/Protection/worker.lock').exists():
  subprocess.run([str(exe),'--stop-protection'],check=True,timeout=90)
 stage=manager.stage
 (stage/'plan.json').write_text(json.dumps(dict(schema=1,version=manifest['version'],owner_pid=owner.pid,restart_shared=True,interactive=False,legacy_pilot=True)))
 helper=subprocess.Popen([local_powershell_path(),'-NoProfile','-NonInteractive','-File',str(stage/'Apply-Update.ps1'),'-Plan',str(stage/'plan.json')])
 until=time.monotonic()+30
 while not (stage/'ready.json').exists():
  if helper.poll() is not None or time.monotonic()>until:raise RuntimeError('Native updater did not verify signature/installer')
  time.sleep(.2)
 # Stop only this disposable child. Production uses voluntary window closure after draining.
 owner.terminate();owner.wait(15)
 if helper.wait(300)!=0:raise RuntimeError('Native installer upgrade failed')
 result=json.loads((root/'.metakampo-updates'/'result.json').read_text(encoding='utf-8-sig'))
 if result['status']!='success' or result['version']!=manifest['version']:raise RuntimeError('Upgrade not confirmed')
 restarted=result['restarted_pid'];ready()
 reopened=Store(folder)
 assert reopened.identity==identity and reopened.values==store.values
 assert (folder/'installation.dpapi').read_bytes()==installation
 with connection(app.db_path) as db:
  assert db.execute('SELECT hash FROM admin WHERE id=1').fetchone()[0]==admin
  assert unseal(key,identifier,db.execute('SELECT secret FROM vault WHERE id=?',(identifier,)).fetchone()[0])==secret
 assert (backup/'installation.dpapi').exists() and (backup/'demo'/'access.sqlite3').exists()
 subprocess.run([sys.executable,str(Path(__file__).parent/'verify-background.py'),str(exe),str(release/'BACKGROUND-SMOKE.txt')],check=True,timeout=140)
 (release/'UPGRADE-SMOKE.txt').write_text('Signed installed upgrade '+old_version+' -> '+manifest['version']+' passed. RSA trust, SHA256, protected staging, real installer, installed self-test, same Windows identity, unchanged DPAPI config/admin hash/vault secret, SQLite backup and reopened shared owner verified. No real user data or Telegram used.\n')
 print('Native signed installed upgrade + DPAPI/data preservation passed.')
finally:
 if owner and owner.poll() is None:owner.terminate();owner.wait(15)
 if restarted:
  command="$p=Get-Process -Id "+str(int(restarted))+" -ErrorAction SilentlyContinue;if($p -and $p.Path -eq 'C:\MetakampoUpgradePilot\MetakampoAccess.exe'){Stop-Process -Id $p.Id -Force}"
  subprocess.run([local_powershell_path(),'-NoProfile','-NonInteractive','-Command',command],timeout=20,capture_output=True)
 if helper and helper.poll() is None:helper.terminate();helper.wait(15)
