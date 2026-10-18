"""CI-only installed SYSTEM task proof after all GUI windows have closed."""
import json,os,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from directory import local_powershell_path
from storage import connection
if os.name!='nt' or os.environ.get('GITHUB_ACTIONS')!='true':raise SystemExit('Disposable Windows CI only')
exe=Path(sys.argv[1]).resolve();report=Path(sys.argv[2]);db=Path(os.environ['ProgramData'])/'Metakampo/Access/Protection/protection.sqlite3'
until=time.monotonic()+90;first=None
while time.monotonic()<until:
 try:
  with connection(db) as conn:row=conn.execute('SELECT heartbeat,pid FROM runtime WHERE id=1').fetchone()
  if row and row[0] and time.time()-row[0]<30:first=row;break
 except Exception:pass
 time.sleep(.5)
if not first:raise RuntimeError('Installed background protection did not become healthy')
script="$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')+';'+$env:PSModulePath;$t=Get-ScheduledTask -TaskName 'Metakampo Access IP Protection' -ErrorAction Stop;$p=Get-CimInstance Win32_Process -Filter 'ProcessId="+str(int(first[1]))+"';$sid=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid;@{user=$t.Principal.UserId;command=$t.Actions[0].Execute;args=$t.Actions[0].Arguments;sid=$sid.Sid;path=$p.ExecutablePath}|ConvertTo-Json -Compress"
r=subprocess.run([local_powershell_path(),'-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,timeout=30)
if r.returncode:raise RuntimeError('Could not verify installed task identity')
data=json.loads(r.stdout)
assert data['user'] in ('SYSTEM','S-1-5-18') and data['sid']=='S-1-5-18'
acl_script="$acl=[IO.Directory]::GetAccessControl((Join-Path $env:ProgramData 'Metakampo\\Access\\Protection'));@($acl.Access|ForEach-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value})|ConvertTo-Json -Compress"
r=subprocess.run([local_powershell_path(),'-NoProfile','-NonInteractive','-Command',acl_script],capture_output=True,text=True,check=True,timeout=20)
assert set(json.loads(r.stdout))=={'S-1-5-18','S-1-5-32-544'}
assert Path(data['command']).resolve()==exe and Path(data['path']).resolve()==exe and data['args']=='--protection-worker'
until=time.monotonic()+30
while time.monotonic()<until:
 with connection(db) as conn:latest=conn.execute('SELECT heartbeat FROM runtime WHERE id=1').fetchone()[0]
 if latest and latest>first[0]:break
 time.sleep(.5)
else:raise RuntimeError('Background heartbeat did not advance without owner GUI')
report.write_text('Installed boot task runs as SYSTEM with fixed installed executable. Private policy ACL permits only SYSTEM/Administrators. Heartbeat advances after owner/shared GUI windows close; no interactive owner or vault credentials required. Policy remains disabled until configured.\n')
print('Installed background protection identity and owner-independent heartbeat verified.')
