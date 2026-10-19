"""Disposable Windows CI: real SCM, isolated owner profile and unchanged CurrentUser DPAPI."""
import base64,json,os,sys,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
if os.name!='nt' or os.environ.get('GITHUB_ACTIONS')!='true':raise SystemExit('Disposable Windows CI only')
import win32api,win32security,win32profile,win32net,win32netcon,win32serviceutil,win32process
from desktop import Store,validate_settings
from security import generate_password,seal
from storage import connection
from service_host import install,remove,start,stop,status,NAME
from shared_desktop import PipeClient
from werkzeug.security import generate_password_hash

exe=Path(sys.argv[1]).resolve();report=Path(sys.argv[2]).resolve()
username='mksvc'+uuid.uuid4().hex[:10];password=generate_password(30);admin_password=generate_password(24)
folder=Path(os.environ['ProgramData'])/('MetakampoServicePilot-'+uuid.uuid4().hex)
token=None;profile=None;created=False;identifier=str(uuid.uuid4());secret=generate_password(24)
try:
    if status()!='unconfigured':raise RuntimeError('Refusing to replace existing service')
    win32net.NetUserAdd(None,1,dict(name=username,password=password,priv=win32netcon.USER_PRIV_USER,home_dir='',comment='Disposable Metakampo service CI',flags=win32netcon.UF_SCRIPT|win32netcon.UF_NORMAL_ACCOUNT|win32netcon.UF_DONT_EXPIRE_PASSWD,script_path=''));created=True
    group=win32security.LookupAccountSid(None,win32security.ConvertStringSidToSid('S-1-5-32-544'))[0]
    account=os.environ['COMPUTERNAME']+'\\'+username
    win32net.NetLocalGroupAddMembers(None,group,3,[dict(domainandname=account)])
    token=win32security.LogonUser(username,'.',password,win32security.LOGON32_LOGON_INTERACTIVE,win32security.LOGON32_PROVIDER_DEFAULT)
    process_token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32security.TOKEN_ALL_ACCESS)
    win32security.AdjustTokenPrivileges(process_token,False,[(win32security.LookupPrivilegeValue(None,n),win32security.SE_PRIVILEGE_ENABLED) for n in ('SeBackupPrivilege','SeRestorePrivilege')]);process_token.Close()
    if win32security.GetTokenInformation(token,win32security.TokenElevationType)==3:
        linked=win32security.GetTokenInformation(token,win32security.TokenLinkedToken);token.Close();token=linked
    profile=win32profile.LoadUserProfile(token,dict(UserName=username,Flags=1))
    folder.mkdir()
    from windows_native import restrict_folder
    sid=win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token,win32security.TokenUser)[0]);restrict_folder(folder,sid)
    win32security.ImpersonateLoggedOnUser(token)
    try:
        store=Store(folder);store.save(validate_settings(dict(mode='local',store='CurrentUser')));app=store.application()
        with connection(app.db_path) as db:
            db.execute('INSERT INTO admin VALUES(1,?)',(generate_password_hash(admin_password),))
            db.execute('INSERT INTO vault(id,title,username,secret) VALUES(?,?,?,?)',(identifier,'Service pilot','synthetic',seal(base64.b64decode(store.values['key']),identifier,secret)))
        protected=(folder/'installation.dpapi').read_bytes();key=store.values['key']
    finally:win32security.RevertToSelf()
    win32profile.UnloadUserProfile(token,profile);profile=None
    win32security.ImpersonateLoggedOnUser(token)
    try:install(store,account,password,executable=exe)
    finally:win32security.RevertToSelf();token.Close();token=None
    def protected_bytes():
        reader=win32security.LogonUser(username,'.',password,win32security.LOGON32_LOGON_INTERACTIVE,win32security.LOGON32_PROVIDER_DEFAULT)
        win32security.ImpersonateLoggedOnUser(reader)
        try:return (folder/'installation.dpapi').read_bytes()
        finally:win32security.RevertToSelf();reader.Close()
    pipe=PipeClient(exe)
    def request(method,path,data=None,cookie=None,csrf=None):
        headers={}
        if data is not None:headers['Content-Type']='application/json'
        if cookie:headers['Cookie']=cookie
        if csrf:headers['X-CSRF-Token']=csrf
        response=pipe.request(dict(method=method,path=path,headers=headers,body=base64.b64encode(json.dumps(data).encode()).decode() if data is not None else ''))
        return response,json.loads(base64.b64decode(response['body']))
    def ready():
        until=time.monotonic()+90
        while time.monotonic()<until:
            try:
                response,body=request('GET','/api/session')
                if response['status']==200:return response,body['csrf']
            except Exception:pass
            time.sleep(.5)
        raise RuntimeError('SCM service did not open its DPAPI store/pipe')
    def login():
        initial,csrf=ready();initial_cookie=next(value.split(';')[0] for name,value in initial['headers'] if name.lower()=='set-cookie')
        response,body=request('POST','/api/login',dict(username='admin',password=admin_password),cookie=initial_cookie,csrf=csrf)
        assert response['status']==200,body
        cookie=next(value.split(';')[0] for name,value in response['headers'] if name.lower()=='set-cookie')
        return cookie,body['csrf']
    cookie,csrf=login()
    response,body=request('GET','/api/service/status',cookie=cookie)
    assert response['status']==200 and body['service'] and len(body['tasks'])>=2 and all(t['running'] for t in body['tasks']),body
    import win32service
    scm=win32service.OpenSCManager(None,None,win32service.SC_MANAGER_CONNECT)
    handle=win32service.OpenService(scm,NAME,win32service.SERVICE_QUERY_STATUS)
    try:pid=win32service.QueryServiceStatusEx(handle)['ProcessId']
    finally:win32service.CloseServiceHandle(handle);win32service.CloseServiceHandle(scm)
    import ctypes
    from ctypes import wintypes as W
    session=W.DWORD();function=ctypes.WinDLL('kernel32',use_last_error=True).ProcessIdToSessionId
    function.argtypes=[W.DWORD,ctypes.POINTER(W.DWORD)];function.restype=W.BOOL
    assert function(pid,ctypes.byref(session)) and session.value==0
    assert protected_bytes()==protected
    import subprocess
    gui=report.with_name('SERVICE-CLIENT-SMOKE.txt')
    child=subprocess.Popen([str(exe.with_name('MetakampoClient.exe')),'--gui-smoke-test','--gui-smoke-report',str(gui)])
    assert child.wait(90)==0 and gui.exists()
    assert status()=='running'
    stop();assert status()=='stopped';start();cookie,csrf=login()
    assert protected_bytes()==protected
    # Reinstall exercises installer stop/repair/restart without another Windows password.
    installer=report.parent/'Metakampo-Access-Setup-x64.exe'
    result=subprocess.run([str(installer),'/VERYSILENT','/SUPPRESSMSGBOXES','/SP-','/NORESTART','/DIR='+str(exe.parent)],timeout=240)
    assert result.returncode==0
    cookie,csrf=login();assert status()=='running' and protected_bytes()==protected
    # Verify original vault material after cold SCM restart, not an interactive host.
    token=win32security.LogonUser(username,'.',password,win32security.LOGON32_LOGON_INTERACTIVE,win32security.LOGON32_PROVIDER_DEFAULT)
    profile=win32profile.LoadUserProfile(token,dict(UserName=username,Flags=1));win32security.ImpersonateLoggedOnUser(token)
    try:
        reopened=Store(folder);assert reopened.values['key']==key
        from security import unseal
        with connection(app.db_path) as db:assert unseal(base64.b64decode(key),identifier,db.execute('SELECT secret FROM vault WHERE id=?',(identifier,)).fetchone()[0])==secret
    finally:win32security.RevertToSelf()
    report.write_text('Real Windows SCM automatic service runs in session 0 under the original isolated owner account. CurrentUser DPAPI configuration, key, administrator login and vault ciphertext survive service activation, stop/start and installer repair without any owner GUI or interactive owner process. LocalCollector and AccountExpiry run as service workers. No real domain or Telegram used.\n')
finally:
    try:remove()
    except Exception:pass
    if profile and token:
        try:win32profile.UnloadUserProfile(token,profile)
        except Exception:pass
    if token:token.Close()
    if created:
        try:win32net.NetUserDel(None,username)
        except Exception:pass
