"""Machine-wide IP guard, started by Task Scheduler as SYSTEM, without vault credentials."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from storage import connection
from directory import local_powershell_path

TASK=r'\Metakampo Access IP Protection'


def folder():
    if os.name!='nt':raise OSError('La protección en segundo plano requiere Windows.')
    return Path(os.environ['ProgramData'])/'Metakampo'/'Access'/'Protection'


def prepare_folder():
    root=folder()
    from updater import no_reparse
    no_reparse(root);root.mkdir(parents=True,exist_ok=True)
    subprocess.run(['icacls.exe',str(root),'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'],check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    return root


class MachineLock:
    def __init__(self,path):self.path=Path(path);self.local=threading.RLock();self.depth=threading.local()
    def __enter__(self):
        self.local.acquire()
        depth=getattr(self.depth,'value',0)
        if depth:self.depth.value=depth+1;return self
        stream=None
        try:
            import msvcrt
            stream=self.path.open('a+b')
            if stream.tell()==0:stream.write(b'0');stream.flush()
            until=time.monotonic()+40
            while True:
                try:stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1);break
                except OSError:
                    if time.monotonic()>=until:raise OSError('La protección está procesando otra operación. Espera y vuelve a intentar.')
                    time.sleep(.1)
            self.depth.stream=stream;self.depth.value=1;return self
        except Exception:
            if stream:stream.close()
            self.local.release();raise
    def __exit__(self,*args):
        try:
            self.depth.value-=1
            if not self.depth.value:
                import msvcrt
                stream=self.depth.stream
                try:stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
                finally:stream.close()
        finally:self.local.release()


def migrate_legacy(guard,legacy):
    legacy=Path(legacy)
    if not legacy.exists() or legacy.resolve()==guard.path.resolve():return
    # First real owner only; never merge different installations or override configured policy.
    with guard.lock,guard.db() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT 1 FROM migration').fetchone():return
        c=db.execute('SELECT * FROM config').fetchone()
        if c['since'] or db.execute('SELECT COUNT(*) FROM whitelist').fetchone()[0] or db.execute('SELECT COUNT(*) FROM blocks').fetchone()[0]:return
        db.execute('ATTACH DATABASE ? AS legacy',(str(legacy),))
        for table in ('config','whitelist','blocks','resets','notifications','history'):
            db.execute('DELETE FROM main.'+table)
            db.execute('INSERT INTO main.'+table+' SELECT * FROM legacy.'+table)
        db.execute('INSERT INTO migration VALUES(1,?)',(time.time(),))


def shared_guard(legacy,event_database,key):
    from ip_protection import IPProtection,native
    root=prepare_folder()
    guard=IPProtection(root/'protection.sqlite3',event_database,key,failure_reader=native)
    guard.lock=MachineLock(root/'operations.lock');guard.autonomous=True
    migrate_legacy(guard,legacy)
    return guard


def stop_worker(timeout=70):
    root=prepare_folder();request=root/'stop.request';request.write_text('stop',encoding='ascii')
    until=time.monotonic()+timeout
    import msvcrt
    while True:
        try:
            with (root/'worker.lock').open('a+b') as stream:
                if not stream.tell():stream.write(b'0');stream.flush()
                stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            return
        except OSError:
            if time.monotonic()>=until:raise OSError('La protección sigue trabajando. No se reemplazarán archivos hasta que termine.')
            time.sleep(.2)


def start_worker():
    result=subprocess.run(['schtasks.exe','/Run','/TN',TASK],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise OSError('No se inició la protección en segundo plano. Repara la instalación de Metakampo.')


def install_task():
    root=prepare_folder()
    # XML escaping is handled by ElementTree; no command interpolation or user script paths.
    import xml.etree.ElementTree as E
    ns='http://schemas.microsoft.com/windows/2004/02/mit/task'
    E.register_namespace('',ns)
    def element(parent,name,text=None,**attrs):
        node=E.SubElement(parent,'{'+ns+'}'+name,attrs);node.text=text;return node
    task=E.Element('{'+ns+'}Task',{'version':'1.4'})
    registration=element(task,'RegistrationInfo');element(registration,'Description','Metakampo Access: protección IP local independiente de las sesiones RDP.')
    triggers=element(task,'Triggers');boot=element(triggers,'BootTrigger');element(boot,'Enabled','true');element(boot,'Delay','PT15S')
    principals=element(task,'Principals');principal=element(principals,'Principal',id='System');element(principal,'UserId','S-1-5-18');element(principal,'RunLevel','HighestAvailable')
    settings=element(task,'Settings');element(settings,'MultipleInstancesPolicy','IgnoreNew');element(settings,'DisallowStartIfOnBatteries','false');element(settings,'StopIfGoingOnBatteries','false');element(settings,'StartWhenAvailable','true');element(settings,'ExecutionTimeLimit','PT0S');restart=element(settings,'RestartOnFailure');element(restart,'Interval','PT1M');element(restart,'Count','3')
    actions=element(task,'Actions',Context='System');action=element(actions,'Exec');element(action,'Command',str(Path(sys.executable).resolve()));element(action,'Arguments','--protection-worker');element(action,'WorkingDirectory',str(Path(sys.executable).resolve().parent))
    path=root/'task.xml';E.ElementTree(task).write(path,encoding='utf-16',xml_declaration=True)
    result=subprocess.run(['schtasks.exe','/Create','/TN',TASK,'/XML',str(path),'/F'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise OSError('Windows no registró la protección de inicio automático.')
    (root/'stop.request').unlink(missing_ok=True);start_worker()


def worker():
    import msvcrt
    from ip_protection import IPProtection,native
    from updater import maintenance_requested
    root=prepare_folder()
    with (root/'worker.lock').open('a+b') as lease:
        if not lease.tell():lease.write(b'0');lease.flush()
        lease.seek(0)
        try:msvcrt.locking(lease.fileno(),msvcrt.LK_NBLCK,1)
        except OSError:return
        (root/'stop.request').unlink(missing_ok=True)
        guard=IPProtection(root/'protection.sqlite3',root/'unused-events.sqlite3',b'',failure_reader=native)
        guard.lock=MachineLock(root/'operations.lock');guard.autonomous=True
        done=threading.Event()
        def watch():
            while not done.wait(.2):
                if (root/'stop.request').exists():guard.cancel.set();return
        thread=threading.Thread(target=watch,daemon=True);thread.start()
        try:
            while not guard.cancel.is_set():
                if not maintenance_requested():
                    guard.tick()
                    with guard.db() as db:db.execute('UPDATE runtime SET heartbeat=?,pid=? WHERE id=1',(time.time(),os.getpid()))
                guard.cancel.wait(10)
        finally:
            done.set();thread.join(2)
            with guard.db() as db:db.execute('UPDATE runtime SET heartbeat=NULL,pid=NULL WHERE id=1')
            lease.seek(0);msvcrt.locking(lease.fileno(),msvcrt.LK_UNLCK,1)


def remove_task():
    stop_worker()
    result=subprocess.run(['schtasks.exe','/Delete','/TN',TASK,'/F'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise OSError('Windows no retiró la tarea de protección.')
