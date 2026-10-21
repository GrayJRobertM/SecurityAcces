"""Unelevated window for an authorized Metakampo administrator in any local RDP session."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import sys
import tempfile
import threading


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--gui-smoke-test',action='store_true');parser.add_argument('--gui-smoke-report');args=parser.parse_args()
    if os.name!='nt':raise OSError('Este acceso requiere una sesión Windows del servidor instalado.')
    from updater import maintenance_requested
    if maintenance_requested():raise OSError('Metakampo se está actualizando. Espera a que termine.')
    import webview
    from waitress import create_server
    from desktop import DesktopGate
    from shared_desktop import PipeClient,LocalProxy
    expected=Path(sys.executable).parent/'MetakampoAccess.exe' if getattr(sys,'frozen',False) else Path(sys.executable)
    client=PipeClient(expected)
    # Check the installed owner process before opening a login window.
    if args.gui_smoke_test:
        client.request(dict(method='GET',path='/api/session',headers={},body=''))
    else:
        from service_host import binding,status,bootstrap,wait_for_pipe
        if not binding() or status() not in ('running','starting'):bootstrap(expected)
        wait_for_pipe(client)
    gate=DesktopGate(LocalProxy(client));server=create_server(gate,host='127.0.0.1',port=0,threads=4,clear_untrusted_proxy_headers=True)
    gate.host='127.0.0.1:'+str(server.effective_port)
    threading.Thread(target=server.run,daemon=True).start()
    temporary=tempfile.TemporaryDirectory(prefix='metakampo-session-')
    webview.settings.update(ALLOW_DOWNLOADS=True,ALLOW_FILE_URLS=False,OPEN_EXTERNAL_LINKS_IN_BROWSER=False,REMOTE_DEBUGGING_PORT=None)
    window=webview.create_window('Metakampo Access · Sesión del servidor',url='http://'+gate.host+'/desktop-open?token='+gate.bootstrap,width=1360,height=900,min_size=(900,650),text_select=True)
    errors=[]
    finished=threading.Event()
    def follow_owner():
        while not finished.wait(2):
            try:
                import base64,json
                response=client.request(dict(method='GET',path='/api/session',headers={},body=''))
                if json.loads(base64.b64decode(response['body'])).get('updating'):
                    window.destroy();return
            except Exception:pass
    threading.Thread(target=follow_owner,daemon=True,name='metakampo-client-maintenance').start()
    if args.gui_smoke_test:
        def check():
            try:
                Path(args.gui_smoke_report).write_text('Checking installed login and stylesheets.\n',encoding='utf-8')
                details = window.evaluate_js("""(() => {
                    const sheets = [...document.querySelectorAll('link[rel="stylesheet"]')];
                    return {login: !!document.getElementById('login-form') && !document.getElementById('login-screen').hidden,
                        sheets: sheets.map(link => {
                            try { return {path: link.getAttribute('href'), rules: link.sheet ? link.sheet.cssRules.length : 0}; }
                            catch (_) { return {path: link.getAttribute('href'), rules: 0}; }
                        }),
                        theme: getComputedStyle(document.documentElement).getPropertyValue('--fk-theme-primary').trim(),
                        display: getComputedStyle(document.querySelector('.login-layout')).display};
                })()""")
                Path(args.gui_smoke_report).write_text(json.dumps(details,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
                if not details or not details['login']:raise RuntimeError('No se cargó el acceso compartido.')
                if len(details['sheets']) < 5 or not all(s['rules'] > 0 for s in details['sheets']) or not details['theme'] or details['display'] != 'grid':raise RuntimeError('No se aplicaron las hojas de estilo del acceso compartido.')
                Path(args.gui_smoke_report).write_text('Shared-session WebView2 login and all stylesheets applied through verified local named pipe.\n',encoding='utf-8')
            except Exception as exc:errors.append(str(exc))
            finally:window.destroy()
        window.events.loaded+=check
    try:webview.start(gui='edgechromium',private_mode=True,debug=False,storage_path=str(Path(temporary.name)/'webview'))
    finally:finished.set();server.close();temporary.cleanup()
    if errors:raise RuntimeError(errors[0])


if __name__=='__main__':
    try:main()
    except Exception as exc:
        if '--gui-smoke-test' in sys.argv:raise SystemExit(1)
        if os.name=='nt':ctypes.windll.user32.MessageBoxW(None,str(exc),'Metakampo Access · Sesión compartida',16)
        else:raise
