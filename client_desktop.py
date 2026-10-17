"""Unelevated window for an authorized Metakampo administrator in any local RDP session."""
import argparse
import ctypes
import os
from pathlib import Path
import sys
import tempfile
import threading


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--gui-smoke-test',action='store_true');parser.add_argument('--gui-smoke-report');args=parser.parse_args()
    if os.name!='nt':raise OSError('Este acceso requiere una sesión Windows del servidor instalado.')
    import webview
    from waitress import create_server
    from desktop import DesktopGate
    from shared_desktop import PipeClient,LocalProxy
    expected=Path(sys.executable).parent/'MetakampoAccess.exe' if getattr(sys,'frozen',False) else Path(sys.executable)
    client=PipeClient(expected)
    # Check the installed owner process before opening a login window.
    client.request(dict(method='GET',path='/api/session',headers={},body=''))
    gate=DesktopGate(LocalProxy(client));server=create_server(gate,host='127.0.0.1',port=0,threads=4,clear_untrusted_proxy_headers=True)
    gate.host='127.0.0.1:'+str(server.effective_port)
    threading.Thread(target=server.run,daemon=True).start()
    temporary=tempfile.TemporaryDirectory(prefix='metakampo-session-')
    webview.settings.update(ALLOW_DOWNLOADS=True,ALLOW_FILE_URLS=False,OPEN_EXTERNAL_LINKS_IN_BROWSER=False,REMOTE_DEBUGGING_PORT=None)
    window=webview.create_window('Metakampo Access · Sesión del servidor',url='http://'+gate.host+'/desktop-open?token='+gate.bootstrap,width=1360,height=900,min_size=(900,650),text_select=True)
    errors=[]
    if args.gui_smoke_test:
        def check():
            try:
                if not window.evaluate_js("!!document.getElementById('login-form') && !document.getElementById('login-screen').hidden"):raise RuntimeError('No se cargó el acceso compartido.')
                Path(args.gui_smoke_report).write_text('Shared-session WebView2 login loaded through verified local named pipe.\n',encoding='utf-8')
            except Exception as exc:errors.append(str(exc))
            finally:window.destroy()
        window.events.loaded+=check
    try:webview.start(gui='edgechromium',private_mode=True,debug=False,storage_path=str(Path(temporary.name)/'webview'))
    finally:server.close();temporary.cleanup()
    if errors:raise RuntimeError(errors[0])


if __name__=='__main__':
    try:main()
    except Exception as exc:
        if '--gui-smoke-test' in sys.argv:raise
        if os.name=='nt':ctypes.windll.user32.MessageBoxW(None,str(exc),'Metakampo Access · Sesión compartida',16)
        else:raise
