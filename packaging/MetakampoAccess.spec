# PyInstaller spec: build on Windows x64, embed Python and all local application assets.
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

root = Path(SPECPATH).parent
datas, binaries, hiddenimports = collect_all('webview')
datas += [(str(root / 'static'), 'static'), (str(root / 'windows'), 'windows')]
datas += [(str(root / 'geodata' / filename), 'geodata') for filename in ('city.mmdb','source.json','NOTICE.txt')]
a = Analysis([str(root / 'desktop.py')], pathex=[str(root)], binaries=binaries,
             datas=datas, hiddenimports=hiddenimports + ['webview.platforms.edgechromium', 'clr'],
             excludes=['PyQt5', 'PyQt6', 'PySide2', 'PySide6', 'cefpython3'], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='MetakampoAccess',
          debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
          console=False, disable_windowed_traceback=True, uac_admin=True,
          icon=str(root / 'packaging' / 'MetakampoAccess.ico'),
          version=str(root / 'packaging' / 'version.txt'))
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='MetakampoAccess')
