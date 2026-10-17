"""CI-only readiness probe of the installed owner's local pipe."""
from pathlib import Path
import sys,time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from shared_desktop import PipeClient
client=PipeClient(Path(sys.argv[1]));deadline=time.monotonic()+45
while time.monotonic()<deadline:
    try:
        result=client.request(dict(method='GET',path='/api/session',headers={},body=''))
        if result['status']==200:print('Installed shared host ready');break
    except OSError:pass
    time.sleep(.25)
else:raise SystemExit('Installed owner did not expose the verified local pipe')
