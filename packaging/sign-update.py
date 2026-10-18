"""Trusted tag workflow only: sign installer metadata, never embed the private key."""
import argparse,base64,hashlib,json,os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding
from update_trust import VERSION,PUBLIC_KEY
from updater import ASSET,ENVELOPE,verified_manifest
p=argparse.ArgumentParser();p.add_argument('folder',type=Path);p.add_argument('--tag',required=True);args=p.parse_args()
if args.tag!='metakampo-v'+VERSION:raise SystemExit('Tag does not match application version')
try:
 private=serialization.load_pem_private_key(base64.b64decode(os.environ['METAKAMPO_UPDATE_SIGNING_KEY'],validate=True),password=None)
 public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
 if public!=PUBLIC_KEY or private.key_size!=3072:raise ValueError()
 file=args.folder/ASSET
 raw=json.dumps(dict(schema=1,version=VERSION,tag=args.tag,platform='windows-x64',asset=ASSET,size=file.stat().st_size,sha256=hashlib.sha256(file.read_bytes()).hexdigest(),published_at=int(time.time())),sort_keys=True,separators=(',',':')).encode()
 signed=json.dumps(dict(payload=base64.b64encode(raw).decode(),signature=base64.b64encode(private.sign(raw,padding.PKCS1v15(),hashes.SHA256())).decode()),separators=(',',':')).encode()
 verified_manifest(signed)
 (args.folder/ENVELOPE).write_bytes(signed)
 print('Release manifest signed and checked against the embedded public key.')
except Exception:raise SystemExit('Release signing failed; no private key data is printed.') from None
