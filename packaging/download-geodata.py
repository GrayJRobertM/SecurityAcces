"""Fetch a pinned, licensed public dataset for offline use. No access records leave the app."""
import gzip
import hashlib
import json
import shutil
import tempfile
import urllib.request
from pathlib import Path

root=Path(__file__).parents[1]/'geodata'
metadata=json.loads((root/'source.json').read_text(encoding='utf-8'))
with tempfile.TemporaryDirectory() as folder:
    compressed=Path(folder)/'city.mmdb.gz'
    with urllib.request.urlopen(metadata['url'],timeout=120) as source,compressed.open('wb') as output:
        shutil.copyfileobj(source,output)
    if hashlib.sha256(compressed.read_bytes()).hexdigest()!=metadata['compressed_sha256']:
        raise SystemExit('Dataset download checksum mismatch')
    target=root/'city.mmdb'
    with gzip.open(compressed,'rb') as source,target.open('wb') as output:
        shutil.copyfileobj(source,output)
    if hashlib.sha256(target.read_bytes()).hexdigest()!=metadata['database_sha256']:
        target.unlink()
        raise SystemExit('Dataset content checksum mismatch')
print('DB-IP City Lite '+metadata['release']+' verified for offline use.')
