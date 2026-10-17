"""Validate the manifest embedded in the real frozen Windows executable."""
from pathlib import Path
import pefile
path=Path('dist/MetakampoAccess/MetakampoAccess.exe')
with pefile.PE(str(path)) as pe:
    manifests=[]
    for kind in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if kind.id != 24:continue
        for item in kind.directory.entries:
            for language in item.directory.entries:
                data=language.data.struct
                manifests.append(pe.get_data(data.OffsetToData,data.Size))
    assert any(b'requireAdministrator' in value for value in manifests), 'Missing automatic UAC elevation'
print('Embedded requireAdministrator manifest verified')

client=Path('dist/MetakampoAccess/MetakampoClient.exe')
with pefile.PE(str(client)) as pe:
    manifests=[]
    for kind in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if kind.id != 24:continue
        for item in kind.directory.entries:
            for language in item.directory.entries:
                data=language.data.struct;manifests.append(pe.get_data(data.OffsetToData,data.Size))
    assert any(b'asInvoker' in value for value in manifests), 'Client must not request elevation'
    assert all(b'requireAdministrator' not in value for value in manifests), 'Client unexpectedly requires UAC'
print('Unelevated client manifest verified')
