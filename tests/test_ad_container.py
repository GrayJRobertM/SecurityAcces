"""AD scope regression: real PowerShell adapter with a fake directory module, no domain writes."""
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from desktop import validate_settings

BASE=Path(__file__).resolve().parents[1]

class ADSettingsTests(unittest.TestCase):
    def settings(self,**values):
        return dict(mode='ad',server='dc.example.test',suffix='example.test',ou='CN=Users,DC=example,DC=test',store='CurrentUser',**values)

    def test_container_and_ou_accepted_but_root_and_malformed_rejected(self):
        data=self.settings()
        for base in ('CN=Users,DC=example,DC=test','OU=Domain Users,DC=example,DC=test'):
            self.assertEqual(validate_settings(dict(data,ou=base))['ou'],base)
        for base in ('DC=example,DC=test','Users','CN=Users;whoami,DC=example,DC=test'):
            with self.assertRaises(ValueError):validate_settings(dict(data,ou=base))

    def test_dns_errors_identify_the_field(self):
        for field,label in (('server','Controlador de dominio'),('suffix','Sufijo UPN')):
            with self.assertRaisesRegex(ValueError,label):validate_settings(dict(self.settings(),**{field:'Domain Controllers'}))


MOCK=r'''
function Get-ADObject {
 [CmdletBinding()]param($Identity,$Server)
 if($Identity -ne $env:MK_TEST_BASE -or $Server -ne 'dc.example.test'){throw 'Unexpected directory lookup'}
 [pscustomobject]@{DistinguishedName=$Identity;ObjectClass=$env:MK_TEST_CLASS}
}
function Get-ADUser {
 [CmdletBinding()]param($Identity,$Filter,$SearchBase,$SearchScope,$Properties,$Server)
 if($Filter){if($SearchBase -ne $env:MK_TEST_BASE -or $SearchScope -ne 'Subtree'){throw 'Unscoped query'}}
 $dn='CN=Contract User,'+$env:MK_TEST_BASE
 if($env:MK_TEST_USER -eq 'outside'){$dn='CN=Contract User,OU=Elsewhere,DC=example,DC=test'}
 $protected=if($env:MK_TEST_USER -eq 'protected'){1}else{0}
 [pscustomobject]@{DistinguishedName=$dn;ObjectGUID=[guid]'11111111-2222-4333-8444-555555555555';SamAccountName='contract';Name='Contract User';DisplayName='Contract User';Department='';UserPrincipalName='contract@example.test';Enabled=$true;LockedOut=$false;adminCount=$protected;AccountExpirationDate=$null}
}
function New-ADUser {
 [CmdletBinding()]param($Name,$DisplayName,$SamAccountName,$UserPrincipalName,$Path,$AccountPassword,$ChangePasswordAtLogon,$Enabled,[switch]$PassThru,$Server)
 if($Path -ne $env:MK_TEST_BASE){throw 'Unscoped creation'}
 'create' | Add-Content -LiteralPath $env:MK_TEST_WRITES
 Get-ADUser -Identity '11111111-2222-4333-8444-555555555555'
}
function Enable-ADAccount {
 [CmdletBinding()]param($Identity,$Server)
 'enable' | Add-Content -LiteralPath $env:MK_TEST_WRITES
}
function Get-ADDomain {
 [CmdletBinding()]param($Server)
 [pscustomobject]@{ObjectGUID=[guid]'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'}
}
function Get-ADReplicationAttributeMetadata {
 [CmdletBinding()]param($Object,$Server,$Properties)
 [pscustomobject]@{Version=1;LastOriginatingChangeUsn=123;LastOriginatingChangeDirectoryServerInvocationId=[guid]'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'}
}
Export-ModuleMember -Function *
'''

@unittest.skipUnless(os.name=='nt','Windows PowerShell adapter contract (simulated directory)')
class WindowsADContainerContractTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);module=self.folder/'ActiveDirectory';module.mkdir()
        (module/'ActiveDirectory.psm1').write_text(MOCK,encoding='utf-8-sig')
        # Only the fake-directory test copy reports exception details; production stays sanitized.
        self.scripts=self.folder/'scripts';self.scripts.mkdir()
        for filename in ('directory.ps1','Check-Desktop.ps1','ad-scope.ps1','department-groups.ps1'):
            shutil.copy2(BASE/'windows'/filename,self.scripts/filename)
        adapter=self.scripts/'directory.ps1'
        adapter.write_text(adapter.read_text(encoding='utf-8-sig').replace("error='AD_OPERATION_FAILED'","error='AD_OPERATION_FAILED';diagnostic=$_.Exception.Message;location=$_.ScriptStackTrace"),encoding='utf-8-sig')
        self.writes=self.folder/'writes.txt'
        self.env=dict(os.environ,PSModulePath=str(self.folder)+os.pathsep+os.environ.get('PSModulePath',''),MK_TEST_BASE='CN=Users,DC=example,DC=test',MK_TEST_CLASS='container',MK_TEST_USER='normal',MK_TEST_WRITES=str(self.writes))

    def run_script(self,action='list',script='directory.ps1',**values):
        data=dict(action=action,server='dc.example.test',ou=self.env['MK_TEST_BASE'],upnSuffix='example.test',**values)
        result=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-File',str(self.scripts/script)],input=json.dumps(data),capture_output=True,text=True,encoding='utf-8',env=self.env,timeout=30)
        try:body=json.loads(result.stdout.lstrip('\ufeff'))
        except ValueError:self.fail('Invalid PowerShell adapter response: '+result.stdout+' '+result.stderr)
        return result.returncode,body

    def test_list_container_and_ou_preserves_user_properties(self):
        for dn,kind in [('CN=Users,DC=example,DC=test','container'),('OU=Domain Users,DC=example,DC=test','organizationalUnit')]:
            with self.subTest(kind=kind):
                self.env.update(MK_TEST_BASE=dn,MK_TEST_CLASS=kind)
                code,body=self.run_script();self.assertEqual(code,0,body)
                self.assertEqual(len(body['data']),1);self.assertEqual(body['data'][0]['username'],'contract');self.assertTrue(body['data'][0]['enabled'])
        self.assertFalse(self.writes.exists())

    def test_setup_accepts_container(self):
        code,body=self.run_script(script='Check-Desktop.ps1');self.assertEqual(code,0,body);self.assertTrue(body['ad'])

    def test_non_container_and_domain_root_rejected(self):
        for dn,kind in [('CN=Not A Container,DC=example,DC=test','user'),('CN=Group,DC=example,DC=test','group'),('DC=example,DC=test','domainDNS')]:
            with self.subTest(kind=kind):
                self.env.update(MK_TEST_BASE=dn,MK_TEST_CLASS=kind)
                code,body=self.run_script();self.assertNotEqual(code,0);self.assertFalse(body['ok'])
        self.assertFalse(self.writes.exists())

    def test_user_changes_stay_in_base_and_reject_protected_accounts(self):
        for user in ('outside','protected'):
            self.env['MK_TEST_USER']=user
            code,body=self.run_script('enable',identifier='11111111-2222-4333-8444-555555555555')
            self.assertNotEqual(code,0);self.assertFalse(body['ok']);self.assertFalse(self.writes.exists())
        self.env['MK_TEST_USER']='normal'
        code,body=self.run_script('enable',identifier='11111111-2222-4333-8444-555555555555')
        self.assertEqual(code,0,body);self.assertEqual(self.writes.read_text().strip(),'enable')

    def test_creation_uses_container_without_moving_existing_users(self):
        code,body=self.run_script('create',username='contract',name='Contract User',department='',password='Contract-test-value!123')
        self.assertEqual(code,0,body);self.assertEqual(body['data']['username'],'contract');self.assertEqual(self.writes.read_text().strip(),'create')
