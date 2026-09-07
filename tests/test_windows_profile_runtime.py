"""Native command/worker coverage; real Credential Manager, synthetic UUID only."""
from __future__ import annotations
import _test_bootstrap  # noqa: F401
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

import platform_process
import windows_credentials as wc

PLUGIN=Path(__file__).resolve().parents[1] / "plugins/gemini-subagent"
RUNNER=PLUGIN/'scripts/gemini_subagent.py'
MOCK=Path(__file__).resolve().parent / "mock_google_cli.py"
SUPPORT=Path(__file__).resolve().parent / "support"
A=b'synthetic-native-account-a-record'
B=b'synthetic-native-account-b-record'
REFRESHED=b'synthetic-provider-refreshed-record'


@unittest.skipUnless(os.name=='nt','requires native Windows; synthetic UUID vault only')
class WindowsProfileRuntimeTests(unittest.TestCase):
    def setUp(self):
        context=platform_process.current_context()
        if context['elevated'] or context['session_id']==0 or context['integrity_level']!=8192:
            self.skipTest('requires ordinary desktop context; hosted CI is not native acceptance')
        self.temp=tempfile.TemporaryDirectory(prefix='agy-vault-测试 ')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.runtime=self.root/'runtime';self.project=self.root/'project';self.project.mkdir()
        self.namespace=str(uuid.uuid4())
        # Keep every target intent in the outer lab audit, including after an
        # interrupted child or test process. Never depend on a deleted tempdir.
        self.audit=Path(os.environ.get('GEMINI_SUBAGENT_TEST_AUDIT_ROOT',
                                      str(Path(tempfile.gettempdir())/'gemini-subagent-native-audit')))
        self.store=wc.WindowsCredentialManagerAccess(test_namespace=self.namespace,persist=wc.CRED_PERSIST_SESSION,username='antigravity',strict_metadata=True)
        self.active=self.store.test_target_prefix+'active'
        self.env={**os.environ,'GEMINI_SUBAGENT_TESTING':'1','GEMINI_SUBAGENT_RUNTIME_ROOT':str(self.runtime),
                  'GEMINI_SUBAGENT_ALLOWED_ROOTS':str(self.project),'GEMINI_SUBAGENT_AGY_BIN':str(MOCK),
                  'GEMINI_SUBAGENT_TEST_WINDOWS_VAULT_NAMESPACE':self.namespace,'GEMINI_SUBAGENT_TEST_AUDIT_ROOT':str(self.audit),
                  'PYTHONPATH':os.pathsep.join([str(SUPPORT),str(PLUGIN/'scripts')]),'PYTHONUTF8':'1'}
        self.jobs=[]
        self.addCleanup(self.cleanup)
        from support.native_resource_audit import record
        record('intent',self.active)
        self.store.write(self.active,A)

    def invoke(self,*args,check=True,env=None):
        p=subprocess.run([sys.executable,'-B',str(RUNNER),*args,'--json'],env=env or self.env,cwd=self.project,capture_output=True,text=True,encoding='utf-8',timeout=35)
        if check:self.assertEqual(p.returncode,0,p.stderr)
        return p

    def account(self,name,value):
        self.store.write(self.active,value)
        added=json.loads(self.invoke('account','add',name,'--provider','agy','--credential-profile').stdout)
        # Force is only for claiming this fixture's externally selected synthetic account.
        captured=json.loads(self.invoke('account','import-current',name,'--force','--timeout','10').stdout)
        self.assertEqual(captured['credential_state'],'ready')
        return added['id']

    def read(self,target):
        value=self.store.read(target)
        try:return bytes(value) if value is not None else None
        finally:wc._wipe(value)

    def start(self,prompt,seconds=20,env=None):
        p=self.invoke('start','--provider','agy','--account','first','--model','gemini-mock-model','--cwd',str(self.project),'--mode','read','--prompt',prompt,'--timeout-seconds',str(seconds),env=env)
        job=json.loads(p.stdout);self.jobs.append(job['job_id']);return job['job_id']

    def cleanup(self):
        for jid in self.jobs:
            path=self.runtime/'jobs'/(jid+'.json')
            if path.exists() and json.loads(path.read_text())['state'] in ['queued','running','cancelling']:
                self.invoke('cancel',jid,check=False)
        targets={self.active}
        for p in self.audit.glob('*.json'):
            item=json.loads(p.read_text())
            if item.get('kind')=='synthetic_credential' and item['target'].startswith(self.store.test_target_prefix):
                targets.add(item['target'])
        from support.native_resource_audit import record
        for target in targets:
            self.assertTrue(target.startswith(self.store.test_target_prefix))
            self.store.delete(target);self.assertIsNone(self.store.read(target));record('deleted',target)

    def test_two_saved_accounts_survive_new_cli_and_refresh_goes_to_owner(self):
        first=self.account('first',A);second=self.account('second',B)
        self.invoke('account','activate','first')
        self.assertEqual(self.read(self.active),A)
        listed=json.loads(self.invoke('account','list').stdout)
        self.assertEqual({a['name'] for a in listed if a['profile_mode']=='windows-credential-manager-vault'},{'first','second'})
        env={**self.env,'GEMINI_SUBAGENT_TEST_PROFILE_REFRESH':'1'}
        jid=self.start('Return synthetic result',env=env)
        result=json.loads(self.invoke('wait',jid,'--timeout','25').stdout)
        self.assertEqual(result['state'],'completed')
        self.assertEqual(self.read(self.store.test_target_prefix+first),REFRESHED)
        self.assertEqual(self.read(self.store.test_target_prefix+second),B)
        self.invoke('account','activate','second');self.assertEqual(self.read(self.active),B)
        self.invoke('account','activate','first');self.assertEqual(self.read(self.active),REFRESHED)
        for p in self.runtime.rglob('*'):
            if p.is_file():
                data=p.read_bytes()
                for secret in [A,B,REFRESHED]:self.assertNotIn(secret,data,str(p))

    def test_switch_is_refused_during_worker_and_cancel_releases_account(self):
        self.account('first',A);self.account('second',B)
        jid=self.start('SLEEP_FOR_CANCEL',seconds=30)
        deadline=time.monotonic()+8
        members=[]
        while time.monotonic()<deadline:
            job=json.loads((self.runtime/'jobs'/(jid+'.json')).read_text())
            lease=Path(job['provider_lease_path'])
            if lease.exists():
                owner=json.loads(lease.read_text())
                members=platform_process.group_members(owner['pid'])
                if job['state']=='running' and len(members)>1:break
            time.sleep(.1)
        self.assertEqual(job['state'],'running')
        self.assertGreater(len(members),1)
        rejected=self.invoke('account','activate','second',check=False)
        self.assertNotEqual(rejected.returncode,0)
        cancelled=json.loads(self.invoke('cancel',jid).stdout)
        self.assertEqual(cancelled['state'],'cancelled')
        self.assertTrue(all(not platform_process.alive(pid) for pid in members))
        self.assertFalse(lease.exists())
        self.invoke('account','activate','second');self.assertEqual(self.read(self.active),B)

    def test_import_crash_is_recovered_from_journal_in_original_context(self):
        self.invoke('account','add','first','--provider','agy','--credential-profile')
        code=f'''import sys,os;sys.path.insert(0,{str(PLUGIN/'scripts')!r});import gemini_subagent as r
original=r._mark_login_metadata_committed
def crash(record):os._exit(17)
r._mark_login_metadata_committed=crash
sys.argv=[str(r.SCRIPT_PATH),'account','import-current','first','--timeout','10','--json']
raise SystemExit(r.main())'''
        p=subprocess.run([sys.executable,'-B','-c',code],env=self.env,cwd=self.project,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,17)
        journal=self.runtime/'test-auth-domain/login-transaction.json';self.assertTrue(journal.exists())
        # Another import reaches the same recovery path under the canonical lock.
        self.invoke('account','import-current','first','--timeout','10')
        self.assertFalse(journal.exists())
        accounts=json.loads((self.runtime/'accounts.json').read_text())['accounts']
        saved=accounts['first'];self.assertEqual(saved['credential_state'],'ready')
        self.assertEqual(self.read(self.store.test_target_prefix+saved['id']),A)
