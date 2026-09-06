"""Bounded Windows agy adapter, using only synthetic in-memory credentials."""
from __future__ import annotations

import _test_bootstrap  # noqa: F401
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest import mock

import gemini_subagent as runtime
import keychain_profiles as profiles
import windows_agy_contract as contract
import windows_credentials as credentials
from test_windows_credentials import FakeCredentialAPI
from login_journal import new_login_journal, validate_login_journal, LoginJournalError

CONTEXT = {'user_sid': 'S-1-5-21-1-2-3-1001', 'session_id': 7,
           'logon_id': '000000000000009a', 'elevated': False, 'integrity_level': 8192}
A = b'synthetic-account-a-record-only'
B = b'synthetic-account-b-record-only'
REFRESHED = b'synthetic-account-a-refreshed-only'


class MetadataAPI(FakeCredentialAPI):
    def __init__(self):
        super().__init__()
        self.metadata_override = {}

    def read(self, target, kind, flags, output):
        success = super().read(target, kind, flags, output)
        if success and target in self.items:
            import ctypes
            pointer = ctypes.cast(output, ctypes.POINTER(credentials.PCREDENTIALW))[0]
            record = self.allocations[ctypes.addressof(pointer.contents)][0]
            record.TargetName = target
            record.UserName = contract.USERNAME
            record.Persist = 2
            for key, value in self.metadata_override.items():
                setattr(record, key, value)
        return success


class WindowsAgyAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.api = MetadataAPI()
        self.api.items[contract.ACTIVE_TARGET] = bytearray(A)
        self.access = profiles.WindowsAntigravityAccess(Path(self.temp.name)/'agy.exe')
        self.access._backend = credentials.WindowsCredentialManagerAccess(
            api=self.api, username=contract.USERNAME, strict_metadata=True)
        self.store = profiles.KeychainProfileStore(self.access, lock_path=Path(self.temp.name)/'auth.lock')
        self.guard = mock.patch.object(contract, 'require_binary', return_value={'contract':contract.CONTRACT_ID,'user_sid':CONTEXT['user_sid']})
        self.guard.start(); self.addCleanup(self.guard.stop)
        self.first, self.second = str(uuid.uuid4()), str(uuid.uuid4())

    def test_capture_switch_refresh_and_reopen_do_not_mix_profiles(self):
        self.store.capture(self.first)
        self.api.items[contract.ACTIVE_TARGET] = bytearray(B)
        self.store.capture(self.second)
        self.store.restore(self.first)
        self.assertEqual(self.api.items[contract.ACTIVE_TARGET], A)
        self.api.items[contract.ACTIVE_TARGET] = bytearray(REFRESHED)
        self.store.capture(self.first, overwrite=True)
        reopened = profiles.KeychainProfileStore(self.access, lock_path=self.store.lock_path)
        reopened.restore(self.second)
        self.assertEqual(self.api.items[contract.ACTIVE_TARGET], B)
        reopened.restore(self.first)
        self.assertEqual(self.api.items[contract.ACTIVE_TARGET], REFRESHED)
        self.assertEqual(self.api.items[contract.PROFILE_TARGET_PREFIX+self.second], B)
        self.assertTrue(reopened.delete(self.second))
        self.assertFalse(reopened.delete(self.second))
        self.assertTrue(all(self.api.freed_wiped))

    def test_failed_capture_rolls_back_without_secret_in_exception(self):
        self.store.capture(self.first)
        self.api.items[contract.ACTIVE_TARGET] = bytearray(REFRESHED)
        original = self.api.CredWriteW.function
        count = 0
        def corrupt_once(pointer, flags):
            nonlocal count
            result = original(pointer, flags); count += 1
            if count == 1:
                self.api.items[contract.PROFILE_TARGET_PREFIX+self.first] = bytearray(B)
            return result
        self.api.CredWriteW.function = corrupt_once
        with self.assertRaises(profiles.KeychainTransactionError) as caught:
            self.store.capture(self.first, overwrite=True)
        self.assertEqual(self.api.items[contract.PROFILE_TARGET_PREFIX+self.first], A)
        self.assertNotIn(REFRESHED.decode(), str(caught.exception))
        self.assertEqual(self.api.items[contract.ACTIVE_TARGET], REFRESHED)

    def test_unknown_targets_and_provider_drift_reject_before_native_access(self):
        for item in [profiles.KeychainTuple('other','antigravity'), profiles.KeychainTuple(profiles.PROFILE_SERVICE,'NOT-A-UUID')]:
            for op in ('read','delete'):
                with self.assertRaises(profiles.CredentialShapeError):getattr(self.access,op)(item)
        self.assertFalse(self.api.calls)
        with mock.patch.object(contract,'require_binary',side_effect=credentials.WindowsCredentialUnavailableError('contract changed')):
            with self.assertRaises(profiles.ProfilePlatformUnsupportedError):self.store.capture(self.first)
        self.assertFalse(self.api.calls)

    def test_unexpected_metadata_is_retained_and_native_buffer_wiped(self):
        for key,value in [('Persist',1),('UserName','wrong-user'),('Flags',2),('AttributeCount',1),('Comment','foreign'),('TargetAlias','foreign'),('TargetName','other')]:
            with self.subTest(key=key):
                self.api.metadata_override = {key:value}
                with self.assertRaises(profiles.KeychainProfileError):self.store.capture(self.first)
                self.assertNotIn(contract.PROFILE_TARGET_PREFIX+self.first,self.api.items)
                self.assertTrue(self.api.freed_wiped[-1])
        self.api.metadata_override = {}

    def test_invalid_record_bounds_and_framing_never_saved(self):
        for value in (b'x'*15,b'x'*2561,b'synthetic-invalid\nrecord',b'synthetic-invalid\0record'):
            self.api.items[contract.ACTIVE_TARGET]=bytearray(value)
            with self.assertRaises(profiles.KeychainProfileError):self.store.capture(self.first)
            self.assertNotIn(contract.PROFILE_TARGET_PREFIX+self.first,self.api.items)


class WindowsAgyIdentityTests(unittest.TestCase):
    def test_binary_is_pinned_and_replacement_or_link_rejected(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(contract,'require_context',return_value=CONTEXT):
            binary=Path(temporary).resolve()/'agy.exe';binary.write_bytes(b'synthetic-provider')
            digest=hashlib.sha256(binary.read_bytes()).hexdigest()
            with mock.patch.dict(contract.VERIFIED_BINARIES,{digest:'synthetic'}):
                self.assertEqual(contract.require_binary(binary)['version'],'synthetic')
                binary.write_bytes(b'replaced-provider')
                with self.assertRaises(credentials.WindowsCredentialUnavailableError):contract.require_binary(binary)
            with self.assertRaises(credentials.WindowsCredentialUnavailableError):contract.require_binary('relative.exe')

    def test_wrong_desktop_identity_refused_without_credential_access(self):
        with mock.patch.object(contract.platform_fs,'IS_WINDOWS',True):
            for changes in ({'elevated':True},{'session_id':0},{'integrity_level':4096},{'logon_id':'bad'}):
                with self.subTest(changes=changes), mock.patch.object(contract.platform_process,'current_context',return_value={**CONTEXT,**changes}):
                    with self.assertRaises(credentials.WindowsCredentialUnavailableError):contract.require_context()

    def test_dirty_slot_and_interrupted_import_cannot_cross_logon(self):
        account={'id':str(uuid.uuid4()),'name':'synthetic','provider':'agy','profile_mode':runtime.WINDOWS_PROFILE_MODE,'credential_revision':1}
        slot={'active_account_id':account['id'],'credential_revision':1,'dirty':True,'windows_context':{**CONTEXT,'logon_id':'000000000000009b'}}
        lease=mock.Mock()
        with mock.patch.object(runtime,'IS_WINDOWS',True), mock.patch.object(runtime.platform_process,'current_context',return_value=CONTEXT), mock.patch.object(runtime,'recover_login_transaction'), mock.patch.object(runtime,'load_auth_slot',return_value=slot), mock.patch.object(runtime,'account_by_id',return_value=account), mock.patch.object(runtime,'account_profile_key',return_value=account['id']):
            with self.assertRaisesRegex(runtime.BridgeError,'context'):runtime.reconcile_auth_slot(lease)
            lease.capture.assert_not_called()
        record=new_login_journal(target_account_id=account['id'],target_account_name='synthetic',target_original_revision=0,target_was_ready=False,previous_account_id=None,previous_account_revision=None,recovery_profile_uuid=str(uuid.uuid4()),windows_context=slot['windows_context'])
        with mock.patch.object(runtime,'IS_WINDOWS',True), mock.patch.object(runtime.platform_process,'current_context',return_value=CONTEXT), mock.patch.object(runtime,'load_login_journal',return_value=record), mock.patch.object(runtime,'login_transaction_path',return_value=Path('unused')), mock.patch.object(runtime,'_login_journal_target') as target:
            with self.assertRaisesRegex(runtime.BridgeError,'context'):runtime.recover_login_transaction(lease)
            target.assert_not_called();lease.verify.assert_not_called()
        changed=dict(record);changed['windows_context']={**CONTEXT,'secret':'forbidden'}
        with self.assertRaises(LoginJournalError):validate_login_journal(changed)

    def test_account_user_and_platform_must_match(self):
        evidence={'user_sid':CONTEXT['user_sid'],'contract':contract.CONTRACT_ID}
        account={'id':str(uuid.uuid4()),'name':'test','binary':'test.exe','profile_mode':runtime.WINDOWS_PROFILE_MODE,'windows_owner_sid':CONTEXT['user_sid'],'windows_credential_contract':contract.CONTRACT_ID}
        with mock.patch.object(runtime,'IS_WINDOWS',True), mock.patch.object(contract,'require_binary',return_value=evidence):
            self.assertEqual(runtime.account_profile_key(account),account['id'])
            for changes in ({'windows_owner_sid':'S-1-5-21-2-3-4-1001'},{'profile_mode':runtime.KEYCHAIN_PROFILE_MODE},{'windows_credential_contract':'unknown'}):
                with self.assertRaises(runtime.BridgeError):runtime.account_profile_key({**account,**changes})
