"""Opt-in native test vault confined to a random synthetic namespace.

Loaded only by test sitecustomize; production scripts never import this file.
No caller-controlled target can escape WindowsCredentialManagerAccess's UUID
namespace check. The provider writes only a hard-coded synthetic refresh value.
"""
import os
from pathlib import Path
import uuid


def install():
    namespace=os.environ.get('GEMINI_SUBAGENT_TEST_WINDOWS_VAULT_NAMESPACE')
    if namespace is None:return
    if os.name!='nt' or os.environ.get('GEMINI_SUBAGENT_TESTING')!='1':
        raise RuntimeError('Synthetic Windows profiles require native mock mode')
    parsed=uuid.UUID(namespace)
    if parsed.version!=4 or str(parsed)!=namespace:raise RuntimeError('Invalid test namespace')
    import windows_credentials as wc
    import windows_agy_contract as contract
    import keychain_profiles as profiles
    import platform_process
    from native_resource_audit import record

    def verified_mock_binary(binary):
        return {'contract':contract.CONTRACT_ID,'user_sid':platform_process.current_context()['user_sid'],'version':'synthetic-only','sha256':'synthetic-only'}
    contract.require_binary=verified_mock_binary
    original=profiles.WindowsAntigravityAccess
    class SyntheticAccess(original):
        def __init__(self,provider_binary=None):
            super().__init__(provider_binary)
            self._backend=wc.WindowsCredentialManagerAccess(test_namespace=namespace,
                persist=wc.CRED_PERSIST_SESSION,username=contract.USERNAME,strict_metadata=True)
        def _target(self,item):
            target=super()._target(item)  # still enforce known tuples and UUIDs
            suffix='active' if target==contract.ACTIVE_TARGET else target.removeprefix(contract.PROFILE_TARGET_PREFIX)
            bounded=self._backend.test_target_prefix+suffix
            record('intent',bounded)  # journal before every potential mutation
            return bounded
    profiles.WindowsAntigravityAccess=SyntheticAccess
    if Path(__import__('sys').argv[0]).name=='mock_google_cli.py' and os.environ.get('GEMINI_SUBAGENT_TEST_PROFILE_REFRESH')=='1':
        import atexit
        def refresh():
            store=wc.WindowsCredentialManagerAccess(test_namespace=namespace,
                persist=wc.CRED_PERSIST_SESSION,username=contract.USERNAME,strict_metadata=True)
            target=store.test_target_prefix+'active';record('intent',target)
            store.write(target,b'synthetic-provider-refreshed-record')
        atexit.register(refresh)
