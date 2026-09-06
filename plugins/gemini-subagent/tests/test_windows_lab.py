import _test_bootstrap  # noqa: F401
import importlib.util
import os
from pathlib import Path
import tempfile
import hashlib
import subprocess
import sys
import uuid
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("windows_lab_under_test", ROOT / "tools/windows_lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LabRollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = lab.Ledger(self.root / "run", [self.root])

    def test_preview_apply_and_repeat_restore_original_configuration(self):
        target = self.root / "config.toml"
        target.write_bytes(b"original\n")
        parent_acl = lab.acl(target.parent)
        self.ledger.write(target, b"test\n")
        self.assertEqual(lab.acl(target.parent), parent_acl)
        self.assertEqual(self.ledger.rollback()[0]["status"], "WOULD_REVERT")
        self.assertEqual(target.read_bytes(), b"test\n")
        restored = self.ledger.rollback(True)[0]
        self.assertEqual(restored["status"], "REVERTED", restored)
        self.assertEqual(target.read_bytes(), b"original\n")
        self.assertEqual(self.ledger.rollback(True)[0]["status"], "ALREADY_REVERTED")

    def test_later_manual_changes_are_preserved(self):
        target = self.root / "config.toml"
        self.ledger.write(target, b"test")
        target.write_bytes(b"user edit")
        self.assertEqual(self.ledger.rollback(True)[0]["status"], "CONFLICT")
        self.assertEqual(target.read_bytes(), b"user edit")

    def test_crash_after_write_before_receipt_uses_predeclared_digest(self):
        target = self.root / "config.toml"
        with mock.patch.object(self.ledger, "finish", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(RuntimeError):
                self.ledger.write(target, b"registered bytes")
        self.assertEqual(self.ledger.rollback(True)[0]["status"], "REVERTED")
        self.assertFalse(target.exists())

    def test_installation_tree_removes_only_verified_owned_content(self):
        target = self.root / "tool"
        operation = self.ledger.begin("tool", target)
        target.mkdir()
        (target / "binary").write_bytes(b"fixture")
        self.ledger.finish(operation)
        self.assertEqual(self.ledger.rollback(True)[0]["status"], "REVERTED")
        self.assertFalse(target.exists())

    def test_unregistered_file_prevents_recursive_installation_deletion(self):
        target = self.root / "tool"
        operation = self.ledger.begin("tool", target)
        target.mkdir()
        (target / "binary").write_bytes(b"fixture")
        self.ledger.finish(operation)
        (target / "user.txt").write_bytes(b"keep")
        self.assertEqual(self.ledger.rollback(True)[0]["status"], "CONFLICT")
        self.assertTrue((target / "user.txt").exists())

    def test_changed_child_permissions_prevent_recursive_deletion(self):
        target = self.root / "tool"
        operation = self.ledger.begin("tool", target)
        target.mkdir()
        child = target / "binary"
        child.write_bytes(b"fixture")
        self.ledger.finish(operation)
        if os.name == "nt":
            lab.fs.secure_chmod(child, 0o600)
        else:
            child.chmod(0o400)
        self.assertEqual(self.ledger.rollback(True)[0]["status"], "CONFLICT")
        self.assertTrue(child.exists())

    @unittest.skipUnless(os.name == "nt", "requires native owned DACL restoration")
    def test_native_private_dacl_restores_without_audit_privilege(self):
        target = self.root / "acl-fixture"
        target.write_bytes(b"fixture")
        lab.fs.secure_chmod(target, 0o600)
        original = lab.acl(target)
        changed = original.replace("(A;;FA;;;BA)", "")
        self.assertNotEqual(changed, original)
        try:
            lab.fs.restore_dacl(target, changed)
            self.assertNotEqual(lab.acl(target), original)
        finally:
            lab.fs.restore_dacl(target, original)
        self.assertEqual(lab.acl(target), original)

    def test_interrupted_unknown_installer_is_retained(self):
        target = self.root / "tool"
        self.ledger.begin("tool", target)
        target.mkdir()
        (target / "partial").write_bytes(b"not yet verified")
        self.assertEqual(self.ledger.rollback(True)[0]["status"], "CONFLICT")
        self.assertTrue(target.exists())

    def test_modified_task_is_not_deleted(self):
        name = "GeminiSubagentLab-" + uuid.uuid4().hex
        with mock.patch.object(lab, "ps", return_value="manually changed registration") as query:
            with self.assertRaisesRegex(ValueError, "subsequently modified"):
                lab.cleanup_task(name, hashlib.sha256(b"original").hexdigest(), True)
        self.assertEqual(query.call_count, 1)
        self.assertNotIn("Unregister", query.call_args.args[0])

    def test_foreign_credential_context_is_rejected_before_native_lookup(self):
        context = {"user_sid": "S-1-5-21-1", "session_id": 7, "logon_id": "0000000000000001"}
        other = dict(context, session_id=8)
        import windows_credentials as credentials
        with mock.patch.object(lab.processes, "current_context", return_value=other), \
             mock.patch.object(credentials, "WindowsCredentialManagerAccess", side_effect=AssertionError("must not access credentials")):
            with self.assertRaisesRegex(ValueError, "original SID"):
                lab.cleanup_synthetic_credential({"context": context, "target": "unused"}, True)

    @unittest.skipUnless(os.name == "nt", "requires native process handles and birth tokens")
    def test_registered_process_cleanup_rejects_wrong_birth_and_preserves_sentinel(self):
        with subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"]) as child, \
             subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"]) as sentinel:
            try:
                identity = lab.processes.identity(child.pid)
                wrong = dict(identity, start_usec=identity["start_usec"] + 1)
                with self.assertRaisesRegex(ValueError, "PID was reused"):
                    lab.cleanup_process(wrong, True)
                self.assertIsNone(child.poll())
                self.assertEqual(lab.cleanup_process(identity, False), "WOULD_REMOVE")
                self.assertIsNone(child.poll())
                self.assertEqual(lab.cleanup_process(identity, True), "REMOVED")
                child.wait(timeout=10)
                self.assertIsNone(sentinel.poll())
            finally:
                for process in (child, sentinel):
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=10)

    @unittest.skipUnless(os.name == "nt", "requires native synthetic Credential Manager cleanup")
    def test_registered_synthetic_credential_is_previewed_then_cleaned(self):
        import windows_credentials as credentials
        from support.native_resource_audit import record
        store = credentials.WindowsCredentialManagerAccess(test_namespace=str(uuid.uuid4()),
                                                            persist=credentials.CRED_PERSIST_SESSION)
        target = store.test_target_prefix + "lab-rollback"
        record("intent", target)
        self.ledger.event("resource_intent", kind="synthetic_credential", target=target,
                          context=lab.processes.current_context())
        try:
            store.write(target, b"synthetic-rollback-only")
            self.assertEqual(self.ledger.rollback()[0]["status"], "WOULD_REMOVE")
            self.assertEqual(self.ledger.rollback(True)[0]["status"], "REMOVED")
            self.assertIsNone(store.read(target))
            self.assertEqual(self.ledger.rollback(True)[0]["status"], "ALREADY_REMOVED")
        finally:
            store.delete(target)
            self.assertIsNone(store.read(target))
            record("deleted", target)

    def test_links_and_outside_paths_cannot_widen_cleanup(self):
        outside = self.root.parent / (self.root.name + "-outside")
        outside.mkdir()
        self.addCleanup(outside.rmdir)
        with self.assertRaises(ValueError):
            self.ledger.begin("outside", outside)
        link = self.root / "link"
        if os.name == "nt":
            # Directory junction creation requires no symlink privilege.
            import subprocess
            subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(outside)],
                           check=True, capture_output=True)
            self.addCleanup(link.rmdir)
        else:
            link.symlink_to(outside, target_is_directory=True)
            self.addCleanup(link.unlink)
        with self.assertRaises(ValueError):
            self.ledger.write(link / "victim", b"no")
        self.assertEqual(list(outside.iterdir()), [])

    def test_credentials_are_never_backed_up_or_automatically_removed(self):
        target = self.root / "auth.json"
        with self.assertRaises(ValueError):
            self.ledger.write(target, b"not a credential")
        tool = self.root / "profile"
        operation = self.ledger.begin("profile", tool)
        tool.mkdir()
        (tool / "auth.json").write_bytes(b"synthetic auth fixture")
        self.ledger.finish(operation)
        events = "".join(p.read_text(encoding="utf-8") for p in self.ledger.events.glob("*.json"))
        self.assertNotIn("synthetic auth fixture", events)
        self.assertEqual(self.ledger.rollback(True)[0]["status"], "CONFLICT")
