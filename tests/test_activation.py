"""Security behavior tests for local WebShield activation planning."""

from __future__ import annotations

import json
import stat
from pathlib import Path
import tempfile
import unittest

from webshield.activation import ActivationError, ActivationTransaction, DEBIAN_SYSTEMD_PROFILE, verify_bundle
from webshield.output import write_fragments
from webshield.policy import load_policy
from webshield.render import render_all

from tests.test_policy import VALID_POLICY


class BundleVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        policy_path = self.root / "policy.toml"
        policy_path.write_text(VALID_POLICY, encoding="utf-8")
        self.bundle = self.root / "bundle"
        write_fragments(self.bundle, render_all(load_policy(policy_path)))

    def manifest(self) -> dict[str, object]:
        return json.loads((self.bundle / "manifest.json").read_text(encoding="utf-8"))

    def write_manifest(self, manifest: dict[str, object]) -> None:
        (self.bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def test_verifies_exact_expected_fragments(self) -> None:
        """A changed profile file set must fail this trust-boundary test."""
        verified = verify_bundle(self.bundle, DEBIAN_SYSTEMD_PROFILE)

        self.assertEqual(set(verified.files), set(DEBIAN_SYSTEMD_PROFILE.destinations))

    def test_rejects_an_extra_bundle_file(self) -> None:
        """Accepting unlisted content would let a bundle expand activation scope."""
        (self.bundle / "extra.conf").write_text("unexpected", encoding="utf-8")

        with self.assertRaisesRegex(ActivationError, "unexpected file"):
            verify_bundle(self.bundle, DEBIAN_SYSTEMD_PROFILE)

    def test_rejects_a_manifest_hash_mismatch(self) -> None:
        """Skipping content verification would permit a post-render modification."""
        manifest = self.manifest()
        manifest["files"]["nginx/webshield.conf"] = "0" * 64
        self.write_manifest(manifest)

        with self.assertRaisesRegex(ActivationError, "checksum"):
            verify_bundle(self.bundle, DEBIAN_SYSTEMD_PROFILE)

    def test_rejects_a_traversing_manifest_path(self) -> None:
        """Trusting a relative manifest path would escape the profile mapping."""
        manifest = self.manifest()
        digest = manifest["files"].pop("nginx/webshield.conf")
        manifest["files"]["../etc/nginx.conf"] = digest
        self.write_manifest(manifest)

        with self.assertRaisesRegex(ActivationError, "file set"):
            verify_bundle(self.bundle, DEBIAN_SYSTEMD_PROFILE)

    def test_rejects_a_symlinked_expected_fragment(self) -> None:
        """Following a symlink would let a bundle read an uncontrolled file."""
        target = self.bundle / "nginx" / "webshield.conf"
        target.unlink()
        target.symlink_to(self.bundle / "manifest.json")

        with self.assertRaisesRegex(ActivationError, "symlink"):
            verify_bundle(self.bundle, DEBIAN_SYSTEMD_PROFILE)


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.outcomes: dict[tuple[str, ...], bool] = {}

    def run(self, command: tuple[str, ...]) -> bool:
        self.commands.append(command)
        return self.outcomes.get(command, True)


class SnapshotRunner(RecordingRunner):
    def __init__(self, activation_root: Path, observed_command: tuple[str, ...]) -> None:
        super().__init__()
        self.activation_root = activation_root
        self.observed_command = observed_command
        self.snapshot_at_syntax: dict[str, bytes | None] | None = None

    def run(self, command: tuple[str, ...]) -> bool:
        if command == self.observed_command:
            self.snapshot_at_syntax = {
                destination: (
                    (self.activation_root / destination).read_bytes()
                    if (self.activation_root / destination).exists()
                    else None
                )
                for destination in DEBIAN_SYSTEMD_PROFILE.destinations.values()
            }
        return super().run(command)


class ActivationTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        policy_path = self.root / "policy.toml"
        policy_path.write_text(VALID_POLICY, encoding="utf-8")
        self.bundle = self.root / "bundle"
        write_fragments(self.bundle, render_all(load_policy(policy_path)))
        self.activation_root = self.root / "activation-root"
        self.activation_root.mkdir()
        self.runner = RecordingRunner()
        self.transaction = ActivationTransaction(DEBIAN_SYSTEMD_PROFILE, self.activation_root, self.runner)

    def target_snapshot(self) -> dict[str, bytes | None]:
        snapshot: dict[str, bytes | None] = {}
        for destination in DEBIAN_SYSTEMD_PROFILE.destinations.values():
            path = self.activation_root / destination
            snapshot[destination] = path.read_bytes() if path.exists() else None
        return snapshot

    def write_existing_targets(self) -> dict[str, bytes | None]:
        for index, destination in enumerate(DEBIAN_SYSTEMD_PROFILE.destinations.values()):
            path = self.activation_root / destination
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"previous-{index}\n", encoding="utf-8")
        return self.target_snapshot()

    def test_plan_changes_no_files_and_runs_no_commands(self) -> None:
        """A plan mode that stages or reloads would violate its safe contract."""
        before = self.target_snapshot()

        plan = self.transaction.plan(self.bundle)

        self.assertEqual(set(plan.destinations), set(DEBIAN_SYSTEMD_PROFILE.destinations.values()))
        self.assertEqual(self.target_snapshot(), before)
        self.assertEqual(self.runner.commands, [])

    def test_syntax_failure_leaves_targets_unchanged(self) -> None:
        """Writing before all fixed syntax checks pass would risk a broken service."""
        before = self.write_existing_targets()
        self.runner.outcomes[DEBIAN_SYSTEMD_PROFILE.syntax_commands[0]] = False

        with self.assertRaisesRegex(ActivationError, "syntax"):
            self.transaction.activate(self.bundle)

        self.assertEqual(self.target_snapshot(), before)
        self.assertEqual(self.runner.commands, [DEBIAN_SYSTEMD_PROFILE.syntax_commands[0]])

    def test_syntax_check_observes_new_targets_before_rollback(self) -> None:
        """Checking the old files would approve an unvalidated new configuration."""
        before = self.write_existing_targets()
        runner = SnapshotRunner(self.activation_root, DEBIAN_SYSTEMD_PROFILE.syntax_commands[0])
        runner.outcomes[DEBIAN_SYSTEMD_PROFILE.syntax_commands[0]] = False
        transaction = ActivationTransaction(DEBIAN_SYSTEMD_PROFILE, self.activation_root, runner)
        expected = {
            destination: (self.bundle / source).read_bytes()
            for source, destination in DEBIAN_SYSTEMD_PROFILE.destinations.items()
        }

        with self.assertRaisesRegex(ActivationError, "syntax"):
            transaction.activate(self.bundle)

        self.assertEqual(runner.snapshot_at_syntax, expected)
        self.assertEqual(self.target_snapshot(), before)
        self.assertEqual(runner.commands, [DEBIAN_SYSTEMD_PROFILE.syntax_commands[0]])

    def test_successful_activation_writes_only_profile_destinations_and_backs_up(self) -> None:
        """Expanding writes beyond profile destinations must fail this boundary test."""
        self.write_existing_targets()

        result = self.transaction.activate(self.bundle)

        self.assertTrue(result.backup_directory.is_dir())
        self.assertEqual(
            set(result.destinations),
            set(DEBIAN_SYSTEMD_PROFILE.destinations.values()),
        )
        self.assertEqual(
            self.runner.commands,
            list(DEBIAN_SYSTEMD_PROFILE.syntax_commands)
            + list(DEBIAN_SYSTEMD_PROFILE.reload_commands)
            + list(DEBIAN_SYSTEMD_PROFILE.health_commands),
        )
        self.assertFalse((self.activation_root / "etc/nginx/nginx.conf").exists())

    def test_activation_creates_private_backup_and_staging_bases(self) -> None:
        """World-readable activation state could expose prior server configuration."""
        self.transaction.activate(self.bundle)

        for relative_path in (
            DEBIAN_SYSTEMD_PROFILE.backup_relative,
            DEBIAN_SYSTEMD_PROFILE.staging_relative,
        ):
            mode = stat.S_IMODE((self.activation_root / relative_path).stat().st_mode)
            self.assertEqual(mode, 0o700)

    def test_health_failure_restores_previous_targets_and_reloads_recovery_state(self) -> None:
        """Leaving a partially activated service after a failed health check is unsafe."""
        before = self.write_existing_targets()
        self.runner.outcomes[DEBIAN_SYSTEMD_PROFILE.health_commands[0]] = False

        with self.assertRaisesRegex(ActivationError, "health"):
            self.transaction.activate(self.bundle)

        self.assertEqual(self.target_snapshot(), before)
        self.assertEqual(
            self.runner.commands,
            list(DEBIAN_SYSTEMD_PROFILE.syntax_commands)
            + list(DEBIAN_SYSTEMD_PROFILE.reload_commands)
            + [DEBIAN_SYSTEMD_PROFILE.health_commands[0]]
            + list(DEBIAN_SYSTEMD_PROFILE.reload_commands),
        )
