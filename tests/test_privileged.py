"""Security-boundary tests for the local WebShield root helper."""

from __future__ import annotations

from io import StringIO
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from webshield.activation import ActivationError, DEBIAN_SYSTEMD_PROFILE
from webshield.output import write_fragments
from webshield.policy import load_policy
from webshield.privileged import ClosedProfileRunner, require_confirmation, require_root, run_activation
from webshield.render import render_all

from tests.test_policy import VALID_POLICY


class TerminalInput(StringIO):
    def isatty(self) -> bool:
        return True


class PrivilegedBoundaryTests(unittest.TestCase):
    def test_non_root_caller_is_rejected(self) -> None:
        """Removing the effective-UID gate would expose configuration writes."""
        with self.assertRaisesRegex(ActivationError, "root"):
            require_root(1000)

    def test_exact_activation_confirmation_is_accepted(self) -> None:
        """A weak confirmation could let an accidental Enter activate services."""
        require_confirmation(TerminalInput("ACTIVATE\n"), StringIO())

    def test_any_other_confirmation_is_rejected(self) -> None:
        """Accepting a partial phrase would weaken the destructive-action gate."""
        with self.assertRaisesRegex(ActivationError, "confirmation"):
            require_confirmation(TerminalInput("activate\n"), StringIO())

    def test_non_terminal_confirmation_is_rejected(self) -> None:
        """Piped input would permit non-interactive triggering of the helper."""
        with self.assertRaisesRegex(ActivationError, "terminal"):
            require_confirmation(StringIO("ACTIVATE\n"), StringIO())

    def test_closed_runner_rejects_unregistered_command(self) -> None:
        """A freely dispatched tuple would turn the helper into command execution."""
        runner = ClosedProfileRunner(DEBIAN_SYSTEMD_PROFILE)

        with self.assertRaisesRegex(ActivationError, "profile"):
            runner.run(("/bin/echo", "unexpected"))

    def test_closed_runner_treats_a_missing_registered_binary_as_failure(self) -> None:
        """A missing local binary must trigger rollback instead of a traceback."""
        runner = ClosedProfileRunner(DEBIAN_SYSTEMD_PROFILE)

        with patch("webshield.privileged.subprocess.run", side_effect=FileNotFoundError):
            result = runner.run(DEBIAN_SYSTEMD_PROFILE.syntax_commands[0])

        self.assertFalse(result)


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, command: tuple[str, ...]) -> bool:
        self.commands.append(command)
        return True


class PrivilegedIntegrationTests(unittest.TestCase):
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

    def test_confirmed_root_activation_runs_only_profile_commands(self) -> None:
        """Bypassing the verified transaction would permit scope expansion."""
        result = run_activation(
            [str(self.bundle), "--profile", "debian-systemd"],
            euid=0,
            reader=TerminalInput("ACTIVATE\n"),
            writer=StringIO(),
            activation_root=self.activation_root,
            runner=self.runner,
        )

        self.assertEqual(result, 0)
        self.assertEqual(
            self.runner.commands,
            list(DEBIAN_SYSTEMD_PROFILE.syntax_commands)
            + list(DEBIAN_SYSTEMD_PROFILE.reload_commands)
            + list(DEBIAN_SYSTEMD_PROFILE.health_commands),
        )

    def test_tampered_bundle_runs_no_commands_and_changes_no_targets(self) -> None:
        """A manifest failure must stop before privileged command dispatch."""
        manifest_path = self.bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"]["nginx/webshield.conf"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = run_activation(
            [str(self.bundle), "--profile", "debian-systemd"],
            euid=0,
            reader=TerminalInput("ACTIVATE\n"),
            writer=StringIO(),
            activation_root=self.activation_root,
            runner=self.runner,
        )

        self.assertEqual(result, 2)
        self.assertEqual(self.runner.commands, [])
        self.assertFalse((self.activation_root / "etc").exists())


class PackagingTests(unittest.TestCase):
    def test_project_exposes_the_local_root_helper_entry_point(self) -> None:
        """Omitting the script entry point would make the reviewed command unavailable."""
        project_root = Path(__file__).resolve().parents[1]
        metadata = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(
            metadata["project"]["scripts"]["webshield-activate"],
            "webshield.privileged:main",
        )
