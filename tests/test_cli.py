"""End-to-end behavior tests for the WebShield command line interface."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from webshield.output import write_fragments
from webshield.policy import load_policy
from webshield.render import render_all


VALID_POLICY = """
[server]
listen_port = 443
server_name = "example.test"
document_root = "/srv/example/public"
tls = true
certificate_path = "/etc/ssl/example/fullchain.pem"
certificate_key_path = "/etc/ssl/example/private.key"

[php]
enabled = true
socket_path = "/run/php/php-fpm.sock"
allowed_extensions = [".php"]

[limits]
max_body_size = "8m"
request_rate_per_minute = 60

[security]
deny_hidden_files = true
deny_script_execution_in_uploads = true
disable_command_execution = true

[isolation.app]
service_user = "webapp"
read_only_paths = ["/srv/example"]
read_write_paths = ["/var/lib/example/cache"]
allowed_socket_paths = ["/run/php/php-fpm.sock"]
outbound_network = "none"
command_execution = false

[isolation.upload]
service_user = "webupload"
read_only_paths = []
read_write_paths = ["/var/lib/example/quarantine", "/var/lib/example/released"]
allowed_socket_paths = []
outbound_network = "none"
command_execution = false
"""


class CommandLineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.policy = self.root / "policy.toml"
        self.policy.write_text(VALID_POLICY, encoding="utf-8")

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "webshield", *arguments],
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=False,
        )

    def create_bundle(self) -> Path:
        bundle = self.root / "bundle"
        write_fragments(bundle, render_all(load_policy(self.policy)))
        return bundle

    def test_dry_run_does_not_create_the_output_directory(self) -> None:
        """Accidentally writing during a dry run must fail this test."""
        output = self.root / "generated"

        result = self.run_cli("render", str(self.policy), "--output", str(output), "--dry-run")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())

    def test_render_refuses_to_replace_existing_output(self) -> None:
        """Removing the empty-directory guard must fail this test."""
        output = self.root / "generated"
        output.mkdir()
        sentinel = output / "keep.txt"
        sentinel.write_text("unchanged", encoding="utf-8")

        result = self.run_cli("render", str(self.policy), "--output", str(output))

        self.assertEqual(result.returncode, 1)
        self.assertIn("output directory", result.stderr)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")

    def test_manifest_hashes_every_emitted_fragment(self) -> None:
        """A manifest that omits or mis-hashes a file must fail this test."""
        output = self.root / "generated"

        result = self.run_cli("render", str(self.policy), "--output", str(output))

        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest["files"]), {
            "nginx/webshield.conf",
            "php-fpm/webshield.conf",
            "systemd/nginx/webshield-hardening.conf",
            "systemd/app/webshield-hardening.conf",
            "systemd/upload/webshield-hardening.conf",
        })
        for relative_path, digest in manifest["files"].items():
            content = (output / relative_path).read_bytes()
            self.assertEqual(digest, hashlib.sha256(content).hexdigest())

    def test_invalid_policy_returns_usage_error_without_traceback(self) -> None:
        """Leaking an internal traceback for malformed operator input must fail this."""
        invalid = self.root / "invalid.toml"
        invalid.write_text("[server]\nlisten_port = 443\n", encoding="utf-8")

        result = self.run_cli("validate", str(invalid))

        self.assertEqual(result.returncode, 2)
        self.assertIn("policy error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_activation_plan_validates_a_bundle_without_changing_the_root(self) -> None:
        """A planning command that creates files or reloads services must fail this test."""
        bundle = self.create_bundle()
        activation_root = self.root / "activation-root"
        activation_root.mkdir()

        result = self.run_cli(
            "activation-plan",
            str(bundle),
            "--profile",
            "debian-systemd",
            "--root",
            str(activation_root),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("5 destinations", result.stdout)
        self.assertEqual(list(activation_root.iterdir()), [])

    def test_activation_plan_rejects_an_unknown_profile_without_traceback(self) -> None:
        """A caller-selectable profile could select arbitrary destination mappings."""
        bundle = self.create_bundle()
        activation_root = self.root / "activation-root"
        activation_root.mkdir()

        result = self.run_cli(
            "activation-plan",
            str(bundle),
            "--profile",
            "not-a-profile",
            "--root",
            str(activation_root),
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("activation error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
