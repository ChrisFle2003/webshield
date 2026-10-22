"""Behavior tests for loading and validating WebShield policies."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webshield.policy import PolicyError, load_policy


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


class PolicyLoadingTests(unittest.TestCase):
    def write_policy(self, content: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "policy.toml"
        path.write_text(content, encoding="utf-8")
        return path

    def test_loads_a_complete_safe_policy(self) -> None:
        """Removing a required field or mis-parsing scalars must fail this."""
        policy = load_policy(self.write_policy(VALID_POLICY))

        self.assertEqual(policy.server.listen_port, 443)
        self.assertEqual(policy.server.document_root, "/srv/example/public")
        self.assertTrue(policy.php.enabled)
        self.assertEqual(policy.php.allowed_extensions, (".php",))
        self.assertEqual(policy.isolation.app.service_user, "webapp")
        self.assertEqual(policy.isolation.upload.service_user, "webupload")

    def test_accepts_a_webroot_inside_read_only_application_code(self) -> None:
        """Rejecting a safe read-only parent would make normal deployments impossible."""
        policy = load_policy(self.write_policy(VALID_POLICY))

        self.assertIn("/srv/example", policy.isolation.app.read_only_paths)
        self.assertEqual(policy.server.document_root, "/srv/example/public")

    def test_rejects_an_unknown_key_instead_of_ignoring_a_typo(self) -> None:
        """A permissive parser would silently omit a protection setting."""
        path = self.write_policy(
            VALID_POLICY.replace(
                "deny_script_execution_in_uploads = true",
                "deny_script_execution_in_uploads = true\nextra_switch = true",
            )
        )

        with self.assertRaisesRegex(PolicyError, "unknown key"):
            load_policy(path)

    def test_rejects_a_relative_document_root(self) -> None:
        """A relative web root could resolve differently in production."""
        path = self.write_policy(VALID_POLICY.replace('"/srv/example/public"', '"public"'))

        with self.assertRaisesRegex(PolicyError, "absolute path"):
            load_policy(path)

    def test_rejects_a_newline_in_a_path_before_rendering(self) -> None:
        """Accepting a newline would permit configuration-directive injection."""
        path = self.write_policy(VALID_POLICY.replace('"/srv/example/public"', '"/srv/example\\nadd_header X-Injected yes;"'))

        with self.assertRaisesRegex(PolicyError, "line break"):
            load_policy(path)

    def test_rejects_enabled_tls_without_certificate_paths(self) -> None:
        """A TLS listener without key material references must not be rendered."""
        with self.assertRaisesRegex(PolicyError, "certificate"):
            load_policy(
                self.write_policy(
                    VALID_POLICY.replace(
                        'certificate_path = "/etc/ssl/example/fullchain.pem"\n'
                        'certificate_key_path = "/etc/ssl/example/private.key"\n',
                        "",
                    )
                )
            )

    def test_rejects_root_as_an_isolation_service_user(self) -> None:
        """Allowing a privileged app service would defeat the service boundary."""
        path = self.write_policy(VALID_POLICY.replace('service_user = "webapp"', 'service_user = "root"'))

        with self.assertRaisesRegex(PolicyError, "service user"):
            load_policy(path)

    def test_rejects_an_unknown_outbound_network_mode(self) -> None:
        """Silently accepting an unclear network mode could expose the service."""
        path = self.write_policy(VALID_POLICY.replace('outbound_network = "none"', 'outbound_network = "internet"', 1))

        with self.assertRaisesRegex(PolicyError, "outbound_network"):
            load_policy(path)

    def test_rejects_protected_system_paths_for_service_writes(self) -> None:
        """Allowing a service write path under /etc would enable host modification."""
        path = self.write_policy(VALID_POLICY.replace('"/var/lib/example/cache"', '"/etc/example-cache"'))

        with self.assertRaisesRegex(PolicyError, "protected path"):
            load_policy(path)

    def test_rejects_overlapping_writable_service_paths(self) -> None:
        """Sibling services must not share an ancestor/descendant write boundary."""
        path = self.write_policy(VALID_POLICY.replace('"/var/lib/example/cache"', '"/var/lib/example"'))

        with self.assertRaisesRegex(PolicyError, "overlap"):
            load_policy(path)

    def test_rejects_conflicting_command_execution_settings(self) -> None:
        """A contradictory legacy and isolation setting must not weaken PHP hardening."""
        path = self.write_policy(VALID_POLICY.replace("disable_command_execution = true", "disable_command_execution = false"))

        with self.assertRaisesRegex(PolicyError, "command execution"):
            load_policy(path)

    def test_rejects_noncanonical_isolation_paths(self) -> None:
        """Equivalent spellings such as // could bypass overlap checks."""
        path = self.write_policy(VALID_POLICY.replace('"/var/lib/example/cache"', '"//var/lib/example/cache"'))

        with self.assertRaisesRegex(PolicyError, "unsafe path"):
            load_policy(path)
