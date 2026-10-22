"""Behavior tests for pure WebShield configuration renderers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from webshield.policy import load_policy
from webshield.render import render_all


def policy_from_toml(php_enabled: bool) -> object:
    content = f"""
[server]
listen_port = 443
server_name = "example.test"
document_root = "/srv/example/public"
tls = true
certificate_path = "/etc/ssl/example/fullchain.pem"
certificate_key_path = "/etc/ssl/example/private.key"

[php]
enabled = {str(php_enabled).lower()}
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
    directory = tempfile.TemporaryDirectory()
    path = Path(directory.name) / "policy.toml"
    path.write_text(content, encoding="utf-8")
    policy = load_policy(path)
    directory.cleanup()
    return policy


class FragmentRenderingTests(unittest.TestCase):
    def test_enabled_php_generates_all_hardening_fragments(self) -> None:
        """Dropping a renderer or FastCGI boundary must fail this test."""
        fragments = render_all(policy_from_toml(php_enabled=True))

        self.assertEqual(
            set(fragments),
            {
                "nginx/webshield.conf",
                "php-fpm/webshield.conf",
                "systemd/nginx/webshield-hardening.conf",
                "systemd/app/webshield-hardening.conf",
                "systemd/upload/webshield-hardening.conf",
            },
        )
        self.assertIn("fastcgi_pass unix:/run/php/php-fpm.sock;", fragments["nginx/webshield.conf"])
        self.assertIn("location ~ /\\.", fragments["nginx/webshield.conf"])
        app = fragments["systemd/app/webshield-hardening.conf"]
        upload = fragments["systemd/upload/webshield-hardening.conf"]
        self.assertIn("User=webapp", app)
        self.assertIn("ProtectSystem=strict", app)
        self.assertIn("ReadOnlyPaths=/srv/example", app)
        self.assertIn("ReadWritePaths=/var/lib/example/cache", app)
        self.assertIn("NoNewPrivileges=true", app)
        self.assertIn("IPAddressDeny=any", app)
        self.assertIn("ReadWritePaths=/var/lib/example/quarantine", upload)
        self.assertNotIn("/srv/example/public", upload)
        self.assertNotIn("/run/php/php-fpm.sock", upload)
        self.assertNotIn("/var/lib/example/quarantine", fragments["nginx/webshield.conf"])

    def test_disabled_php_emits_no_fastcgi_or_php_fpm_fragment(self) -> None:
        """Accidentally exposing PHP when it is disabled must fail this test."""
        fragments = render_all(policy_from_toml(php_enabled=False))

        self.assertNotIn("php-fpm/webshield.conf", fragments)
        self.assertNotIn("fastcgi_pass", fragments["nginx/webshield.conf"])
        self.assertIn("return 404;", fragments["nginx/webshield.conf"])
        self.assertIn("systemd/app/webshield-hardening.conf", fragments)

    def test_rendered_output_contains_no_shell_expansion_syntax(self) -> None:
        """Switching from fixed templates to shell interpolation must fail this."""
        fragments = render_all(policy_from_toml(php_enabled=True))

        rendered = "\n".join(fragments.values())
        self.assertNotIn("$()", rendered)
        self.assertNotIn("`", rendered)
        self.assertNotIn("exec ", rendered)

    def test_command_execution_policy_disables_php_process_start_functions(self) -> None:
        """Dropping the command-execution control must fail this test."""
        fragments = render_all(policy_from_toml(php_enabled=True))

        self.assertIn(
            "php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec",
            fragments["php-fpm/webshield.conf"],
        )
