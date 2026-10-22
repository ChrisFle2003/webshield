# WebShield

> Policy-driven hardening for NGINX, PHP-FPM and systemd.

WebShield turns a reviewed TOML policy into narrowly scoped NGINX, PHP-FPM and systemd hardening fragments. It validates isolation boundaries before rendering, verifies generated bundles exactly, and provides a local, confirmation-gated activation path with rollback-aware error handling.

## What it does

- Validates explicit server, PHP-FPM and service-isolation policies.
- Renders deterministic fragments for NGINX, PHP-FPM and systemd.
- Rejects unsafe paths, root service identities, overlapping writable areas, malformed bundles and unknown activation profiles.
- Limits activation to a fixed Debian/systemd profile with fixed commands and destinations.
- Requires a local root administrator and an interactive `ACTIVATE` confirmation for activation.

## What it does not do

WebShield is not a web dashboard, remote-management API, deployment service, or complete application sandbox. It does not replace operating-system, NGINX, PHP or application updates, authentication, authorization, backups, or monitoring.

## Security model

```text
policy author → unprivileged compiler → verified bundle
local administrator → confirmation-gated helper → fixed profile → NGINX / PHP-FPM / systemd
```

The privileged helper accepts no arbitrary shell commands, unit names or destination paths. It only dispatches profile-owned argument lists without a shell.

## Status

The current implementation is an early, tested foundation for local policy compilation and controlled activation. Test coverage validates policy boundaries, rendering, bundle integrity, rollback behavior, confirmation gates and closed command dispatch.

## Contributing and security

Please see `CONTRIBUTING.md` for development guidance and `SECURITY.md` for vulnerability reporting. Do not report security-sensitive details in public issues.
