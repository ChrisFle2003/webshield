"""Closed-profile validation primitives for local WebShield activation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
from types import MappingProxyType
from typing import Mapping, Protocol


class ActivationError(ValueError):
    """Raised when an activation bundle crosses a closed trust boundary."""


@dataclass(frozen=True)
class TargetProfile:
    name: str
    destinations: Mapping[str, str]
    syntax_commands: tuple[tuple[str, ...], ...]
    reload_commands: tuple[tuple[str, ...], ...]
    health_commands: tuple[tuple[str, ...], ...]
    backup_relative: str
    staging_relative: str


@dataclass(frozen=True)
class VerifiedFile:
    relative_path: str
    source: Path
    sha256: str


@dataclass(frozen=True)
class VerifiedBundle:
    profile: TargetProfile
    bundle: Path
    files: Mapping[str, VerifiedFile]


@dataclass(frozen=True)
class ActivationPlan:
    profile_name: str
    destinations: tuple[str, ...]


@dataclass(frozen=True)
class ActivationResult:
    destinations: tuple[str, ...]
    backup_directory: Path


class CommandRunner(Protocol):
    def run(self, command: tuple[str, ...]) -> bool: ...


DEBIAN_SYSTEMD_PROFILE = TargetProfile(
    name="debian-systemd",
    destinations=MappingProxyType(
        {
            "nginx/webshield.conf": "etc/nginx/conf.d/webshield.conf",
            "php-fpm/webshield.conf": "etc/php/8.4/fpm/pool.d/webshield.conf",
            "systemd/nginx/webshield-hardening.conf": "etc/systemd/system/nginx.service.d/webshield-hardening.conf",
            "systemd/app/webshield-hardening.conf": "etc/systemd/system/php8.4-fpm.service.d/webshield-hardening.conf",
            "systemd/upload/webshield-hardening.conf": "etc/systemd/system/webshield-upload.service.d/webshield-hardening.conf",
        }
    ),
    syntax_commands=(
        ("/usr/sbin/nginx", "-t"),
        ("/usr/sbin/php-fpm8.4", "-t"),
    ),
    reload_commands=(
        ("/bin/systemctl", "reload", "nginx.service"),
        ("/bin/systemctl", "reload", "php8.4-fpm.service"),
        ("/bin/systemctl", "restart", "webshield-upload.service"),
    ),
    health_commands=(
        ("/bin/systemctl", "is-active", "--quiet", "nginx.service"),
        ("/bin/systemctl", "is-active", "--quiet", "php8.4-fpm.service"),
        ("/bin/systemctl", "is-active", "--quiet", "webshield-upload.service"),
    ),
    backup_relative="var/lib/webshield/backups",
    staging_relative="var/lib/webshield/staging",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def verify_bundle(bundle: Path, profile: TargetProfile) -> VerifiedBundle:
    """Verify an exact, regular-file bundle for one code-owned target profile."""
    if bundle.is_symlink() or not bundle.is_dir():
        raise ActivationError("bundle must be a regular directory")
    manifest_path = bundle / "manifest.json"
    manifest = _load_manifest(manifest_path)
    expected_files = set(profile.destinations)
    if set(manifest["files"]) != expected_files:
        raise ActivationError("bundle manifest has an unexpected file set")
    _verify_bundle_tree(bundle, expected_files)

    verified: dict[str, VerifiedFile] = {}
    for relative_path in sorted(expected_files):
        expected_hash = manifest["files"][relative_path]
        if type(expected_hash) is not str or not _SHA256.fullmatch(expected_hash):
            raise ActivationError("bundle manifest has an invalid checksum")
        source = bundle / relative_path
        _require_regular_file(source)
        actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise ActivationError("bundle checksum verification failed")
        verified[relative_path] = VerifiedFile(relative_path, source, actual_hash)
    return VerifiedBundle(profile=profile, bundle=bundle, files=MappingProxyType(verified))


class ActivationTransaction:
    """Apply one verified bundle through a closed profile and runner interface."""

    def __init__(self, profile: TargetProfile, activation_root: Path, command_runner: CommandRunner) -> None:
        if activation_root.is_symlink() or not activation_root.is_dir():
            raise ActivationError("activation root must be a regular directory")
        self.profile = profile
        self.activation_root = activation_root.resolve()
        self.command_runner = command_runner

    def plan(self, bundle: Path) -> ActivationPlan:
        verified = verify_bundle(bundle, self.profile)
        return ActivationPlan(verified.profile.name, tuple(self.profile.destinations.values()))

    def activate(self, bundle: Path) -> ActivationResult:
        verified = verify_bundle(bundle, self.profile)
        targets = self._targets(verified)
        backup_directory, previous = self._backup(targets)
        reload_attempted = False
        try:
            self._replace_from_staging(targets)
            if not self._run_all(self.profile.syntax_commands):
                raise ActivationError("profile syntax check failed")
            reload_attempted = True
            if not self._run_all(self.profile.reload_commands):
                raise ActivationError("profile reload failed")
            if not self._run_all(self.profile.health_commands):
                raise ActivationError("profile health check failed")
        except ActivationError:
            self._restore(previous)
            if reload_attempted:
                self._run_all(self.profile.reload_commands)
            raise
        return ActivationResult(tuple(self.profile.destinations.values()), backup_directory)

    def _targets(self, verified: VerifiedBundle) -> dict[str, tuple[VerifiedFile, Path]]:
        targets: dict[str, tuple[VerifiedFile, Path]] = {}
        for relative_path, destination in self.profile.destinations.items():
            target = self._destination_path(destination)
            targets[destination] = (verified.files[relative_path], target)
        return targets

    def _destination_path(self, destination: str) -> Path:
        if Path(destination).is_absolute() or ".." in Path(destination).parts:
            raise ActivationError("profile contains an unsafe destination")
        target = (self.activation_root / destination).resolve()
        if target == self.activation_root or self.activation_root not in target.parents:
            raise ActivationError("profile destination escapes activation root")
        raw_target = self.activation_root / destination
        if raw_target.is_symlink():
            raise ActivationError("profile destination must not be a symlink")
        return target

    def _backup(self, targets: Mapping[str, tuple[VerifiedFile, Path]]) -> tuple[Path, dict[Path, bytes | None]]:
        base = self._private_directory(self.profile.backup_relative)
        backup_directory = Path(tempfile.mkdtemp(prefix="activation-", dir=base))
        previous: dict[Path, bytes | None] = {}
        for destination, (_, target) in targets.items():
            if target.is_symlink() or (target.exists() and not target.is_file()):
                raise ActivationError("managed target must be a regular file")
            content = target.read_bytes() if target.exists() else None
            previous[target] = content
            if content is not None:
                backup_target = backup_directory / destination
                backup_target.parent.mkdir(parents=True, exist_ok=True)
                backup_target.write_bytes(content)
        return backup_directory, previous

    def _replace_from_staging(self, targets: Mapping[str, tuple[VerifiedFile, Path]]) -> None:
        staging_root = self._private_directory(self.profile.staging_relative)
        with tempfile.TemporaryDirectory(prefix="activation-", dir=staging_root) as temporary:
            stage = Path(temporary)
            for destination, (source, target) in targets.items():
                staged = stage / destination
                staged.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source.source, staged)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.is_symlink():
                    raise ActivationError("managed target must not be a symlink")
                staged.replace(target)

    def _restore(self, previous: Mapping[Path, bytes | None]) -> None:
        for target, content in previous.items():
            if content is None:
                if target.exists() and not target.is_symlink():
                    target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(target.name + ".webshield-restore")
            temporary.write_bytes(content)
            temporary.replace(target)

    def _private_directory(self, relative_path: str) -> Path:
        directory = self._destination_path(relative_path)
        if directory.exists() and not directory.is_dir():
            raise ActivationError("profile runtime path must be a directory")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        return directory

    def _run_all(self, commands: tuple[tuple[str, ...], ...]) -> bool:
        return all(self.command_runner.run(command) for command in commands)


def _load_manifest(path: Path) -> dict[str, object]:
    _require_regular_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ActivationError("cannot read bundle manifest") from error
    if type(value) is not dict or set(value) != {"files"} or type(value["files"]) is not dict:
        raise ActivationError("bundle manifest has an invalid format")
    return value


def _verify_bundle_tree(bundle: Path, expected_files: set[str]) -> None:
    expected_entries = {"manifest.json", *expected_files}
    for entry in bundle.rglob("*"):
        relative = entry.relative_to(bundle).as_posix()
        if entry.is_symlink():
            raise ActivationError("bundle must not contain symlinks")
        if entry.is_dir():
            continue
        if relative not in expected_entries:
            raise ActivationError("bundle contains an unexpected file")
        _require_regular_file(entry)


def _require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ActivationError("bundle entry must be a regular file")
