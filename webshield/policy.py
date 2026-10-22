"""Strict TOML policy loading for WebShield.

This module intentionally accepts a small allow-list of values.  Renderers
receive only these validated dataclasses and never handle raw user text.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import tomllib
from typing import Any


class PolicyError(ValueError):
    """Raised when a policy cannot be safely interpreted."""


@dataclass(frozen=True)
class ServerPolicy:
    listen_port: int
    server_name: str
    document_root: str
    tls: bool
    certificate_path: str
    certificate_key_path: str


@dataclass(frozen=True)
class PhpPolicy:
    enabled: bool
    socket_path: str
    allowed_extensions: tuple[str, ...]


@dataclass(frozen=True)
class LimitsPolicy:
    max_body_size: str
    request_rate_per_minute: int


@dataclass(frozen=True)
class SecuritySettings:
    deny_hidden_files: bool
    deny_script_execution_in_uploads: bool
    disable_command_execution: bool


@dataclass(frozen=True)
class IsolationServicePolicy:
    service_user: str
    read_only_paths: tuple[str, ...]
    read_write_paths: tuple[str, ...]
    allowed_socket_paths: tuple[str, ...]
    outbound_network: str
    command_execution: bool


@dataclass(frozen=True)
class IsolationPolicy:
    app: IsolationServicePolicy
    upload: IsolationServicePolicy


@dataclass(frozen=True)
class SecurityPolicy:
    server: ServerPolicy
    php: PhpPolicy
    limits: LimitsPolicy
    security: SecuritySettings
    isolation: IsolationPolicy


_SECTION_KEYS = {
    "server": {
        "listen_port",
        "server_name",
        "document_root",
        "tls",
        "certificate_path",
        "certificate_key_path",
    },
    "php": {"enabled", "socket_path", "allowed_extensions"},
    "limits": {"max_body_size", "request_rate_per_minute"},
    "security": {
        "deny_hidden_files",
        "deny_script_execution_in_uploads",
        "disable_command_execution",
    },
    "isolation": {"app", "upload"},
}
_ISOLATION_SERVICE_KEYS = {
    "service_user",
    "read_only_paths",
    "read_write_paths",
    "allowed_socket_paths",
    "outbound_network",
    "command_execution",
}
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/@+:-]*$")
_HOSTNAME = re.compile(
    r"^(?:localhost|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$"
)
_BODY_SIZE = re.compile(r"^[1-9][0-9]*[kKmMgG]$")
_PHP_EXTENSION = re.compile(r"^\.[A-Za-z0-9]+$")
_SERVICE_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_PROTECTED_PATHS = ("/", "/etc", "/home", "/root", "/proc", "/sys", "/dev")
_NETWORK_MODES = {"none", "local-only"}


def load_policy(path: Path) -> SecurityPolicy:
    """Load a complete TOML policy, rejecting ambiguity and unsafe values."""
    try:
        with path.open("rb") as policy_file:
            document = tomllib.load(policy_file)
    except OSError as error:
        raise PolicyError(f"cannot read policy: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise PolicyError(f"invalid TOML: {error}") from error

    _validate_document_shape(document)
    server = document["server"]
    php = document["php"]
    limits = document["limits"]
    security = document["security"]
    isolation = _isolation(document["isolation"], php["socket_path"], server["document_root"])
    disable_command_execution = _bool(
        security["disable_command_execution"],
        "security.disable_command_execution",
    )
    if disable_command_execution == isolation.app.command_execution:
        raise PolicyError("security and isolation command execution settings conflict")

    return SecurityPolicy(
        server=ServerPolicy(
            listen_port=_port(server["listen_port"], "server.listen_port"),
            server_name=_host(server["server_name"], "server.server_name"),
            document_root=_path(server["document_root"], "server.document_root"),
            tls=_bool(server["tls"], "server.tls"),
            certificate_path=_path(server["certificate_path"], "server.certificate_path"),
            certificate_key_path=_path(server["certificate_key_path"], "server.certificate_key_path"),
        ),
        php=PhpPolicy(
            enabled=_bool(php["enabled"], "php.enabled"),
            socket_path=_path(php["socket_path"], "php.socket_path"),
            allowed_extensions=_extensions(php["allowed_extensions"]),
        ),
        limits=LimitsPolicy(
            max_body_size=_body_size(limits["max_body_size"]),
            request_rate_per_minute=_rate(limits["request_rate_per_minute"]),
        ),
        security=SecuritySettings(
            deny_hidden_files=_bool(security["deny_hidden_files"], "security.deny_hidden_files"),
            deny_script_execution_in_uploads=_bool(
                security["deny_script_execution_in_uploads"],
                "security.deny_script_execution_in_uploads",
            ),
            disable_command_execution=disable_command_execution,
        ),
        isolation=isolation,
    )


def _validate_document_shape(document: dict[str, Any]) -> None:
    if set(document) != set(_SECTION_KEYS):
        unknown = sorted(set(document) - set(_SECTION_KEYS))
        missing = sorted(set(_SECTION_KEYS) - set(document))
        details = []
        if unknown:
            details.append(f"unknown section(s): {', '.join(unknown)}")
        if missing:
            details.append(f"missing section(s): {', '.join(missing)}")
        raise PolicyError("; ".join(details))
    for section, allowed_keys in _SECTION_KEYS.items():
        values = document[section]
        if type(values) is not dict:
            raise PolicyError(f"{section} must be a table")
        unknown = sorted(set(values) - allowed_keys)
        missing = sorted(allowed_keys - set(values))
        if unknown:
            raise PolicyError(f"unknown key(s) in {section}: {', '.join(unknown)}")
        if missing:
            raise PolicyError(f"missing key(s) in {section}: {', '.join(missing)}")


def _isolation(value: dict[str, Any], php_socket: Any, document_root: Any) -> IsolationPolicy:
    app = _isolation_service(value["app"], "isolation.app")
    upload = _isolation_service(value["upload"], "isolation.upload")
    if upload.allowed_socket_paths:
        raise PolicyError("isolation.upload.allowed_socket_paths must be empty")
    socket_path = _path(php_socket, "php.socket_path")
    document_root_path = _path(document_root, "server.document_root")
    if socket_path not in app.allowed_socket_paths:
        raise PolicyError("php.socket_path must be listed in isolation.app.allowed_socket_paths")
    if _overlaps_any(document_root_path, app.read_write_paths + upload.read_write_paths):
        raise PolicyError("document root must not overlap a writable isolation path")
    _reject_cross_service_overlaps(app, upload)
    return IsolationPolicy(app=app, upload=upload)


def _isolation_service(value: Any, name: str) -> IsolationServicePolicy:
    if type(value) is not dict:
        raise PolicyError(f"{name} must be a table")
    unknown = sorted(set(value) - _ISOLATION_SERVICE_KEYS)
    missing = sorted(_ISOLATION_SERVICE_KEYS - set(value))
    if unknown:
        raise PolicyError(f"unknown key(s) in {name}: {', '.join(unknown)}")
    if missing:
        raise PolicyError(f"missing key(s) in {name}: {', '.join(missing)}")
    service = IsolationServicePolicy(
        service_user=_service_user(value["service_user"], f"{name}.service_user"),
        read_only_paths=_paths(value["read_only_paths"], f"{name}.read_only_paths"),
        read_write_paths=_paths(value["read_write_paths"], f"{name}.read_write_paths"),
        allowed_socket_paths=_paths(value["allowed_socket_paths"], f"{name}.allowed_socket_paths"),
        outbound_network=_network_mode(value["outbound_network"], f"{name}.outbound_network"),
        command_execution=_bool(value["command_execution"], f"{name}.command_execution"),
    )
    all_paths = service.read_only_paths + service.read_write_paths + service.allowed_socket_paths
    if len(set(all_paths)) != len(all_paths):
        raise PolicyError(f"{name} must not repeat a path")
    if _has_overlap(service.read_only_paths, service.read_write_paths):
        raise PolicyError(f"{name} read-only and writable paths must not overlap")
    return service


def _service_user(value: Any, name: str) -> str:
    if type(value) is not str or not _SERVICE_USER.fullmatch(value) or value == "root":
        raise PolicyError(f"{name} must be a non-root service user")
    return value


def _network_mode(value: Any, name: str) -> str:
    if type(value) is not str or value not in _NETWORK_MODES:
        raise PolicyError(f"{name} must be one of: none, local-only")
    return value


def _paths(value: Any, name: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise PolicyError(f"{name} must be a list")
    paths = tuple(_path(item, name) for item in value)
    for path in paths:
        if path in _PROTECTED_PATHS or any(path.startswith(prefix + "/") for prefix in _PROTECTED_PATHS[1:]):
            raise PolicyError(f"{name} contains a protected path")
    return paths


def _reject_cross_service_overlaps(app: IsolationServicePolicy, upload: IsolationServicePolicy) -> None:
    app_paths = app.read_only_paths + app.read_write_paths + app.allowed_socket_paths
    upload_paths = upload.read_only_paths + upload.read_write_paths
    if _has_overlap(app_paths, upload_paths):
        raise PolicyError("app and upload isolation paths must not overlap")


def _overlaps_any(path: str, candidates: tuple[str, ...]) -> bool:
    return any(_paths_overlap(path, candidate) for candidate in candidates)


def _has_overlap(first: tuple[str, ...], second: tuple[str, ...]) -> bool:
    return any(_paths_overlap(left, right) for left in first for right in second)


def _paths_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(right.rstrip("/") + "/") or right.startswith(left.rstrip("/") + "/")


def _bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise PolicyError(f"{name} must be a boolean")
    return value


def _port(value: Any, name: str) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise PolicyError(f"{name} must be an integer from 1 to 65535")
    return value


def _host(value: Any, name: str) -> str:
    if type(value) is not str or not value:
        raise PolicyError(f"{name} must be a non-empty hostname")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if not _HOSTNAME.fullmatch(value):
            raise PolicyError(f"{name} must be a safe hostname or IP literal")
        return value.lower()


def _path(value: Any, name: str) -> str:
    if type(value) is not str or not value.startswith("/"):
        raise PolicyError(f"{name} must be an absolute path")
    if "\x00" in value:
        raise PolicyError(f"{name} must not contain a NUL byte")
    if "\n" in value or "\r" in value:
        raise PolicyError(f"{name} must not contain a line break")
    if (
        not _SAFE_PATH.fullmatch(value)
        or "//" in value
        or "/./" in f"{value}/"
        or "/../" in f"{value}/"
        or value.endswith("/..")
    ):
        raise PolicyError(f"{name} contains unsafe path characters")
    return value


def _body_size(value: Any) -> str:
    if type(value) is not str or not _BODY_SIZE.fullmatch(value):
        raise PolicyError("limits.max_body_size must look like '8m'")
    return value.lower()


def _rate(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 10000:
        raise PolicyError("limits.request_rate_per_minute must be an integer from 1 to 10000")
    return value


def _extensions(value: Any) -> tuple[str, ...]:
    if type(value) is not list or not value:
        raise PolicyError("php.allowed_extensions must be a non-empty list")
    if any(type(extension) is not str or not _PHP_EXTENSION.fullmatch(extension) for extension in value):
        raise PolicyError("php.allowed_extensions must contain safe extensions such as '.php'")
    return tuple(value)
