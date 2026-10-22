"""Narrow local primitives for a root-only WebShield activation command."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
from typing import TextIO

from .activation import (
    ActivationError,
    ActivationTransaction,
    CommandRunner,
    DEBIAN_SYSTEMD_PROFILE,
    TargetProfile,
)


_PROFILES = {DEBIAN_SYSTEMD_PROFILE.name: DEBIAN_SYSTEMD_PROFILE}


def require_root(euid: int) -> None:
    """Reject any caller other than the effective root user."""
    if euid != 0:
        raise ActivationError("activation requires root")


def require_confirmation(reader: TextIO, writer: TextIO) -> None:
    """Require the exact confirmation on an interactive terminal."""
    if not reader.isatty():
        raise ActivationError("activation confirmation requires a terminal")
    writer.write("Type ACTIVATE to continue: ")
    writer.flush()
    if reader.readline() != "ACTIVATE\n":
        raise ActivationError("activation confirmation was declined")


class ClosedProfileRunner:
    """Dispatch only fixed command tuples registered by one target profile."""

    def __init__(self, profile: TargetProfile) -> None:
        self._allowed_commands = frozenset(
            profile.syntax_commands + profile.reload_commands + profile.health_commands
        )

    def run(self, command: tuple[str, ...]) -> bool:
        if command not in self._allowed_commands:
            raise ActivationError("command is not registered by the activation profile")
        try:
            completed = subprocess.run(
                list(command),
                check=False,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return False
        return completed.returncode == 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Activate one verified local WebShield bundle.")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--profile", required=True)
    return parser


def run_activation(
    arguments: list[str] | None,
    *,
    euid: int,
    reader: TextIO,
    writer: TextIO,
    activation_root: Path,
    runner: CommandRunner | None = None,
) -> int:
    """Run the closed activation flow with injectable local boundary dependencies."""
    args = _build_parser().parse_args(arguments)
    try:
        require_root(euid)
        profile = _PROFILES.get(args.profile)
        if profile is None:
            raise ActivationError("unknown activation profile")
        require_confirmation(reader, writer)
        transaction = ActivationTransaction(profile, activation_root, runner or ClosedProfileRunner(profile))
        transaction.activate(args.bundle)
        writer.write("activation completed\n")
        return 0
    except ActivationError as error:
        writer.write(f"activation error: {error}\n")
        return 2


def main(arguments: list[str] | None = None) -> int:
    """Run the local helper against the real root filesystem and terminal."""
    return run_activation(
        arguments,
        euid=os.geteuid(),
        reader=sys.stdin,
        writer=sys.stdout,
        activation_root=Path("/"),
    )


if __name__ == "__main__":
    raise SystemExit(main())
