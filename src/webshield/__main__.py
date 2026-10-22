"""Command-line interface for the local WebShield policy compiler."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .activation import ActivationError, ActivationTransaction, DEBIAN_SYSTEMD_PROFILE
from .output import OutputError, write_fragments
from .policy import PolicyError, load_policy
from .render import render_all


_PROFILES = {DEBIAN_SYSTEMD_PROFILE.name: DEBIAN_SYSTEMD_PROFILE}


class _PlanOnlyRunner:
    def run(self, command: tuple[str, ...]) -> bool:
        raise ActivationError("activation-plan must not run service commands")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate reviewed server-hardening fragments.")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate a TOML policy")
    validate.add_argument("policy", type=Path)
    render = commands.add_parser("render", help="render fragments into a new directory")
    render.add_argument("policy", type=Path)
    render.add_argument("--output", required=True, type=Path)
    render.add_argument("--dry-run", action="store_true")

    activation_plan = commands.add_parser("activation-plan", help="validate a bundle without activating it")
    activation_plan.add_argument("bundle", type=Path)
    activation_plan.add_argument("--profile", required=True)
    activation_plan.add_argument("--root", required=True, type=Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        if args.command == "activation-plan":
            profile = _PROFILES.get(args.profile)
            if profile is None:
                raise ActivationError("unknown activation profile")
            plan = ActivationTransaction(profile, args.root, _PlanOnlyRunner()).plan(args.bundle)
            print(f"activation plan: {plan.profile_name}, {len(plan.destinations)} destinations")
            return 0

        policy = load_policy(args.policy)
        if args.command == "validate":
            print("policy is valid")
            return 0
        fragments = render_all(policy)
        if args.dry_run:
            print("dry run: would generate " + ", ".join(sorted(fragments)))
            return 0
        manifest = write_fragments(args.output, fragments)
        print(f"generated {len(fragments)} fragments and {manifest.name}")
        return 0
    except PolicyError as error:
        print(f"policy error: {error}", file=sys.stderr)
        return 2
    except OutputError as error:
        print(f"output error: {error}", file=sys.stderr)
        return 1
    except ActivationError as error:
        print(f"activation error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
