"""Filesystem boundary for WebShield rendering."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


class OutputError(RuntimeError):
    """Raised when a generated configuration cannot be written safely."""


def write_fragments(output_directory: Path, fragments: dict[str, str]) -> Path:
    """Write generated fragments to a new directory and return its manifest path."""
    if output_directory.exists() or output_directory.is_symlink():
        raise OutputError("output directory must not already exist")
    try:
        output_directory.mkdir()
        checksums: dict[str, str] = {}
        for relative_path, content in sorted(fragments.items()):
            destination = output_directory / relative_path
            destination.parent.mkdir(parents=True, exist_ok=False)
            encoded = content.encode("utf-8")
            destination.write_bytes(encoded)
            checksums[relative_path] = hashlib.sha256(encoded).hexdigest()
        manifest = output_directory / "manifest.json"
        manifest.write_text(
            json.dumps({"files": checksums}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return manifest
    except OSError as error:
        raise OutputError(f"cannot write output: {error}") from error
