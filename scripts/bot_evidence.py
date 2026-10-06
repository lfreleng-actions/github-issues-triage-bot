# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Verify trusted evidence, and hold the caps on untrusted session files.

``verify --directory DIR --expect NAME=SHA256 [--expect ...]`` checks
the exact bytes of each named file against a digest the trusted job
that wrote it published as a job output, never against a value found
in the downloaded artifact. A consumer that downloads evidence by
artifact ID still has to prove the bytes are the ones it was promised;
this is that proof.

``SESSION_FILES`` is the cap table for what an untrusted agent session
may hand to a trusted job: ``session-summary.md`` is required,
``usage.json`` optional, and each has a byte cap that
``artifact_fetch`` enforces while extracting the artifact. A bot that
needs more from its sessions extends this table; nothing else from a
session is read.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from pathlib import Path

MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_SUMMARY_BYTES = 8 * 1024 * 1024
MAX_USAGE_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

# (name, byte cap, required)
SESSION_FILES: tuple[tuple[str, int, bool], ...] = (
    ("session-summary.md", MAX_SUMMARY_BYTES, True),
    ("usage.json", MAX_USAGE_BYTES, False),
)

Expectation = tuple[str, str, int]


def read_regular(path: Path, limit: int) -> bytes:
    """Read bounded bytes from a regular file without following a final symlink."""
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # NONBLOCK lets fstat reject a FIFO without waiting for a writer.
        # Check the opened descriptor, not a prior stat that could race.
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(path.name, flags, dir_fd=directory_fd), "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"{path.name} must be a regular non-symlink file")
            if info.st_size > limit:
                raise ValueError(f"{path.name} exceeds the {limit}-byte limit")
            content = source.read(limit + 1)
            if len(content) > limit:
                raise ValueError(f"{path.name} exceeds the {limit}-byte limit")
            return content
    finally:
        os.close(directory_fd)


def verify(directory: Path, expectations: list[Expectation]) -> None:
    """Authenticate evidence files against independently held hashes.

    Each expectation is ``(name, sha256, limit)``. Every digest is
    checked for shape before any file is opened, so a malformed
    expectation fails fast rather than after reading megabytes.
    """
    if not expectations:
        raise ValueError("at least one expectation is required")
    for name, digest, _ in expectations:
        if not NAME_RE.fullmatch(name):
            raise ValueError(f"evidence name {name!r} must be a plain file name")
        if not SHA256_RE.fullmatch(digest):
            raise ValueError(f"trusted SHA-256 for {name} must contain 64 hex digits")
    for name, digest, limit in expectations:
        content = read_regular(directory / name, limit)
        if hashlib.sha256(content).hexdigest() != digest.lower():
            raise ValueError(f"SHA-256 mismatch for {name}")


def parse_expectation(text: str, limit: int) -> Expectation:
    """Split one ``NAME=SHA256`` argument into an expectation."""
    name, separator, digest = text.partition("=")
    if not separator or not name or not digest:
        raise ValueError(f"--expect must be NAME=SHA256, got {text!r}")
    return (name, digest, limit)


def main(argv: list[str] | None = None) -> None:
    """Dispatch the verify command."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verification = commands.add_parser("verify", help="check trusted evidence digests")
    verification.add_argument("--directory", type=Path, required=True)
    verification.add_argument(
        "--expect", action="append", default=[], metavar="NAME=SHA256", required=True
    )
    verification.add_argument("--limit-bytes", type=int, default=MAX_EVIDENCE_BYTES)
    args = parser.parse_args(argv)
    try:
        if args.limit_bytes <= 0:
            raise ValueError("--limit-bytes must be positive")
        expected = [parse_expectation(item, args.limit_bytes) for item in args.expect]
        verify(args.directory, expected)
    except (OSError, ValueError) as exc:
        message = ascii(str(exc)).replace("::", ": :").replace("##[", "# #[")
        parser.exit(1, f"evidence: {message}\n")


if __name__ == "__main__":
    main()
