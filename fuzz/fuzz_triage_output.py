# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Fuzz evidence verification and the rendering of untrusted log text.

Contract under test, in the code's own words:

- ``triage_evidence.verify`` "checks exact bytes against digests
  supplied by trusted prepare-job outputs", and "Authenticate[s] the
  two fixed evidence files against independently trusted hashes".
  ``bot_evidence.read_regular`` reads "a regular file without
  following a final symlink". A refusal is an ``OSError`` or a
  ``ValueError``, the two ``triage_evidence.main`` reports by design;
  anything else, or a pass on bytes that do not match, is a breach.
  DESIGN.md gives each file its cap: "16 MiB for the snapshot and
  1 MiB for exclusions"; a file over its cap is refused.
- ``apply_triage.one_line`` renders "untrusted text without control
  characters or runner commands", escaping "the legacy ``##[command]``
  syntax" and "the modern ``::`` syntax as well as folding control
  characters". The rendering is printed to the runner's stdout.

Each input drives both targets. Its first two bytes choose, for each
evidence file, what sits on disk and which digest the trusted job
supplies; the third, scaled over the rest, where the rest splits
between the two files. The oracle derives the verdict from those
choices and ``hashlib`` alone.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unicodedata
from collections.abc import Callable
from importlib import import_module
from pathlib import Path

from fuzz_support import ContractBreach, emitted, libfuzzer_arguments, use_scripts

use_scripts()
apply_triage = import_module("apply_triage")
evidence = import_module("triage_evidence")

EVIDENCE = ("before.json", "excluded-repos.txt")
# The caps DESIGN.md states, kept apart from the constants verify uses.
CAPS = (16 * 1024 * 1024, 1024 * 1024)
HEX = "0123456789abcdef"
# What the trusted job may hand over as a digest.
DIGESTS = ("lower", "upper", "flipped", "short", "newline", "spaced", "wide", "empty")


def digest_for(content: bytes, mode: str) -> str:
    """The digest the trusted job supplies, honest or otherwise."""
    honest = hashlib.sha256(content).hexdigest()
    last = HEX[(HEX.index(honest[-1]) + 1) % len(HEX)]
    return {
        "lower": honest,
        "upper": honest.upper(),
        "flipped": honest[:-1] + last,
        "short": honest[:-1],
        "newline": honest + "\n",
        "spaced": " " + honest,
        # A fullwidth digit is a digit to str.isdigit, not to SHA-256.
        "wide": honest[:-1] + chr(0xFF10 + int(honest[-1], 16) % 10),
        "empty": "",
    }[mode]


def make_regular(target: Path, content: bytes) -> None:
    """Write the evidence as a plain file."""
    target.write_bytes(content)


def make_missing(_target: Path, _content: bytes) -> None:
    """Leave the evidence absent."""


def make_directory(target: Path, _content: bytes) -> None:
    """Put a directory where the evidence belongs."""
    target.mkdir()


def make_fifo(target: Path, _content: bytes) -> None:
    """Put a named pipe where the evidence belongs."""
    os.mkfifo(target)


def real_sibling(target: Path, content: bytes) -> Path:
    """Write the right bytes beside ``target``, for a link to reach.

    Only the link itself then stands between the file and a pass.
    """
    elsewhere = target.with_name(f"{target.name}.real")
    elsewhere.write_bytes(content)
    return elsewhere


def make_symlink(target: Path, content: bytes) -> None:
    """Make the evidence a relative symbolic link to the right bytes."""
    target.symlink_to(real_sibling(target, content).name)


def make_hardlink(target: Path, content: bytes) -> None:
    """Make the evidence a second hard link to the right bytes."""
    os.link(real_sibling(target, content), target)


# What may sit on disk under the evidence name.
PLACERS: dict[str, Callable[[Path, bytes], None]] = {
    "regular": make_regular,
    "missing": make_missing,
    "symlink": make_symlink,
    "directory": make_directory,
    "fifo": make_fifo,
    "hardlink": make_hardlink,
}
KINDS = tuple(PLACERS)


def place(directory: Path, name: str, content: bytes, kind: str) -> None:
    """Put the evidence file on disk in the chosen shape."""
    PLACERS[kind](directory / name, content)


def expected_pass(modes: list[tuple[str, str]], sizes: tuple[int, int]) -> bool:
    """The verdict the contract requires, derived without the code under test."""
    return all(
        kind in ("regular", "hardlink") and digest in ("lower", "upper") and size <= cap
        for (digest, kind), size, cap in zip(modes, sizes, CAPS, strict=True)
    )


def check_verdict(
    expected: bool, passed: bool, modes: list[tuple[str, str]], sizes: tuple[int, int]
) -> None:
    """Fail when ``verify`` and the contract disagree."""
    if passed != expected:
        verdict = "accepted" if passed else "refused"
        raise ContractBreach(f"verify {verdict} evidence shaped {modes}, sizes {sizes}")


def split_contents(data: bytes) -> tuple[bytes, bytes]:
    """Share the body between the two files, as the third byte says.

    The byte is scaled over the whole body, so either file can take
    all of it, at any length.
    """
    body = data[3:]
    split = len(body) * data[2] // 255
    return body[:split], body[split:]


def check_verify(data: bytes) -> None:
    """Verify two evidence files whose shape and digest the input chooses."""
    if len(data) < 3:
        return
    modes = [
        (DIGESTS[byte % len(DIGESTS)], KINDS[(byte // len(DIGESTS)) % len(KINDS)])
        for byte in data[:2]
    ]
    contents = split_contents(data)
    with tempfile.TemporaryDirectory(prefix="fuzz-evidence-") as scratch:
        directory = Path(scratch)
        for name, content, (_, kind) in zip(EVIDENCE, contents, modes, strict=True):
            place(directory, name, content, kind)
        before, exclusions = (
            digest_for(content, digest)
            for content, (digest, _) in zip(contents, modes, strict=True)
        )
        try:
            evidence.verify(directory, before, exclusions)
        except (OSError, ValueError):
            passed = False
        else:
            passed = True
    sizes = (len(contents[0]), len(contents[1]))
    check_verdict(expected_pass(modes, sizes), passed, modes, sizes)


def check_rendered(value: str, output: str) -> None:
    """One printed line, with nothing the runner would act on."""
    if not output.endswith("\n") or "\n" in output[:-1]:
        raise ContractBreach(f"rendering of {value!r} is not one line: {output!r}")
    line = output[:-1]
    if "::" in line or "##[" in line:
        raise ContractBreach(f"rendering carries a runner command: {line!r}")
    if any(unicodedata.category(char) == "Cc" for char in line):
        raise ContractBreach(f"rendering carries a control character: {line!r}")
    plain = all(
        char not in ":#" and unicodedata.category(char) not in ("Cc", "Cs")
        for char in value
    )
    if plain and line != value:
        raise ContractBreach(f"rendering altered plain text: {value!r} -> {line!r}")


def check_one_line(data: bytes) -> None:
    """Print the input's text through ``one_line`` as the report does."""
    # surrogateescape keeps every byte, so undecodable input reaches
    # one_line as the lone surrogates a JSON escape can also produce.
    value = data.decode("utf-8", "surrogateescape")
    check_rendered(value, emitted(lambda: print(apply_triage.one_line(value))))


def check(data: bytes) -> None:
    """Drive both targets from one input."""
    check_one_line(data)
    check_verify(data)


# Split byte 0 gives the whole body to the exclusions file.
OVERSIZED_EXCLUSIONS = b"\x00\x00\x00" + b"x" * (CAPS[1] + 1)
SEEDS: tuple[bytes, ...] = (
    b"\x00\x00\x30[]\nbuilder-repo\n",
    b"\x01\x01\x20{}owner/excluded",
    b"\x02\x00\x00",
    b"\x08\x08\x80abcdefgh",
    b"\x10\x18\x80xyzabc",
    b"\x20\x28\x80ab",
    b"\x03\x04\x05\x06\x07",
    b"\x07\x00\x00",
    b"::error::forged\n##[group]x\r\x1b[31m\x7f",
    b"\x00\x00\x00caf\xc3\xa9 \xe2\x80\xa8 \xc2\x85 tail",
    b"\x00\x00\xe6\xed\xa0\x80\xff\xfe lone",
    b"\x00\x00\x40" + bytes(range(256)) * 4,
    # Exclusions one byte over their cap: libFuzzer sizes the inputs it
    # makes from the largest seed, so this one lets it reach the cap.
    OVERSIZED_EXCLUSIONS,
)


def main() -> None:
    """Fuzz ``check``, seeded from ``SEEDS``."""
    import atheris  # pyright: ignore[reportMissingModuleSource]

    arguments = libfuzzer_arguments(
        sys.argv, SEEDS, Path(tempfile.mkdtemp(prefix="fuzz-triage-output-"))
    )
    # The bundled stubs omit instrument_all; atheris exports it.
    atheris.instrument_all()  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
    atheris.Setup(arguments, check)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
