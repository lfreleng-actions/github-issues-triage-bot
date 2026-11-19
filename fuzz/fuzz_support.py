# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Plumbing the fuzz harnesses share, kept free of any fuzzer import.

A harness module holds the check it fuzzes as a plain function, so
the unit suite can replay its seeds on a machine without Atheris.
This module carries the parts of the harness contract that are not
the check itself: where the seeds go on the command line, how a
breach is reported, how output is captured the way the runner
receives it, and how a final json block decodes without the
extractor that the policy harness checks.
"""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable, Sequence
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, cast

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
# libFuzzer's ceiling on input length when no -max_len is given.
LIBFUZZER_MAX_LEN = 1024 * 1024


class ContractBreach(Exception):
    """An input made the code under test break its documented contract.

    Raised explicitly rather than through ``assert``, which ``-O``
    strips and would turn every verdict into a pass.
    """


def use_scripts() -> None:
    """Put the repository's scripts directory on ``sys.path``."""
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))


def libfuzzer_arguments(
    argv: Sequence[str], seeds: Sequence[bytes], directory: Path
) -> list[str]:
    """Return ``argv`` with a seed directory appended, unless it names a file.

    Naming an existing file asks libFuzzer to run those inputs once,
    so no corpus belongs on that command line. Otherwise the seeds
    go after any directories given, which keeps a caller's first
    directory as the one libFuzzer writes new inputs to.

    libFuzzer sizes the inputs it makes from the largest seed, but no
    larger than ``LIBFUZZER_MAX_LEN`` and truncates any seed beyond
    it. When a seed is longer and the caller sets no ``-max_len``,
    one sized to that seed is added, so the seed arrives whole.
    """
    arguments = list(argv)
    if any(not arg.startswith("-") and Path(arg).is_file() for arg in arguments[1:]):
        return arguments
    for index, seed in enumerate(seeds):
        (directory / f"seed-{index:03d}").write_bytes(seed)
    longest = max((len(seed) for seed in seeds), default=0)
    if longest > LIBFUZZER_MAX_LEN and not any(
        arg.startswith("-max_len=") for arg in arguments[1:]
    ):
        arguments.insert(1, f"-max_len={longest}")
    return [*arguments, str(directory)]


def emitted(produce: Callable[[], None]) -> str:
    """Run ``produce`` and return what it printed, encoded as the runner would.

    The runner's stdout is a strict UTF-8 stream. A buffer that
    accepts any ``str`` would hide text that stream cannot encode,
    so the capture refuses it exactly as production does.
    """
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="utf-8", errors="strict", newline="\n")
    with redirect_stdout(stream):
        produce()
    stream.flush()
    stream.detach()
    return raw.getvalue().decode("utf-8")


def fence_shaped(text: str) -> bool:
    """Whether any line could open or close a fence."""
    return any(
        line.lstrip(" \t").startswith(("```", "~~~")) for line in text.split("\n")
    )


def identical(left: object, right: object) -> bool:
    """Whether two decoded JSON values match in type, order and value.

    ``True == 1 == 1.0``, so ``==`` would let an extractor turn a flag
    into a number. The walk is iterative because the parser accepts
    nesting deeper than recursion here would follow.
    """
    pending: list[tuple[object, object]] = [(left, right)]
    while pending:
        one, other = pending.pop()
        if type(one) is not type(other):
            return False
        if isinstance(one, dict):
            first = cast("dict[str, Any]", one)
            second = cast("dict[str, Any]", other)
            if list(first) != list(second):
                return False
            pending.extend((first[key], second[key]) for key in first)
        elif isinstance(one, list):
            first_list = cast("list[Any]", one)
            second_list = cast("list[Any]", other)
            if len(first_list) != len(second_list):
                return False
            pending.extend(zip(first_list, second_list, strict=True))
        elif repr(one) != repr(other):
            return False
    return True


def decode_block(text: str) -> dict[str, Any] | None:
    """Decode ``text`` as a final json block, without the extractor.

    Returns the object the prompt says such a block carries, or
    ``None`` when ``text`` is not one: not JSON, not an object with
    ``proposals``, or carrying a line that would end the fence.
    """
    if fence_shaped(text):
        return None
    try:
        decoded: object = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(decoded, dict) or "proposals" not in decoded:
        return None
    return cast("dict[str, Any]", decoded)
