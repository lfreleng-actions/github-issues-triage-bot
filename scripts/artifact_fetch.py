# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Fetch an artifact without letting it expand unbounded.

``download-artifact`` extracts an archive before anything can check
its size, so a small, highly compressible upload could fill the
runner's disk. This fetch instead finds the artifact through the
API, refuses one whose zip exceeds the sum of the permitted file caps,
streams the zip to disk under that limit, inspects the zip directory,
and extracts the permitted files alone, each read with a hard stop so
a zip that lies about sizes cannot expand past its cap.

Two profiles exist: ``session`` takes an agent session's summary and
usage file from one run; ``ledger`` takes a prior run's ledger. The
apply job uses the first; the prepare job uses the second through
``ledger.py``.

Exit status: 0 accepted, with ``artifact_id=<id>`` on stdout; 3 no
such artifact; 4 artifact refused. Anything else is an operational
failure, after the download has retried a failure GitHub never
answered or answered with a 500, 502, 503 or 504.
"""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

import bot_github as github
import ledger
from bot_evidence import SESSION_FILES

Profile = tuple[tuple[str, int, bool], ...]
ZIP_OVERHEAD = 1024 * 1024
MAX_ENTRIES = 64
CHUNK = 64 * 1024
TIMEOUT_SECONDS = 300
# The tail of gh's stderr, where it appends the HTTP status; none of
# it is logged.
ERROR_BYTES = 4096
NOT_FOUND = 3
REFUSED = 4


class Refused(Exception):
    """The artifact breaks a bound; its contents are not accepted."""


class Missing(Exception):
    """No such artifact exists."""


def profiles() -> dict[str, Profile]:
    """The named cap tables an artifact may be fetched under.

    Built on demand: ``ledger`` imports this module, so its table is
    read when the command runs rather than while modules load.
    """
    return {"session": SESSION_FILES, "ledger": ledger.LEDGER_FILES}


def zip_limit(profile: Profile) -> int:
    """The permitted files at their caps, plus zip overhead."""
    return sum(limit for _, limit, _ in profile) + ZIP_OVERHEAD


def live_artifacts(entries: Any, name: str) -> list[dict[str, Any]]:
    """Filter an artifact listing to unexpired artifacts of one name."""
    if not isinstance(entries, list):
        raise github.GitHubError("artifact listing carried no artifacts")
    return [
        cast("dict[str, Any]", entry)
        for entry in cast("list[Any]", entries)
        if isinstance(entry, dict)
        and cast("dict[str, Any]", entry).get("name") == name
        and not cast("dict[str, Any]", entry).get("expired")
    ]


def artifact_size(entry: dict[str, Any]) -> int:
    """The recorded zip size of one artifact listing entry."""
    size = entry.get("size_in_bytes")
    if type(size) is not int or size < 0:
        raise github.GitHubError("artifact carries no size")
    return size


def find_run_artifact(repository: str, run_id: str, name: str) -> tuple[int, int]:
    """The id and zip size of the one live artifact of this name in the run."""
    listing = github.api_object(
        f"repos/{repository}/actions/runs/{run_id}/artifacts"
        f"?name={quote(name, safe='')}&per_page=10"
    )
    live = live_artifacts(listing.get("artifacts"), name)
    if not live:
        raise Missing(f"no artifact named {name}")
    if len(live) > 1:
        raise Refused(f"{len(live)} artifacts named {name}")
    return github.require_int(live[0], "id", "artifact"), artifact_size(live[0])


def list_named_artifacts(
    repository: str, name: str, limit: int
) -> list[dict[str, Any]]:
    """The newest ``limit`` live artifacts of one name across the repository's runs.

    The API lists newest first, so one page of up to 100 holds more
    than any caller here asks for.
    """
    listing = github.api_object(
        f"repos/{repository}/actions/artifacts?name={quote(name, safe='')}&per_page=100"
    )
    live = live_artifacts(listing.get("artifacts"), name)
    for entry in live:
        github.require_int(entry, "id", "artifact")
        artifact_size(entry)
    return live[:limit]


def timed_out() -> github.GitHubError:
    """The failure for a download that ran past its deadline."""
    return github.GitHubError(
        f"artifact download timed out after {TIMEOUT_SECONDS} seconds"
    )


def stream(
    repository: str, artifact_id: int, target: Path, limit: int, deadline: float
) -> tuple[int, int | None]:
    """Make one attempt at streaming the zip to ``target``.

    Returns gh's exit status and the HTTP status its stderr names,
    or None for the status when no reply arrived.
    """
    written = 0
    expired = threading.Event()
    # stderr goes to a file rather than a pipe, which gh could fill
    # and block on while this loop waits for its stdout.
    with target.open("wb") as sink, tempfile.TemporaryFile() as errors:
        proc = subprocess.Popen(
            ["gh", "api", f"repos/{repository}/actions/artifacts/{artifact_id}/zip"],
            stdout=subprocess.PIPE,
            stderr=errors,
        )
        stdout = proc.stdout
        if stdout is None:
            proc.kill()
            raise github.GitHubError("could not read the artifact download")

        def expire() -> None:
            expired.set()
            proc.kill()

        # A read blocks until gh writes or exits, so no check between
        # reads can enforce a deadline; killing gh ends the read instead.
        # The budget is read once gh is running, so its start-up counts.
        seconds = deadline - time.monotonic()
        timer = threading.Timer(seconds, expire)
        if seconds > 0:
            timer.start()
        else:
            expire()
        try:
            while True:
                chunk = stdout.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > limit:
                    raise Refused(f"artifact zip exceeds {limit} bytes")
                sink.write(chunk)
        except BaseException:
            # Refusing mid-stream: stop gh rather than drain the rest.
            proc.kill()
            raise
        finally:
            stdout.close()
            # Still under the timer, so this wait is bounded too.
            proc.wait()
            timer.cancel()
        # gh appends the status, so read the tail: a long message before
        # it cannot push it out of reach.
        size = errors.seek(0, os.SEEK_END)
        errors.seek(max(0, size - ERROR_BYTES))
        reported = errors.read(ERROR_BYTES).decode("utf-8", "replace")
    if expired.is_set():
        raise timed_out()
    return proc.returncode, github.parse_status(reported)


def download(repository: str, artifact_id: int, target: Path, limit: int) -> None:
    """Stream the zip to ``target``, stopping past ``limit`` or the deadline.

    A failure GitHub never answered, which gh reports without an HTTP
    status, and a 500, 502, 503 or 504 are retried with the read
    backoff of ``bot_github``: a runner can lose DNS for a second while
    harden-runner restarts its resolver, and a download caught in
    that second fails on the redirect to storage. Any other status or
    a refusal ends the download at once. One deadline spans every
    attempt: a backoff that would reach it ends the download rather
    than sleep past it, and no retry starts once it has passed. gh's
    message stays out of the error,
    since for a failed redirect it quotes the signed storage URL,
    which grants read access to the zip.
    """
    deadline = time.monotonic() + TIMEOUT_SECONDS
    attempts = github.READ_ATTEMPTS
    for attempt in range(1, attempts + 1):
        code, status = stream(repository, artifact_id, target, limit, deadline)
        if code == 0:
            return
        reply = "with no HTTP status" if status is None else f"(HTTP {status})"
        failure = (
            f"artifact download failed on attempt {attempt} of {attempts}:"
            f" gh exit {code} {reply}"
        )
        transient = status is None or status in github.TRANSIENT
        if attempt == attempts or not transient:
            raise github.GitHubError(failure, status)
        delay = github.RETRY_DELAY_SECONDS * attempt
        no_time = github.GitHubError(f"{failure}, with no time left to retry", status)
        if time.monotonic() + delay >= deadline:
            raise no_time
        time.sleep(delay)
        if time.monotonic() >= deadline:
            # The sleep resumed late: no retry starts past the deadline.
            raise no_time
    raise AssertionError("unreachable")  # pragma: no cover


def check_entry(entry: zipfile.ZipInfo, cap: int) -> None:
    """Refuse a zip entry that is not a plain, bounded, readable file."""
    # A recorded type must be a regular file; symlinks and the like
    # are refused. No type bits means none recorded.
    kind = stat.S_IFMT(entry.external_attr >> 16)
    if entry.is_dir() or kind not in (0, stat.S_IFREG):
        raise Refused(f"{entry.filename} is not a regular file")
    if entry.file_size > cap:
        raise Refused(f"{entry.filename} exceeds its cap")
    # zipfile raises NotImplementedError or RuntimeError for these on
    # read; refuse them here instead.
    if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise Refused(f"{entry.filename} uses unsupported compression")
    if entry.flag_bits & 0x1:
        raise Refused(f"{entry.filename} is encrypted")


def extract(archive: Path, output: Path, profile: Profile) -> list[str]:
    """Extract the permitted files from the zip, each under its cap."""
    caps = {name: (limit, required) for name, limit, required in profile}
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            if len(entries) > MAX_ENTRIES:
                raise Refused(f"artifact holds {len(entries)} entries")
            found: dict[str, zipfile.ZipInfo] = {}
            for entry in entries:
                if entry.filename not in caps:
                    continue
                if entry.filename in found:
                    raise Refused(f"artifact holds {entry.filename} twice")
                check_entry(entry, caps[entry.filename][0])
                found[entry.filename] = entry
            output.mkdir(parents=True, exist_ok=True)
            copied: list[str] = []
            for name, (limit, required) in caps.items():
                if name not in found:
                    if required:
                        raise Refused(f"artifact lacks {name}")
                    continue
                with bundle.open(found[name]) as source:
                    # Read past the cap by one byte: a header that
                    # understates the size cannot expand further.
                    content = source.read(limit + 1)
                if len(content) > limit:
                    raise Refused(f"{name} expands past its cap")
                (output / name).write_bytes(content)
                copied.append(name)
            return copied
    except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
        raise Refused(f"artifact is not a valid zip: {exc}") from exc


def fetch_artifact(
    repository: str, artifact_id: int, size: int, output: Path, profile: Profile
) -> list[str]:
    """Bound, download and extract one artifact already located by id."""
    limit = zip_limit(profile)
    if size > limit:
        raise Refused(f"artifact zip is {size} bytes, over {limit}")
    with tempfile.TemporaryDirectory() as holder:
        archive = Path(holder) / "artifact.zip"
        download(repository, artifact_id, archive, limit)
        return extract(archive, output, profile)


def fetch_from_run(
    repository: str, run_id: str, name: str, output: Path, profile: Profile
) -> tuple[int, list[str]]:
    """Find, bound, download and extract one artifact of the given run.

    Returns the artifact ID, which names the session that produced
    it, and the files extracted.
    """
    artifact_id, size = find_run_artifact(repository, run_id, name)
    return artifact_id, fetch_artifact(repository, artifact_id, size, output, profile)


def main(argv: list[str] | None = None) -> None:
    """Fetch the artifact; the exit status says what happened."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--name", required=True)
    tables = profiles()
    parser.add_argument("--profile", choices=sorted(tables), default="session")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        artifact_id, copied = fetch_from_run(
            args.repository, args.run_id, args.name, args.output, tables[args.profile]
        )
    except Missing as exc:
        print(f"artifact: {exc}", file=sys.stderr)
        raise SystemExit(NOT_FOUND) from exc
    except Refused as exc:
        print(f"artifact refused: {exc}", file=sys.stderr)
        raise SystemExit(REFUSED) from exc
    except (OSError, subprocess.SubprocessError, github.GitHubError) as exc:
        parser.exit(1, f"artifact fetch: {github.safe_message(exc)}\n")
    print(f"accepted: {', '.join(copied)}", file=sys.stderr)
    # Stdout is the step's output file: each upload gets a new ID, so
    # the report can tell a rerun session from an apply retry.
    print(f"artifact_id={artifact_id}")


if __name__ == "__main__":
    main()
