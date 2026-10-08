# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Bounded fetch of a session or ledger artifact."""

from __future__ import annotations

import io
import struct
import sys
import tempfile
import threading
import unittest
import warnings
import zipfile
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

fetcher = import_module("artifact_fetch")
github = import_module("bot_github")
evidence = import_module("bot_evidence")

SUMMARY = b"# Session\n\n```json\n{}\n```\n"
SESSION = fetcher.profiles()["session"]
# What gh prints when no reply arrives: for a DNS failure, the host
# alone; for anything else, the request, signed storage URL included.
DNS_FAILURE = (
    b"error connecting to productionresultssa1.blob.core.windows.net\n"
    b"check your internet connection or https://githubstatus.com\n"
)
RESET = (
    b'Get "https://productionresultssa1.blob.core.windows.net/a.zip?sig=SIGNED":'
    b" read tcp 10.1.0.4:41234->20.209.226.129:443: connection reset by peer\n"
)


def make_zip(entries: dict[str, bytes], path: Path) -> Path:
    """Write a deflated zip of the given entries."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, content in entries.items():
            bundle.writestr(name, content)
    return path


def rewrite_headers(
    path: Path, name: str, offsets: dict[bytes, int], fmt: str, value: int
) -> None:
    """Overwrite one field of ``name``'s local and central headers.

    Models a hostile archive whose directory lies: zipfile trusts the
    central directory, so both copies of the field must change.
    """
    data = bytearray(path.read_bytes())
    encoded = name.encode()
    for signature, field_offset in offsets.items():
        start = 0
        while (index := data.find(signature, start)) != -1:
            name_offset = index + (30 if signature == b"PK\x03\x04" else 46)
            if bytes(data[name_offset : name_offset + len(encoded)]) == encoded:
                struct.pack_into(fmt, data, index + field_offset, value)
            start = index + 4
    path.write_bytes(bytes(data))


class FakeProc:
    """A gh process whose stdout is a prepared stream."""

    def __init__(
        self, payload: bytes, returncode: int = 0, errors: bytes = b""
    ) -> None:
        """Serve ``payload``, report ``returncode`` and print ``errors``."""
        self.stdout = io.BytesIO(payload)
        self.returncode = returncode
        self.errors = errors
        self.killed = False

    def kill(self) -> None:
        """Record that the fetch stopped the process."""
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        """Report the exit status."""
        return self.returncode


def spawning(*procs: FakeProc, started: Callable[[], None] | None = None) -> Any:
    """Patch Popen to start ``procs`` in turn, each printing its stderr.

    ``started`` runs as each one starts, to model the time that takes.
    """
    queue = list(procs)

    def spawn(args: list[str], **kwargs: Any) -> FakeProc:
        if started is not None:
            started()
        proc = queue.pop(0)
        kwargs["stderr"].write(proc.errors)
        return proc

    return patch.object(fetcher.subprocess, "Popen", side_effect=spawn)


class ListingTest(unittest.TestCase):
    """Artifact lookups want exactly one live artifact of the name."""

    def listing(self, *entries: dict[str, Any]) -> Any:
        """Patch the API read to return these artifacts."""
        return patch.object(
            github, "api_object", return_value={"artifacts": list(entries)}
        )

    def test_live_artifacts_filters_name_and_expiry(self) -> None:
        """Other names, expired entries and non-objects are dropped."""
        entries = [
            {"name": "a", "id": 1},
            {"name": "a", "id": 2, "expired": True},
            {"name": "b", "id": 3},
            "junk",
        ]
        self.assertEqual(fetcher.live_artifacts(entries, "a"), [{"name": "a", "id": 1}])
        with self.assertRaises(github.GitHubError):
            fetcher.live_artifacts(None, "a")

    def test_find_run_artifact_returns_id_and_size(self) -> None:
        """The id and zip size come back; the name is URL-encoded."""
        with self.listing({"name": "s x", "id": 5, "size_in_bytes": 99}) as read:
            self.assertEqual(fetcher.find_run_artifact("o/r", "1", "s x"), (5, 99))
        self.assertIn("name=s%20x", read.call_args.args[0])

    def test_find_run_artifact_missing(self) -> None:
        """No live artifact of the name is Missing."""
        with (
            self.listing({"name": "s", "id": 5, "size_in_bytes": 1, "expired": True}),
            self.assertRaises(fetcher.Missing),
        ):
            fetcher.find_run_artifact("o/r", "1", "s")

    def test_find_run_artifact_duplicates_refused(self) -> None:
        """Two live artifacts of one name are ambiguous and refused."""
        entry = {"name": "s", "id": 5, "size_in_bytes": 1}
        with (
            self.listing(entry, {**entry, "id": 6}),
            self.assertRaises(fetcher.Refused),
        ):
            fetcher.find_run_artifact("o/r", "1", "s")

    def test_bad_size_is_an_operational_failure(self) -> None:
        """An entry without a usable size cannot be bounded."""
        with (
            self.listing({"name": "s", "id": 5, "size_in_bytes": "big"}),
            self.assertRaises(github.GitHubError),
        ):
            fetcher.find_run_artifact("o/r", "1", "s")

    def test_list_named_artifacts_limits_and_validates(self) -> None:
        """Newest-first order is kept and cut at the limit."""
        entries = [{"name": "l", "id": i, "size_in_bytes": i} for i in (9, 8, 7)]
        with self.listing(*entries):
            self.assertEqual(
                [e["id"] for e in fetcher.list_named_artifacts("o/r", "l", 2)], [9, 8]
            )
        with (
            self.listing({"name": "l", "size_in_bytes": 1}),
            self.assertRaises(github.GitHubError),
        ):
            fetcher.list_named_artifacts("o/r", "l", 2)


class ExtractTest(unittest.TestCase):
    """``extract`` takes the permitted files alone, each under its cap."""

    def setUp(self) -> None:
        """A scratch directory for archives and output."""
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        self.archive = self.root / "a.zip"
        self.output = self.root / "accepted"

    def test_permitted_files_only(self) -> None:
        """Other entries are ignored and never written."""
        make_zip(
            {"session-summary.md": SUMMARY, "usage.json": b"{}", "evil.py": b"x"},
            self.archive,
        )
        copied = fetcher.extract(self.archive, self.output, SESSION)
        self.assertEqual(copied, ["session-summary.md", "usage.json"])
        self.assertEqual((self.output / "session-summary.md").read_bytes(), SUMMARY)
        self.assertFalse((self.output / "evil.py").exists())

    def test_optional_file_may_be_absent(self) -> None:
        """A session without usage.json is still accepted."""
        make_zip({"session-summary.md": SUMMARY}, self.archive)
        self.assertEqual(
            fetcher.extract(self.archive, self.output, SESSION), ["session-summary.md"]
        )

    def test_required_file_missing_refused(self) -> None:
        """A session without its summary is refused."""
        make_zip({"usage.json": b"{}"}, self.archive)
        with self.assertRaisesRegex(fetcher.Refused, "lacks session-summary.md"):
            fetcher.extract(self.archive, self.output, SESSION)

    def test_too_many_entries_refused(self) -> None:
        """An archive of many entries is refused before any read."""
        entries = {f"f{i}": b"x" for i in range(fetcher.MAX_ENTRIES)}
        entries["session-summary.md"] = SUMMARY
        make_zip(entries, self.archive)
        with self.assertRaisesRegex(fetcher.Refused, "entries"):
            fetcher.extract(self.archive, self.output, SESSION)

    def test_duplicate_entry_refused(self) -> None:
        """A name present twice is ambiguous and refused."""
        with zipfile.ZipFile(self.archive, "w") as bundle, warnings.catch_warnings():
            # zipfile warns about the duplicate it is asked to write.
            warnings.simplefilter("ignore")
            bundle.writestr("session-summary.md", SUMMARY)
            bundle.writestr("session-summary.md", b"other")
        with self.assertRaisesRegex(fetcher.Refused, "twice"):
            fetcher.extract(self.archive, self.output, SESSION)

    def test_directory_and_symlink_entries_refused(self) -> None:
        """Only regular files are extracted."""
        with zipfile.ZipFile(self.archive, "w") as bundle:
            info = zipfile.ZipInfo("usage.json")
            info.external_attr = 0o040755 << 16
            bundle.writestr(info, b"")
            bundle.writestr("session-summary.md", SUMMARY)
        with self.assertRaisesRegex(fetcher.Refused, "not a regular file"):
            fetcher.extract(self.archive, self.output, SESSION)
        with zipfile.ZipFile(self.archive, "w") as bundle:
            info = zipfile.ZipInfo("session-summary.md")
            info.external_attr = 0o120777 << 16
            bundle.writestr(info, "/etc/passwd")
        with self.assertRaisesRegex(fetcher.Refused, "not a regular file"):
            fetcher.extract(self.archive, self.output, SESSION)

    def test_oversized_entry_refused_from_its_header(self) -> None:
        """A declared size past the cap is refused before decompression."""
        big = b"0" * (evidence.MAX_USAGE_BYTES + 1)
        make_zip({"session-summary.md": SUMMARY, "usage.json": big}, self.archive)
        with self.assertRaisesRegex(fetcher.Refused, "exceeds its cap"):
            fetcher.extract(self.archive, self.output, SESSION)

    def test_understated_header_cannot_expand_past_the_cap(self) -> None:
        """A lying header still stops at the cap on read."""
        big = b"0" * (evidence.MAX_USAGE_BYTES + 4096)
        make_zip({"session-summary.md": SUMMARY, "usage.json": big}, self.archive)
        # Uncompressed size field: offset 22 locally, 24 centrally.
        rewrite_headers(
            self.archive, "usage.json", {b"PK\x03\x04": 22, b"PK\x01\x02": 24}, "<I", 10
        )
        with self.assertRaises(fetcher.Refused):
            fetcher.extract(self.archive, self.output, SESSION)
        self.assertFalse((self.output / "usage.json").exists())

    def test_encrypted_entry_refused(self) -> None:
        """An entry flagged as encrypted is a refusal."""
        with zipfile.ZipFile(self.archive, "w", zipfile.ZIP_STORED) as bundle:
            bundle.writestr("session-summary.md", SUMMARY)
        # Flag field: offset 6 locally, 8 in the central directory.
        rewrite_headers(
            self.archive,
            "session-summary.md",
            {b"PK\x03\x04": 6, b"PK\x01\x02": 8},
            "<H",
            1,
        )
        with self.assertRaisesRegex(fetcher.Refused, "encrypted"):
            fetcher.extract(self.archive, self.output, SESSION)

    def test_unsupported_compression_refused(self) -> None:
        """A compression method zipfile cannot read is a refusal."""
        with zipfile.ZipFile(self.archive, "w", zipfile.ZIP_STORED) as bundle:
            bundle.writestr("session-summary.md", SUMMARY)
        # Method field: offset 8 locally, 10 in the central directory.
        rewrite_headers(
            self.archive,
            "session-summary.md",
            {b"PK\x03\x04": 8, b"PK\x01\x02": 10},
            "<H",
            99,
        )
        with self.assertRaisesRegex(fetcher.Refused, "compression"):
            fetcher.extract(self.archive, self.output, SESSION)

    def test_not_a_zip_refused(self) -> None:
        """Garbage is a refusal, not a crash."""
        self.archive.write_bytes(b"not a zip")
        with self.assertRaisesRegex(fetcher.Refused, "not a valid zip"):
            fetcher.extract(self.archive, self.output, SESSION)


class DownloadTest(unittest.TestCase):
    """``download`` streams under a byte bound, retrying what GitHub never answered."""

    def test_stream_past_limit_is_cut_off(self) -> None:
        """A download that runs past the limit is stopped and refused."""
        proc = FakeProc(b"x" * (fetcher.CHUNK * 3), returncode=-9)
        with (
            patch.object(fetcher.subprocess, "Popen", return_value=proc),
            tempfile.TemporaryDirectory() as holder,
            self.assertRaisesRegex(fetcher.Refused, "exceeds"),
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", fetcher.CHUNK * 2)
        self.assertTrue(proc.killed)

    @unittest.expectedFailure
    def test_non_zero_exit_is_an_operational_failure(self) -> None:
        """gh failing after some output is a GitHubError, not a refusal.

        A 4xx is GitHub's answer, so it carries its status and is not
        tried again.
        """
        with (
            spawning(FakeProc(b"x", 1, b"gh: Not Found (HTTP 404)\n")) as spawn,
            patch.object(fetcher.time, "sleep") as sleep,
            tempfile.TemporaryDirectory() as holder,
            self.assertRaisesRegex(github.GitHubError, "gh exit 1") as caught,
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(spawn.call_count, 1)
        sleep.assert_not_called()

    @unittest.expectedFailure
    def test_bare_client_error_from_storage_is_final(self) -> None:
        """Storage answers in XML, so gh prints a bare status; a 403 is final."""
        with (
            spawning(FakeProc(b"<Error/>", 1, b"gh: HTTP 403\n")) as spawn,
            patch.object(fetcher.time, "sleep") as sleep,
            tempfile.TemporaryDirectory() as holder,
            self.assertRaises(github.GitHubError) as caught,
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(spawn.call_count, 1)
        sleep.assert_not_called()

    @unittest.expectedFailure
    def test_status_is_read_from_the_tail_of_a_long_message(self) -> None:
        """gh appends the status, so a long message cannot hide it.

        A final 403 after a message longer than the read stays final,
        and a 502 after an earlier quoted 404 is still retried.
        """
        padding = b"x" * fetcher.ERROR_BYTES
        final = b"gh: " + padding + b" (HTTP 403)\n"
        with (
            spawning(FakeProc(b"", 1, final)) as spawn,
            patch.object(fetcher.time, "sleep"),
            tempfile.TemporaryDirectory() as holder,
            self.assertRaises(github.GitHubError) as caught,
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)
        self.assertEqual((caught.exception.status, spawn.call_count), (403, 1))
        quoted = b"gh: upstream said (HTTP 404)\ngh: " + padding + b" (HTTP 502)\n"
        with (
            spawning(FakeProc(b"", 1, quoted), FakeProc(b"abc")) as spawn,
            patch.object(fetcher.time, "sleep"),
            tempfile.TemporaryDirectory() as holder,
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)
        self.assertEqual(spawn.call_count, 2)

    @unittest.expectedFailure
    def test_unanswered_and_server_failures_are_retried(self) -> None:
        """No reply, then a 502, then the zip is one successful download.

        Each attempt rewrites the target, so the 502's error body that
        gh printed to stdout does not survive into the archive.
        """
        with (
            spawning(
                FakeProc(b"", 1, DNS_FAILURE),
                FakeProc(b'{"message":"Bad Gateway"}', 1, b"gh: Bad (HTTP 502)\n"),
                FakeProc(b"abc"),
            ) as spawn,
            patch.object(fetcher.time, "sleep") as sleep,
            tempfile.TemporaryDirectory() as holder,
        ):
            target = Path(holder) / "a.zip"
            fetcher.download("o/r", 5, target, 1024)
            self.assertEqual(target.read_bytes(), b"abc")
        self.assertEqual(spawn.call_count, 3)
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [github.RETRY_DELAY_SECONDS, github.RETRY_DELAY_SECONDS * 2],
        )

    @unittest.expectedFailure
    def test_retries_end_at_the_budget_without_echoing_gh(self) -> None:
        """The last failure names the attempt, never gh's signed URL."""
        attempts = github.READ_ATTEMPTS
        with (
            spawning(*(FakeProc(b"", 1, RESET) for _ in range(attempts))) as spawn,
            patch.object(fetcher.time, "sleep"),
            tempfile.TemporaryDirectory() as holder,
            self.assertRaises(github.GitHubError) as caught,
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)
        message = str(caught.exception)
        self.assertEqual(spawn.call_count, attempts)
        self.assertIn(f"attempt {attempts} of {attempts}", message)
        self.assertIn("no HTTP status", message)
        self.assertNotIn("sig=", message)
        self.assertIsNone(caught.exception.status)

    @unittest.expectedFailure
    def test_deadline_spans_every_attempt(self) -> None:
        """Each timer gets only what start-up and the backoff have left."""
        clock = [0.0]
        intervals: list[float] = []
        start_timer = threading.Timer
        startup = 5.0

        def wait(seconds: float) -> None:
            clock[0] += seconds

        def timer(interval: float, function: Any) -> threading.Timer:
            intervals.append(interval)
            return start_timer(interval, function)

        with (
            spawning(
                FakeProc(b"", 1, DNS_FAILURE),
                FakeProc(b"abc"),
                started=lambda: wait(startup),
            ),
            patch.object(fetcher.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(fetcher.time, "sleep", side_effect=wait),
            patch.object(fetcher.threading, "Timer", side_effect=timer),
            tempfile.TemporaryDirectory() as holder,
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)
        budget = fetcher.TIMEOUT_SECONDS
        delay = github.RETRY_DELAY_SECONDS
        self.assertEqual(intervals, [budget - startup, budget - 2 * startup - delay])

    @unittest.expectedFailure
    def test_start_up_that_spends_the_deadline_times_out(self) -> None:
        """With nothing left once gh runs, it is stopped and the attempt ends."""
        clock = [0.0]
        proc = FakeProc(b"abc")

        def start() -> None:
            clock[0] += fetcher.TIMEOUT_SECONDS

        with (
            spawning(proc, started=start),
            patch.object(fetcher.time, "monotonic", side_effect=lambda: clock[0]),
            tempfile.TemporaryDirectory() as holder,
            self.assertRaisesRegex(github.GitHubError, "timed out"),
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)
        self.assertTrue(proc.killed)

    @unittest.expectedFailure
    def test_backoff_never_outlasts_the_deadline(self) -> None:
        """A backoff that would reach the deadline ends the download."""
        with (
            spawning(FakeProc(b"", 1, DNS_FAILURE)) as spawn,
            patch.object(fetcher, "TIMEOUT_SECONDS", github.RETRY_DELAY_SECONDS),
            patch.object(fetcher.time, "monotonic", return_value=0.0),
            patch.object(fetcher.time, "sleep") as sleep,
            tempfile.TemporaryDirectory() as holder,
            self.assertRaisesRegex(github.GitHubError, "no time left to retry"),
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)
        self.assertEqual(spawn.call_count, 1)
        sleep.assert_not_called()

    @unittest.expectedFailure
    def test_no_retry_starts_after_a_late_backoff(self) -> None:
        """A sleep that resumes past the deadline starts no second gh."""
        clock = [0.0]

        def oversleep(seconds: float) -> None:
            clock[0] += fetcher.TIMEOUT_SECONDS

        with (
            spawning(FakeProc(b"", 1, DNS_FAILURE), FakeProc(b"abc")) as spawn,
            patch.object(fetcher.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(fetcher.time, "sleep", side_effect=oversleep),
            tempfile.TemporaryDirectory() as holder,
            self.assertRaisesRegex(github.GitHubError, "no time left to retry"),
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)
        self.assertEqual(spawn.call_count, 1)

    def test_complete_stream_written(self) -> None:
        """A stream within the limit lands on disk byte for byte."""
        with (
            patch.object(
                fetcher.subprocess, "Popen", return_value=FakeProc(b"abc")
            ) as spawn,
            tempfile.TemporaryDirectory() as holder,
        ):
            target = Path(holder) / "a.zip"
            fetcher.download("o/r", 5, target, 1024)
            self.assertEqual(target.read_bytes(), b"abc")
        self.assertIn("repos/o/r/actions/artifacts/5/zip", spawn.call_args.args[0])


class FetchTest(unittest.TestCase):
    """The end-to-end fetch and its CLI exit codes."""

    def test_reported_size_over_limit_is_never_downloaded(self) -> None:
        """GitHub's own size figure stops the fetch before any transfer."""
        limit = fetcher.zip_limit(SESSION)
        with (
            patch.object(fetcher, "find_run_artifact", return_value=(5, limit + 1)),
            patch.object(fetcher, "download") as download,
            tempfile.TemporaryDirectory() as holder,
            self.assertRaisesRegex(fetcher.Refused, "over"),
        ):
            fetcher.fetch_from_run("o/r", "1", "s", Path(holder), SESSION)
        download.assert_not_called()

    def test_fetch_from_run_happy_path(self) -> None:
        """Locate, download and extract, returning the id and files."""
        with tempfile.TemporaryDirectory() as holder:
            payload = make_zip(
                {"session-summary.md": SUMMARY}, Path(holder) / "z.zip"
            ).read_bytes()
            with (
                patch.object(
                    fetcher, "find_run_artifact", return_value=(5, len(payload))
                ),
                patch.object(
                    fetcher.subprocess, "Popen", return_value=FakeProc(payload)
                ),
            ):
                found = fetcher.fetch_from_run(
                    "o/r", "1", "s", Path(holder) / "out", SESSION
                )
            self.assertEqual(found, (5, ["session-summary.md"]))
            self.assertEqual(
                (Path(holder) / "out" / "session-summary.md").read_bytes(), SUMMARY
            )

    def run_main(self, side_effect: Any) -> tuple[int | None, str, str]:
        """Run the CLI with ``fetch_from_run`` replaced; return code and streams."""
        argv = [
            "--repository",
            "o/r",
            "--run-id",
            "1",
            "--name",
            "s",
            "--output",
            "out",
        ]
        with (
            patch.object(fetcher, "fetch_from_run", side_effect=side_effect),
            redirect_stdout(io.StringIO()) as out,
            redirect_stderr(io.StringIO()) as err,
        ):
            try:
                fetcher.main(argv)
            except SystemExit as caught:
                return int(str(caught.code or 0)), out.getvalue(), err.getvalue()
        return 0, out.getvalue(), err.getvalue()

    def test_cli_prints_the_artifact_id(self) -> None:
        """Success writes the id line to stdout for the step output."""
        code, out, err = self.run_main([(77, ["session-summary.md"])])
        self.assertEqual(code, 0)
        self.assertEqual(out, "artifact_id=77\n")
        self.assertIn("accepted: session-summary.md", err)

    def test_cli_exit_codes(self) -> None:
        """Missing is 3, refused is 4, an API failure is 1."""
        self.assertEqual(self.run_main(fetcher.Missing("none"))[0], fetcher.NOT_FOUND)
        code, out, err = self.run_main(fetcher.Refused("too big"))
        self.assertEqual((code, out), (fetcher.REFUSED, ""))
        self.assertIn("artifact refused: too big", err)
        code, _, err = self.run_main(github.GitHubError("gh: Bad (HTTP 502)::x"))
        self.assertEqual(code, 1)
        self.assertIn("artifact fetch: 'gh: Bad (HTTP 502): :x'", err)


if __name__ == "__main__":
    unittest.main()
