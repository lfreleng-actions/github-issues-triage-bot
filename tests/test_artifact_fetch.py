# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Bounded fetch of a session or ledger artifact."""

from __future__ import annotations

import io
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
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

    def __init__(self, payload: bytes, returncode: int = 0) -> None:
        """Serve ``payload`` and report ``returncode`` once drained."""
        self.stdout = io.BytesIO(payload)
        self.returncode = returncode
        self.killed = False

    def kill(self) -> None:
        """Record that the fetch stopped the process."""
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        """Report the exit status."""
        return self.returncode


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
    """``download`` streams under a byte bound and reports gh's exit."""

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

    def test_non_zero_exit_is_an_operational_failure(self) -> None:
        """gh failing after some output is a GitHubError, not a refusal."""
        with (
            patch.object(fetcher.subprocess, "Popen", return_value=FakeProc(b"x", 1)),
            tempfile.TemporaryDirectory() as holder,
            self.assertRaisesRegex(github.GitHubError, "gh exit 1"),
        ):
            fetcher.download("o/r", 5, Path(holder) / "a.zip", 1024)

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
