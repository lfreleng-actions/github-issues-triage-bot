# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Bounded reads of regular files and verification of trusted evidence."""

from __future__ import annotations

import hashlib
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

evidence = import_module("bot_evidence")

SELECTION = b'{"schema": 1, "targets": []}\n'
LEDGER = b'{"schema": 1, "entries": []}\n'
LIMIT = evidence.MAX_EVIDENCE_BYTES


def digest(content: bytes) -> str:
    """The hex SHA-256 of some bytes."""
    return hashlib.sha256(content).hexdigest()


def expect(selection: str, ledger: str) -> list[tuple[str, str, int]]:
    """Expectations for the two sample files at the default limit."""
    return [("selection.json", selection, LIMIT), ("ledger.json", ledger, LIMIT)]


class ReadRegularTest(unittest.TestCase):
    """``read_regular`` takes a bounded regular file and nothing else."""

    def setUp(self) -> None:
        """A scratch directory holding the files under test."""
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)

    def test_reads_a_regular_file_within_the_limit(self) -> None:
        """A file at exactly the limit is returned whole."""
        path = self.root / "f"
        path.write_bytes(b"x" * 16)
        self.assertEqual(evidence.read_regular(path, 16), b"x" * 16)

    def test_oversize_file_refused(self) -> None:
        """One byte past the limit is a refusal."""
        path = self.root / "f"
        path.write_bytes(b"x" * 17)
        with self.assertRaisesRegex(ValueError, "exceeds the 16-byte limit"):
            evidence.read_regular(path, 16)

    def test_symlink_refused(self) -> None:
        """A symlink in the final component is never followed."""
        target = self.root / "real"
        target.write_bytes(b"x")
        linked = self.root / "link"
        linked.symlink_to(target)
        with self.assertRaises(OSError):
            evidence.read_regular(linked, 16)

    def test_symlinked_parent_refused(self) -> None:
        """A symlink standing in for the directory is refused too."""
        real = self.root / "dir"
        real.mkdir()
        (real / "f").write_bytes(b"x")
        (self.root / "alias").symlink_to(real)
        with self.assertRaises(OSError):
            evidence.read_regular(self.root / "alias" / "f", 16)

    def test_directory_refused(self) -> None:
        """A directory where a file should be is refused."""
        (self.root / "d").mkdir()
        with self.assertRaises((OSError, ValueError)):
            evidence.read_regular(self.root / "d", 16)

    def test_fifo_refused_without_blocking(self) -> None:
        """A FIFO with no writer is rejected rather than waited on."""
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular non-symlink file"):
            evidence.read_regular(fifo, 16)

    def test_missing_file_is_an_os_error(self) -> None:
        """An absent file surfaces as OSError for the caller to report."""
        with self.assertRaises(OSError):
            evidence.read_regular(self.root / "absent", 16)


class VerifyTest(unittest.TestCase):
    """``verify`` authenticates every expected file against its digest."""

    def setUp(self) -> None:
        """A directory holding a selection and a ledger."""
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        (self.root / "selection.json").write_bytes(SELECTION)
        (self.root / "ledger.json").write_bytes(LEDGER)

    def test_matching_digests_accepted(self) -> None:
        """Correct digests pass; upper-case hex is the same digest."""
        evidence.verify(self.root, expect(digest(SELECTION), digest(LEDGER)))
        evidence.verify(self.root, expect(digest(SELECTION).upper(), digest(LEDGER)))

    def test_mismatch_rejected(self) -> None:
        """A wrong digest for either file names the file."""
        with self.assertRaisesRegex(ValueError, "mismatch for ledger.json"):
            evidence.verify(self.root, expect(digest(SELECTION), digest(b"other")))
        with self.assertRaisesRegex(ValueError, "mismatch for selection.json"):
            evidence.verify(self.root, expect(digest(b"other"), digest(LEDGER)))

    def test_malformed_digest_rejected_before_reading(self) -> None:
        """A digest that is not 64 hex digits is refused outright."""
        for bad in ("", "abc", "g" * 64, digest(SELECTION) + "0"):
            with (
                self.subTest(bad=bad),
                self.assertRaisesRegex(ValueError, "64 hex digits"),
            ):
                evidence.verify(self.root, expect(bad, digest(LEDGER)))

    def test_bad_name_and_empty_list_rejected(self) -> None:
        """A path-like name or no expectations at all is a usage error."""
        for name in ("../x", "a/b", ".hidden", ""):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ValueError, "plain file name"),
            ):
                evidence.verify(self.root, [(name, digest(SELECTION), LIMIT)])
        with self.assertRaisesRegex(ValueError, "at least one"):
            evidence.verify(self.root, [])

    def test_limit_applies_per_expectation(self) -> None:
        """A file over its own cap is refused even with the right digest."""
        with self.assertRaisesRegex(ValueError, "exceeds the 4-byte limit"):
            evidence.verify(self.root, [("ledger.json", digest(LEDGER), 4)])

    def test_missing_file_is_an_os_error(self) -> None:
        """An absent evidence file is an operational failure."""
        (self.root / "ledger.json").unlink()
        with self.assertRaises(OSError):
            evidence.verify(self.root, expect(digest(SELECTION), digest(LEDGER)))


class MainTest(unittest.TestCase):
    """The CLI exits 1 with a safe message on any verification failure."""

    def setUp(self) -> None:
        """A directory holding both sample files."""
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        (self.root / "selection.json").write_bytes(SELECTION)
        (self.root / "ledger.json").write_bytes(LEDGER)

    def argv(self, *expectations: str) -> list[str]:
        """A verify command line over the scratch directory."""
        argv = ["verify", "--directory", str(self.root)]
        for item in expectations:
            argv += ["--expect", item]
        return argv

    def test_failure_exits_one_with_message(self) -> None:
        """The message is prefixed and carries no workflow command syntax."""
        argv = self.argv(
            f"selection.json={digest(b'wrong')}", f"ledger.json={digest(LEDGER)}"
        )
        with (
            redirect_stderr(io.StringIO()) as err,
            self.assertRaises(SystemExit) as caught,
        ):
            evidence.main(argv)
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("evidence: 'SHA-256 mismatch for selection.json'", err.getvalue())

    def test_malformed_expect_and_limit_exit_one(self) -> None:
        """An --expect without '=' or a non-positive limit is refused."""
        for argv in (
            self.argv("selection.json"),
            self.argv(f"selection.json={digest(SELECTION)}") + ["--limit-bytes", "0"],
        ):
            with (
                self.subTest(argv=argv),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as caught,
            ):
                evidence.main(argv)
            self.assertEqual(caught.exception.code, 1)

    def test_success_is_silent(self) -> None:
        """Matching digests exit normally, with a custom limit honoured."""
        argv = self.argv(
            f"selection.json={digest(SELECTION)}", f"ledger.json={digest(LEDGER)}"
        )
        evidence.main(argv)
        evidence.main(argv + ["--limit-bytes", "64"])


if __name__ == "__main__":
    unittest.main()
