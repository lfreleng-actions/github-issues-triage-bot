# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The ledger: shape, merge rules, skip asymmetry and the fetch command."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
RECORDED = frozenset({"done", "would-do", "needs-human"})

ledger = import_module("ledger")
fetcher = import_module("artifact_fetch")

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
SHA = "a" * 40


def stamp(when: datetime) -> str:
    """A timestamp in the ledger's own form."""
    return when.strftime(ledger.TIMESTAMP)


def make_entry(**overrides: Any) -> dict[str, Any]:
    """A valid ledger entry with overrides applied."""
    entry: dict[str, Any] = {
        "repository": "lfreleng-actions/repo",
        "number": 157,
        "head_sha": SHA,
        "verdict": "done",
        "tier": "trivial",
        "dry_run": False,
        "run_id": 1,
        "assessed_at": stamp(NOW),
    }
    entry.update(overrides)
    return entry


def make_ledger(*entries: dict[str, Any]) -> dict[str, Any]:
    """A ledger holding these entries."""
    return {"schema": ledger.SCHEMA, "entries": list(entries)}


class ParseLedgerTest(unittest.TestCase):
    """``parse_ledger`` admits only what this module writes."""

    def test_valid_ledger_normalised(self) -> None:
        """Known keys come back; unknown ones are dropped; odd extras null."""
        raw = make_entry(extra="x", tier=5, run_id="7")
        parsed = ledger.parse_ledger(json.dumps(make_ledger(raw)).encode())
        self.assertEqual(parsed["entries"], [make_entry(tier=None, run_id=None)])

    def test_top_level_shape(self) -> None:
        """Not JSON, not an object, wrong schema, no entries array: all refused."""
        for content in (
            b"{nope",
            b"[]",
            b'{"schema": 2, "entries": []}',
            b'{"schema": 1}',
        ):
            with self.subTest(content=content), self.assertRaises(ledger.LedgerError):
                ledger.parse_ledger(content)

    def test_entry_fields(self) -> None:
        """Every identifying field, the verdict, the mode and the stamp are checked."""
        bad: list[dict[str, Any]] = [
            {"repository": "nope"},
            {"number": 0},
            {"number": True},
            {"head_sha": "A" * 40},
            {"verdict": "Not Lower"},
            {"verdict": ""},
            {"dry_run": "no"},
            {"assessed_at": "2026-10-05"},
            {"assessed_at": None},
        ]
        for overrides in bad:
            content = json.dumps(make_ledger(make_entry(**overrides))).encode()
            with (
                self.subTest(overrides=overrides),
                self.assertRaises(ledger.LedgerError),
            ):
                ledger.parse_ledger(content)
        not_an_object: Any = "entry"
        with self.assertRaises(ledger.LedgerError):
            ledger.parse_ledger(json.dumps(make_ledger(not_an_object)).encode())


class MergeTest(unittest.TestCase):
    """``merge`` keeps one assessment per head within retention."""

    def test_newest_wins_per_head_and_repository_case_is_folded(self) -> None:
        """Duplicates collapse to the latest; owner case does not split them."""
        older = make_entry(assessed_at=stamp(NOW - timedelta(days=2)), run_id=1)
        newer = make_entry(
            repository="LFReleng-Actions/Repo",
            assessed_at=stamp(NOW - timedelta(days=1)),
            run_id=2,
        )
        other = make_entry(head_sha="b" * 40, run_id=3)
        merged = ledger.merge([make_ledger(newer), make_ledger(older, other)], now=NOW)
        self.assertEqual([e["run_id"] for e in merged["entries"]], [2, 3])

    def test_entries_past_retention_pruned(self) -> None:
        """An entry older than RETENTION_DAYS is dropped; one just inside stays."""
        stale = make_entry(
            assessed_at=stamp(NOW - timedelta(days=ledger.RETENTION_DAYS, seconds=1))
        )
        kept = make_entry(
            head_sha="b" * 40,
            assessed_at=stamp(NOW - timedelta(days=ledger.RETENTION_DAYS - 1)),
        )
        merged = ledger.merge([make_ledger(stale, kept)], now=NOW)
        self.assertEqual(merged["entries"], [kept])

    def test_empty_input_is_an_empty_ledger(self) -> None:
        """No prior ledgers merge to the empty ledger."""
        self.assertEqual(ledger.merge([], now=NOW), ledger.empty_ledger())


class AlreadyAssessedTest(unittest.TestCase):
    """Dry-run entries count for dry runs alone."""

    def test_live_entry_counts_for_both_modes(self) -> None:
        """A live assessment skips the head in a dry run and a live run."""
        held = make_ledger(make_entry(dry_run=False))
        for dry_run in (True, False):
            with self.subTest(dry_run=dry_run):
                found = ledger.already_assessed(
                    held, "LFRELENG-ACTIONS/repo", 157, SHA, dry_run=dry_run
                )
                self.assertIsNotNone(found)

    def test_dry_run_entry_counts_for_dry_runs_only(self) -> None:
        """The first live run must still approve what dry runs only reported."""
        held = make_ledger(make_entry(dry_run=True))
        self.assertIsNotNone(
            ledger.already_assessed(
                held, "lfreleng-actions/repo", 157, SHA, dry_run=True
            )
        )
        self.assertIsNone(
            ledger.already_assessed(
                held, "lfreleng-actions/repo", 157, SHA, dry_run=False
            )
        )

    def test_other_head_not_assessed(self) -> None:
        """A new push to the same pull request is a fresh head."""
        held = make_ledger(make_entry())
        self.assertIsNone(
            ledger.already_assessed(
                held, "lfreleng-actions/repo", 157, "b" * 40, dry_run=True
            )
        )


class RecordTest(unittest.TestCase):
    """``record`` adds assessments and ignores non-assessments."""

    def result(self, verdict: str) -> dict[str, Any]:
        """A result.json-shaped object with the given verdict."""
        return {
            "repository": "lfreleng-actions/repo",
            "number": 157,
            "head_sha": SHA,
            "verdict": verdict,
            "tier": "low-risk",
            "dry_run": True,
        }

    def test_recorded_verdicts_get_run_id_and_timestamp(self) -> None:
        """Every verdict in RECORDED_VERDICTS becomes an entry."""
        held = ledger.empty_ledger()
        for verdict in sorted(RECORDED):
            self.assertTrue(
                ledger.record(
                    held, self.result(verdict), run_id=9, recorded=RECORDED, now=NOW
                )
            )
        self.assertEqual(
            held["entries"],
            [
                make_entry(verdict=verdict, tier="low-risk", dry_run=True, run_id=9)
                for verdict in sorted(RECORDED)
            ],
        )

    def test_failed_and_skipped_not_recorded(self) -> None:
        """The next run should look at those heads again."""
        held = ledger.empty_ledger()
        for verdict in ("failed", "skipped", ""):
            self.assertFalse(
                ledger.record(
                    held, self.result(verdict), run_id=9, recorded=RECORDED, now=NOW
                )
            )
        self.assertEqual(held["entries"], [])

    def test_malformed_result_is_a_ledger_error(self) -> None:
        """A recordable verdict on a result missing its mode cannot be written."""
        result = self.result("done")
        del result["dry_run"]
        with self.assertRaises(ledger.LedgerError):
            ledger.record(
                ledger.empty_ledger(), result, run_id=9, recorded=RECORDED, now=NOW
            )


class FetchTest(unittest.TestCase):
    """``fetch`` merges what it can and notes what it leaves out."""

    def fake_fetch(self, payloads: dict[int, bytes | Exception]) -> Any:
        """Replace ``fetch_artifact`` with one that writes canned ledgers."""

        def fetch_artifact(
            repository: str, artifact_id: int, size: int, output: Path, profile: Any
        ) -> list[str]:
            """Write the canned ledger for this id, or raise."""
            payload = payloads[artifact_id]
            if isinstance(payload, Exception):
                raise payload
            (output / "ledger.json").write_bytes(payload)
            return ["ledger.json"]

        return patch.object(fetcher, "fetch_artifact", side_effect=fetch_artifact)

    def test_merges_artifacts_and_notes_the_bad_ones(self) -> None:
        """A refused and an invalid artifact each leave a note, not a failure."""
        listing = [{"id": i, "size_in_bytes": 10} for i in (4, 3, 2, 1)]
        # Real clock: ``fetch`` prunes by now, so these must be fresh.
        fresh = stamp(datetime.now(UTC))
        first = make_entry(run_id=3, assessed_at=fresh)
        second = make_entry(head_sha="b" * 40, run_id=1, assessed_at=fresh)
        payloads: dict[int, bytes | Exception] = {
            4: json.dumps(make_ledger(first)).encode(),
            3: fetcher.Refused("too big"),
            2: json.dumps(make_ledger(second)).encode(),
            1: b'{"schema": 9}',
        }
        with (
            patch.object(
                fetcher, "list_named_artifacts", return_value=listing
            ) as listed,
            self.fake_fetch(payloads),
        ):
            merged, notes = ledger.fetch("o/r", limit=4)
        self.assertEqual(
            listed.call_args.args, ("o/r", ledger.DEFAULT_ARTIFACT_NAME, 4)
        )
        self.assertEqual({e["run_id"] for e in merged["entries"]}, {3, 1})
        self.assertEqual(len(notes), 2)
        self.assertIn("skipped artifact 3: 'too big'", notes[0])
        self.assertIn("skipped artifact 1: ", notes[1])

    def test_main_writes_the_file_and_warns(self) -> None:
        """Notes become ``::warning::`` lines; the merged ledger is written."""
        with tempfile.TemporaryDirectory() as holder:
            output = Path(holder) / "nested" / "ledger.json"
            with (
                patch.object(
                    ledger, "fetch", return_value=(ledger.empty_ledger(), ["n1"])
                ) as fetched,
                redirect_stdout(io.StringIO()) as out,
            ):
                ledger.main(
                    [
                        "fetch",
                        "--repository",
                        "o/r",
                        "--output",
                        str(output),
                        "--artifact-name",
                        "my-ledger",
                    ]
                )
            self.assertEqual(fetched.call_args.args, ("o/r", 5, "my-ledger"))
            self.assertEqual(json.loads(output.read_text()), ledger.empty_ledger())
            self.assertTrue(output.read_text().endswith("\n"))
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "::warning::ledger: n1")
        self.assertIn("0 prior assessment(s)", lines[1])

    def test_main_api_failure_exits_one(self) -> None:
        """An unreachable listing is an operational failure."""
        with (
            patch.object(
                fetcher,
                "list_named_artifacts",
                side_effect=fetcher.github.GitHubError("down"),
            ),
            redirect_stderr(io.StringIO()) as err,
            self.assertRaises(SystemExit) as caught,
        ):
            ledger.main(["fetch", "--repository", "o/r", "--output", "x"])
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(err.getvalue(), "ledger: 'down'\n")


if __name__ == "__main__":
    unittest.main()
