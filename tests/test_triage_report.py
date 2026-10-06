# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Rendering contracts for the run report's observed label movement."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from importlib import import_module
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

report = import_module("triage_report")


def snapshot(*issues: tuple[str, int, list[str]]) -> str:
    """Serialise a `gh search issues --json` dump for the given issues."""
    return json.dumps(
        [
            {
                "repository": {"name": repo},
                "number": number,
                "title": f"Issue {number}",
                "url": f"https://example.invalid/{repo}/{number}",
                "labels": [{"name": name} for name in labels],
            }
            for repo, number, labels in issues
        ]
    )


class LabelChangeTableTests(unittest.TestCase):
    """The table reports what a run added, keeping removals visible."""

    def setUp(self) -> None:
        """Load snapshots from disk, exercising the real parser."""
        temporary = tempfile.TemporaryDirectory(prefix="triage-report-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def load(self, name: str, *issues: tuple[str, int, list[str]]) -> dict[Any, Any]:
        """Write a snapshot dump and parse it back through the loader."""
        path = self.root / name
        path.write_text(snapshot(*issues), encoding="utf-8")
        return report.load_snapshot(path)

    def render(self, *changes: tuple[list[str], list[str]]) -> str:
        """Render the report for issues moving from one label set to another."""
        before = self.load(
            "before.json",
            *[("repo", index, item[0]) for index, item in enumerate(changes, 1)],
        )
        after = self.load(
            "after.json",
            *[("repo", index, item[1]) for index, item in enumerate(changes, 1)],
        )
        return report.render_markdown(
            report.repo_rows(before, after),
            report.diff_snapshots(before, after),
            dry_run=False,
        )

    def test_table_reports_added_labels_without_a_before_column(self) -> None:
        """Triage acts on unlabelled issues, so a before column stays empty."""
        markdown = self.render(([], ["bug"]))
        self.assertIn("| Issue | New labels |", markdown)
        self.assertNotIn("Labels before", markdown)
        self.assertNotIn("Labels after", markdown)
        self.assertIn("[repo#1](https://example.invalid/repo/1) | `bug` |", markdown)
        self.assertNotIn("Labels removed", markdown)

    def test_table_claims_observation_rather_than_authorship(self) -> None:
        """A diff cannot attribute a change, and dry runs write nothing.

        A human relabelling mid-run lands in the same diff, so the
        report must not present these rows as this run's doing.
        """
        markdown = self.render(([], ["bug"]))
        self.assertIn("Observed between the snapshots", markdown)
        self.assertIn("a human editing during the run appears here too", markdown)
        self.assertIn("`apply-result.json` records what this run applied", markdown)
        self.assertNotIn("this run added", markdown)

    def test_retriage_row_excludes_labels_the_run_did_not_add(self) -> None:
        """A renamed column must not present pre-existing labels as new."""
        markdown = self.render((["bug"], ["bug", "CI"]))
        self.assertIn("| [repo#1](https://example.invalid/repo/1) | `CI` |", markdown)
        self.assertNotIn("`bug`", markdown)

    def test_migration_removal_survives_the_dropped_before_column(self) -> None:
        """`enhancement` to `feature` removes a label; keep that observable."""
        markdown = self.render(([], ["documentation"]), (["enhancement"], ["feature"]))
        self.assertIn(
            "| [repo#2](https://example.invalid/repo/2) | `feature` |", markdown
        )
        self.assertIn("Labels removed:", markdown)
        self.assertIn(
            "- [repo#2](https://example.invalid/repo/2): `enhancement`", markdown
        )
        self.assertEqual(markdown.count("Labels removed:"), 1)
        self.assertNotIn("repo#1", markdown.split("Labels removed:")[1])

    def test_removal_only_change_still_reports_the_issue(self) -> None:
        """An issue that only lost labels must not disappear from the report."""
        markdown = self.render((["stale"], []))
        self.assertIn(
            "| [repo#1](https://example.invalid/repo/1) | *(none)* |", markdown
        )
        self.assertIn("- [repo#1](https://example.invalid/repo/1): `stale`", markdown)

    def test_incomplete_and_unchanged_runs_render_no_table(self) -> None:
        """Absent after-state and a genuine no-op stay distinguishable."""
        rows = report.repo_rows(self.load("before.json", ("repo", 1, [])), None)
        incomplete = report.render_markdown(rows, None, dry_run=False)
        self.assertIn("after-snapshot is missing", incomplete)
        self.assertNotIn("New labels", incomplete)
        unchanged = report.render_markdown(rows, [], dry_run=True)
        self.assertIn("The snapshots show no label changes.", unchanged)
        self.assertNotIn("New labels", unchanged)


class ReportCommandTests(unittest.TestCase):
    """The rendered summary and JSON stay consistent through the real CLI."""

    def test_cli_writes_matching_markdown_json_and_step_summary(self) -> None:
        """JSON keeps added and removed labels even though the table splits them."""
        with tempfile.TemporaryDirectory(prefix="triage-report-") as directory:
            root = Path(directory)
            (root / "before.json").write_text(
                snapshot(("repo", 1, []), ("repo", 2, ["enhancement"])),
                encoding="utf-8",
            )
            (root / "after.json").write_text(
                snapshot(("repo", 1, ["bug"]), ("repo", 2, ["feature"])),
                encoding="utf-8",
            )
            summary = root / "step-summary"
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "triage_report.py"),
                    "--before",
                    str(root / "before.json"),
                    "--after",
                    str(root / "after.json"),
                    "--output-md",
                    str(root / "report.md"),
                    "--output-json",
                    str(root / "report.json"),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
                env={"GITHUB_STEP_SUMMARY": str(summary), "PATH": ""},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            markdown = (root / "report.md").read_text(encoding="utf-8")
            self.assertEqual(summary.read_text(encoding="utf-8"), markdown)
            self.assertIn("| Issue | New labels |", markdown)
            self.assertIn(
                "- [repo#2](https://example.invalid/repo/2): `enhancement`", markdown
            )
            payload: dict[str, Any] = json.loads(
                (root / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                [
                    (c["number"], c["labels_added"], c["labels_removed"])
                    for c in payload["changes"]
                ],
                [(1, ["bug"], []), (2, ["feature"], ["enhancement"])],
            )


if __name__ == "__main__":
    unittest.main()
