# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Build the triage run report from before/after issue snapshots.

The triage workflow captures the organisation's open-issue state
before and after the agent session (``gh search issues --json``
output). This script diffs the two snapshots and emits:

- a Markdown report (also appended to ``$GITHUB_STEP_SUMMARY`` when
  that variable is set), showing per-repository before/after counts
  and a per-issue table of the labels the run added, with any
  removals listed beneath it
- a machine-readable JSON report with the same content

The diff is the ground truth for what the run changed: the report
reflects observed label movement, not the agent's own claims.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

UNKNOWN = "unknown"


@dataclass(frozen=True)
class Issue:
    """One open issue from a snapshot, reduced to what the diff needs."""

    repo: str
    number: int
    title: str
    url: str
    labels: frozenset[str]

    @property
    def key(self) -> tuple[str, int]:
        """Identity of the issue across snapshots."""
        return (self.repo, self.number)


def load_snapshot(path: Path) -> dict[tuple[str, int], Issue]:
    """Parse a ``gh search issues --json`` dump into issues by key."""
    raw: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    issues: dict[tuple[str, int], Issue] = {}
    for entry in raw:
        repository: dict[str, Any] = entry.get("repository") or {}
        repo = str(repository.get("name", UNKNOWN))
        issue = Issue(
            repo=repo,
            number=int(entry.get("number", 0)),
            title=str(entry.get("title", "")),
            url=str(entry.get("url", "")),
            labels=frozenset(
                str(label.get("name", ""))
                for label in entry.get("labels", [])
                if label.get("name")
            ),
        )
        issues[issue.key] = issue
    return issues


@dataclass(frozen=True)
class IssueChange:
    """Observed label movement on one issue between snapshots."""

    issue: Issue
    before: frozenset[str]
    after: frozenset[str]

    @property
    def added(self) -> list[str]:
        """Labels present after the run but not before, sorted."""
        return sorted(self.after - self.before)

    @property
    def removed(self) -> list[str]:
        """Labels present before the run but not after, sorted."""
        return sorted(self.before - self.after)


def diff_snapshots(
    before: dict[tuple[str, int], Issue],
    after: dict[tuple[str, int], Issue],
) -> list[IssueChange]:
    """Issues whose label sets differ between the two snapshots."""
    changes: list[IssueChange] = []
    for key, issue in sorted(before.items()):
        later = after.get(key)
        if later is not None and later.labels != issue.labels:
            changes.append(
                IssueChange(issue=later, before=issue.labels, after=later.labels)
            )
    return changes


def repo_rows(
    before: dict[tuple[str, int], Issue],
    after: dict[tuple[str, int], Issue] | None,
) -> list[dict[str, Any]]:
    """Per-repository open/untriaged counts, before and after.

    Without an after-snapshot the after column reports ``None``
    rather than repeating the before value: an incomplete run has
    unknown outcomes, not zero change.
    """
    repos = sorted({issue.repo for issue in before.values()})
    rows: list[dict[str, Any]] = []
    for repo in repos:
        b_issues = [i for i in before.values() if i.repo == repo]
        untriaged_after: int | None = None
        if after is not None:
            a_issues = [i for i in after.values() if i.repo == repo]
            untriaged_after = sum(1 for i in a_issues if not i.labels)
        rows.append(
            {
                "repository": repo,
                "open": len(b_issues),
                "untriaged_before": sum(1 for i in b_issues if not i.labels),
                "untriaged_after": untriaged_after,
            }
        )
    return rows


def _labels_cell(labels: Iterable[str]) -> str:
    """Render a label set for a Markdown table cell."""
    return ", ".join(f"`{name}`" for name in sorted(labels)) or "*(none)*"


def render_markdown(
    rows: list[dict[str, Any]],
    changes: list[IssueChange] | None,
    dry_run: bool,
) -> str:
    """Render the full Markdown report.

    ``changes`` of ``None`` marks an incomplete run: the after
    snapshot never arrived, so the report says so explicitly
    instead of presenting a fabricated zero diff.
    """
    lines = ["# Issues Triage Report", ""]
    mode = "dry-run (no labels applied)" if dry_run else "live"
    lines += [f"- **Mode:** {mode}"]
    if changes is None:
        lines += [
            "- **Issues changed:** unknown — the run produced no"
            " after-snapshot (incomplete run)"
        ]
    else:
        lines += [f"- **Issues changed:** {len(changes)}"]
    lines += ["", "## Untriaged issues by repository", ""]
    lines += [
        "| Repository | Open | Untriaged before | Untriaged after |",
        "| ---------- | ---- | ---------------- | --------------- |",
    ]
    for row in rows:
        after_cell = row["untriaged_after"]
        shown = "unknown" if after_cell is None else after_cell
        lines += [
            f"| {row['repository']} | {row['open']} "
            f"| {row['untriaged_before']} | {shown} |"
        ]
    lines += ["", "## Label changes", ""]
    if changes is None:
        lines += [
            "Unknown: the after-snapshot is missing, so the run"
            " cannot verify label movement. Consult the session"
            " summary and workflow logs."
        ]
    elif changes:
        # The column reports what appeared since the before-snapshot,
        # not the whole post-state: triage normally acts on unlabelled
        # issues, so a "before" column would be empty on every row.
        # Removals are rare but real -- migrating `enhancement` to
        # `feature` drops a label -- so they follow the table instead
        # of vanishing with the column.
        #
        # A diff observes movement; it does not attribute it. A human
        # relabelling during the run shows up here too, and a dry run
        # writes nothing yet can still produce rows. Cross-check
        # apply-result.json before crediting a change to this run.
        lines += [
            "Observed between the snapshots; a human editing during"
            " the run appears here too. `apply-result.json` records"
            " what this run applied.",
            "",
            "| Issue | New labels |",
            "| ----- | ---------- |",
        ]
        for change in changes:
            issue = change.issue
            link = f"[{issue.repo}#{issue.number}]({issue.url})"
            lines += [f"| {link} | {_labels_cell(change.added)} |"]
        removals = [change for change in changes if change.removed]
        if removals:
            lines += ["", "Labels removed:", ""]
            lines += [
                f"- [{change.issue.repo}#{change.issue.number}]"
                f"({change.issue.url}): {_labels_cell(change.removed)}"
                for change in removals
            ]
    else:
        lines += ["The snapshots show no label changes."]
    lines += [""]
    return "\n".join(lines)


def build_json(
    rows: list[dict[str, Any]],
    changes: list[IssueChange] | None,
    dry_run: bool,
) -> dict[str, Any]:
    """Assemble the machine-readable report."""
    return {
        "dry_run": dry_run,
        "complete": changes is not None,
        "issues_changed": None if changes is None else len(changes),
        "repositories": rows,
        "changes": [
            {
                "repository": c.issue.repo,
                "number": c.issue.number,
                "title": c.issue.title,
                "url": c.issue.url,
                "labels_added": c.added,
                "labels_removed": c.removed,
            }
            for c in changes or []
        ],
    }


def main() -> None:
    """Parse arguments, build the report, and write every output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--output-md", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    before = load_snapshot(args.before)
    after = None if args.after is None else load_snapshot(args.after)

    changes = None if after is None else diff_snapshots(before, after)
    rows = repo_rows(before, after)
    markdown = render_markdown(rows, changes, args.dry_run)
    args.output_md.write_text(markdown, encoding="utf-8")
    args.output_json.write_text(
        json.dumps(build_json(rows, changes, args.dry_run), indent=2) + "\n",
        encoding="utf-8",
    )

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(markdown)


if __name__ == "__main__":
    main()
