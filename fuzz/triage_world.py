# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The fixed, fake GitHub the triage policy harness checks against.

Every live read the triage checks make lands here, and a read of a
target outside the scan's snapshot, or any call that would reach the
network, is a contract breach: ``validate`` bounds each target to
"what this run's scan actually saw".
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import import_module
from typing import Any

from fuzz_support import ContractBreach, use_scripts

use_scripts()
policy = import_module("triage_policy")
github = import_module("triage_github")
LiveIssue = github.LiveIssue

# DESIGN.md section 6, restated so the oracle does not read the
# policy module's own copy.
LABEL_TABLE = (
    "bug",
    "feature",
    "documentation",
    "code-quality",
    "CI",
    "chore",
    "refactor",
    "breaking-change",
    "performance",
    "question",
)
GRADES = ("High", "Medium", "Low")
BATCH_LIMIT = 100


@dataclass(frozen=True)
class Issue:
    """One issue in the fake world, as a live read would see it."""

    pull_request: bool
    state: str
    labels: tuple[str, ...]
    priority: str | None


REPO_LABELS: dict[str, frozenset[str]] = {
    "owner/repo": frozenset({*LABEL_TABLE, "enhancement", "wontfix", "duplicate"}),
    "owner/sparse": frozenset({"Bug", "documentation", "wontfix"}),
    "owner/skipme": frozenset(LABEL_TABLE),
    "other/repo": frozenset(LABEL_TABLE),
}
WORLD: dict[tuple[str, int], Issue] = {
    ("owner/repo", 1): Issue(False, "open", (), None),
    ("owner/repo", 2): Issue(False, "closed", (), None),
    ("owner/repo", 3): Issue(True, "open", (), None),
    ("owner/repo", 4): Issue(False, "open", ("enhancement",), None),
    ("owner/repo", 5): Issue(False, "open", ("BUG", "wontfix"), None),
    ("owner/repo", 6): Issue(False, "open", (), "High"),
    ("owner/repo", 7): Issue(False, "open", ("documentation", "ci"), None),
    ("owner/repo", 8): Issue(False, "open", (), None),
    ("owner/sparse", 1): Issue(False, "open", (), None),
    ("owner/sparse", 2): Issue(False, "open", ("Enhancement",), None),
    ("owner/skipme", 1): Issue(False, "open", (), None),
    ("other/repo", 1): Issue(False, "open", (), None),
}
# owner/repo#8 exists but the scan never saw it.
SNAPSHOT = frozenset(key for key in WORLD if key != ("owner/repo", 8))


@dataclass(frozen=True)
class Scope:
    """One run's configuration, as the oracle reads it."""

    org: str
    only: str | None
    excluded: frozenset[str]
    retriage: bool
    priorities: frozenset[str] | None
    types: frozenset[str]

    def context(self) -> Any:
        """Build a fresh ``Context``, with an empty label cache."""
        fields: dict[str, dict[str, int]] = {}
        if self.priorities is not None:
            options = {name: index for index, name in enumerate(self.priorities)}
            fields["Priority"] = {github.FIELD_ID_KEY: 99, **options}
        return policy.Context(
            self.org,
            self.only,
            set(self.excluded),
            self.retriage,
            fields,
            set(self.types),
            set(SNAPSHOT),
        )


SCOPES = (
    Scope(
        "owner",
        None,
        frozenset({"skipme"}),
        False,
        frozenset({"High", "Medium"}),
        frozenset({"Bug", "Feature", "Task", "Epic"}),
    ),
    Scope("OWNER", "repo", frozenset(), True, None, frozenset()),
)


def world_issue(repo: str, number: int) -> Issue:
    """Look a target up, refusing one the run had no business reading."""
    key = (repo.lower(), number)
    if key not in SNAPSHOT:
        raise ContractBreach(f"live read of a target outside the snapshot: {key}")
    return WORLD[key]


def fake_read_issue(repo: str, number: int) -> Any:
    """Stand in for ``triage_github.read_issue``."""
    issue = world_issue(repo, number)
    return LiveIssue(issue.pull_request, issue.state, frozenset(issue.labels))


def fake_repo_labels(repo: str, cache: dict[str, set[str]]) -> set[str]:
    """Stand in for ``triage_github.repo_labels``."""
    return set(REPO_LABELS.get(repo.lower(), frozenset()))


def fake_existing_priority(repo: str, number: int) -> str | None:
    """Stand in for ``triage_github.existing_priority``."""
    return world_issue(repo, number).priority


def no_network(*_: object) -> Any:
    """Refuse any call that would reach GitHub."""
    raise ContractBreach("the checks tried to call GitHub")


@contextmanager
def fake_github() -> Generator[None]:
    """Swap the fake world in for GitHub while the checks run."""
    swaps = (
        (policy, "read_issue", fake_read_issue),
        (policy, "repo_labels", fake_repo_labels),
        (policy, "existing_priority", fake_existing_priority),
        (github, "run_gh", no_network),
        (github, "api_list", no_network),
    )
    saved = [(module, name, getattr(module, name)) for module, name, _ in swaps]
    for module, name, replacement in swaps:
        setattr(module, name, replacement)
    try:
        yield
    finally:
        for module, name, original in saved:
            setattr(module, name, original)
