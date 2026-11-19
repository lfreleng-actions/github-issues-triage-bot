# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The rules a triage proposal must satisfy.

Kept apart from the GitHub calls in ``triage_github`` and the
orchestration in ``apply_triage`` so the policy reads as policy:
what may be proposed, against which run, and on whose authority.

Everything here treats the agent's output as untrusted input.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from triage_github import (
    GitHubError,
    Rejected,
    existing_priority,
    load_field_options,
    load_issue_types,
    read_issue,
    repo_labels,
)

PRIORITIES = ("High", "Medium", "Low")
HUMAN_ONLY = ("Urgent",)
# The vocabulary triage may use, mirroring the table in
# prompt/triage.md. Repository membership is too weak a test on
# its own: every repository carries labels this pipeline has no
# business applying, so an injected proposal naming `wontfix` or
# `duplicate` would clear a check that asks whether a label
# exists rather than whether it belongs. Keep the two in step;
# they are a pair.
#
# The retired `enhancement` is absent by design. apply() removes
# it and then adds the proposed set, so a proposal naming it in
# both would put it straight back and report a migration that
# did nothing.
TAXONOMY = frozenset(
    {
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
    }
)
# Separates "the agent left this out" from "the agent said null".
MISSING = object()
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$")
MAX_LABELS = 2
MAX_BATCH_ISSUES = 100
# Track all fences, not just completed JSON blocks: otherwise a
# truncated or mislabelled final answer falls back to the prompt's
# worked example. Opening and closing delimiters must match. The
# quantifiers are possessive because the summary is untrusted: with
# greedy ones, a long fence run followed by a lone carriage return
# makes the run and the info string trade characters on every failed
# match, costing time quadratic in the line. Giving characters back
# never lets such a line match, so the possessive form accepts the
# same lines and captures the same groups in one pass.
FENCE_RE = re.compile(r"^[ \t]*+(`{3,}+|~{3,}+)([^\r\n]*+)\r?$", re.MULTILINE)
CANONICAL_LABELS = {name.lower(): name for name in TAXONOMY}


@dataclass
class Context:
    """Everything a proposal is checked against.

    Gathered once so validation takes the proposal and the run,
    rather than a long tail of positional arguments that invite
    being passed in the wrong order.
    """

    org: str
    only: str | None
    excluded: set[str]
    retriage: bool
    fields: dict[str, dict[str, int]]
    types: set[str]
    snapshot: set[tuple[str, int]]
    label_cache: dict[str, set[str]] = field(default_factory=dict)


def extract_proposal(text: str) -> dict[str, Any]:
    """Pull the proposal object out of the agent's final message."""
    opening: re.Match[str] | None = None
    block: str | None = None
    for fence in FENCE_RE.finditer(text):
        if opening is None:
            opening = fence
            block = None
        elif (
            fence[1][0] == opening[1][0]
            and len(fence[1]) >= len(opening[1])
            and not fence[2].strip()
        ):
            if opening[2].strip() == "json":
                block = text[opening.end() : fence.start()]
            opening = None
    if opening is not None:
        raise Rejected("the final proposal fence is unterminated")
    if block is None:
        raise Rejected("the final fenced block must be json")
    try:
        parsed: Any = json.loads(block)
    except (ValueError, RecursionError) as exc:
        raise Rejected(f"the final proposal block is malformed: {exc}") from exc
    if not isinstance(parsed, dict):
        raise Rejected("the final proposal block is not an object")
    if "proposals" not in parsed:
        raise Rejected("the final json block carries no 'proposals' key")
    return cast("dict[str, Any]", parsed)


def load_exclusions(path: str | None) -> set[str]:
    """Read the excluded repository names, lowercased."""
    if not path:
        return set()
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise GitHubError(f"could not read exclusions: {exc}") from exc
    return {line.strip().lower() for line in lines if line.strip()}


def load_snapshot(path: Path) -> set[tuple[str, int]]:
    """The set of targets the run's scan actually saw.

    Membership answers "did this run's scan look at this issue",
    which bounds an untrusted proposal to the population the scan
    covered rather than every issue in the organisation. What each
    issue looked like at scan time is deliberately not kept: by
    the time a proposal arrives that picture is up to twenty
    minutes old, so validation reads the live issue instead.
    """
    entries: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    index: set[tuple[str, int]] = set()
    for entry in entries:
        repository: dict[str, Any] = entry.get("repository") or {}
        full_name = str(repository.get("nameWithOwner", ""))
        index.add((full_name.lower(), int(entry["number"])))
    return index


def check_scope(repo: str, ctx: Context) -> None:
    """Refuse targets outside the run's declared scope."""
    if not REPO_RE.fullmatch(repo):
        raise Rejected(f"repository fails validation: {repo}")
    owner, _, name = repo.partition("/")
    if owner.lower() != ctx.org.lower():
        raise Rejected(f"repository outside triage scope ({ctx.org}): {repo}")
    if ctx.only and name.lower() != ctx.only.lower():
        raise Rejected(f"run restricted to {ctx.org}/{ctx.only}: {repo}")
    if name.lower() in ctx.excluded:
        raise Rejected(f"repository is excluded from triage: {repo}")


def require(item: dict[str, Any], key: str, hint: str) -> Any:
    """Read a field the contract asks for on every proposal.

    Absent and empty are different answers. ``null`` for priority
    or type is the agent declining to guess, and ``[]`` for
    labels is a migration supplying its own; an absent key is
    neither, because it means the output departed from the
    schema. Treating the two alike would let malformed output
    apply labels while classifying nothing, and count as a
    success. The hint says which answer the field wanted.
    """
    value: Any = item.get(key, MISSING)
    if value is MISSING:
        raise Rejected(f"{key} is absent; {hint}")
    return value


def check_labels(
    repo: str, item: dict[str, Any], ctx: Context, carried: frozenset[str]
) -> tuple[list[str], list[str]]:
    """Validate the proposed labels against the repository's own.

    Returns the labels to apply and the set the issue ends up
    carrying. The two differ when a migration supplies `feature`,
    and when a retriage run adds to labels already there:
    `--add-label` adds, so the ceiling and the consistency checks
    have to count what the issue finishes with, not what this
    proposal contributes.

    An empty list is the migration case, where `feature` arrives
    from the migration itself. Absent or `null` is neither that
    nor a set of labels: it is output that left the schema, and
    reading it as "no labels" would let a malformed proposal
    migrate a label and report success.
    """
    raw: Any = require(item, "labels", "send [] where a migration supplies them")
    if not isinstance(raw, list) or not all(
        isinstance(name, str) for name in cast("list[Any]", raw)
    ):
        raise Rejected(f"labels must be a list of strings: {raw!r}")
    labels = cast("list[str]", raw)
    if not labels and item.get("migrate_enhancement") is not True:
        raise Rejected("propose at least one label")
    # What the issue ends up with: whatever taxonomy labels it
    # already carries, plus these, plus the `feature` a migration
    # adds without the proposal naming it. Labels outside the
    # taxonomy are somebody else's and do not count.
    effective = [name for name in carried if name in TAXONOMY]
    for name in labels:
        if name not in effective:
            effective.append(name)
    if item.get("migrate_enhancement") is True and "feature" not in effective:
        effective.append("feature")
    if len(effective) > MAX_LABELS:
        raise Rejected(f"at most {MAX_LABELS} labels per issue")
    # Taxonomy first, so a proposal that cannot pass costs no
    # round trip to list the repository's labels.
    for name in labels:
        if name not in TAXONOMY:
            raise Rejected(f"label sits outside the triage taxonomy: {name}")
    known = {name.lower() for name in repo_labels(repo, ctx.label_cache)}
    for name in labels:
        if name.lower() not in known:
            raise Rejected(f"label does not exist in {repo}: {name}")
    return labels, effective


def permitted_types(labels: list[str]) -> set[str]:
    """The types the prompt's table allows for a label set.

    A set rather than one value, because a proposal may carry two
    labels and the table maps one at a time: `bug` beside
    `code-quality` reads as either `Bug` or `Task`. What it rules
    out is the mismatch -- `bug` typed `Feature` -- which is how
    an injected proposal would misfile an issue while looking
    well-formed.
    """
    allowed: set[str] = set()
    if "bug" in labels:
        allowed.add("Bug")
    if "feature" in labels:
        allowed.add("Feature")
    if any(name not in ("bug", "feature") for name in labels):
        allowed.add("Task")
    return allowed


def duplicate_targets(items: list[Any]) -> set[tuple[str, int]]:
    """Targets named more than once across the whole proposal.

    The label ceiling counts per proposal object, so repeating a
    target would let each entry add its own two labels and
    overwrite the type again. Detected before any write, so no
    member of a duplicated group is half-applied.
    """
    seen: dict[tuple[str, int], int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        entry = cast("dict[str, Any]", item)
        repo = entry.get("repository")
        number = entry.get("issue")
        # Booleans are excluded for the reason validate() gives:
        # True hashes as 1, so `issue: true` beside the genuine
        # issue 1 would mark both a duplicate and lose the valid
        # one to a malformed neighbour.
        if (
            isinstance(repo, str)
            and isinstance(number, int)
            and not isinstance(number, bool)
        ):
            key = (repo.lower(), number)
            seen[key] = seen.get(key, 0) + 1
    return {key for key, count in seen.items() if count > 1}


def validate(item: dict[str, Any], ctx: Context) -> dict[str, Any]:
    """Check one proposal, returning the actions it authorises."""
    repo = str(item.get("repository", ""))
    number = item.get("issue")
    # bool is a subclass of int, so a bare isinstance check reads
    # JSON `true` as issue 1 and `false` as issue 0. A number
    # below 1 is malformed rather than merely absent, and saying
    # so here keeps it a rejection instead of a failed lookup
    # that fails the whole run.
    if isinstance(number, bool) or not isinstance(number, int):
        raise Rejected(f"issue number is not an integer: {number!r}")
    if number < 1:
        raise Rejected(f"issue number is not positive: {number}")

    check_scope(repo, ctx)

    # Bound the proposal to what this run's scan actually saw.
    # Without this, an agent could name any issue in an allowed
    # repository, including ones the scan deliberately passed over.
    key = (repo.lower(), number)
    if key not in ctx.snapshot:
        raise Rejected(f"{repo}#{number} is absent from this run's snapshot")

    # The snapshot bounds which issues may be named; it does not
    # describe any of them now. A session runs for up to twenty
    # minutes, during which a human can close an issue or label it
    # themselves, so eligibility is decided on a fresh read -- as
    # the priority guard below already does.
    live = read_issue(repo, number)
    if live.is_pull_request:
        raise Rejected(f"target is a pull request, not an issue: {repo}#{number}")
    if live.state != "open":
        raise Rejected(f"{repo}#{number} is no longer open; leaving it")
    if live.labels and not ctx.retriage:
        raise Rejected(f"{repo}#{number} already carries labels; not retriaging")

    # GitHub treats label names case-insensitively, including labels
    # applied by humans. Count those under their taxonomy spelling.
    carried = frozenset(
        CANONICAL_LABELS.get(name.lower(), name.lower()) for name in live.labels
    )
    labels, effective = check_labels(repo, item, ctx, carried)
    if "bug" in effective and "feature" in effective:
        raise Rejected("bug and feature contradict each other")

    # Checked whatever the agent proposed, including nothing: a
    # human-set priority takes the whole issue out of scope, so an
    # omitted priority must not become a way to relabel it.
    current = existing_priority(repo, number)
    if current is not None:
        raise Rejected(f"priority already set to {current}; leaving it")

    # Unavailable fields are a configuration fact, not a bad
    # proposal: a user-owned target has no organisation fields,
    # and an App-less dry run cannot read them. Rejecting the
    # whole proposal would discard the label work too, which is
    # everything the pipeline did before issue fields existed. So
    # drop what cannot be written and record why.
    dropped: list[str] = []

    priority = require(item, "priority", "send null where undecided")
    # Kept before the drop below, because an escalation stays an
    # escalation even where the organisation exposes no Priority
    # field to write it to.
    proposed = priority
    if priority is not None:
        if not isinstance(priority, str):
            raise Rejected(f"priority must be a string: {priority!r}")
        if priority in HUMAN_ONLY:
            raise Rejected(
                f"{priority} is reserved for humans; propose High and set "
                "escalate to flag it"
            )
        if priority not in PRIORITIES:
            raise Rejected(f"unknown priority: {priority!r}")
        if "Priority" not in ctx.fields:
            dropped.append("priority: no readable organisation Priority field")
            priority = None
        elif priority not in ctx.fields["Priority"]:
            raise Rejected(f"organisation defines no Priority option: {priority}")

    issue_type = require(item, "type", "send null where undecided")
    if issue_type is not None:
        if not isinstance(issue_type, str):
            raise Rejected(f"type must be a string: {issue_type!r}")
        if not ctx.types:
            dropped.append("type: no readable organisation issue types")
            issue_type = None
        elif issue_type not in ctx.types:
            raise Rejected(f"organisation defines no issue type: {issue_type!r}")
        elif issue_type not in permitted_types(effective):
            raise Rejected(
                f"type {issue_type} contradicts the labels {sorted(effective)}"
            )

    migrate = item.get("migrate_enhancement", False)
    if not isinstance(migrate, bool):
        raise Rejected(f"migrate_enhancement must be a boolean: {migrate!r}")
    if migrate:
        if "enhancement" not in carried:
            raise Rejected(f"{repo}#{number} does not carry 'enhancement'")
        if "feature" not in {
            name.lower() for name in repo_labels(repo, ctx.label_cache)
        }:
            raise Rejected(f"{repo} has no 'feature' label to migrate to")

    escalate = item.get("escalate", False)
    if not isinstance(escalate, bool):
        raise Rejected(f"escalate must be a boolean: {escalate!r}")
    # The contract pairs escalation with a High proposal. Letting
    # a Low or undecided one carry the flag would put "may warrant
    # Urgent" in front of a human on the say-so of an agent that
    # graded the issue as neither.
    if escalate and proposed != "High":
        raise Rejected(f"escalate needs a High proposal, not {proposed!r}")

    return {
        "repository": repo,
        "issue": number,
        "labels": labels,
        "priority": priority,
        "type": issue_type,
        "migrate_enhancement": migrate,
        "escalate": escalate,
        "dropped": dropped,
        "rationale": str(item.get("rationale", "")),
    }


def build_context(
    snapshot: set[tuple[str, int]], *, allow_unavailable: bool = False
) -> Context:
    """Assemble configuration, tolerating known unavailability only for dry runs."""
    org = os.environ.get("TRIAGE_ORG", "")
    if not org:
        sys.exit("TRIAGE_ORG is not set")
    return Context(
        org=org,
        only=os.environ.get("TRIAGE_REPOSITORY") or None,
        excluded=load_exclusions(os.environ.get("TRIAGE_EXCLUDE_FILE")),
        retriage=os.environ.get("TRIAGE_RETRIAGE", "") == "true",
        fields=load_field_options(org, allow_unavailable=allow_unavailable),
        types=load_issue_types(org, allow_unavailable=allow_unavailable),
        snapshot=snapshot,
    )
