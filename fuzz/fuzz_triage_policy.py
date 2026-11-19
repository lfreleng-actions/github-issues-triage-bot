# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Fuzz the triage proposal rules from the agent's message to the log.

Contract under test, in the code's and the documents' own words:

- ``triage_policy``: "The rules a triage proposal must satisfy ...
  Everything here treats the agent's output as untrusted input."
- ``extract_proposal`` pulls "the proposal object out of the agent's
  final message"; prompt/triage.md: "End your final message with one
  fenced ``json`` block ... prose around it serves humans and the
  workflow ignores it." Anything else is a ``Rejected``, the refusal
  ``apply_triage.main`` catches by design.
- ``apply_triage.process`` returns "the actions taken, those refused,
  and those the applier could not settle". DESIGN.md section 6 lists
  what an applied action may carry: "existing taxonomy labels, with
  at most two effective taxonomy labels after application"; "``bug``
  and ``feature`` must not coexist"; "Skip labelled issues unless
  ``retriage`` is true"; "Skip the entire issue when it already has a
  Priority"; type checked "against the effective labels"; "Reserve
  ``Urgent`` for humans ... escalation with another grade fails
  validation". ``validate`` bounds each target to "what this run's
  scan actually saw", and ``duplicate_targets`` refuses a target
  "named more than once across the whole proposal".
- ``apply_triage.report`` prints through ``one_line``, which renders
  "untrusted text without control characters or runner commands".

``process`` is the level the contract holds at: it is the caller that
turns ``Rejected`` into a refusal. GitHub is a fixed, fake world, and
the oracle judges every applied action against that world and the
raw proposal, never against the code's own answer. An input that is
itself a JSON document stands for the final block: the harness wraps
it in a message, decodes it with ``json.loads`` on its own, requires
``extract_proposal`` to return exactly that, and judges ``process``
against its own decode rather than the extractor's.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unicodedata
from functools import partial
from importlib import import_module
from pathlib import Path
from typing import Any, cast

from fuzz_support import (
    ContractBreach,
    decode_block,
    emitted,
    fence_shaped,
    identical,
    libfuzzer_arguments,
    use_scripts,
)
from triage_world import (
    BATCH_LIMIT,
    GRADES,
    LABEL_TABLE,
    REPO_LABELS,
    SCOPES,
    Scope,
    fake_github,
    world_issue,
)

use_scripts()
apply_triage = import_module("apply_triage")
policy = import_module("triage_policy")
github = import_module("triage_github")
Rejected = github.Rejected

PROSE = "Examined 3, proposed 1, skipped 2, errors 0."
FINAL = {"proposals": [{"repository": "owner/repo", "issue": 1}]}
FINAL_BLOCK = "\n```json\n" + json.dumps(FINAL) + "\n```\n"
# Final blocks extract_proposal must refuse rather than fall back on
# an earlier one: no proposals, not an object, not JSON, not json.
REFUSED_BLOCKS = (
    "\n```json\n{}\n```\n",
    "\n```json\n[]\n```\n",
    "\n```json\nnot json\n```\n",
    "\n```text\n" + json.dumps(FINAL) + "\n```\n",
)


def extract(text: str) -> object:
    """Return what ``extract_proposal`` returns, or ``None`` for its refusal."""
    try:
        result: object = policy.extract_proposal(text)
    except Rejected:
        return None
    return result


def check_extraction(text: str) -> dict[str, Any] | None:
    """Check ``extract_proposal`` against the prompt's reporting contract."""
    proposal = extract(text)
    if proposal is not None:
        if not isinstance(proposal, dict) or "proposals" not in proposal:
            raise ContractBreach(f"accepted a block without proposals: {proposal!r}")
        if extract(text + "\n" + PROSE) != proposal:
            raise ContractBreach("trailing prose changed the proposal")
    # A final block after balanced fences, or after none at all, is
    # the one the workflow must read, and an unusable one is refused.
    if proposal is not None or not fence_shaped(text):
        if extract(text + FINAL_BLOCK) != FINAL:
            raise ContractBreach("the final json block did not win")
        for refused in REFUSED_BLOCKS:
            if extract(text + refused) is not None:
                raise ContractBreach(f"accepted despite a final {refused!r}")
    return cast("dict[str, Any] | None", proposal)


def proposed_target(item: object) -> tuple[str, int] | None:
    """The key a well-formed raw item names, or ``None``."""
    if not isinstance(item, dict):
        return None
    entry = cast("dict[str, Any]", item)
    repo, number = entry.get("repository"), entry.get("issue")
    if isinstance(repo, str) and type(number) is int:
        return repo.lower(), number
    return None


def source_item(items: list[Any], action: dict[str, Any]) -> dict[str, Any]:
    """Find the raw item an applied action came from.

    ``True == 1`` and ``1.0 == 1``, so the issue must be an ``int``
    as well as equal, or a malformed neighbour would stand in.
    """
    for item in items:
        if not isinstance(item, dict):
            continue
        entry = cast("dict[str, Any]", item)
        number = entry.get("issue")
        if (
            entry.get("repository") == action["repository"]
            and type(number) is int
            and number == action["issue"]
        ):
            return entry
    raise ContractBreach(f"applied an action nobody proposed: {action!r}")


def check_type(chosen: Any, effective: set[str], scope: Scope) -> None:
    """Type against the prompt's table, one label at a time."""
    if chosen not in scope.types:
        raise ContractBreach(f"applied a type the organisation lacks: {chosen!r}")
    allowed = {"bug": "Bug", "feature": "Feature"}
    if chosen in ("Bug", "Feature"):
        if not any(allowed.get(name) == chosen for name in effective):
            raise ContractBreach(f"type {chosen} contradicts {sorted(effective)}")
    elif chosen == "Task":
        if not effective - {"bug", "feature"}:
            raise ContractBreach(f"type Task contradicts {sorted(effective)}")
    else:
        raise ContractBreach(f"the label table never permits type {chosen!r}")


def raw_flag(item: dict[str, Any], key: str) -> bool:
    """A flag as ``validate`` reads it: absent is false, else a boolean.

    ``validate`` refuses a flag that is present but not a boolean, so a
    proposal carrying one must never be applied, whatever the action.
    """
    value = item.get(key, False)
    if type(value) is not bool:
        raise ContractBreach(f"applied a non-boolean {key}: {value!r}")
    return value


def check_action(action: dict[str, Any], item: dict[str, Any], scope: Scope) -> None:
    """Judge one applied action against the world and its raw item."""
    repo, number = action["repository"], action["issue"]
    if type(number) is not int or number < 1:
        raise ContractBreach(f"applied a malformed issue number: {number!r}")
    owner, _, name = str(repo).partition("/")
    if owner.lower() != scope.org.lower() or name.lower() in scope.excluded:
        raise ContractBreach(f"applied outside the run's scope: {repo}")
    if scope.only is not None and name.lower() != scope.only.lower():
        raise ContractBreach(f"applied outside the restricted repository: {repo}")
    issue = world_issue(str(repo), number)
    if issue.pull_request or issue.state != "open" or issue.priority is not None:
        raise ContractBreach(f"applied to an ineligible target: {repo}#{number}")
    if issue.labels and not scope.retriage:
        raise ContractBreach(f"retriaged a labelled issue: {repo}#{number}")

    raw_labels: Any = action["labels"]
    if raw_labels != item.get("labels"):
        raise ContractBreach(f"applied labels nobody proposed: {raw_labels!r}")
    # check_labels: "labels must be a list of strings". A dictionary
    # would pass the checks below, which see only its keys.
    if not isinstance(raw_labels, list) or not all(
        isinstance(label, str) for label in cast("list[Any]", raw_labels)
    ):
        raise ContractBreach(f"applied labels that are not strings: {raw_labels!r}")
    labels = cast("list[str]", raw_labels)
    known = {label.lower() for label in REPO_LABELS[str(repo).lower()]}
    for label in labels:
        if label not in LABEL_TABLE or label.lower() not in known:
            raise ContractBreach(f"applied a label outside the vocabulary: {label!r}")
    migrate = action["migrate_enhancement"]
    if migrate is not raw_flag(item, "migrate_enhancement"):
        raise ContractBreach("the migration flag departs from the proposal")
    if migrate and (
        "enhancement" not in {label.lower() for label in issue.labels}
        or "feature" not in known
    ):
        raise ContractBreach(f"migrated an issue that cannot migrate: {repo}#{number}")
    if not labels and not migrate:
        raise ContractBreach("applied a proposal with no labels")
    canonical = {label.lower(): label for label in LABEL_TABLE}
    effective = {canonical[x.lower()] for x in issue.labels if x.lower() in canonical}
    effective |= set(labels) | ({"feature"} if migrate else set())
    if len(effective) > 2 or {"bug", "feature"} <= effective:
        raise ContractBreach(f"effective labels break the ceiling: {effective}")

    if "priority" not in item or "type" not in item:
        raise ContractBreach("applied a proposal missing priority or type")
    # validate refuses Urgent and unknown grades before it drops a
    # Priority the organisation cannot store, so the raw grade must be
    # valid whatever this scope's fields are.
    if item["priority"] is not None and item["priority"] not in GRADES:
        raise ContractBreach(f"applied an invalid priority: {item['priority']!r}")
    grade = action["priority"]
    if grade is not None and (
        grade != item["priority"]
        or grade not in GRADES
        or scope.priorities is None
        or grade not in scope.priorities
    ):
        raise ContractBreach(f"applied an unavailable priority: {grade!r}")
    if grade is None and item["priority"] is not None and scope.priorities is not None:
        raise ContractBreach("dropped a priority the organisation can store")
    # validate refuses a non-string type before it drops a type the
    # organisation cannot store, so the raw type must be a string or
    # null whatever this scope's types are.
    if item["type"] is not None and not isinstance(item["type"], str):
        raise ContractBreach(f"applied an invalid type: {item['type']!r}")
    chosen = action["type"]
    if chosen is not None:
        if chosen != item["type"]:
            raise ContractBreach(f"applied a type nobody proposed: {chosen!r}")
        check_type(chosen, effective, scope)
    elif item["type"] is not None and scope.types:
        raise ContractBreach("dropped a type the organisation defines")
    if action["escalate"] is not raw_flag(item, "escalate"):
        raise ContractBreach("the escalation flag departs from the proposal")
    if action["escalate"] and item["priority"] != "High":
        raise ContractBreach("escalated without a High proposal")


def check_outcome(
    items: list[Any],
    scope: Scope,
    applied: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    failed: list[dict[str, Any]],
) -> None:
    """Judge what ``process`` did with one proposal list."""
    if failed:
        raise ContractBreach(f"the fake world cannot fail, yet: {failed!r}")
    if len(applied) + len(rejected) != len(items):
        raise ContractBreach("an item was neither applied nor rejected")
    targets = [proposed_target(item) for item in items]
    for action in applied:
        key = (str(action["repository"]).lower(), action["issue"])
        if targets.count(key) > 1:
            raise ContractBreach(f"applied a target proposed twice: {key}")
        check_action(action, source_item(items, action), scope)


def check_report(
    output: str, applied: list[dict[str, Any]], rejected: list[dict[str, Any]]
) -> None:
    """Every report line stays one line, with no runner command in it."""
    expected = 3 + len(rejected)
    expected += sum(bool(a["escalate"]) + len(a["dropped"]) for a in applied)
    lines = output.split("\n")
    if lines[-1] != "" or len(lines) - 1 != expected:
        raise ContractBreach(f"report wrote {len(lines) - 1} lines, not {expected}")
    for line in lines[:-1]:
        if "::" in line or "##[" in line:
            raise ContractBreach(f"report line carries a runner command: {line!r}")
        if any(unicodedata.category(char) == "Cc" for char in line):
            raise ContractBreach(f"report line carries a control character: {line!r}")


def check(data: bytes) -> None:
    """Run one agent message through extraction, validation and the report."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        # apply_triage.main refuses an undecodable proposal file.
        return
    check_extraction(text)
    decoded = decode_block(text)
    if decoded is None:
        return
    wrapped = PROSE + "\n```json\n" + text + "\n```\n"
    raw = decoded["proposals"]
    if not isinstance(raw, list) or len(cast("list[Any]", raw)) > BATCH_LIMIT:
        if not identical(extract(wrapped), decoded):
            raise ContractBreach("the extractor altered the final json block")
        return
    items = cast("list[Any]", raw)
    for scope in SCOPES:
        # process gets the extractor's answer, as in production, fresh
        # for each scope; the oracle judges it against its own decode,
        # which nothing process or the extractor does can rewrite.
        fresh = extract(wrapped)
        if not identical(fresh, decoded):
            raise ContractBreach("the extractor altered the final json block")
        own = cast("dict[str, Any]", fresh)["proposals"]
        with fake_github():
            applied, rejected, failed = apply_triage.process(own, scope.context(), True)
        check_outcome(items, scope, applied, rejected, failed)
        counts = {
            "proposed": len(items),
            "applied": len(applied),
            "rejected": len(rejected),
            "failed": len(failed),
        }
        output = emitted(
            partial(apply_triage.report, applied, rejected, failed, counts, True)
        )
        check_report(output, applied, rejected)


def block(*proposals: dict[str, Any]) -> bytes:
    """A final json block's contents, which the harness wraps itself."""
    return json.dumps({"proposals": list(proposals)}, indent=2).encode()


def message(*proposals: dict[str, Any], prose: str = "Summary.\n") -> bytes:
    """Wrap proposals in a final message the way the prompt asks."""
    return f"{prose}\n```json\n{block(*proposals).decode()}\n```\n".encode()


GOOD = {
    "repository": "owner/repo",
    "issue": 1,
    "labels": ["bug"],
    "priority": "High",
    "type": "Bug",
    "migrate_enhancement": False,
    "escalate": True,
    "rationale": "Stack trace and reproduction steps",
}
SEEDS: tuple[bytes, ...] = (
    block(GOOD),
    block(),
    block(
        {**GOOD, "issue": 4, "labels": [], "migrate_enhancement": True},
        {**GOOD, "issue": 5, "labels": ["code-quality"], "type": "Task"},
        {**GOOD, "issue": 7, "labels": ["chore"], "escalate": False},
        {**GOOD, "repository": "owner/sparse", "issue": 2, "labels": []}
        | {"migrate_enhancement": True},
        {**GOOD, "repository": "OWNER/Sparse", "labels": ["Bug"]},
        {**GOOD, "issue": 6, "priority": None, "escalate": False},
    ),
    block(
        {**GOOD, "issue": True},
        {**GOOD, "issue": 0},
        {**GOOD, "issue": [1]},
        {**GOOD, "repository": "owner/../repo"},
        {**GOOD, "repository": "other/repo"},
        {**GOOD, "repository": "owner/skipme"},
        {**GOOD, "issue": 8},
        {**GOOD, "issue": 2},
        {**GOOD, "issue": 3},
    ),
    block(GOOD, {**GOOD, "repository": "Owner/Repo"}, {**GOOD, "issue": 1.0}),
    block({**GOOD, "issue": True, "escalate": False}, GOOD),
    # Fields escaped one by one once joined into "##[" and "::".
    block({**GOOD, "repository": "owner/rep#", "issue": "[1]"}),
    block({**GOOD, "issue": "1:"}),
    block(
        {**GOOD, "labels": ["bug", "feature"]},
        {**GOOD, "labels": ["wontfix"]},
        {**GOOD, "labels": ["bug", "chore", "CI"]},
        {**GOOD, "type": "Feature"},
        {**GOOD, "type": "Epic"},
        {**GOOD, "priority": "Urgent"},
        {**GOOD, "issue": 7, "priority": "Urgent", "escalate": False},
        {**GOOD, "priority": "Low"},
        {**GOOD, "priority": "Medium"},
        {k: v for k, v in GOOD.items() if k != "type"},
        {**GOOD, "labels": None},
        {**GOOD, "labels": {"bug": "not a list"}},
        {**GOOD, "escalate": "yes"},
        {**GOOD, "issue": 7, "labels": ["chore"], "escalate": None},
        {**GOOD, "issue": 4, "labels": [], "migrate_enhancement": "yes"},
        {**GOOD, "issue": 5, "labels": ["code-quality"], "type": 1},
    ),
    block(
        {**GOOD, "rationale": "::error::forged\n##[group]x\x85\x1b[31m"},
        {**GOOD, "issue": 2, "repository": "owner/repo\n::warning::x"},
    ),
    # Fenced messages exercise the extractor's choice of final block.
    message(GOOD),
    message(GOOD, prose="```json\n" + json.dumps(FINAL) + "\n```\nThe example above."),
    # A JSON escape decodes to a lone surrogate, which the runner's
    # UTF-8 stdout cannot encode.
    b'{"proposals": [{"repository": "owner/repo", "issue": 1,'
    b' "labels": ["\\ud800"], "priority": null, "type": null}]}',
    block(*[{**GOOD, "issue": n % 9, "rationale": "x" * 40} for n in range(40)]),
    b'~~~json\n{"proposals": []}\n~~~\n````\n```json\n{}\n````\n',
    # An unused field nested deeper than recursion here would follow.
    b'{"proposals": [{"repository": "owner/repo", "issue": 1,'
    b' "labels": ["bug"], "priority": "High", "type": "Bug", "escalate": true,'
    b' "rationale": ' + b"[" * 600 + b"]" * 600 + b"}]}",
)


def main() -> None:
    """Fuzz ``check``, seeded from ``SEEDS``."""
    import atheris  # pyright: ignore[reportMissingModuleSource]

    arguments = libfuzzer_arguments(
        sys.argv, SEEDS, Path(tempfile.mkdtemp(prefix="fuzz-triage-policy-"))
    )
    # The bundled stubs omit instrument_all; atheris exports it.
    atheris.instrument_all()  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
    atheris.Setup(arguments, check)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
