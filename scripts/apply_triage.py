# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Validate an agent's triage proposal and apply it.

The agent proposes; this applies. Keeping the two apart means the
repository credential a session holds is read-only, so the
containment weaknesses of any particular harness stop mattering
for writes (see DESIGN.md section 12.7).

The rules live in ``triage_policy``; the GitHub calls in
``triage_github``. This module decides what to do with each
outcome, and how the run reports itself.

Usage:
    apply_triage.py --proposal <file> --snapshot <before.json>
                    --output-json <file> [--dry-run]

Environment:
    GH_TOKEN             token for the gh CLI
    TRIAGE_ORG           (required) owner every target must match
    TRIAGE_REPOSITORY    restrict targets to this repository name
    TRIAGE_EXCLUDE_FILE  file of excluded repository names
    TRIAGE_RETRIAGE      'true' when labelled issues are in scope
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, cast

from triage_github import GitHubError, Rejected, apply
from triage_policy import (
    MAX_BATCH_ISSUES,
    Context,
    build_context,
    duplicate_targets,
    extract_proposal,
    load_snapshot,
    validate,
)

# Control characters, the line breaks among them.
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def one_line(value: object) -> str:
    """Render untrusted text without control characters or runner commands.

    The legacy ``##[command]`` syntax is recognised even after a
    log prefix. Escape it and the modern ``::`` syntax as well as
    folding control characters; keep the original in JSON evidence.
    """
    return (
        CONTROL_RE.sub(" ", str(value))
        .replace("::", "%3A%3A")
        .replace("##[", "%23%23[")
    )


def process(
    items: list[Any], ctx: Context, dry_run: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Check each proposal and, unless dry-running, apply it.

    Returns the actions taken, those refused, and those the
    applier could not settle — three outcomes a caller must not
    conflate. A refusal is this code working. The third is it
    unable to do its job, which fails the step.
    """
    applied: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    duplicates = duplicate_targets(items)

    for item in items:
        if not isinstance(item, dict):
            rejected.append({"item": repr(item), "reason": "not an object"})
            continue
        entry = cast("dict[str, Any]", item)
        number = entry.get("issue")
        where = {
            "repository": entry.get("repository"),
            "issue": number,
        }
        # Only a well-shaped target can key the duplicate set.
        # An unhashable one such as [] would raise here, killing
        # the run before validate() could reject it and before
        # apply-result.json existed to say why.
        if isinstance(number, int) and not isinstance(number, bool):
            key = (str(entry.get("repository", "")).lower(), number)
            if key in duplicates:
                rejected.append({**where, "reason": "target proposed more than once"})
                continue
        try:
            action = validate(entry, ctx)
        except Rejected as exc:
            rejected.append({**where, "reason": str(exc)})
            continue
        except GitHubError as exc:
            # Not a rejection: the checks never reached a verdict.
            # Counting an unreachable API as "proposal refused"
            # would let a transient outage turn a live run into a
            # green no-op.
            failed.append({**where, "reason": f"could not verify: {exc}"})
            continue
        if not dry_run:
            try:
                apply(action, ctx.fields)
            except (GitHubError, Rejected) as exc:
                # A write that failed part-way leaves the issue in
                # an unknown state, so it is recorded here rather
                # than counting as a rejection the run can shrug
                # off.
                failed.append({**where, "reason": str(exc)})
                continue
        applied.append(action)

    return applied, rejected, failed


def report(
    applied: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    failed: list[dict[str, Any]],
    counts: dict[str, int],
    dry_run: bool,
) -> None:
    """Print the run's outcome, then fail if any write failed."""
    verb = "would apply" if dry_run else "applied"
    print(f"Proposals: {counts['proposed']}")
    print(f"{verb.capitalize()}: {counts['applied']}")
    print(f"Rejected: {counts['rejected']}")
    for action in applied:
        if action["escalate"]:
            print(
                f"  ESCALATE {one_line(action['repository'])}"
                f"#{one_line(action['issue'])}: "
                f"agent judged this may warrant Urgent — "
                f"{one_line(action['rationale'])}"
            )
        for note in action["dropped"]:
            print(
                f"  dropped from {one_line(action['repository'])}"
                f"#{one_line(action['issue'])}: {one_line(note)}"
            )
    for entry in rejected:
        print(
            f"  rejected {one_line(entry.get('repository'))}"
            f"#{one_line(entry.get('issue'))}: "
            f"{one_line(entry.get('reason'))}"
        )
    if failed:
        print(f"Failed: {counts['failed']}")
        for entry in failed:
            print(
                f"  FAILED {one_line(entry.get('repository'))}"
                f"#{one_line(entry.get('issue'))}: "
                f"{one_line(entry.get('reason'))}"
            )
        sys.exit("one or more proposals could not be settled; see apply-result.json")


def main() -> None:
    """Validate every proposal, then apply those that survive."""
    parser = argparse.ArgumentParser(description="Apply a triage proposal")
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.proposal.is_file():
        sys.exit(f"no proposal file at {one_line(args.proposal)}")
    if not args.snapshot.is_file():
        sys.exit(f"no snapshot file at {one_line(args.snapshot)}")

    try:
        proposal = extract_proposal(args.proposal.read_text(encoding="utf-8"))
    except (Rejected, OSError, UnicodeError) as exc:
        # A proposal nobody can read is a failed run, not a quiet
        # no-op: the session spent its budget and produced nothing
        # usable, and the operator needs to see that.
        parser.exit(1, f"Could not read the agent's proposal: {one_line(exc)}\n")

    # An empty list is a run that found nothing to do; anything
    # else in this field is a proposal nobody can act on. Treating
    # a missing or null value as "no proposals" would let a
    # malformed session report success, which is the outcome
    # reading the block at all is meant to rule out.
    raw_items: Any = proposal.get("proposals")
    if not isinstance(raw_items, list):
        parser.exit(
            1,
            "Could not read the agent's proposal: 'proposals' is "
            f"{type(raw_items).__name__}, not a list\n",
        )
    items = cast("list[Any]", raw_items)
    if len(items) > MAX_BATCH_ISSUES:
        parser.exit(
            1,
            f"Could not read the agent's proposal: {len(items)} proposals exceed "
            f"the {MAX_BATCH_ISSUES}-issue limit; narrow the repository scope "
            "or add exclusions and rerun.\n",
        )

    # A configuration read that failed is not a proposal problem
    # and has no per-proposal outcome to record: without it the
    # applier cannot tell a missing option from an unreachable
    # API, so the run stops here rather than guessing.
    try:
        ctx = build_context(
            load_snapshot(args.snapshot), allow_unavailable=args.dry_run
        )
    except GitHubError as exc:
        sys.exit(f"Could not read the organisation's configuration: {one_line(exc)}")

    applied, rejected, failed = process(items, ctx, args.dry_run)

    counts = {
        "proposed": len(items),
        "applied": len(applied),
        "rejected": len(rejected),
        "failed": len(failed),
    }
    result: dict[str, Any] = {
        "dry_run": args.dry_run,
        "applied": applied,
        "rejected": rejected,
        "failed": failed,
        "skipped": proposal.get("skipped", []),
        "injection_attempts": proposal.get("injection_attempts", []),
        "counts": counts,
    }
    args.output_json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    report(applied, rejected, failed, counts, args.dry_run)


if __name__ == "__main__":
    main()
