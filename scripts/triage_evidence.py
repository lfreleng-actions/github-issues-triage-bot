# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Prepare an offline issue packet and separate evidence from agent output.

``packet --snapshot before.json --output issue-packet.json`` reads GitHub only.
The packet is {"repositories": [{"repository": "owner/repo", "labels":
[{"name": "bug", "description": "..."}], "issues": [{"number": 1,
"title": "...", "body": "...", "state": "open", "labels": ["bug"],
"priority": null, "type": null}]}]}. Existing Priority and type names are
preserved; a non-null Priority tells the proposing agent to skip that issue.

``verify --directory evidence --before-sha256 HEX --exclusions-sha256 HEX``
checks exact bytes against digests supplied by trusted prepare-job outputs,
never against digests from the agent or the downloaded artifact. The check
itself is the shared ``bot_evidence.verify``; this wrapper names the two
files and gives each its own byte cap.

``proposal --directory session --output artefacts/session-summary.md`` copies
only the summary, without interpreting its content or importing other files.
Verification and proposal extraction are offline and require no credentials.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

import bot_github as github
from bot_evidence import MAX_SUMMARY_BYTES, read_regular
from bot_evidence import verify as verify_evidence
from triage_github import existing_priority
from triage_policy import MAX_BATCH_ISSUES, REPO_RE

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_EXCLUSIONS_BYTES = 1024 * 1024


def snapshot_membership(path: Path, *, retriage: bool = False) -> dict[str, set[int]]:
    """Validate all targets and labels, then deduplicate eligible snapshot members."""
    parsed: Any = json.loads(read_regular(path, MAX_SNAPSHOT_BYTES))
    if not isinstance(parsed, list):
        raise ValueError("snapshot must be an array")
    repositories: dict[str, set[int]] = {}
    for entry in cast("list[Any]", parsed):
        if not isinstance(entry, dict):
            raise ValueError("snapshot entries must be objects")
        entry = cast("dict[str, Any]", entry)
        repository = entry.get("repository")
        if not isinstance(repository, dict):
            raise ValueError("snapshot entry must contain a repository object")
        repo = cast("dict[str, Any]", repository).get("nameWithOwner")
        number = entry.get("number")
        if (
            not isinstance(repo, str)
            or not REPO_RE.fullmatch(repo)
            or repo.partition("/")[2] in (".", "..")
        ):
            raise ValueError("snapshot repository must be an owner/repo name")
        if type(number) is not int or number <= 0:
            raise ValueError("snapshot issue number must be a positive integer")
        labels = entry.get("labels")
        if not isinstance(labels, list):
            raise ValueError("snapshot entry must contain a labels array")
        for label in cast("list[Any]", labels):
            name = (
                cast("dict[str, Any]", label).get("name")
                if isinstance(label, dict)
                else label
            )
            if not isinstance(name, str) or not name:
                raise ValueError("snapshot label must have a nonempty name")
        if labels and not retriage:
            continue
        repositories.setdefault(repo.lower(), set()).add(number)
    return repositories


def repository_labels(repo: str) -> list[dict[str, Any]]:
    """Read the label vocabulary once for each repository in the packet."""
    entries = github.api_list(f"repos/{repo}/labels")
    labels: list[dict[str, Any]] = []
    for entry in entries:
        name = entry.get("name")
        description = entry.get("description")
        if not isinstance(name, str) or not name:
            raise github.GitHubError("repository label has no name")
        if description is not None and not isinstance(description, str):
            raise github.GitHubError("invalid repository label description")
        labels.append({"name": name, "description": description})
    return labels


def issue_details(repo: str, number: int) -> dict[str, Any]:
    """Read current issue content and Priority without invoking any write helper."""
    parsed = github.decode_response(
        github.run_gh(["api", f"repos/{repo}/issues/{number}"])
    )
    if not isinstance(parsed, dict):
        raise github.GitHubError("expected an issue object")
    issue = cast("dict[str, Any]", parsed)
    if type(issue.get("number")) is not int or issue["number"] != number:
        raise github.GitHubError("issue response does not match the requested number")
    if issue.get("pull_request") is not None:
        raise github.GitHubError("snapshot target is a pull request, not an issue")
    title = issue.get("title")
    body = issue.get("body")
    state = issue.get("state")
    if (
        not isinstance(title, str)
        or "body" not in issue
        or (body is not None and not isinstance(body, str))
        or state not in ("open", "closed")
    ):
        raise github.GitHubError("invalid issue title, body or state")
    raw_labels = issue.get("labels")
    if not isinstance(raw_labels, list):
        raise github.GitHubError("expected an issue label array")
    labels: list[str] = []
    for label in cast("list[Any]", raw_labels):
        name = (
            cast("dict[str, Any]", label).get("name")
            if isinstance(label, dict)
            else label
        )
        if not isinstance(name, str) or not name:
            raise github.GitHubError("issue label has no name")
        labels.append(name)
    issue_type = issue.get("type")
    type_name: str | None = None
    if issue_type is not None:
        if not isinstance(issue_type, dict):
            raise github.GitHubError("expected an issue type object")
        name = cast("dict[str, Any]", issue_type).get("name")
        if not isinstance(name, str) or not name:
            raise github.GitHubError("issue type has no name")
        type_name = name
    return {
        "number": number,
        "title": title,
        "body": body,
        "state": state,
        "labels": labels,
        "priority": existing_priority(repo, number),
        "type": type_name,
    }


def build_packet(snapshot: Path, *, retriage: bool = False) -> dict[str, Any]:
    """Fetch eligible snapshot members only after validating the whole batch limit."""
    membership = snapshot_membership(snapshot, retriage=retriage)
    count = sum(len(numbers) for numbers in membership.values())
    if count > MAX_BATCH_ISSUES:
        raise ValueError(
            f"snapshot contains {count} eligible issues, exceeding the "
            f"{MAX_BATCH_ISSUES}-issue limit; narrow the repository scope "
            "or add exclusions and rerun"
        )
    repositories: list[dict[str, Any]] = []
    for repo, numbers in sorted(membership.items()):
        repositories.append(
            {
                "repository": repo,
                "labels": repository_labels(repo),
                "issues": [issue_details(repo, number) for number in sorted(numbers)],
            }
        )
    return {"repositories": repositories}


def verify(directory: Path, before_sha256: str, exclusions_sha256: str) -> None:
    """Authenticate the two fixed evidence files against independently trusted hashes.

    The exclusions list keeps its own, far smaller cap: a one-line
    file per excluded repository has no business approaching the
    snapshot's limit.
    """
    verify_evidence(
        directory,
        [
            ("before.json", before_sha256, MAX_SNAPSHOT_BYTES),
            ("excluded-repos.txt", exclusions_sha256, MAX_EXCLUSIONS_BYTES),
        ],
    )


def copy_proposal(directory: Path, output: Path) -> None:
    """Copy only the bounded summary bytes into the caller's trusted destination."""
    content = read_regular(directory / "session-summary.md", MAX_SUMMARY_BYTES)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(content)


def main(argv: list[str] | None = None) -> None:
    """Dispatch the read-only packet, evidence verification and proposal commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    packet = commands.add_parser(
        "packet", help="build a read-only offline issue packet"
    )
    packet.add_argument("--snapshot", type=Path, required=True)
    packet.add_argument("--output", type=Path, required=True)
    packet.add_argument(
        "--retriage", action="store_true", help="include labelled issues"
    )
    verification = commands.add_parser("verify", help="check trusted evidence digests")
    verification.add_argument("--directory", type=Path, required=True)
    verification.add_argument("--before-sha256", required=True)
    verification.add_argument("--exclusions-sha256", required=True)
    proposal = commands.add_parser("proposal", help="extract only the session summary")
    proposal.add_argument("--directory", type=Path, required=True)
    proposal.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "packet":
            content = (
                json.dumps(
                    build_packet(args.snapshot, retriage=args.retriage), indent=2
                )
                + "\n"
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(content, encoding="utf-8")
        elif args.command == "verify":
            verify(args.directory, args.before_sha256, args.exclusions_sha256)
        else:
            copy_proposal(args.directory, args.output)
    except (OSError, ValueError, RecursionError, github.GitHubError) as exc:
        message = ascii(str(exc)).replace("::", ": :").replace("##[", "# #[")
        parser.exit(1, f"triage evidence: {message}\n")


if __name__ == "__main__":
    main()
