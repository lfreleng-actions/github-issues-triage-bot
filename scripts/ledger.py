# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The run-to-run memory of which targets a run already handled.

Every run's report job uploads ``ledger.json`` as an artifact (named
``bot-ledger`` unless the workflow passes ``--artifact-name``): the
entries it inherited plus one for every target this run reached a
verdict on. The next run's prepare job fetches the newest few of
those artifacts, merges them and skips any target already handled at
the same head, so an unchanged target costs one agent session rather
than one every schedule tick.

Nothing here lives on the target. Dry runs record their verdicts too,
so a rollout in dry-run does not repeat the same work every run, but
a live run ignores dry-run entries: the first live run after the flip
must still act on what dry runs only reported.

An entry names a target as ``repository``, ``number`` and
``head_sha``; a bot whose targets are issues rather than pull
requests can use the issue's number and the branch head it looked
at. ``record`` takes the set of verdicts worth remembering, so each
bot states its own without editing this module: a skip or a failure
is not recorded, and the next run looks at that target again. Stored
entries carry any lower-case verdict token, so one bot's ledger
remains readable by a later version with different verdicts.

``fetch --repository OWNER/REPO --output FILE`` writes the merged
prior ledger, or an empty one when no run has published yet.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import artifact_fetch
import bot_github as github
from bot_evidence import read_regular

SCHEMA = 1
DEFAULT_ARTIFACT_NAME = "bot-ledger"
MAX_LEDGER_BYTES = 4 * 1024 * 1024
# (name, byte cap, required): the cap table artifact_fetch applies to
# a prior run's ledger artifact.
LEDGER_FILES: tuple[tuple[str, int, bool], ...] = (
    ("ledger.json", MAX_LEDGER_BYTES, True),
)
RECENT_RUNS = 5
RETENTION_DAYS = 90
VERDICT_RE = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"


class LedgerError(Exception):
    """A ledger file is not one this module wrote."""


def empty_ledger() -> dict[str, Any]:
    """A ledger with no entries."""
    return {"schema": SCHEMA, "entries": []}


def parse_timestamp(text: Any) -> datetime:
    """Read a UTC timestamp in the form this module writes."""
    if not isinstance(text, str):
        raise LedgerError("entry timestamp is not a string")
    try:
        return datetime.strptime(text, TIMESTAMP).replace(tzinfo=UTC)
    except ValueError as exc:
        raise LedgerError(f"invalid entry timestamp {text!r}") from exc


def check_entry(raw: Any) -> dict[str, Any]:
    """Validate one entry's shape, returning it with the known keys alone."""
    if not isinstance(raw, dict):
        raise LedgerError("ledger entry is not an object")
    entry = cast("dict[str, Any]", raw)
    repository = entry.get("repository")
    number = entry.get("number")
    head_sha = entry.get("head_sha")
    verdict = entry.get("verdict")
    if (
        not isinstance(repository, str)
        or not github.REPO_RE.fullmatch(repository)
        or type(number) is not int
        or number <= 0
        or not isinstance(head_sha, str)
        or not github.SHA_RE.fullmatch(head_sha)
        or not isinstance(verdict, str)
        or not VERDICT_RE.fullmatch(verdict)
        or not isinstance(entry.get("dry_run"), bool)
    ):
        raise LedgerError("ledger entry has an invalid target, verdict or mode")
    parse_timestamp(entry.get("assessed_at"))
    tier = entry.get("tier")
    run_id = entry.get("run_id")
    return {
        "repository": repository,
        "number": number,
        "head_sha": head_sha,
        "verdict": verdict,
        "tier": tier if isinstance(tier, str) else None,
        "dry_run": entry["dry_run"],
        "run_id": run_id if type(run_id) is int else None,
        "assessed_at": entry["assessed_at"],
    }


def parse_ledger(content: bytes) -> dict[str, Any]:
    """Decode and validate ledger bytes."""
    try:
        parsed: Any = json.loads(content)
    except (ValueError, RecursionError) as exc:
        raise LedgerError(f"ledger is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LedgerError("ledger is not an object")
    data = cast("dict[str, Any]", parsed)
    if data.get("schema") != SCHEMA:
        raise LedgerError(f"ledger schema is not {SCHEMA}")
    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list):
        raise LedgerError("ledger carries no entries array")
    return {
        "schema": SCHEMA,
        "entries": [check_entry(entry) for entry in cast("list[Any]", raw_entries)],
    }


def load_ledger(path: Path) -> dict[str, Any]:
    """Read a bounded, regular ledger file."""
    return parse_ledger(read_regular(path, MAX_LEDGER_BYTES))


def entry_key(entry: dict[str, Any]) -> tuple[str, int, str]:
    """Identity of an assessment: one target at one head."""
    return (
        str(entry["repository"]).lower(),
        int(entry["number"]),
        str(entry["head_sha"]),
    )


def merge(
    ledgers: list[dict[str, Any]], *, now: datetime | None = None
) -> dict[str, Any]:
    """Combine ledgers, keeping the newest assessment per head within retention.

    Entries older than the artifact retention would have expired with
    their artifact anyway; pruning them keeps the snowball bounded.
    """
    current = now or datetime.now(UTC)
    cutoff = current - timedelta(days=RETENTION_DAYS)
    newest: dict[tuple[str, int, str], dict[str, Any]] = {}
    for ledger in ledgers:
        for entry in ledger["entries"]:
            if parse_timestamp(entry["assessed_at"]) < cutoff:
                continue
            key = entry_key(entry)
            held = newest.get(key)
            if held is None or parse_timestamp(held["assessed_at"]) < parse_timestamp(
                entry["assessed_at"]
            ):
                newest[key] = entry
    entries = sorted(
        newest.values(),
        key=lambda item: (str(item["assessed_at"]), entry_key(item)),
    )
    return {"schema": SCHEMA, "entries": entries}


def already_assessed(
    ledger: dict[str, Any],
    repository: str,
    number: int,
    head_sha: str,
    *,
    dry_run: bool,
) -> dict[str, Any] | None:
    """The entry that makes this head a skip, or None.

    A live entry always counts. A dry-run entry counts for another dry
    run alone: the verdict it recorded was never applied.
    """
    key = (repository.lower(), number, head_sha)
    for entry in ledger["entries"]:
        if entry_key(entry) == key and (dry_run or not entry["dry_run"]):
            return entry
    return None


def record(
    ledger: dict[str, Any],
    result: dict[str, Any],
    *,
    run_id: int,
    recorded: frozenset[str],
    now: datetime | None = None,
) -> bool:
    """Add one result's verdict to the ledger; return whether it was recorded.

    ``recorded`` names the verdicts that make a target a skip next
    run. Skips and failures are not among them: the next run should
    look at those heads again.
    """
    verdict = result.get("verdict")
    if not isinstance(verdict, str) or verdict not in recorded:
        return False
    stamp = (now or datetime.now(UTC)).strftime(TIMESTAMP)
    entry = check_entry(
        {
            "repository": result.get("repository"),
            "number": result.get("number"),
            "head_sha": result.get("head_sha"),
            "verdict": verdict,
            "tier": result.get("tier"),
            "dry_run": result.get("dry_run"),
            "run_id": run_id,
            "assessed_at": stamp,
        }
    )
    ledger["entries"].append(entry)
    return True


def fetch_one(repository: str, entry: dict[str, Any]) -> dict[str, Any] | str:
    """Load one published ledger, or explain why it was left out.

    A ledger that fails its bounds or shape is skipped rather than
    failing the run: the memory is an optimisation, and losing one
    run's entries costs at most a repeated assessment.
    """
    artifact_id = github.require_int(entry, "id", "artifact")
    size = artifact_fetch.artifact_size(entry)
    with tempfile.TemporaryDirectory() as holder:
        output = Path(holder)
        try:
            artifact_fetch.fetch_artifact(
                repository, artifact_id, size, output, LEDGER_FILES
            )
            return load_ledger(output / "ledger.json")
        except (artifact_fetch.Refused, LedgerError, OSError, ValueError) as exc:
            return f"skipped artifact {artifact_id}: {github.safe_message(exc)}"


def fetch(
    repository: str,
    limit: int = RECENT_RUNS,
    artifact_name: str = DEFAULT_ARTIFACT_NAME,
) -> tuple[dict[str, Any], list[str]]:
    """Merge the newest published ledgers of the repository's runs.

    Returns the merged ledger and a note for every artifact left out.
    """
    ledgers: list[dict[str, Any]] = []
    notes: list[str] = []
    for entry in artifact_fetch.list_named_artifacts(repository, artifact_name, limit):
        loaded = fetch_one(repository, entry)
        if isinstance(loaded, str):
            notes.append(loaded)
        else:
            ledgers.append(loaded)
    return merge(ledgers), notes


def main(argv: list[str] | None = None) -> None:
    """Write the merged prior ledger for this run."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fetcher = commands.add_parser("fetch", help="merge the newest published ledgers")
    fetcher.add_argument("--repository", required=True)
    fetcher.add_argument("--output", type=Path, required=True)
    fetcher.add_argument("--limit", type=int, default=RECENT_RUNS)
    fetcher.add_argument("--artifact-name", default=DEFAULT_ARTIFACT_NAME)
    args = parser.parse_args(argv)
    try:
        ledger, notes = fetch(args.repository, args.limit, args.artifact_name)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
    except (OSError, subprocess.SubprocessError, github.GitHubError) as exc:
        parser.exit(1, f"ledger: {github.safe_message(exc)}\n")
    for note in notes:
        print(f"::warning::ledger: {note}")
    print(f"ledger: {len(ledger['entries'])} prior assessment(s) -> {args.output}")


if __name__ == "__main__":
    main()
