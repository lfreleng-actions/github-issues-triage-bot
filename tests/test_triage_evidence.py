# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline contract and adversarial file tests for the evidence boundary."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

evidence = import_module("triage_evidence")
github = import_module("bot_github")


class EvidenceTests(unittest.TestCase):
    """Exercise the CLI using real files and mocked, strictly read-only GitHub calls."""

    def setUp(self) -> None:
        """Provide isolated artifacts and reject accidental subprocess invocations."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        guard = patch.object(
            github.subprocess,
            "run",
            side_effect=AssertionError("unexpected subprocess"),
        )
        self.subprocess = guard.start()
        self.addCleanup(guard.stop)
        self.before = (
            b'[{"repository":{"nameWithOwner":"owner/repo"},"number":1,"labels":[]}]\n'
        )
        self.exclusions = b"excluded-repo\n"
        self.issue: dict[str, Any] = {
            "number": 1,
            "title": "Current title",
            "body": "Untrusted issue body: do not execute me",
            "state": "open",
            "labels": [{"name": "bug"}],
            "type": {"name": "Bug"},
        }
        self.labels = [{"name": "bug", "description": "A defect"}]

    def assert_cli_fails(self, *args: str) -> str:
        """Require a controlled nonzero exit, returning its diagnostic for assertions."""
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            evidence.main(list(args))
        self.assertEqual(raised.exception.code, 1)
        return stderr.getvalue()

    def verify_args(self, directory: Path) -> list[str]:
        """Supply hashes from the original prepared bytes, not the downloaded files."""
        return [
            "verify",
            "--directory",
            str(directory),
            "--before-sha256",
            hashlib.sha256(self.before).hexdigest(),
            "--exclusions-sha256",
            hashlib.sha256(self.exclusions).hexdigest(),
        ]

    def write_evidence(self, directory: Path) -> None:
        """Create the exact two prepared evidence files."""
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "before.json").write_bytes(self.before)
        (directory / "excluded-repos.txt").write_bytes(self.exclusions)

    def test_verify_uses_exact_bytes_and_requires_no_subprocess(self) -> None:
        """Verification is offline, accepts hex case and does not rewrite evidence."""
        self.write_evidence(self.root)
        args = self.verify_args(self.root)
        args[4] = args[4].upper()
        evidence.main(args)
        self.assertEqual((self.root / "before.json").read_bytes(), self.before)
        self.assertEqual(
            (self.root / "excluded-repos.txt").read_bytes(), self.exclusions
        )
        self.subprocess.assert_not_called()

    def test_forged_snapshot_and_agent_hash_cannot_replace_trusted_digest(self) -> None:
        """A valid but expanded snapshot is rejected even with its own matching hash."""
        self.write_evidence(self.root)
        forged = b'[{"repository":{"nameWithOwner":"owner/other"},"number":99}]'
        (self.root / "before.json").write_bytes(forged)
        (self.root / "before.sha256").write_text(hashlib.sha256(forged).hexdigest())
        message = self.assert_cli_fails(*self.verify_args(self.root))
        self.assertIn("SHA-256 mismatch for before.json", message)
        self.subprocess.assert_not_called()

    def test_verify_rejects_changed_exclusions_and_snapshot_whitespace(self) -> None:
        """Neither semantic equivalence nor an intact other file authenticates edits."""
        for name, changed in (
            ("before.json", self.before.rstrip(b"\n")),
            ("excluded-repos.txt", b""),
        ):
            with self.subTest(name=name):
                self.write_evidence(self.root)
                (self.root / name).write_bytes(changed)
                self.assertIn(
                    "SHA-256 mismatch",
                    self.assert_cli_fails(*self.verify_args(self.root)),
                )

    def test_verify_rejects_malformed_trusted_hashes(self) -> None:
        """Digests must be complete hex values, not artifact paths or partial hashes."""
        self.write_evidence(self.root)
        for index in (4, 6):
            for digest in (
                "",
                "a" * 63,
                "a" * 65,
                "g" * 64,
                "a" * 64 + "\n",
                "before.sha256",
            ):
                with self.subTest(index=index, digest=digest):
                    args = self.verify_args(self.root)
                    args[index] = digest
                    self.assertIn("64 hex digits", self.assert_cli_fails(*args))

    def test_evidence_and_proposal_reject_unsafe_files(self) -> None:
        """Missing, nonregular, linked and oversized files are never accepted."""
        for name, limit in (
            ("before.json", 16 * 1024 * 1024),
            ("excluded-repos.txt", 1024 * 1024),
            ("session-summary.md", 8 * 1024 * 1024),
        ):
            for kind in (
                "missing",
                "directory",
                "symlink",
                "dangling",
                "fifo",
                "oversized",
            ):
                with self.subTest(name=name, kind=kind):
                    directory = self.root / f"{name}-{kind}"
                    self.write_evidence(directory)
                    source = directory / name
                    source.unlink(missing_ok=True)
                    if kind == "directory":
                        source.mkdir()
                    elif kind == "symlink":
                        target = directory / "target"
                        target.write_bytes(
                            self.before if name == "before.json" else self.exclusions
                        )
                        source.symlink_to(target)
                    elif kind == "dangling":
                        source.symlink_to(directory / "absent")
                    elif kind == "fifo":
                        os.mkfifo(source)
                    elif kind == "oversized":
                        with source.open("wb") as stream:
                            stream.truncate(limit + 1)
                    output = directory / "trusted" / "session-summary.md"
                    args = self.verify_args(directory)
                    if name == "session-summary.md":
                        args = [
                            "proposal",
                            "--directory",
                            str(directory),
                            "--output",
                            str(output),
                        ]
                    message = self.assert_cli_fails(*args)
                    if kind == "oversized":
                        self.assertIn("byte limit", message)
                    self.assertFalse(output.exists())
        self.subprocess.assert_not_called()

    def test_linked_input_directory_is_rejected(self) -> None:
        """A symlink cannot redirect the evidence or session directory itself."""
        actual = self.root / "actual"
        self.write_evidence(actual)
        (actual / "session-summary.md").write_bytes(b"summary")
        link = self.root / "link"
        link.symlink_to(actual, target_is_directory=True)
        self.assert_cli_fails(*self.verify_args(link))
        self.assert_cli_fails(
            "proposal",
            "--directory",
            str(link),
            "--output",
            str(self.root / "summary.md"),
        )

    def test_proposal_copies_only_summary_not_malicious_evidence(self) -> None:
        """An agent artifact cannot overwrite trusted evidence through extraction."""
        session = self.root / "untrusted"
        trusted = self.root / "trusted"
        session.mkdir()
        self.write_evidence(trusted)
        summary = b'A proposal\r\n```json\n{"proposals": []}\n```\n\xff'
        (session / "session-summary.md").write_bytes(summary)
        (session / "before.json").write_bytes(b"malicious snapshot")
        (session / "excluded-repos.txt").write_bytes(b"malicious exclusions")
        (session / "nested").mkdir()
        (session / "other-file").symlink_to(self.root / "missing")
        output = trusted / "session-summary.md"
        evidence.main(
            ["proposal", "--directory", str(session), "--output", str(output)]
        )
        self.assertEqual(output.read_bytes(), summary)
        self.assertEqual((trusted / "before.json").read_bytes(), self.before)
        self.assertEqual((trusted / "excluded-repos.txt").read_bytes(), self.exclusions)
        self.assertEqual(
            {path.name for path in trusted.iterdir()},
            {"before.json", "excluded-repos.txt", "session-summary.md"},
        )
        self.subprocess.assert_not_called()

    def test_proposal_limit_is_inclusive_and_creates_output_parent(self) -> None:
        """A summary at the cap is copied byte-for-byte into a new trusted directory."""
        summary = b"x" * (8 * 1024 * 1024)
        (self.root / "session-summary.md").write_bytes(summary)
        output = self.root / "artefacts" / "session-summary.md"
        evidence.main(
            ["proposal", "--directory", str(self.root), "--output", str(output)]
        )
        self.assertEqual(output.read_bytes(), summary)

    def test_repository_labels_include_more_than_1000_with_descriptions(self) -> None:
        """The packet vocabulary must include later pages without losing descriptions."""
        labels = [
            {"name": f"custom-{i}", "description": None, "color": "ffffff"}
            for i in range(1000)
        ] + self.labels
        pages = [labels[start : start + 100] for start in range(0, len(labels), 100)]

        def read(args: list[str]) -> str:
            """Model the old CLI cap and the paginated REST label response."""
            if args[:2] == ["label", "list"]:
                return json.dumps(labels[: int(args[args.index("--limit") + 1])])
            self.assertEqual(
                args, ["api", "repos/owner/repo/labels", "--paginate", "--slurp"]
            )
            return json.dumps(pages)

        with patch.object(github, "run_gh", side_effect=read):
            actual = evidence.repository_labels("owner/repo")
        self.assertEqual(len(actual), 1001)
        self.assertEqual(
            actual,
            [
                {"name": label["name"], "description": label["description"]}
                for label in labels
            ],
        )

    def test_packet_reads_snapshot_membership_and_preserves_existing_priority(
        self,
    ) -> None:
        """Only validated members are fetched, with one label list per repository."""
        snapshot = self.root / "before.json"
        entries: list[dict[str, Any]] = [
            {
                "repository": {"nameWithOwner": repo},
                "number": number,
                "url": "../../evil",
                "title": "stale",
                "labels": [],
            }
            for repo, number in (
                ("Owner/Repo", 2),
                ("owner/repo", 1),
                ("OWNER/REPO", 1),
                ("owner/other", 9),
            )
        ]
        snapshot.write_text(json.dumps(entries), encoding="utf-8")
        responses: dict[tuple[str, ...], str] = {}
        for repo, numbers in (("owner/repo", (1, 2)), ("owner/other", (9,))):
            responses[("api", f"repos/{repo}/labels", "--paginate", "--slurp")] = (
                json.dumps([self.labels])
            )
            for number in numbers:
                issue = {**self.issue, "number": number}
                if number != 1:
                    issue.update(
                        {"body": None, "state": "closed", "type": None, "labels": []}
                    )
                responses[("api", f"repos/{repo}/issues/{number}")] = json.dumps(issue)
                values = (
                    []
                    if number != 1
                    else [
                        {
                            "issue_field_name": "Priority",
                            "value": 5,
                            "single_select_option": {"name": "Urgent"},
                        }
                    ]
                )
                responses[
                    (
                        "api",
                        f"repos/{repo}/issues/{number}/issue-field-values",
                        "--paginate",
                        "--slurp",
                    )
                ] = json.dumps([[{"issue_field_name": "Effort", "value": 3}], values])
        seen: list[tuple[str, ...]] = []

        def read(args: list[str]) -> str:
            """Allow exactly the expected GET/list commands; a write fails the test."""
            key = tuple(args)
            seen.append(key)
            return responses[key]

        output = self.root / "artefacts" / "issue-packet.json"
        with patch.object(github, "run_gh", side_effect=read):
            evidence.main(
                ["packet", "--snapshot", str(snapshot), "--output", str(output)]
            )
        packet = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(set(packet), {"repositories"})
        self.assertEqual(
            [repo["repository"] for repo in packet["repositories"]],
            ["owner/other", "owner/repo"],
        )
        repository = packet["repositories"][1]
        self.assertEqual(repository["labels"], self.labels)
        self.assertEqual(
            repository["issues"],
            [
                {
                    "number": 1,
                    "title": self.issue["title"],
                    "body": self.issue["body"],
                    "state": "open",
                    "labels": ["bug"],
                    "priority": "Urgent",
                    "type": "Bug",
                },
                {
                    "number": 2,
                    "title": self.issue["title"],
                    "body": None,
                    "state": "closed",
                    "labels": [],
                    "priority": None,
                    "type": None,
                },
            ],
        )
        self.assertCountEqual(seen, list(responses))
        self.subprocess.assert_not_called()

    def test_packet_capacity_counts_deduplicated_members_across_repositories(
        self,
    ) -> None:
        """Keep all 100 unique targets, but refuse 101 before fetching even labels."""
        snapshot = self.root / "before.json"

        def read(args: list[str]) -> str:
            """Return complete read-only data for each requested snapshot member."""
            endpoint = args[1]
            if endpoint.endswith("/labels"):
                return json.dumps([self.labels])
            if endpoint.endswith("/issue-field-values"):
                return "[[]]"
            return json.dumps({**self.issue, "number": int(endpoint.rsplit("/", 1)[1])})

        for count in (100, 101):
            entries: list[dict[str, Any]] = [
                {
                    "repository": {
                        "nameWithOwner": "owner/repo" if i < 50 else "owner/other"
                    },
                    "number": i + 1 if i < 50 else i - 49,
                    "labels": [],
                }
                for i in range(count)
            ]
            expected = {
                (entry["repository"]["nameWithOwner"], entry["number"])
                for entry in entries
            }
            snapshot.write_text(
                json.dumps(
                    entries
                    + [
                        {
                            **entry,
                            "repository": {
                                "nameWithOwner": entry["repository"][
                                    "nameWithOwner"
                                ].upper()
                            },
                        }
                        for entry in entries
                    ]
                ),
                encoding="utf-8",
            )
            with (
                self.subTest(count=count),
                patch.object(github, "run_gh", side_effect=read) as calls,
            ):
                if count > 100:
                    with self.assertRaisesRegex(
                        ValueError, "101.*100.*repository.*exclusions"
                    ):
                        evidence.build_packet(snapshot)
                    calls.assert_not_called()
                else:
                    repositories = evidence.build_packet(snapshot)["repositories"]
                    self.assertEqual(
                        {
                            (repo["repository"], issue["number"])
                            for repo in repositories
                            for issue in repo["issues"]
                        },
                        expected,
                    )
                    self.assertEqual(
                        sum(len(repo["issues"]) for repo in repositories), 100
                    )
                    self.assertEqual(calls.call_count, 202)

    def test_packet_filters_labelled_issues_before_capacity_check(self) -> None:
        """Skipped labelled targets cost no reads, but retriage counts them all."""
        snapshot = self.root / "before.json"
        output = self.root / "packet.json"
        entries = json.loads(self.before) + [
            {
                "repository": {"nameWithOwner": "owner/labelled"},
                "number": number,
                "labels": [{"name": "human-label"}],
            }
            for number in range(1, 101)
        ]
        snapshot.write_text(json.dumps(entries), encoding="utf-8")
        for retriage in (False, True):
            output.unlink(missing_ok=True)
            with (
                self.subTest(retriage=retriage),
                patch.object(
                    github,
                    "run_gh",
                    side_effect=[
                        json.dumps([self.labels]),
                        json.dumps(self.issue),
                        "[[]]",
                    ],
                ) as read,
            ):
                argv = ["packet", "--snapshot", str(snapshot), "--output", str(output)]
                if retriage:
                    message = self.assert_cli_fails(*argv, "--retriage")
                    self.assertIn("101", message)
                    self.assertIn("100", message)
                    self.assertIn("repository", message)
                    self.assertIn("exclusions", message)
                    read.assert_not_called()
                    self.assertFalse(output.exists())
                else:
                    evidence.main(argv)
                    repositories = json.loads(output.read_text(encoding="utf-8"))[
                        "repositories"
                    ]
                    self.assertEqual(
                        [repo["repository"] for repo in repositories], ["owner/repo"]
                    )
                    self.assertEqual(
                        [issue["number"] for issue in repositories[0]["issues"]], [1]
                    )
                    self.assertEqual(read.call_count, 3)
                    for call in read.call_args_list:
                        self.assertNotIn("owner/labelled", call.args[0][1])

    def test_labelled_only_packet_is_empty_unless_retriaging(self) -> None:
        """Explicit retriage admits labelled members; the default needs no API calls."""
        snapshot = self.root / "before.json"
        entry = json.loads(self.before)[0]
        for labels in ([{"name": "human-label"}], ["human-label"]):
            with self.subTest(labels=labels):
                snapshot.write_text(
                    json.dumps([{**entry, "labels": labels}]), encoding="utf-8"
                )
                self.assertEqual(evidence.build_packet(snapshot), {"repositories": []})
                self.subprocess.assert_not_called()
                with patch.object(
                    github,
                    "run_gh",
                    side_effect=[
                        json.dumps([self.labels]),
                        json.dumps(self.issue),
                        "[[]]",
                    ],
                ) as read:
                    repositories = evidence.build_packet(snapshot, retriage=True)[
                        "repositories"
                    ]
                self.assertEqual(
                    [issue["number"] for issue in repositories[0]["issues"]], [1]
                )
                self.assertEqual(read.call_count, 3)

    def test_snapshot_labels_must_be_explicit_and_well_formed(self) -> None:
        """Missing or malformed labels must not imply eligibility in either mode."""
        snapshot = self.root / "before.json"
        output = self.root / "packet.json"
        valid = json.loads(self.before)[0]
        invalid = [{key: value for key, value in valid.items() if key != "labels"}]
        label_cases: tuple[Any, ...] = (
            None,
            {},
            "",
            False,
            [None],
            [{}],
            [""],
            [1],
            [{"name": None}],
            ["valid", {}],
        )
        invalid.extend({**valid, "labels": labels} for labels in label_cases)
        for entry in invalid:
            for retriage in (False, True):
                with self.subTest(entry=entry, retriage=retriage):
                    snapshot.write_text(json.dumps([valid, entry]), encoding="utf-8")
                    message = self.assert_cli_fails(
                        "packet",
                        "--snapshot",
                        str(snapshot),
                        "--output",
                        str(output),
                        *(["--retriage"] if retriage else []),
                    )
                    self.assertIn("label", message)
                    self.assertFalse(output.exists())
        self.subprocess.assert_not_called()

    def test_packet_validates_entire_snapshot_before_any_api_call(self) -> None:
        """Path traversal, CLI options and noninteger targets never become endpoints."""
        valid = json.loads(self.before)[0]
        invalid: list[Any] = [None, {}, {"repository": None, "number": 1}]
        invalid.extend(
            {"repository": {"nameWithOwner": repo}, "number": 1}
            for repo in (
                "../repo",
                "owner/..",
                "owner/.",
                "owner/repo/../../evil",
                "owner/repo?x=y",
                "owner/repo#x",
                "--hostname/evil",
                "https://evil/repo",
                "owner/repo\n",
                "owner/repo%2f..",
                "owner\\repo",
                "owner/",
                None,
            )
        )
        invalid_numbers: tuple[Any, ...] = (
            True,
            False,
            0,
            -1,
            1.0,
            "1",
            "../../evil",
            None,
            [],
        )
        invalid.extend({**valid, "number": number} for number in invalid_numbers)
        snapshot = self.root / "before.json"
        output = self.root / "packet.json"
        for entry in invalid:
            with self.subTest(entry=entry):
                snapshot.write_text(json.dumps([valid, entry]), encoding="utf-8")
                self.assert_cli_fails(
                    "packet", "--snapshot", str(snapshot), "--output", str(output)
                )
                self.assertFalse(output.exists())
        for raw in (b"null", b"{}", b"not json", b"[", b"\xff"):
            with self.subTest(raw=raw):
                snapshot.write_bytes(raw)
                self.assert_cli_fails(
                    "packet", "--snapshot", str(snapshot), "--output", str(output)
                )
        self.subprocess.assert_not_called()

    def test_empty_packet_does_not_query_github(self) -> None:
        """An empty scan needs no API reads or credentials."""
        snapshot = self.root / "before.json"
        snapshot.write_text("[]", encoding="utf-8")
        self.assertEqual(evidence.build_packet(snapshot), {"repositories": []})
        self.subprocess.assert_not_called()

    def test_packet_timeout_is_a_controlled_failure(self) -> None:
        """A timed-out label read retries, then fails without a partial packet."""
        snapshot = self.root / "before.json"
        snapshot.write_bytes(self.before)
        output = self.root / "packet.json"
        self.subprocess.side_effect = subprocess.TimeoutExpired(
            ["gh"], github.TIMEOUT_SECONDS
        )
        with patch.object(github.time, "sleep"):
            message = self.assert_cli_fails(
                "packet", "--snapshot", str(snapshot), "--output", str(output)
            )
        self.assertIn(f"timed out after {github.TIMEOUT_SECONDS} seconds", message)
        self.assertEqual(self.subprocess.call_count, github.READ_ATTEMPTS)
        self.assertFalse(output.exists())

    def test_packet_fails_closed_on_api_errors(self) -> None:
        """No packet is written on label, issue or priority failures, including 404."""
        snapshot = self.root / "before.json"
        snapshot.write_bytes(self.before)
        output = self.root / "packet.json"
        for stage in range(3):
            for message in (
                "gh: unavailable (HTTP 404)",
                "gh: rate limit (HTTP 403)",
                "timeout",
            ):
                with self.subTest(stage=stage, message=message):
                    responses: list[Any] = [
                        json.dumps([self.labels]),
                        json.dumps(self.issue),
                    ][:stage]
                    responses.append(github.GitHubError(message))
                    with patch.object(github, "run_gh", side_effect=responses):
                        self.assert_cli_fails(
                            "packet",
                            "--snapshot",
                            str(snapshot),
                            "--output",
                            str(output),
                        )
                    self.assertFalse(output.exists())

    def test_packet_rejects_malformed_api_content(self) -> None:
        """Unknown API values cannot be reported as an empty or eligible issue."""
        snapshot = self.root / "before.json"
        snapshot.write_bytes(self.before)
        output = self.root / "packet.json"
        invalid_issues: list[Any] = [
            None,
            {},
            {**self.issue, "pull_request": {}},
            {**self.issue, "number": 2},
        ]
        invalid_fields: tuple[tuple[str, Any], ...] = (
            ("number", True),
            ("title", None),
            ("body", []),
            ("state", "unknown"),
            ("labels", None),
            ("labels", [{}]),
            ("type", "Bug"),
            ("type", {}),
        )
        invalid_issues.extend(
            {**self.issue, key: value} for key, value in invalid_fields
        )
        responses = [
            [json.dumps([self.labels]), json.dumps(issue)] for issue in invalid_issues
        ]
        responses.extend(
            [raw]
            for raw in (
                "not json",
                "null",
                "{}",
                "[null]",
                "[[null]]",
                "[[{}]]",
                '[[{"name": ""}]]',
                '[[{"name": 1}]]',
                '[[{"name":"bug","description":1}]]',
                '[[{"name":"valid","description":null}], [{"name":"bug","description":1}]]',
            )
        )
        responses.append(
            [
                json.dumps([self.labels]),
                json.dumps(self.issue),
                json.dumps(
                    [
                        [
                            {
                                "issue_field_name": "Priority",
                                "value": 5,
                                "single_select_option": None,
                            }
                        ]
                    ]
                ),
            ]
        )
        for response in responses:
            with (
                self.subTest(response=response),
                patch.object(github, "run_gh", side_effect=response),
            ):
                self.assert_cli_fails(
                    "packet", "--snapshot", str(snapshot), "--output", str(output)
                )
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
