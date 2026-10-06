# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Mocked GitHub contract tests; no network or GitHub writes."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from collections.abc import Generator
from contextlib import contextmanager
from functools import partial
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

github = import_module("triage_github")
plumbing = import_module("bot_github")


@contextmanager
def fake_run_gh(**kwargs: Any) -> Generator[MagicMock]:
    """Intercept every gh call with one mock.

    ``triage_github`` binds ``run_gh`` by name, so its own callers
    reach the copy in this module while ``api_list`` reaches the
    original in ``bot_github``; a test must replace both.
    """
    with (
        patch.object(plumbing, "run_gh", **kwargs) as mock,
        patch.object(github, "run_gh", mock),
    ):
        yield mock


class GitHubReadTests(unittest.TestCase):
    """Check pagination, unavailable endpoints and malformed read responses."""

    def setUp(self) -> None:
        """Stop any unexpected real gh invocation."""
        guard = patch.object(
            plumbing.subprocess, "run", side_effect=AssertionError("unexpected gh call")
        )
        guard.start()
        self.addCleanup(guard.stop)

    @staticmethod
    def page_response(args: list[str], pages: list[list[dict[str, Any]]]) -> str:
        """Model gh's first-page default and slurped pagination output."""
        if "--paginate" not in args:
            return json.dumps(pages[0])
        if "--slurp" in args:
            return json.dumps(pages)
        return "\n".join(json.dumps(page) for page in pages)

    def test_reads_pin_api_version(self) -> None:
        """Single-object and paginated reads use the same explicit REST contract."""
        readers = (
            (
                partial(github.read_issue, "owner/repo", 1),
                '{"pr": false, "state": "open", "labels": []}',
            ),
            (partial(github.repo_labels, "owner/repo", {}), "[[]]"),
            (partial(github.existing_priority, "owner/repo", 1), "[[]]"),
            (partial(github.load_field_options, "owner"), "[[]]"),
            (partial(github.load_issue_types, "owner"), "[[]]"),
        )
        for read, response in readers:
            with (
                self.subTest(reader=read),
                patch.object(
                    plumbing.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(["gh"], 0, response, ""),
                ) as runner,
            ):
                read()
                runner.assert_called_once()
                args = runner.call_args.args[0]
                self.assertEqual(args[:2], ["gh", "api"])
                self.assertEqual(
                    args[-2:], ["--header", "X-GitHub-Api-Version: 2026-03-10"]
                )
                self.assertIsNone(runner.call_args.kwargs["input"])
                self.assertEqual(
                    runner.call_args.kwargs["timeout"], plumbing.TIMEOUT_SECONDS
                )

    def test_human_priority_on_later_page_is_not_missing(self) -> None:
        """A Priority outside the first 30 values must still veto writes."""
        pages: list[list[dict[str, Any]]] = [
            [{"issue_field_name": f"Other {i}", "value": "human"} for i in range(30)],
            [
                {
                    "issue_field_name": "Priority",
                    "value": 1,
                    "single_select_option": {"name": "Urgent"},
                }
            ],
        ]
        with fake_run_gh(side_effect=partial(self.page_response, pages=pages)):
            self.assertEqual(github.existing_priority("owner/repo", 1), "Urgent")

    def test_field_options_and_types_include_later_pages(self) -> None:
        """Definitions beyond page one must not be silently dropped."""
        fields: list[list[dict[str, Any]]] = [
            [{"id": i + 1, "name": f"Other {i}", "options": []} for i in range(30)],
            [{"id": 50, "name": "Priority", "options": [{"name": "High", "id": 99}]}],
        ]
        with fake_run_gh(side_effect=partial(self.page_response, pages=fields)):
            self.assertEqual(
                github.load_field_options("owner")["Priority"],
                {github.FIELD_ID_KEY: 50, "High": 99},
            )
        types: list[list[dict[str, Any]]] = [
            [{"name": "Task", "is_enabled": True}],
            [
                {"name": "Bug", "is_enabled": True},
                {"name": "Feature", "is_enabled": False},
            ],
        ]
        with fake_run_gh(side_effect=partial(self.page_response, pages=types)):
            self.assertEqual(github.load_issue_types("owner"), {"Task", "Bug"})

    def test_repo_labels_are_not_capped_and_cache_only_success(self) -> None:
        """All repository labels are visible and failed reads never poison the cache."""
        pages: list[list[dict[str, Any]]] = [
            [{"name": f"custom-{i}"} for i in range(200)],
            [{"name": "bug"}],
        ]
        cache: dict[str, set[str]] = {}
        with fake_run_gh(side_effect=partial(self.page_response, pages=pages)) as read:
            self.assertIn("bug", github.repo_labels("owner/repo", cache))
            self.assertIn("bug", github.repo_labels("owner/repo", cache))
            read.assert_called_once()
        with (
            fake_run_gh(side_effect=github.GitHubError("later page failed")),
            self.assertRaises(github.GitHubError),
        ):
            github.repo_labels("owner/other", cache)
        self.assertNotIn("owner/other", cache)

    def test_missing_priority_option_name_is_not_an_unset_field(self) -> None:
        """A value whose option cannot be resolved is unknown, not writable."""
        pages: list[list[dict[str, Any]]] = [
            [
                {
                    "issue_field_name": "Priority",
                    "value": 42,
                    "single_select_option": None,
                }
            ]
        ]
        with (
            fake_run_gh(side_effect=partial(self.page_response, pages=pages)),
            self.assertRaises(github.GitHubError),
        ):
            github.existing_priority("owner/repo", 1)

    def test_unset_priority_is_distinct_from_unreadable(self) -> None:
        """A genuinely empty value leaves the issue eligible."""
        cases: tuple[list[dict[str, Any]], ...] = (
            [],
            [
                {
                    "issue_field_name": "Priority",
                    "value": None,
                    "single_select_option": None,
                }
            ],
        )
        for values in cases:
            with (
                self.subTest(values=values),
                fake_run_gh(side_effect=partial(self.page_response, pages=[values])),
            ):
                self.assertIsNone(github.existing_priority("owner/repo", 1))

    def test_malformed_list_responses_raise_github_error(self) -> None:
        """Protocol errors must reach the structured failed outcome, not crash it."""
        readers = (
            lambda: github.existing_priority("owner/repo", 1),
            lambda: github.repo_labels("owner/repo", {}),
            lambda: github.load_field_options("owner"),
            lambda: github.load_issue_types("owner"),
        )
        for read in readers:
            for raw in ("not json", "null", "{}", "[null]", "[[null]]"):
                with (
                    self.subTest(reader=read, raw=raw),
                    fake_run_gh(return_value=raw),
                    self.assertRaises(github.GitHubError),
                ):
                    read()

    def test_malformed_live_issue_is_not_coerced_to_eligible(self) -> None:
        """Unexpected types must not turn into an open, unlabelled issue."""
        cases: tuple[Any, ...] = (
            None,
            {},
            {"pr": False, "state": "open", "labels": ""},
            {"pr": None, "state": "open", "labels": []},
            {"pr": False, "state": "open", "labels": [None]},
        )
        for data in cases:
            with (
                self.subTest(data=data),
                fake_run_gh(return_value=json.dumps(data)),
                self.assertRaises(github.GitHubError),
            ):
                github.read_issue("owner/repo", 1)

    def test_valid_live_issue(self) -> None:
        """The live read preserves labels and PR status without mutation."""
        with fake_run_gh(
            return_value=json.dumps(
                {"pr": True, "state": "open", "labels": ["human-label"]}
            ),
        ):
            self.assertEqual(
                github.read_issue("owner/repo", 1),
                github.LiveIssue(True, "open", frozenset({"human-label"})),
            )

    def test_configuration_unavailability_requires_opt_in(self) -> None:
        """Live/default reads fail; only explicit dry-run reads may degrade."""
        readers: tuple[tuple[Any, dict[str, Any] | set[str]], ...] = (
            (github.load_field_options, {}),
            (github.load_issue_types, set()),
        )
        for message in (
            "gh: Not Found (HTTP 404)",
            "gh: Gone (HTTP 410)",
            "gh: Resource not accessible by integration (HTTP 403)",
            "gh: Resource not accessible by personal access token (HTTP 403)",
            "gh: RESOURCE NOT ACCESSIBLE BY INTEGRATION (HTTP 403)",
        ):
            for read, empty in readers:
                error = github.GitHubError(message)
                with (
                    self.subTest(message=message, reader=read),
                    fake_run_gh(side_effect=error),
                ):
                    self.assertTrue(github.absent(error))
                    with self.assertRaises(github.GitHubError) as caught:
                        read("owner")
                    self.assertIs(caught.exception, error)
                    with self.assertRaises(github.GitHubError):
                        read("owner", allow_unavailable=False)
                    self.assertEqual(read("owner", allow_unavailable=True), empty)

    def test_unknown_and_transient_errors_never_degrade(self) -> None:
        """An unknown 403 or abuse limit is not evidence of missing permissions."""
        for message in (
            "gh: Forbidden (HTTP 403)",
            "gh: unexpected failure (HTTP 403)",
            "gh: You have triggered an abuse detection mechanism (HTTP 403)",
            "gh: You have exceeded a secondary limit (HTTP 403)",
            "gh: secondary rate limit (HTTP 403)",
            "gh: secondary rate-limit (HTTP 403)",
            "gh: Resource not accessible by integration; rate limit (HTTP 403)",
            "gh: Resource not accessible by integration; abuse detection (HTTP 403)",
            "gh: unavailable (HTTP 500)",
            "gh: Too Many Requests (HTTP 429)",
            "gh: Bad credentials (HTTP 401)",
            "timeout",
        ):
            error = github.GitHubError(message)
            self.assertFalse(github.absent(error), message)
            for read in (github.load_field_options, github.load_issue_types):
                for allow_unavailable in (False, True):
                    with (
                        self.subTest(
                            message=message,
                            reader=read,
                            allow_unavailable=allow_unavailable,
                        ),
                        fake_run_gh(side_effect=error),
                        self.assertRaises(github.GitHubError) as caught,
                    ):
                        read("owner", allow_unavailable=allow_unavailable)
                    self.assertIs(caught.exception, error)

    def test_successful_empty_configuration_is_not_a_read_failure(self) -> None:
        """Do not change policy for organisations that genuinely define nothing."""
        for allow_unavailable in (False, True):
            with (
                self.subTest(allow_unavailable=allow_unavailable),
                fake_run_gh(return_value="[[]]"),
            ):
                self.assertEqual(
                    github.load_field_options(
                        "owner", allow_unavailable=allow_unavailable
                    ),
                    {},
                )
                self.assertEqual(
                    github.load_issue_types(
                        "owner", allow_unavailable=allow_unavailable
                    ),
                    set(),
                )

    def test_issue_priority_unavailability_still_fails(self) -> None:
        """Dry-run config tolerance must never weaken the human-priority guard."""
        with (
            fake_run_gh(side_effect=github.GitHubError("gh: Not Found (HTTP 404)")),
            self.assertRaises(github.GitHubError),
        ):
            github.existing_priority("owner/repo", 1)


class GitHubWriteTests(unittest.TestCase):
    """Assert exact permitted mutations at the subprocess boundary."""

    def setUp(self) -> None:
        """Capture every command instead of executing gh."""
        runner = patch.object(
            plumbing.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["gh"], 0, "", ""),
        )
        self.gh_run = runner.start()
        self.addCleanup(runner.stop)
        sleeper = patch.object(plumbing.time, "sleep")
        self.sleep = sleeper.start()
        self.addCleanup(sleeper.stop)
        self.action: dict[str, Any] = {
            "repository": "owner/repo",
            "issue": 1,
            "labels": ["documentation"],
            "priority": "High",
            "type": "Task",
            "migrate_enhancement": True,
        }
        self.fields = {"Priority": {github.FIELD_ID_KEY: 10, "High": 20}}

    def test_writes_preserve_human_labels_and_other_fields(self) -> None:
        """Only enhancement may be removed; Priority is POSTed by option name."""
        github.apply(self.action, self.fields)
        commands = [call.args[0] for call in self.gh_run.call_args_list]
        self.assertEqual(
            commands,
            [
                [
                    "gh",
                    "issue",
                    "edit",
                    "1",
                    "--repo",
                    "owner/repo",
                    "--remove-label",
                    "enhancement",
                    "--add-label",
                    "feature",
                ],
                [
                    "gh",
                    "issue",
                    "edit",
                    "1",
                    "--repo",
                    "owner/repo",
                    "--add-label",
                    "documentation",
                ],
                ["gh", "issue", "edit", "1", "--repo", "owner/repo", "--type", "Task"],
                [
                    "gh",
                    "api",
                    "--method",
                    "POST",
                    "repos/owner/repo/issues/1/issue-field-values",
                    "--input",
                    "-",
                    "--header",
                    "X-GitHub-Api-Version: 2026-03-10",
                ],
            ],
        )
        self.assertEqual(
            json.loads(self.gh_run.call_args_list[-1].kwargs["input"]),
            {"issue_field_values": [{"field_id": 10, "value": "High"}]},
        )
        for call in self.gh_run.call_args_list:
            self.assertFalse(call.kwargs.get("shell", False))
            self.assertTrue(call.kwargs["capture_output"])
            self.assertEqual(call.kwargs["timeout"], plumbing.TIMEOUT_SECONDS)

    def test_failed_write_stops_subsequent_mutations(self) -> None:
        """No later mutation should run after a partial failure."""
        self.gh_run.side_effect = [
            subprocess.CompletedProcess(["gh"], 0, "", ""),
            subprocess.CompletedProcess(["gh"], 1, "", "gh: forbidden (HTTP 403)"),
        ]
        with self.assertRaises(github.GitHubError):
            github.apply(self.action, self.fields)
        self.assertEqual(self.gh_run.call_count, 2)

    def test_process_launch_failure_becomes_github_error(self) -> None:
        """Missing gh and OS errors must use the same failed outcome as HTTP errors."""
        self.gh_run.side_effect = FileNotFoundError("gh is missing")
        with self.assertRaises(github.GitHubError):
            github.run_gh(["api", "repos/owner/repo"])
        with self.assertRaises(github.GitHubError):
            github.add_fields("owner/repo", "1", "{}")

    def test_timeouts_fail_writes_once_and_reads_after_the_retry_budget(self) -> None:
        """A timed-out write is never repeated; a read retries, then fails closed."""
        operations = (
            (
                partial(github.api_list, "repos/owner/repo/labels"),
                plumbing.READ_ATTEMPTS,
            ),
            (partial(github.add_fields, "owner/repo", "1", "{}"), 1),
            (partial(github.apply, self.action, self.fields), 1),
        )
        for operation, attempts in operations:
            with self.subTest(operation=operation):
                self.gh_run.reset_mock()
                self.sleep.reset_mock()
                error = subprocess.TimeoutExpired(
                    ["gh"],
                    plumbing.TIMEOUT_SECONDS,
                    output=b"partial response",
                    stderr=b"::error::injected",
                )
                self.gh_run.side_effect = error
                with self.assertRaisesRegex(
                    github.GitHubError, f"timed out after {plumbing.TIMEOUT_SECONDS}"
                ) as caught:
                    operation()
                self.assertIs(caught.exception.__cause__, error)
                self.assertFalse(github.absent(caught.exception))
                self.assertEqual(self.gh_run.call_count, attempts)
                self.assertEqual(self.sleep.call_count, attempts - 1)
                self.assertEqual(
                    self.gh_run.call_args.kwargs["timeout"], plumbing.TIMEOUT_SECONDS
                )

    def test_failed_field_write_raises(self) -> None:
        """The POST is not a success just because earlier labels were written."""
        self.gh_run.return_value = subprocess.CompletedProcess(
            ["gh"], 1, "", "gh: unavailable (HTTP 503)"
        )
        with self.assertRaises(github.GitHubError) as caught:
            github.add_fields("owner/repo", "1", "{}")
        self.assertEqual(caught.exception.status, 503)


if __name__ == "__main__":
    unittest.main()
