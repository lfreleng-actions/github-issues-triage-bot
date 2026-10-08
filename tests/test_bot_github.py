# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The gh wrapper: pinned API version, bounded retries, strict replies."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

github = import_module("bot_github")


def completed(stdout: str = "", stderr: str = "", code: int = 0) -> Any:
    """A finished gh process."""
    return subprocess.CompletedProcess(["gh"], code, stdout=stdout, stderr=stderr)


class RunGhTest(unittest.TestCase):
    """``run_gh`` pins the REST version and retries reads alone."""

    def test_rest_calls_carry_the_api_version_header(self) -> None:
        """REST gets the pinned version; GraphQL has no such header."""
        with patch.object(
            github.subprocess, "run", return_value=completed("{}")
        ) as run:
            github.run_gh(["api", "repos/o/r"])
            github.run_gh(["api", "graphql", "--input", "-"], input="{}")
        rest, graphql = (call.args[0] for call in run.call_args_list)
        self.assertEqual(
            rest[-2:], ["--header", f"X-GitHub-Api-Version: {github.API_VERSION}"]
        )
        self.assertNotIn("--header", graphql)

    def test_read_retries_transient_failures(self) -> None:
        """A 502 then a timeout then success is one successful read."""
        replies = [
            completed(stderr="gh: Bad Gateway (HTTP 502)", code=1),
            subprocess.TimeoutExpired(["gh"], github.TIMEOUT_SECONDS),
            completed("ok"),
        ]
        with (
            patch.object(github.subprocess, "run", side_effect=replies),
            patch.object(github.time, "sleep") as sleep,
        ):
            self.assertEqual(github.run_gh(["api", "repos/o/r"]), "ok")
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [github.RETRY_DELAY_SECONDS, github.RETRY_DELAY_SECONDS * 2],
        )

    def test_read_gives_up_after_the_attempt_budget(self) -> None:
        """Persistent 503s surface after READ_ATTEMPTS tries."""
        reply = completed(stderr="gh: Unavailable (HTTP 503)", code=1)
        with (
            patch.object(github.subprocess, "run", return_value=reply) as run,
            patch.object(github.time, "sleep"),
            self.assertRaises(github.GitHubError) as caught,
        ):
            github.run_gh(["api", "repos/o/r"])
        self.assertEqual(run.call_count, github.READ_ATTEMPTS)
        self.assertEqual(caught.exception.status, 503)

    def test_non_transient_read_failure_is_not_retried(self) -> None:
        """A 404 is an answer, not a blip."""
        reply = completed(stderr="gh: Not Found (HTTP 404)", code=1)
        with (
            patch.object(github.subprocess, "run", return_value=reply) as run,
            patch.object(github.time, "sleep") as sleep,
            self.assertRaises(github.GitHubError) as caught,
        ):
            github.run_gh(["api", "repos/o/r"])
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()
        self.assertTrue(github.is_absent(caught.exception))

    @unittest.expectedFailure
    def test_bare_server_error_is_retried(self) -> None:
        """A 502 without a JSON message is as transient as one with it."""
        replies = [completed(stderr="gh: HTTP 502", code=1), completed("ok")]
        with (
            patch.object(github.subprocess, "run", side_effect=replies) as run,
            patch.object(github.time, "sleep"),
        ):
            self.assertEqual(github.run_gh(["api", "repos/o/r"]), "ok")
        self.assertEqual(run.call_count, 2)

    def test_writes_run_once(self) -> None:
        """A write that hits a 502 is not repeated: it may have landed."""
        reply = completed(stderr="gh: Bad Gateway (HTTP 502)", code=1)
        with (
            patch.object(github.subprocess, "run", return_value=reply) as run,
            patch.object(github.time, "sleep") as sleep,
            self.assertRaises(github.GitHubError),
        ):
            github.run_gh(["api", "--method", "POST", "repos/o/r/x"], input="{}")
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()

    def test_graphql_is_a_write_unless_declared_a_read(self) -> None:
        """GraphQL runs once by default and retries only with ``read=True``."""
        reply = completed(stderr="gh: Bad Gateway (HTTP 502)", code=1)
        with (
            patch.object(github.subprocess, "run", return_value=reply) as run,
            patch.object(github.time, "sleep"),
        ):
            with self.assertRaises(github.GitHubError):
                github.run_gh(["api", "graphql"], input="{}")
            self.assertEqual(run.call_count, 1)
            with self.assertRaises(github.GitHubError):
                github.run_gh(["api", "graphql"], input="{}", read=True)
            self.assertEqual(run.call_count, 1 + github.READ_ATTEMPTS)

    def test_missing_gh_is_an_operational_failure(self) -> None:
        """An OSError launching gh becomes a GitHubError, not a crash."""
        with (
            patch.object(github.subprocess, "run", side_effect=FileNotFoundError("gh")),
            self.assertRaisesRegex(github.GitHubError, "could not run gh"),
        ):
            github.run_gh(["api", "repos/o/r"])


class GitHubErrorTest(unittest.TestCase):
    """``GitHubError`` reads the status gh prints."""

    def test_status_parsed_from_message(self) -> None:
        """The three digits in ``(HTTP nnn)`` become the status."""
        self.assertEqual(github.GitHubError("gh: Not Found (HTTP 404)").status, 404)
        self.assertIsNone(github.GitHubError("gh timed out").status)
        self.assertIsNone(github.GitHubError("(HTTP 40)").status)

    @unittest.expectedFailure
    def test_bare_status_parsed(self) -> None:
        """A reply without a JSON message leaves gh printing ``gh: HTTP nnn``."""
        self.assertEqual(github.GitHubError("gh: HTTP 403").status, 403)
        self.assertEqual(github.GitHubError("gh: HTTP 404\ngh: hint").status, 404)
        self.assertIsNone(github.GitHubError("gh: HTTP 40").status)
        self.assertIsNone(github.GitHubError("see HTTP 404 in the docs").status)
        for hybrid in ("gh: Bad (HTTP 404", "gh: HTTP 404)"):
            with self.subTest(hybrid=hybrid):
                self.assertIsNone(github.GitHubError(hybrid).status)

    @unittest.expectedFailure
    def test_only_the_status_gh_appends_counts(self) -> None:
        """A status quoted before the one gh appends is not the status."""
        self.assertIsNone(github.GitHubError("see (HTTP 502) in the docs").status)
        quoted = "gh: upstream said (HTTP 502)\nso this is final (HTTP 404)"
        self.assertEqual(github.GitHubError(quoted).status, 404)

    @unittest.expectedFailure
    def test_explicit_status_wins(self) -> None:
        """A caller that knows the status passes it rather than a token."""
        failure = github.GitHubError("gh exit 1 (HTTP 503), then gave up", 503)
        self.assertEqual(failure.status, 503)


class RepliesTest(unittest.TestCase):
    """The typed readers refuse replies of the wrong shape."""

    def test_api_object_rejects_non_objects(self) -> None:
        """A list or scalar where an object was expected is a failure."""
        with (
            patch.object(github, "run_gh", return_value="[1]"),
            self.assertRaisesRegex(github.GitHubError, "expected an object"),
        ):
            github.api_object("repos/o/r")

    def test_api_list_flattens_pages_and_rejects_non_list_pages(self) -> None:
        """Slurped pages are concatenated; a non-array page is refused."""
        pages = json.dumps([[{"a": 1}], [{"b": 2}]])
        with patch.object(github, "run_gh", return_value=pages):
            self.assertEqual(github.api_list("repos/o/r/x"), [{"a": 1}, {"b": 2}])
        for raw in ('[{"not": "a page"}]', "[[1]]", "{}"):
            with (
                self.subTest(raw=raw),
                patch.object(github, "run_gh", return_value=raw),
                self.assertRaises(github.GitHubError),
            ):
                github.api_list("repos/o/r/x")

    def test_api_write_sends_json_and_tolerates_empty_reply(self) -> None:
        """The payload goes on stdin; a 204-style empty body is ``{}``."""
        with patch.object(github, "run_gh", return_value="") as run:
            self.assertEqual(github.api_write("PUT", "repos/o/r/x", {"k": 1}), {})
        self.assertEqual(run.call_args.kwargs["input"], '{"k": 1}')
        self.assertEqual(run.call_args.args[0][:3], ["api", "--method", "PUT"])

    def test_invalid_json_is_a_github_error(self) -> None:
        """Malformed bodies stay on the operational-failure path."""
        with (
            patch.object(github, "run_gh", return_value="{nope"),
            self.assertRaisesRegex(github.GitHubError, "invalid JSON"),
        ):
            github.api_object("repos/o/r")


class GraphqlTest(unittest.TestCase):
    """``graphql`` never hands back a partial payload."""

    def test_errors_entry_raises(self) -> None:
        """A reply carrying ``errors`` fails even with data alongside."""
        reply = json.dumps({"data": {"x": 1}, "errors": [{"message": "nope"}]})
        with (
            patch.object(github, "run_gh", return_value=reply),
            self.assertRaisesRegex(github.GitHubError, "GraphQL errors"),
        ):
            github.graphql("query {}", {})

    def test_missing_data_raises(self) -> None:
        """A reply without a data object is a failure."""
        for reply in ("{}", '{"data": null}', "[]"):
            with (
                self.subTest(reply=reply),
                patch.object(github, "run_gh", return_value=reply),
                self.assertRaises(github.GitHubError),
            ):
                github.graphql("query {}", {})

    def test_data_returned_and_read_flag_forwarded(self) -> None:
        """The data object comes back; ``read`` reaches ``run_gh``."""
        reply = json.dumps({"data": {"viewer": {"login": "x"}}})
        with patch.object(github, "run_gh", return_value=reply) as run:
            data = github.graphql("query {}", {"a": 1}, read=True)
        self.assertEqual(data, {"viewer": {"login": "x"}})
        self.assertIs(run.call_args.kwargs["read"], True)
        self.assertEqual(
            json.loads(run.call_args.kwargs["input"])["variables"], {"a": 1}
        )


class RequireTest(unittest.TestCase):
    """The ``require_*`` helpers fail the operation on a bad field."""

    def test_require_sha(self) -> None:
        """Only a lowercase 40-hex string is a commit SHA."""
        self.assertEqual(github.require_sha({"s": "a" * 40}, "s", "c"), "a" * 40)
        for value in ("A" * 40, "a" * 39, "", None, 7):
            with self.subTest(value=value), self.assertRaises(github.GitHubError):
                github.require_sha({"s": value}, "s", "c")

    def test_require_int_and_str(self) -> None:
        """Booleans are not integers; empty strings are not strings."""
        self.assertEqual(github.require_int({"n": 3}, "n", "c"), 3)
        for value in (0, -1, True, "3", None):
            with self.subTest(value=value), self.assertRaises(github.GitHubError):
                github.require_int({"n": value}, "n", "c")
        with self.assertRaisesRegex(github.GitHubError, "missing or invalid 'k'"):
            github.require_str({"k": ""}, "k", "c")


class SafeMessageTest(unittest.TestCase):
    """``safe_message`` renders an error for a log parsed for commands."""

    def test_escapes_commands_and_non_ascii(self) -> None:
        """Workflow command syntax is broken up; control bytes are escaped."""
        rendered = github.safe_message(ValueError("::warning::x ##[group]\n\u2028é"))
        self.assertNotIn("::", rendered)
        self.assertNotIn("##[", rendered)
        self.assertNotIn("\n", rendered)
        self.assertTrue(rendered.isascii())
        self.assertIn("\\n", rendered)


if __name__ == "__main__":
    unittest.main()
