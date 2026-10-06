# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline regression tests for proposal orchestration and runner logs."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

apply_triage = import_module("apply_triage")
github = import_module("triage_github")
plumbing = import_module("bot_github")
policy = import_module("triage_policy")
GitHubError = github.GitHubError
LiveIssue = github.LiveIssue
Rejected = github.Rejected
existing_priority = github.existing_priority
TAXONOMY = policy.TAXONOMY
Context = policy.Context


class ApplyTriageTests(unittest.TestCase):
    """Exercise the real validator while keeping all GitHub access mocked."""

    def setUp(self) -> None:
        """Supply one eligible issue and forbid accidental subprocesses."""
        self.ctx = Context("owner", None, set(), False, {}, set(), {("owner/repo", 1)})
        self.item: dict[str, Any] = {
            "repository": "owner/repo",
            "issue": 1,
            "labels": ["bug"],
            "priority": None,
            "type": None,
            "rationale": "A reproducible defect",
        }
        for target, value in (
            ("triage_policy.read_issue", LiveIssue(False, "open", frozenset())),
            ("triage_policy.repo_labels", set(TAXONOMY)),
            ("triage_policy.existing_priority", None),
        ):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        guard = patch(
            "bot_github.subprocess.run",
            side_effect=AssertionError("unexpected gh call"),
        )
        guard.start()
        self.addCleanup(guard.stop)

    def test_log_values_disable_commands_even_mid_line(self) -> None:
        """Keep modern command delimiters inert regardless of log placement."""
        for value in (
            "::add-mask::hidden",
            "prefix ::error::bad",
            "\n::stop-commands::x",
            "\r\x1b[0m:::error::bad",
        ):
            with self.subTest(value=value):
                rendered = apply_triage.one_line(value)
                self.assertNotIn("::", rendered)
                self.assertIsNone(apply_triage.CONTROL_RE.search(rendered))

    def test_legacy_commands_are_inert_even_mid_line(self) -> None:
        """The runner's legacy parser searches anywhere for ##[command]."""
        for value in ("##[add-mask]hidden", "prefix ##[error]bad", "\n##[group]hidden"):
            with self.subTest(value=value):
                self.assertNotIn("##[", apply_triage.one_line(value))

    def test_report_sanitizes_every_untrusted_output_path(self) -> None:
        """Escalations, drops, refusals and failures must all be inert log text."""
        attack = "prefix ::add-mask::hidden\n::error::bad ##[add-mask]hidden"
        action = {
            **self.item,
            "escalate": True,
            "dropped": [attack],
            "rationale": attack,
        }
        entry = {"repository": attack, "issue": attack, "reason": attack}
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit):
            apply_triage.report(
                [action],
                [entry],
                [entry],
                {"proposed": 3, "applied": 1, "rejected": 1, "failed": 1},
                False,
            )
        self.assertNotIn("::", output.getvalue())
        self.assertNotIn("##[", output.getvalue())
        self.assertIn("ESCALATE", output.getvalue())
        self.assertIn("FAILED", output.getvalue())

    def test_dry_run_validates_without_writes(self) -> None:
        """A dry run still validates, but never invokes the write path."""
        with patch.object(apply_triage, "apply") as write:
            applied, rejected, failed = apply_triage.process(
                [self.item], self.ctx, True
            )
        self.assertEqual(len(applied), 1)
        self.assertEqual((rejected, failed), ([], []))
        write.assert_not_called()

    def test_duplicates_rejected_before_any_write(self) -> None:
        """Case variants of a repeated target cannot accumulate extra labels."""
        with patch.object(apply_triage, "apply") as write:
            applied, rejected, failed = apply_triage.process(
                [self.item, {**self.item, "repository": "OWNER/REPO"}], self.ctx, False
            )
        self.assertEqual((applied, failed), ([], []))
        self.assertEqual(len(rejected), 2)
        write.assert_not_called()

    def test_malformed_neighbor_does_not_hide_valid_issue(self) -> None:
        """Unhashable and boolean issue numbers remain per-item refusals."""
        items: list[Any] = [
            None,
            {**self.item, "issue": []},
            {**self.item, "issue": True},
            self.item,
        ]
        applied, rejected, failed = apply_triage.process(items, self.ctx, True)
        self.assertEqual(len(applied), 1)
        self.assertEqual(len(rejected), 3)
        self.assertEqual(failed, [])

    def test_later_page_priority_prevents_all_writes(self) -> None:
        """Exercise pagination through process(), not just the field reader."""
        pages = [
            [{"issue_field_name": "Effort", "value": 3}],
            [
                {
                    "issue_field_name": "Priority",
                    "value": 1,
                    "single_select_option": {"name": "Urgent"},
                }
            ],
        ]
        with (
            patch("triage_policy.existing_priority", existing_priority),
            patch(
                "bot_github.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    ["gh"], 0, json.dumps(pages), ""
                ),
            ) as read,
            patch.object(apply_triage, "apply") as write,
        ):
            applied, rejected, failed = apply_triage.process(
                [self.item], self.ctx, False
            )
        self.assertEqual((applied, failed), ([], []))
        self.assertEqual(len(rejected), 1)
        self.assertIn("priority already set to Urgent", rejected[0]["reason"])
        read.assert_called_once_with(
            [
                "gh",
                "api",
                "repos/owner/repo/issues/1/issue-field-values",
                "--paginate",
                "--slurp",
                "--header",
                "X-GitHub-Api-Version: 2026-03-10",
            ],
            input=None,
            capture_output=True,
            text=True,
            check=False,
            timeout=plumbing.TIMEOUT_SECONDS,
        )
        write.assert_not_called()

    def test_read_and_partial_write_errors_are_failures_not_refusals(self) -> None:
        """An unavailable check or interrupted write cannot report green."""
        for target, error in (
            ("triage_policy.existing_priority", GitHubError("timeout")),
            ("apply_triage.apply", GitHubError("write failed")),
            ("apply_triage.apply", Rejected("write interrupted")),
        ):
            with (
                self.subTest(target=target, error=error),
                patch(target, side_effect=error),
            ):
                applied, rejected, failed = apply_triage.process(
                    [self.item], self.ctx, False
                )
            self.assertEqual((applied, rejected), ([], []))
            self.assertEqual(len(failed), 1)

    def test_malformed_api_response_is_recorded_before_exit(self) -> None:
        """The CLI persists a failed result even when gh returns invalid JSON."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proposal = root / "proposal.md"
            snapshot = root / "before.json"
            output = root / "result.json"
            proposal.write_text(
                "```json\n" + json.dumps({"proposals": [self.item]}) + "\n```\n",
                encoding="utf-8",
            )
            snapshot.write_text("[]", encoding="utf-8")
            argv = [
                "apply_triage.py",
                "--proposal",
                str(proposal),
                "--snapshot",
                str(snapshot),
                "--output-json",
                str(output),
            ]
            # Use the real field reader instead of the policy mock from setUp.

            with (
                patch.object(sys, "argv", argv),
                patch.object(apply_triage, "build_context", return_value=self.ctx),
                patch("triage_policy.existing_priority", existing_priority),
                patch("bot_github.run_gh", return_value="not json"),
                redirect_stdout(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                apply_triage.main()
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                result["counts"],
                {"proposed": 1, "applied": 0, "rejected": 0, "failed": 1},
            )

    def test_cli_configuration_degradation_is_dry_run_only(self) -> None:
        """The real CLI/context/loaders must stop live writes on either failed read."""
        definitions = [
            [{"id": 10, "name": "Priority", "options": [{"id": 1, "name": "High"}]}],
            [{"name": "Bug", "is_enabled": True}],
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proposal = root / "proposal.md"
            snapshot = root / "before.json"
            output = root / "result.json"
            proposal.write_text(
                "```json\n"
                + json.dumps(
                    {"proposals": [{**self.item, "priority": "High", "type": "Bug"}]}
                )
                + "\n```\n",
                encoding="utf-8",
            )
            snapshot.write_text(
                json.dumps(
                    [{"repository": {"nameWithOwner": "owner/repo"}, "number": 1}]
                ),
                encoding="utf-8",
            )
            argv = [
                "apply_triage.py",
                "--proposal",
                str(proposal),
                "--snapshot",
                str(snapshot),
                "--output-json",
                str(output),
            ]
            for message in (
                "gh: Resource not accessible by integration (HTTP 403)",
                "gh: Not Found (HTTP 404)",
                "gh: Gone (HTTP 410)",
            ):
                for failed_read in (0, 1):
                    for dry_run in (False, True):
                        responses: list[Any] = list(definitions)
                        responses[failed_read] = GitHubError(message)
                        output.unlink(missing_ok=True)
                        with (
                            self.subTest(
                                message=message,
                                failed_read=failed_read,
                                dry_run=dry_run,
                            ),
                            patch.object(
                                sys, "argv", argv + (["--dry-run"] if dry_run else [])
                            ),
                            patch.dict(
                                policy.os.environ, {"TRIAGE_ORG": "owner"}, clear=True
                            ),
                            patch.object(github, "api_list", side_effect=responses),
                            patch.object(apply_triage, "apply") as write,
                            redirect_stdout(io.StringIO()),
                        ):
                            if dry_run:
                                apply_triage.main()
                                result = json.loads(output.read_text(encoding="utf-8"))
                                self.assertTrue(result["dry_run"])
                                self.assertEqual(result["counts"]["applied"], 1)
                                action = result["applied"][0]
                                self.assertEqual(
                                    action["priority"],
                                    None if failed_read == 0 else "High",
                                )
                                self.assertEqual(
                                    action["type"], None if failed_read == 1 else "Bug"
                                )
                                self.assertEqual(len(action["dropped"]), 1)
                            else:
                                with self.assertRaisesRegex(
                                    SystemExit,
                                    "Could not read the organisation's configuration",
                                ):
                                    apply_triage.main()
                                self.assertFalse(output.exists())
                            write.assert_not_called()

    def test_configuration_error_exit_is_safe_for_runner(self) -> None:
        """Startup errors bypass report(), but still carry untrusted API text."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proposal = root / "proposal.md"
            snapshot = root / "before.json"
            proposal.write_text('```json\n{"proposals": []}\n```', encoding="utf-8")
            snapshot.write_text("[]", encoding="utf-8")
            argv = [
                "apply_triage.py",
                "--proposal",
                str(proposal),
                "--snapshot",
                str(snapshot),
                "--output-json",
                str(root / "result.json"),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    apply_triage,
                    "build_context",
                    side_effect=GitHubError("::error::injected"),
                ),
                self.assertRaises(SystemExit) as caught,
            ):
                apply_triage.main()
            self.assertNotIn("::", str(caught.exception))


class ApplyCliTests(unittest.TestCase):
    """Exercise input guards before any configuration reads or live mutations."""

    def setUp(self) -> None:
        """Provide real CLI inputs and fail on unexpected GitHub access."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.proposal = root / "proposal.md"
        self.snapshot = root / "before.json"
        self.output = root / "result.json"
        self.proposal.write_text('```json\n{"proposals": []}\n```', encoding="utf-8")
        self.snapshot.write_text("[]", encoding="utf-8")
        self.argv = [
            "apply_triage.py",
            "--proposal",
            str(self.proposal),
            "--snapshot",
            str(self.snapshot),
            "--output-json",
            str(self.output),
        ]
        arguments = patch.object(sys, "argv", self.argv)
        arguments.start()
        self.addCleanup(arguments.stop)
        environment = patch.dict(policy.os.environ, {"TRIAGE_ORG": "owner"}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        runner = patch.object(
            plumbing.subprocess, "run", side_effect=AssertionError("unexpected gh call")
        )
        self.runner = runner.start()
        self.addCleanup(runner.stop)

    def assert_input_failure(self) -> str:
        """Require exit 1, safe diagnostics and no calls or partial result."""
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            apply_triage.main()
        self.assertEqual(caught.exception.code, 1)
        message = stderr.getvalue()
        self.assertIn("Could not read the agent's proposal", message)
        self.assertNotIn("::", message)
        self.assertNotIn("##[", message)
        self.assertNotIn("Traceback", message)
        self.assertIsNone(apply_triage.CONTROL_RE.search(message.rstrip("\n")))
        self.runner.assert_not_called()
        self.assertFalse(self.output.exists())
        return message

    def write_proposals(self, items: Any) -> None:
        """Put a proposal value through the real fenced JSON parser."""
        self.proposal.write_text(
            "```json\n" + json.dumps({"proposals": items}) + "\n```",
            encoding="utf-8",
        )

    def test_proposals_type_is_checked_before_configuration(self) -> None:
        """Even oversized non-list values fail as invalid shape before API reads."""
        empty: dict[str, Any] = {}
        invalid: tuple[Any, ...] = (
            None,
            1,
            "x" * 101,
            {str(i): empty for i in range(101)},
        )
        for items in invalid:
            for dry_run in (False, True):
                with (
                    self.subTest(items=items, dry_run=dry_run),
                    patch.object(
                        sys, "argv", self.argv + (["--dry-run"] if dry_run else [])
                    ),
                ):
                    self.write_proposals(items)
                    self.assertIn("not a list", self.assert_input_failure())

    def test_101_proposals_stop_before_configuration_or_writes(self) -> None:
        """An oversized batch fails in full, including repeated targets and dry runs."""
        for items in ([{"issue": i} for i in range(1, 102)], [{"issue": 1}] * 101):
            for dry_run in (False, True):
                with (
                    self.subTest(duplicates=items[0] == items[-1], dry_run=dry_run),
                    patch.object(
                        sys, "argv", self.argv + (["--dry-run"] if dry_run else [])
                    ),
                ):
                    self.write_proposals(items)
                    message = self.assert_input_failure()
                    self.assertIn("101", message)
                    self.assertIn("100", message)
                    self.assertIn("repository", message)
                    self.assertIn("exclusions", message)

    def test_100_proposals_are_applied_without_sampling(self) -> None:
        """The inclusive boundary reaches the real validator and every permitted write."""
        self.write_proposals(
            [
                {
                    "repository": "owner/repo",
                    "issue": number,
                    "labels": ["bug"],
                    "priority": None,
                    "type": None,
                }
                for number in range(1, 101)
            ]
        )
        self.snapshot.write_text(
            json.dumps(
                [
                    {"repository": {"nameWithOwner": "owner/repo"}, "number": number}
                    for number in range(1, 101)
                ]
            ),
            encoding="utf-8",
        )

        def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            """Supply readable configuration and eligible issues, capturing writes."""
            if "--jq" in args:
                response = '{"pr": false, "state": "open", "labels": []}'
            elif "repos/owner/repo/labels" in args:
                response = '[[{"name": "bug"}]]'
            else:
                response = "[[]]"
            return subprocess.CompletedProcess(args, 0, response, "")

        self.runner.side_effect = run
        with redirect_stdout(io.StringIO()):
            apply_triage.main()
        result = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(
            result["counts"],
            {"proposed": 100, "applied": 100, "rejected": 0, "failed": 0},
        )
        commands = [call.args[0] for call in self.runner.call_args_list]
        self.assertEqual(
            [args[2] for args in commands[:2]],
            ["orgs/owner/issue-fields", "orgs/owner/issue-types"],
        )
        self.assertEqual(
            [args for args in commands if args[1:3] == ["issue", "edit"]],
            [
                [
                    "gh",
                    "issue",
                    "edit",
                    str(number),
                    "--repo",
                    "owner/repo",
                    "--add-label",
                    "bug",
                ]
                for number in range(1, 101)
            ],
        )

    def test_issue_read_timeout_is_recorded_as_a_failure(self) -> None:
        """A timed-out live guard records a failed outcome without attempting writes."""
        self.write_proposals([{"repository": "owner/repo", "issue": 1}])
        self.snapshot.write_text(
            '[{"repository":{"nameWithOwner":"owner/repo"},"number":1}]',
            encoding="utf-8",
        )
        timeout = subprocess.TimeoutExpired(["gh"], plumbing.TIMEOUT_SECONDS)
        self.runner.side_effect = [
            subprocess.CompletedProcess(["gh"], 0, "[[]]", ""),
            subprocess.CompletedProcess(["gh"], 0, "[[]]", ""),
            *[timeout] * plumbing.READ_ATTEMPTS,
        ]
        with (
            patch.object(plumbing.time, "sleep"),
            redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            apply_triage.main()
        result = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(
            result["counts"], {"proposed": 1, "applied": 0, "rejected": 0, "failed": 1}
        )
        self.assertIn(
            f"timed out after {plumbing.TIMEOUT_SECONDS} seconds",
            result["failed"][0]["reason"],
        )
        self.assertEqual(self.runner.call_count, 2 + plumbing.READ_ATTEMPTS)
        for call in self.runner.call_args_list:
            self.assertEqual(call.args[0][:2], ["gh", "api"])
            self.assertNotIn("--method", call.args[0])

    def test_invalid_proposal_bytes_and_json_fail_safely(self) -> None:
        """An untrusted summary cannot escape through a decoder traceback."""
        for raw in (
            b"\xff\n::error::injected ##[error]injected",
            b"```json\n{\n```",
            b'```json\n{"proposals": []}',
        ):
            with self.subTest(raw=raw):
                self.proposal.write_bytes(raw)
                self.assert_input_failure()

    def test_proposal_read_errors_sanitize_untrusted_diagnostics(self) -> None:
        """File errors and Unicode errors use the same controlled CLI failure."""
        attack = "::error::injected\n##[error]injected\x1b"
        for error in (OSError(attack), UnicodeError(attack)):
            with (
                self.subTest(error=error),
                patch.object(Path, "read_text", side_effect=error),
            ):
                self.assert_input_failure()


if __name__ == "__main__":
    unittest.main()
