# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline regressions for untrusted proposals and triage policy."""

from __future__ import annotations

import sys
import unittest
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

policy = import_module("triage_policy")
github = import_module("triage_github")
FIELD_ID_KEY = github.FIELD_ID_KEY
GitHubError = github.GitHubError
LiveIssue = github.LiveIssue
Rejected = github.Rejected


class ProposalParsingTests(unittest.TestCase):
    """Never substitute an earlier example for an unreadable final proposal."""

    example = '```json\n{"proposals": [{"issue": 123}]}\n```\n'

    def test_final_proposal_wins_over_prompt_example(self) -> None:
        """Both ordinary and CRLF fences may carry the final answer."""
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=newline):
                final = newline.join(("```json", '{"proposals": []}', "```"))
                self.assertEqual(
                    policy.extract_proposal(self.example + final), {"proposals": []}
                )

    def test_malformed_final_fence_never_falls_back(self) -> None:
        """Missing, mismatched and malformed fences must fail closed."""
        endings = (
            '```json\n{"proposals": []}',
            "```json",
            '```json\n{"proposals": []}\n``',
            '```json\n{"proposals": []}\n``` trailing',
            '```json {"proposals": []}\n```',
            "```text\nnot a proposal\n```",
            '~~~json\n{"proposals": []}',
            '````json\n{"proposals": []}\n```',
        )
        for ending in endings:
            with self.subTest(ending=ending), self.assertRaises(Rejected):
                policy.extract_proposal(self.example + ending)

    def test_malformed_final_json_never_falls_back(self) -> None:
        """Syntax, root type and actual key membership matter, not substrings."""
        for block in ('{"proposals":', "[]", '{"other": "proposals"}', '["proposals"]'):
            with self.subTest(block=block), self.assertRaises(Rejected):
                policy.extract_proposal(self.example + "```json\n" + block + "\n```\n")

    def test_no_proposal_is_not_an_empty_success(self) -> None:
        """Prose alone cannot authorise any action."""
        with self.assertRaises(Rejected):
            policy.extract_proposal("Nothing to do")


class PolicyTests(unittest.TestCase):
    """Validate hostile proposals against fresh, mocked GitHub state."""

    def setUp(self) -> None:
        """Keep test targets and all reads local and deterministic."""
        self.ctx = policy.Context(
            "owner",
            None,
            set(),
            False,
            {"Priority": {FIELD_ID_KEY: 10, "High": 1, "Medium": 2, "Low": 3}},
            {"Bug", "Feature", "Task"},
            {("owner/repo", 1)},
        )
        self.item: dict[str, Any] = {
            "repository": "owner/repo",
            "issue": 1,
            "labels": ["bug"],
            "priority": "Medium",
            "type": "Bug",
            "rationale": "Reproduced",
        }
        reader = patch.object(
            policy, "read_issue", return_value=LiveIssue(False, "open", frozenset())
        )
        self.read_issue = reader.start()
        self.addCleanup(reader.stop)
        labels = patch.object(
            policy,
            "repo_labels",
            return_value=set(policy.TAXONOMY) | {"enhancement", "wontfix"},
        )
        self.repo_labels = labels.start()
        self.addCleanup(labels.stop)
        priority = patch.object(policy, "existing_priority", return_value=None)
        self.priority = priority.start()
        self.addCleanup(priority.stop)
        guard = patch(
            "bot_github.subprocess.run",
            side_effect=AssertionError("unexpected gh call"),
        )
        guard.start()
        self.addCleanup(guard.stop)

    def test_valid_classification(self) -> None:
        """A permitted proposal retains its intended writes."""
        action = policy.validate(self.item, self.ctx)
        self.assertEqual(
            (action["labels"], action["priority"], action["type"]),
            (["bug"], "Medium", "Bug"),
        )

    def test_scope_rejects_before_live_reads(self) -> None:
        """Paths, wrong owners, excluded repos and absent targets cannot reach gh."""
        for repo in (
            "other/repo",
            "owner/../repo",
            "owner/repo\n",
            "owner/repo?x=1",
            "owner/missing",
        ):
            with self.subTest(repo=repo), self.assertRaises(Rejected):
                policy.validate({**self.item, "repository": repo}, self.ctx)
        self.ctx.only = "different"
        with self.assertRaises(Rejected):
            policy.validate(self.item, self.ctx)
        self.ctx.only = None
        self.ctx.excluded = {"repo"}
        with self.assertRaises(Rejected):
            policy.validate({**self.item, "repository": "OWNER/REPO"}, self.ctx)
        self.read_issue.assert_not_called()

    def test_invalid_issue_numbers_rejected(self) -> None:
        """JSON booleans must not alias issue 1; containers cannot crash validation."""
        numbers: tuple[Any, ...] = (True, False, 0, -1, 1.0, "1", [], {}, None)
        for number in numbers:
            with self.subTest(number=number), self.assertRaises(Rejected):
                policy.validate({**self.item, "issue": number}, self.ctx)
        self.read_issue.assert_not_called()

    def test_required_classification_fields(self) -> None:
        """Missing values are not equivalent to deliberate null choices."""
        for key in ("labels", "priority", "type"):
            item = self.item.copy()
            del item[key]
            with self.subTest(key=key), self.assertRaises(Rejected):
                policy.validate(item, self.ctx)

    def test_live_state_and_human_priority_take_precedence(self) -> None:
        """An issue closed or claimed after the snapshot is left untouched."""
        for live in (
            LiveIssue(True, "open", frozenset()),
            LiveIssue(False, "closed", frozenset()),
            LiveIssue(False, "open", frozenset({"human-label"})),
        ):
            self.read_issue.return_value = live
            with self.subTest(live=live), self.assertRaises(Rejected):
                policy.validate(self.item, self.ctx)
        self.read_issue.return_value = LiveIssue(False, "open", frozenset())
        self.priority.return_value = "Urgent"
        with self.assertRaisesRegex(Rejected, "priority already set"):
            policy.validate({**self.item, "priority": None}, self.ctx)

    def test_api_outage_does_not_authorize_labels(self) -> None:
        """A failed priority read is not evidence that no human set one."""
        self.priority.side_effect = GitHubError("rate limit")
        with self.assertRaises(GitHubError):
            policy.validate(self.item, self.ctx)

    def test_taxonomy_and_field_consistency(self) -> None:
        """Repository membership alone cannot authorise labels or arbitrary types."""
        cases: tuple[dict[str, Any], ...] = (
            {"labels": ["wontfix"]},
            {"labels": ["bug", "feature"]},
            {"labels": ["enhancement"]},
            {"labels": None},
            {"type": "Feature"},
            {"priority": "Urgent"},
            {"priority": []},
            {"escalate": True},
            {"escalate": "true"},
            {"migrate_enhancement": "true"},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                policy.validate({**self.item, **changes}, self.ctx)

    def test_existing_case_variants_count_toward_consistency(self) -> None:
        """GitHub label identity is case-insensitive, including human-applied labels."""
        self.ctx.retriage = True
        for carried, proposed in (
            ({"Feature"}, ["bug"]),
            ({"Documentation", "Code-Quality"}, ["bug"]),
        ):
            self.read_issue.return_value = LiveIssue(False, "open", frozenset(carried))
            with self.subTest(carried=carried), self.assertRaises(Rejected):
                policy.validate({**self.item, "labels": proposed}, self.ctx)

    def test_repo_label_case_variants_are_existing_labels(self) -> None:
        """A canonical taxonomy name can address a differently cased repo label."""
        self.repo_labels.return_value = {"Bug"}
        self.assertEqual(policy.validate(self.item, self.ctx)["labels"], ["bug"])

    def test_migration_counts_feature_and_preserves_other_labels(self) -> None:
        """Only enhancement is removable; feature consumes a taxonomy slot."""
        self.ctx.retriage = True
        self.read_issue.return_value = LiveIssue(
            False, "open", frozenset({"Enhancement", "human-label"})
        )
        action = policy.validate(
            {**self.item, "labels": [], "type": "Feature", "migrate_enhancement": True},
            self.ctx,
        )
        self.assertTrue(action["migrate_enhancement"])
        with self.assertRaises(Rejected):
            policy.validate(
                {
                    **self.item,
                    "labels": ["documentation", "chore"],
                    "type": "Task",
                    "migrate_enhancement": True,
                },
                self.ctx,
            )

    def test_unavailable_configuration_drops_only_unwritable_fields(self) -> None:
        """Existing degradation and escalation semantics stay intact."""
        self.ctx.fields = {}
        self.ctx.types = set()
        action = policy.validate(
            {**self.item, "priority": "High", "escalate": True}, self.ctx
        )
        self.assertEqual(action["labels"], ["bug"])
        self.assertIsNone(action["priority"])
        self.assertIsNone(action["type"])
        self.assertTrue(action["escalate"])
        self.assertEqual(len(action["dropped"]), 2)

    def test_build_context_defaults_to_strict_configuration_reads(self) -> None:
        """The run boundary forwards strict defaults and explicit dry-run opt-in."""
        for options in ({}, {"allow_unavailable": False}, {"allow_unavailable": True}):
            with (
                self.subTest(options=options),
                patch.dict(policy.os.environ, {"TRIAGE_ORG": "owner"}, clear=True),
                patch.object(
                    policy, "load_field_options", return_value=self.ctx.fields
                ) as fields,
                patch.object(
                    policy, "load_issue_types", return_value=self.ctx.types
                ) as types,
            ):
                context = policy.build_context(self.ctx.snapshot, **options)
            expected = options.get("allow_unavailable", False)
            fields.assert_called_once_with("owner", allow_unavailable=expected)
            types.assert_called_once_with("owner", allow_unavailable=expected)
            self.assertEqual(context.fields, self.ctx.fields)
            self.assertEqual(context.types, self.ctx.types)
            self.assertEqual(context.snapshot, self.ctx.snapshot)

    def test_missing_configured_exclusions_fail_closed(self) -> None:
        """An explicit missing scope file must not silently remove restrictions."""
        with (
            patch.object(Path, "is_file", return_value=False),
            patch.object(Path, "read_text", side_effect=FileNotFoundError("missing")),
            self.assertRaises(GitHubError),
        ):
            policy.load_exclusions("missing-exclusions.txt")
        self.assertEqual(policy.load_exclusions(None), set())


if __name__ == "__main__":
    unittest.main()
