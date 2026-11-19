# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Replay the fuzz harnesses' seeds, and show each oracle can fail.

The harnesses under fuzz/ run under Atheris in a central job; this
suite needs no fuzzer. It replays every seed through each check, and
feeds each oracle a deliberately wrong result to prove it rejects one.
"""

from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fuzz"))

support = import_module("fuzz_support")
policy_harness = import_module("fuzz_triage_policy")
output_harness = import_module("fuzz_triage_output")
ContractBreach = support.ContractBreach


class SeedReplayTests(unittest.TestCase):
    """Every seed holds against the current code."""

    def test_every_seed_holds(self) -> None:
        """A seed that breaks a contract is a defect to fix, not to drop."""
        for harness in (policy_harness, output_harness):
            for index, seed in enumerate(harness.SEEDS):
                with self.subTest(harness=harness.__name__, seed=index):
                    harness.check(seed)

    def test_seeds_join_a_corpus_but_not_a_file_replay(self) -> None:
        """Seeds follow the caller's directories; named files run alone."""
        with tempfile.TemporaryDirectory() as scratch:
            seeds = Path(scratch) / "seeds"
            seeds.mkdir()
            arguments = support.libfuzzer_arguments(
                ["harness.py", "-runs=0", "corpus"], [b"a", b"b"], seeds
            )
            self.assertEqual(arguments, ["harness.py", "-runs=0", "corpus", str(seeds)])
            self.assertEqual(len(list(seeds.iterdir())), 2)
            named = Path(scratch) / "input"
            named.write_bytes(b"x")
            argv = ["harness.py", str(named)]
            self.assertEqual(support.libfuzzer_arguments(argv, [b"c"], seeds), argv)

    def test_a_seed_over_the_libfuzzer_ceiling_lifts_max_len(self) -> None:
        """libFuzzer truncates a seed past 1 MiB unless told a longer max."""
        long_seed = b"x" * (support.LIBFUZZER_MAX_LEN + 1)
        with tempfile.TemporaryDirectory() as scratch:
            seeds = Path(scratch)
            arguments = support.libfuzzer_arguments(["harness.py"], [long_seed], seeds)
            self.assertEqual(
                arguments, ["harness.py", f"-max_len={len(long_seed)}", str(seeds)]
            )
            own = ["harness.py", "-max_len=9"]
            arguments = support.libfuzzer_arguments(own, [long_seed], seeds)
            self.assertEqual(arguments, [*own, str(seeds)])


class PolicyOracleTests(unittest.TestCase):
    """The policy harness rejects wrong answers it is shown."""

    def setUp(self) -> None:
        """Take one genuine outcome to corrupt."""
        self.scope = policy_harness.SCOPES[0]
        self.items: list[Any] = [dict(policy_harness.GOOD)]
        with policy_harness.fake_github():
            outcome = policy_harness.apply_triage.process(
                self.items, self.scope.context(), True
            )
        self.applied, self.rejected, self.failed = outcome
        self.assertEqual(len(self.applied), 1)

    def judge(self, applied: list[dict[str, Any]]) -> None:
        """Run the outcome oracle over a corrupted applied list."""
        policy_harness.check_outcome(
            self.items, self.scope, applied, self.rejected, self.failed
        )

    def test_outcome_oracle_rejects_wrong_actions(self) -> None:
        """Each corruption breaks a rule DESIGN.md section 6 states."""
        corruptions: dict[str, dict[str, Any]] = {
            "foreign label": {"labels": ["bug", "wontfix"]},
            "excluded repository": {"repository": "owner/skipme"},
            "outside the snapshot": {"issue": 8},
            "closed issue": {"issue": 2},
            "contradicting type": {"type": "Feature"},
            "human-only priority": {"priority": "Urgent"},
            "altered priority": {"priority": "Medium"},
            "escalation nobody proposed": {"escalate": False},
        }
        for name, change in corruptions.items():
            with self.subTest(name), self.assertRaises(ContractBreach):
                self.judge([{**copy.deepcopy(self.applied[0]), **change}])
        with self.assertRaises(ContractBreach):
            self.judge([])
        self.judge(self.applied)

    def test_outcome_oracle_rejects_a_bad_grade_the_scope_drops(self) -> None:
        """Urgent is refused even where the organisation has no Priority."""
        scope = next(s for s in policy_harness.SCOPES if s.priorities is None)
        items: list[Any] = [{**policy_harness.GOOD, "escalate": False}]
        with policy_harness.fake_github():
            outcome = policy_harness.apply_triage.process(
                copy.deepcopy(items), scope.context(), True
            )
        applied, rejected, failed = outcome
        self.assertEqual(len(applied), 1)
        self.assertIsNone(applied[0]["priority"])
        policy_harness.check_outcome(items, scope, applied, rejected, failed)
        for grade in ("Urgent", "Critical", 1):
            wrong: list[Any] = [{**items[0], "priority": grade}]
            with self.subTest(grade=grade), self.assertRaises(ContractBreach):
                policy_harness.check_outcome(wrong, scope, applied, rejected, failed)

    def test_outcome_oracle_rejects_coerced_flags(self) -> None:
        """A non-boolean flag read as false must not pass as applied."""
        # GOOD proposes no migration, so its action already carries False.
        actions = {
            "escalate": {**copy.deepcopy(self.applied[0]), "escalate": False},
            "migrate_enhancement": self.applied[0],
        }
        for key, action in actions.items():
            for value in ("yes", None, 0):
                wrong: list[Any] = [{**self.items[0], key: value}]
                with self.subTest(key=key, value=value):
                    with self.assertRaises(ContractBreach):
                        policy_harness.check_outcome(
                            wrong, self.scope, [action], self.rejected, self.failed
                        )

    def test_outcome_oracle_rejects_labels_that_are_not_a_list(self) -> None:
        """Labels shaped as an object or a string must not pass as applied."""
        for labels in ({"bug": "not a list"}, "bug", ["bug", 1]):
            wrong: list[Any] = [{**self.items[0], "labels": labels}]
            action = {**copy.deepcopy(self.applied[0]), "labels": labels}
            with self.subTest(labels=labels), self.assertRaises(ContractBreach):
                policy_harness.check_outcome(
                    wrong, self.scope, [action], self.rejected, self.failed
                )

    def test_outcome_oracle_rejects_a_bad_type_the_scope_drops(self) -> None:
        """A non-string type is refused even where the organisation has none."""
        scope = next(s for s in policy_harness.SCOPES if not s.types)
        items: list[Any] = [{**policy_harness.GOOD}]
        with policy_harness.fake_github():
            outcome = policy_harness.apply_triage.process(
                copy.deepcopy(items), scope.context(), True
            )
        applied, rejected, failed = outcome
        self.assertEqual(len(applied), 1)
        self.assertIsNone(applied[0]["type"])
        policy_harness.check_outcome(items, scope, applied, rejected, failed)
        for value in (1, True, ["Bug"]):
            wrong: list[Any] = [{**items[0], "type": value}]
            with self.subTest(type=value), self.assertRaises(ContractBreach):
                policy_harness.check_outcome(wrong, scope, applied, rejected, failed)

    def test_outcome_oracle_survives_a_validator_that_edits_its_input(
        self,
    ) -> None:
        """Rewriting Urgent to High in place must not launder a refusal."""
        real = policy_harness.apply_triage.process

        def downgrading(items: list[Any], context: Any, dry_run: bool) -> Any:
            for item in items:
                if item.get("priority") == "Urgent":
                    item["priority"] = "High"
            return real(items, context, dry_run)

        seed = policy_harness.block({**policy_harness.GOOD, "priority": "Urgent"})
        policy_harness.check(seed)
        with (
            patch.object(policy_harness.apply_triage, "process", new=downgrading),
            self.assertRaises(ContractBreach),
        ):
            policy_harness.check(seed)

    def test_outcome_oracle_does_not_trust_the_extractor(self) -> None:
        """An extractor that rewrites the block, every time alike, is caught."""
        real = policy_harness.policy.extract_proposal

        def rewriting(key: str, old: Any, new: Any) -> Any:
            def extract(text: str) -> Any:
                result = real(text)
                for item in result["proposals"]:
                    if item.get(key) == old and type(item.get(key)) is type(old):
                        item[key] = new
                return result

            return extract

        cases = {
            "Urgent to High": ("priority", "Urgent", "High"),
            "flag to number": ("escalate", True, 1),
        }
        seed = policy_harness.block({**policy_harness.GOOD, "priority": "Urgent"})
        policy_harness.check(seed)
        for name, (key, old, new) in cases.items():
            with (
                self.subTest(name),
                patch.object(
                    policy_harness.policy,
                    "extract_proposal",
                    new=rewriting(key, old, new),
                ),
                self.assertRaises(ContractBreach),
            ):
                policy_harness.check(seed)

    def test_outcome_oracle_rejects_a_duplicated_target(self) -> None:
        """A target proposed twice must not be applied at all."""
        self.items.append(dict(policy_harness.GOOD))
        with self.assertRaises(ContractBreach):
            policy_harness.check_outcome(
                self.items, self.scope, self.applied, self.applied, []
            )

    def test_extraction_oracle_rejects_a_stale_answer(self) -> None:
        """An extractor that ignores the final block is caught."""
        stale: dict[str, Any] = {"proposals": []}
        with (
            patch.object(policy_harness.policy, "extract_proposal", return_value=stale),
            self.assertRaises(ContractBreach),
        ):
            policy_harness.check_extraction("No fences here.")

    def test_extraction_oracle_rejects_a_fallback_to_an_earlier_block(
        self,
    ) -> None:
        """An unusable final block must not hand back an earlier proposal."""
        real = policy_harness.policy.extract_proposal

        def falling_back(text: str) -> Any:
            try:
                return real(text)
            except policy_harness.Rejected:
                closing = text.rindex("\n```")
                return real(text[: text.rindex("\n```", 0, closing)])

        good = policy_harness.message(policy_harness.GOOD).decode()
        policy_harness.check_extraction(good)
        with (
            patch.object(policy_harness.policy, "extract_proposal", new=falling_back),
            self.assertRaises(ContractBreach),
        ):
            policy_harness.check_extraction(good)

    def test_report_oracle_rejects_commands_and_extra_lines(self) -> None:
        """A forged command or a smuggled line break fails the report check."""
        honest = "Proposals: 1\nWould apply: 1\nRejected: 0\n  ESCALATE x\n"
        policy_harness.check_report(honest, self.applied, [])
        for output in (
            honest.replace("x", "::error::x"),
            honest.replace("x", "x\nforged"),
            honest.replace("x", "x\x85forged"),
        ):
            with self.subTest(output=output), self.assertRaises(ContractBreach):
                policy_harness.check_report(output, self.applied, [])


class OutputOracleTests(unittest.TestCase):
    """The evidence and rendering harness rejects wrong answers it is shown."""

    def test_verdict_oracle_rejects_both_wrong_verdicts(self) -> None:
        """Passing bad evidence and refusing good evidence both fail."""
        modes = [("lower", "regular"), ("lower", "regular")]
        output_harness.check_verdict(True, True, modes, (0, 0))
        for expected in (True, False):
            with self.subTest(expected=expected), self.assertRaises(ContractBreach):
                output_harness.check_verdict(expected, not expected, modes, (0, 0))

    def test_oversized_evidence_is_an_expected_refusal(self) -> None:
        """Either file over its cap is refused, and must be."""
        # Byte 0 picks ("lower", "regular") for both; split byte 0 gives
        # the whole body to the exclusions file, and 255 to the snapshot.
        body = b"x" * (output_harness.CAPS[0] + 1)
        snapshot = b"\x00\x00\xff" + body
        before, exclusions = output_harness.split_contents(snapshot)
        self.assertEqual((len(before), len(exclusions)), (len(body), 0))
        for oversized in (output_harness.OVERSIZED_EXCLUSIONS, snapshot):
            with self.subTest(size=len(oversized)):
                output_harness.check_verify(oversized)
                with (
                    patch.object(output_harness.evidence, "verify", return_value=None),
                    self.assertRaises(ContractBreach),
                ):
                    output_harness.check_verify(oversized)

    def test_permissive_verify_is_caught(self) -> None:
        """A verify that accepts a flipped digest fails the harness."""
        # Byte 2 selects ("flipped", "regular") for both files.
        with (
            patch.object(output_harness.evidence, "verify", return_value=None),
            self.assertRaises(ContractBreach),
        ):
            output_harness.check_verify(b"\x02\x02\x01ab")

    def test_rendering_oracle_rejects_unsafe_or_altered_text(self) -> None:
        """Commands, control characters, line breaks and edits all fail."""
        for value, output in (
            ("a::b", "a::b\n"),
            ("##[group]", "##[group]\n"),
            ("a\x85b", "a\x85b\n"),
            ("a\nb", "a\nb\n"),
            ("plain", "plane\n"),
        ):
            with self.subTest(value=value), self.assertRaises(ContractBreach):
                output_harness.check_rendered(value, output)
        output_harness.check_rendered("plain", "plain\n")

    def test_identity_one_line_is_caught(self) -> None:
        """A one_line that renders nothing safe fails the harness."""
        with (
            patch.object(output_harness.apply_triage, "one_line", new=str),
            self.assertRaises(ContractBreach),
        ):
            output_harness.check_one_line(b"::error::x")


if __name__ == "__main__":
    unittest.main()
