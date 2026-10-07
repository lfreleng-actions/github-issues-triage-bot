# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline regression contracts for the prepare/propose/apply trust boundary."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any

# The isolated checker uses bundled YAML stubs. The regression hook
# installs and exercises PyYAML; adding it to the checker exceeds CI's
# 250 MiB environment cap. Suppress source-presence, not type checking.
import yaml  # pyright: ignore[reportMissingModuleSource]

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "issues-triage.yaml"


class WorkflowCase(unittest.TestCase):
    """Read workflow structure, never comments or a duplicated fixture workflow."""

    def setUp(self) -> None:
        """Load a fresh safe YAML document for each independent contract."""
        self.workflow: dict[str, Any] = yaml.safe_load(
            WORKFLOW.read_text(encoding="utf-8")
        )
        self.jobs: dict[str, dict[str, Any]] = self.workflow["jobs"]

    def step(self, job: str, identity: str) -> dict[str, Any]:
        """Find exactly one step by its machine ID or human-readable name."""
        matches = [
            step
            for step in self.jobs[job]["steps"]
            if identity in (step.get("id"), step.get("name"))
        ]
        self.assertEqual(len(matches), 1, f"{job}: expected one {identity!r} step")
        return matches[0]

    def actions(self, job: str, action: str) -> list[dict[str, Any]]:
        """Select action invocations independently of their commit pin."""
        return [
            step
            for step in self.jobs[job]["steps"]
            if step.get("uses", "").startswith(action + "@")
        ]

    def assert_expression(self, actual: str, expected: str) -> None:
        """Compare complete conditions, permitting wrappers and whitespace only."""

        def normalize(expression: str) -> str:
            """Ignore formatting without overlooking a permissive OR or fallback."""
            expression = expression.strip()
            if expression.startswith("${{") and expression.endswith("}}"):
                expression = expression[3:-2]
            return re.sub(r"\s+", "", expression)

        self.assertEqual(normalize(actual), normalize(expected))

    def assert_before(self, job: str, first: str, second: str) -> None:
        """Require the security check to finish before its dependent step."""
        steps = self.jobs[job]["steps"]
        self.assertLess(
            steps.index(self.step(job, first)), steps.index(self.step(job, second))
        )


class WorkflowContractTests(WorkflowCase):
    """Protect trusted provenance, credential isolation and fail-closed job wiring."""

    def test_three_jobs_keep_preparation_outside_the_agent_runner(self) -> None:
        """Only the disposable middle job executes agents or exports their data."""
        self.assertEqual(set(self.jobs), {"prepare", "propose", "apply"})
        self.assertNotIn("needs", self.jobs["prepare"])
        self.assertEqual(self.jobs["propose"]["needs"], "prepare")
        self.assertEqual(set(self.jobs["apply"]["needs"]), {"prepare", "propose"})
        self.assert_expression(
            self.jobs["propose"]["if"], "needs.prepare.outputs.run_agent == 'true'"
        )
        self.assertEqual(
            self.jobs["propose"]["outputs"],
            {"session_id": "${{ steps.session.outputs.artifact-id }}"},
        )
        self.assertEqual(self.workflow["permissions"], {})
        for job in self.jobs.values():
            self.assertNotIn("write", job["permissions"].values())

    def test_concurrency_lock_encompasses_all_three_stages(self) -> None:
        """Live runs share one lock; dry runs lock within their caller run."""
        concurrency = self.workflow["concurrency"]
        # The live operand must keep the historical group so an upgrade
        # still serialises against runs already holding the old lock.
        self.assert_expression(
            concurrency["group"],
            "inputs.dry_run"
            " && format('triage-dry-run-{0}-{1}', github.run_id, inputs.org)"
            " || format('triage-pipeline-{0}-{1}', github.repository, inputs.org)",
        )
        self.assertIs(concurrency["cancel-in-progress"], False)
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                self.assertNotIn("concurrency", job)

    def test_pull_request_plumbing_cannot_cancel_its_own_legs(self) -> None:
        """Dry legs stay in their run's group, which holds one running and one pending."""
        testing: dict[str, Any] = yaml.safe_load(
            (WORKFLOW.parent / "testing.yaml").read_text(encoding="utf-8")
        )
        plumbing = testing["jobs"]["plumbing"]
        self.assertIs(plumbing["with"]["dry_run"], True)
        self.assertLessEqual(len(plumbing["strategy"]["matrix"]["invocation"]), 2)

    def test_caller_groups_keep_dry_dispatches_apart(self) -> None:
        """Caller locks apply first, so dry dispatches need groups of their own."""
        callers = {
            "issues-triage-cron.yaml": (
                "github.event_name == 'workflow_dispatch' && inputs.dry_run"
                " && format('issues-triage-dry-run-{0}', github.run_id)"
                " || 'issues-triage'",
                False,
            ),
            "testing.yaml": (
                "format('testing-{0}', github.event_name == 'pull_request'"
                " && github.ref || github.run_id)",
                True,
            ),
        }
        for name, (group, cancel) in callers.items():
            with self.subTest(caller=name):
                caller: dict[str, Any] = yaml.safe_load(
                    (WORKFLOW.parent / name).read_text(encoding="utf-8")
                )
                self.assert_expression(caller["concurrency"]["group"], group)
                self.assertIs(caller["concurrency"]["cancel-in-progress"], cancel)

    def test_propose_has_no_app_key_token_minter_or_issue_write_permission(
        self,
    ) -> None:
        """Search every parsed propose field, not just steps or comments."""
        propose_json = json.dumps(self.jobs["propose"]).lower()
        for forbidden in (
            "github_app_private_key",
            "create-github-app-token",
            "private-key",
            "app-token",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, propose_json)
        self.assertEqual(self.jobs["propose"]["permissions"], {"contents": "read"})
        prepare_tokens = self.actions("prepare", "actions/create-github-app-token")
        self.assertEqual(len(prepare_tokens), 1)
        self.assertEqual(prepare_tokens[0]["with"]["permission-issues"], "read")

    def test_namespace_and_evidence_provenance_are_prepare_outputs(self) -> None:
        """Agent-controlled outputs cannot choose code, evidence or trusted hashes."""
        expected = {
            "assets_sha": "${{ steps.pinned.outputs.sha }}",
            "namespace": "${{ steps.identity.outputs.namespace }}",
            "evidence_id": "${{ steps.evidence.outputs.artifact-id }}",
            "before_sha256": "${{ steps.digests.outputs.before }}",
            "exclusions_sha256": "${{ steps.digests.outputs.exclusions }}",
        }
        for output, expression in expected.items():
            with self.subTest(output=output):
                self.assertEqual(self.jobs["prepare"]["outputs"][output], expression)
        self.assertEqual(
            self.step("prepare", "identity")["env"],
            {
                "RUN_ID": "${{ github.run_id }}",
                "RUN_ATTEMPT": "${{ github.run_attempt }}",
            },
        )
        self.assert_before("prepare", "before", "digests")
        self.assert_before("prepare", "digests", "evidence")
        self.assert_before("prepare", "identity", "evidence")
        for identity in ("identity", "pinned", "digests", "evidence"):
            with self.subTest(identity=identity):
                step = self.step("prepare", identity)
                self.assertNotIn("if", step)
                self.assertFalse(step.get("continue-on-error", False))

    def test_downstream_code_is_pinned_only_by_prepare(self) -> None:
        """An empty trusted SHA cannot fall back to a branch or the proposal job."""
        for job, guard in (
            ("propose", "Require pinned assets"),
            ("apply", "Require trusted provenance"),
        ):
            with self.subTest(job=job):
                checkouts = self.actions(job, "actions/checkout")
                self.assertEqual(len(checkouts), 1)
                checkout = checkouts[0]
                self.assertEqual(
                    checkout["with"]["ref"], "${{ needs.prepare.outputs.assets_sha }}"
                )
                self.assertIs(checkout["with"]["persist-credentials"], False)
                self.assert_before(job, guard, checkout["name"])
                self.assertNotIn("if", self.step(job, guard))
                self.assertFalse(self.step(job, guard).get("continue-on-error", False))
        self.assertEqual(
            self.step("apply", "Require trusted provenance")["env"],
            {
                "ASSETS_SHA": "${{ needs.prepare.outputs.assets_sha }}",
                "EVIDENCE_ID": "${{ needs.prepare.outputs.evidence_id }}",
                "BEFORE_SHA": "${{ needs.prepare.outputs.before_sha256 }}",
                "EXCLUSIONS_SHA": "${{ needs.prepare.outputs.exclusions_sha256 }}",
            },
        )
        for job in ("propose", "apply"):
            serialized = json.dumps(self.jobs[job])
            for output in (
                "assets_sha",
                "evidence_id",
                "before_sha256",
                "exclusions_sha256",
            ):
                self.assertNotIn(f"needs.propose.outputs.{output}", serialized)

    def test_downloads_use_producer_ids_not_current_attempt_names(self) -> None:
        """Apply-only reruns retain the artifacts produced by earlier attempts."""
        expected = {
            "propose": ["${{ needs.prepare.outputs.evidence_id }}"],
            "apply": [
                "${{ needs.prepare.outputs.evidence_id }}",
                "${{ needs.propose.outputs.session_id }}",
            ],
        }
        for job, artifact_ids in expected.items():
            with self.subTest(job=job):
                downloads = self.actions(job, "actions/download-artifact")
                self.assertEqual(
                    [step["with"].get("artifact-ids") for step in downloads],
                    artifact_ids,
                )
                for step in downloads:
                    options = step["with"]
                    self.assertNotIn("name", options)
                    self.assertNotIn("pattern", options)
                    self.assertNotIn("github.run_attempt", json.dumps(options))
                    self.assertIs(options["merge-multiple"], True)
                    self.assertFalse(step.get("continue-on-error", False))

    def test_upload_names_use_the_trusted_invocation_namespace(self) -> None:
        """Repeated calls and producer-only reruns cannot reuse immutable names."""
        for job, identity, expected in (
            (
                "prepare",
                "evidence",
                "triage-evidence-${{ steps.identity.outputs.namespace }}",
            ),
            (
                "propose",
                "session",
                "triage-session-${{ needs.prepare.outputs.namespace }}-${{ github.run_attempt }}",
            ),
            (
                "apply",
                "Attach run artefacts",
                "issues-triage-${{ needs.prepare.outputs.namespace }}-${{ github.run_attempt }}",
            ),
        ):
            with self.subTest(job=job):
                self.assertEqual(self.step(job, identity)["with"]["name"], expected)

    def test_evidence_verification_precedes_all_apply_credentials(self) -> None:
        """A digest mismatch must stop before any private key reaches an action."""
        verified = self.step("apply", "verified")
        self.assertEqual(
            verified["env"],
            {
                "BEFORE_SHA": "${{ needs.prepare.outputs.before_sha256 }}",
                "EXCLUSIONS_SHA": "${{ needs.prepare.outputs.exclusions_sha256 }}",
            },
        )
        self.assertNotIn("if", verified)
        self.assertFalse(verified.get("continue-on-error", False))
        self.assert_before("apply", "Fetch original evidence", "verified")
        credential_steps = [
            step
            for step in self.jobs["apply"]["steps"]
            if "github_app_private_key" in json.dumps(step)
            or step.get("uses", "").startswith("actions/create-github-app-token@")
        ]
        self.assertEqual(credential_steps, [self.step("apply", "app-token")])
        self.assert_before("apply", "verified", "app-token")
        self.assert_before("apply", "proposal", "app-token")
        self.assert_expression(
            self.step("apply", "app-token")["if"], "inputs.github_app_client_id != ''"
        )

    def test_downloads_cannot_overlay_trusted_evidence_or_executable_assets(
        self,
    ) -> None:
        """The old shared extraction directory let session files replace evidence."""
        evidence = Path(self.step("apply", "Fetch original evidence")["with"]["path"])
        session = Path(self.step("apply", "Fetch untrusted session")["with"]["path"])
        checkout = Path(self.actions("apply", "actions/checkout")[0]["with"]["path"])
        paths = (evidence, session, checkout, Path("artefacts"))
        for index, first in enumerate(paths):
            self.assertFalse(first.is_absolute())
            self.assertNotIn("..", first.parts)
            for second in paths[index + 1 :]:
                with self.subTest(first=first, second=second):
                    self.assertFalse(first.is_relative_to(second))
                    self.assertFalse(second.is_relative_to(first))
        self.assertIn(f"--directory {evidence}", self.step("apply", "verified")["run"])
        self.assertIn(f"--directory {session}", self.step("apply", "proposal")["run"])
        self.assertIn(
            "--output artefacts/session-summary.md",
            self.step("apply", "proposal")["run"],
        )
        applier = self.step("apply", "apply")
        self.assertIn("--proposal artefacts/session-summary.md", applier["run"])
        self.assertIn(f"--snapshot {evidence}/before.json", applier["run"])
        self.assertEqual(
            applier["env"]["TRIAGE_EXCLUDE_FILE"], f"{evidence}/excluded-repos.txt"
        )
        self.assertEqual(
            self.step("apply", "after")["env"]["EXCLUDE_FILE"],
            f"{evidence}/excluded-repos.txt",
        )

    def test_mutations_require_successful_job_and_validated_proposal(self) -> None:
        """Partial agent output is insufficient for either writing or a write token."""
        success = (
            "needs.propose.result == 'success' && steps.proposal.outcome == 'success'"
        )
        self.assert_expression(self.step("apply", "apply")["if"], success)
        self.assert_expression(
            self.step("apply", "app-token")["with"]["permission-issues"],
            f"!inputs.dry_run && {success} && 'write' || 'read'",
        )
        for identity in (
            "Require session artifact identity",
            "Fetch untrusted session",
            "proposal",
        ):
            with self.subTest(identity=identity):
                step = self.step("apply", identity)
                self.assert_expression(
                    step["if"],
                    "needs.prepare.outputs.run_agent == 'true' && needs.propose.result == 'success'",
                )
                self.assertFalse(step.get("continue-on-error", False))
        self.assert_before(
            "apply", "Require session artifact identity", "Fetch untrusted session"
        )
        self.assert_before("apply", "Fetch untrusted session", "proposal")
        self.assert_before("apply", "proposal", "apply")

    def test_apply_org_grants_require_a_validated_proposal(self) -> None:
        """Forward missing manifest inputs without warnings or broader grants."""
        token = self.step("apply", "app-token")
        self.assertEqual(token["with"]["permission-metadata"], "read")
        for grant in ("permission-issue-fields", "permission-issue-types"):
            with self.subTest(grant=grant):
                self.assertNotIn(grant, token["with"])
                environment_key = "INPUT_" + grant.upper()
                self.assert_expression(
                    token.get("env", {}).get(environment_key, ""),
                    "steps.proposal.outcome == 'success' && 'read' || ''",
                )

    def test_schedule_is_live_without_changing_manual_dry_run_defaults(self) -> None:
        """Schedules write; explicit manual and reusable dry runs stay available."""
        cron: dict[str, Any] = yaml.load(
            (WORKFLOW.parent / "issues-triage-cron.yaml").read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        self.assertEqual(cron["on"]["schedule"], [{"cron": "0 7 * * 1-5"}])
        self.assertEqual(
            cron["on"]["workflow_dispatch"]["inputs"]["dry_run"]["default"], "true"
        )
        self.assert_expression(
            cron["jobs"]["triage"]["with"]["dry_run"],
            "github.event_name == 'workflow_dispatch' && inputs.dry_run",
        )
        reusable: dict[str, Any] = yaml.load(
            WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
        )
        self.assertEqual(
            reusable["on"]["workflow_call"]["inputs"]["dry_run"]["default"], "true"
        )

    def test_assets_default_names_this_repository(self) -> None:
        """An external caller relying on the default checks out these assets.

        The repository was renamed and recreated; a stale default named
        a repository that no longer exists, so a caller omitting
        assets_repository failed to check out the prompt and scripts.
        """
        reusable: dict[str, Any] = yaml.load(
            WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
        )
        self.assertEqual(
            reusable["on"]["workflow_call"]["inputs"]["assets_repository"]["default"],
            "lfreleng-actions/github-issues-triage-bot",
        )

    def test_model_defaults_to_an_identifier_and_the_cron_maps_display_names(
        self,
    ) -> None:
        """The CLI receives the caller's model; the cron dispatch picks by name."""
        reusable: dict[str, Any] = yaml.load(
            WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
        )
        model = reusable["on"]["workflow_call"]["inputs"]["model"]
        self.assertEqual(model["default"], "claude-opus-5.5")
        self.assertEqual(model["type"], "string")
        self.assertEqual(
            self.step("propose", "Run triage agent")["env"]["MODEL"],
            "${{ inputs.model }}",
        )
        self.assert_before("prepare", "Check inputs", "Require App for live runs")
        cron: dict[str, Any] = yaml.load(
            (WORKFLOW.parent / "issues-triage-cron.yaml").read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        choice = cron["on"]["workflow_dispatch"]["inputs"]["model"]
        self.assertEqual(choice["type"], "choice")
        self.assertIn(choice["default"], choice["options"])
        self.assertEqual(cron["jobs"]["triage"]["needs"], "options")
        self.assertEqual(
            cron["jobs"]["triage"]["with"]["model"],
            "${{ needs.options.outputs.model }}",
        )
        self.assertEqual(cron["jobs"]["options"]["permissions"], {})
        mapping: str = next(
            step["run"] for step in cron["jobs"]["options"]["steps"] if "run" in step
        )
        for option in choice["options"]:
            with self.subTest(option=option):
                self.assertIn(f"'{option}')", mapping)

    def test_copilot_policy_declares_reads_and_still_denies_writes(self) -> None:
        """Declaring auto-approved reads must not relax the enforced denials."""
        script: str = self.step("propose", "Run triage agent")["run"]
        self.assertIn("for cmd in cat jq grep head tail wc; do", script)
        self.assertIn('allow="$allow,shell($cmd),shell($cmd:*)"', script)
        self.assertIn('--allow-tool="${allow#,}"', script)
        # The deny list is what actually overrides auto-approval,
        # so widening reads must leave these entries untouched.
        self.assertIn(
            "--deny-tool='write,shell(gh),shell(gh:*),shell(git),shell(git:*)'",
            script,
        )
        self.assertIn("--available-tools=bash,list_bash,read_bash,stop_bash", script)

    def test_copilot_cli_lockfile_pins_the_whole_tree(self) -> None:
        """The lockfile, not a version argument, is what pins the CLI.

        npm ci trusts whatever the lockfile says, so an entry without an
        integrity hash, resolved off the registry, or carrying an install
        script would weaken the pin without failing the install.
        """
        pin = ROOT / "tools" / "copilot-cli"
        manifest = json.loads((pin / "package.json").read_text(encoding="utf-8"))
        lock = json.loads((pin / "package-lock.json").read_text(encoding="utf-8"))
        version = manifest["dependencies"]["@github/copilot"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertEqual(lock["packages"][""]["dependencies"], manifest["dependencies"])
        packages = {k: v for k, v in lock["packages"].items() if k}
        self.assertEqual(packages["node_modules/@github/copilot"]["version"], version)
        for name, entry in packages.items():
            self.assertRegex(entry.get("integrity", ""), r"^sha512-", name)
            self.assertTrue(
                entry.get("resolved", "").startswith("https://registry.npmjs.org/"),
                name,
            )
            self.assertNotIn("hasInstallScript", entry, name)
        self.assert_before("propose", "Require pinned assets", "Install Copilot CLI")
        self.assert_before("propose", "Checkout prompt assets", "Install Copilot CLI")
        self.assert_before("propose", "Install Copilot CLI", "Run triage agent")

    def test_allow_list_blesses_no_command_capable_interpreter(self) -> None:
        """An allowed interpreter would bypass the write, gh and git denials.

        The shell tool matches the command it launches, so `awk` running
        `system("gh ...")` never presents as `gh`. awk executes outright
        and GNU sed's `w` command writes files, so neither belongs in a
        list whose stated purpose is read-only access.
        """
        script: str = self.step("propose", "Run triage agent")["run"]
        declared = re.search(r"for cmd in ([^;]+); do", script)
        self.assertIsNotNone(declared)
        assert declared is not None
        allowed = set(declared[1].split())
        capable = {
            "awk",
            "sed",
            "sh",
            "bash",
            "python",
            "python3",
            "perl",
            "node",
            "env",
            "xargs",
            "find",
            "tee",
            "dd",
            "install",
            "rm",
            "cp",
            "mv",
        }
        self.assertEqual(allowed & capable, set())
        self.assertEqual(allowed, {"cat", "jq", "grep", "head", "tail", "wc"})

    def test_prompt_forbids_file_changes_and_guides_projection(self) -> None:
        """The session wasted turns paging bodies and tried to delete a file."""
        raw = (WORKFLOW.parents[2] / "prompt" / "triage.md").read_text(encoding="utf-8")
        # Collapse wrapping so a reflowed paragraph cannot break an
        # assertion about wording the session actually receives.
        prompt = re.sub(r"\s+", " ", raw)
        self.assertIn("Do not change, create or delete files", prompt)
        self.assertIn("Prefer a `jq` projection", prompt)
        self.assertIn("the workflow clears the session's scratch files", prompt)
        for utility in ("grep", "head", "tail"):
            with self.subTest(utility=utility):
                self.assertIn(f"`{utility}`", prompt)
        # Recommending an interpreter the policy will not bless
        # would invite the session to rely on auto-approval.
        for interpreter in ("`awk`", "`sed`"):
            with self.subTest(interpreter=interpreter):
                self.assertNotIn(interpreter, prompt)

    def test_scratch_cleanup_runs_on_the_agent_runner_after_the_session(self) -> None:
        """A later job cannot reach this scratch, and failures must still clear it."""
        cleanup = self.step("propose", "Clear session scratch files")
        self.assert_expression(cleanup["if"], "always()")
        self.assertEqual(cleanup["env"], {"COPILOT_HOME": "${{ runner.temp }}/copilot"})
        self.assert_before("propose", "agent", "Clear session scratch files")
        # Clearing must not reach the proposal the next job consumes.
        self.assertNotIn("artefacts", cleanup["run"].replace("artefacts/ is", ""))

    def test_cleanup_failure_cannot_suppress_writes(self) -> None:
        """This job's result gates the apply path, so hygiene must not fail it.

        Without continue-on-error a failed delete fails Propose, and
        every write-gated apply step reads needs.propose.result, so the
        run would report cleanly having applied nothing.
        """
        cleanup = self.step("propose", "Clear session scratch files")
        self.assertIs(cleanup["continue-on-error"], True)
        gated = [
            step
            for step in self.jobs["apply"]["steps"]
            if "needs.propose.result" in str(step.get("if", ""))
        ]
        self.assertNotEqual(gated, [])
        for step in gated:
            with self.subTest(step=step.get("name")):
                self.assertIn("needs.propose.result == 'success'", step["if"])

    def test_trusted_jobs_block_and_propose_audits(self) -> None:
        """Trusted jobs load the allow-list; the agent job audits.

        The model backend is outside the organisation allow-list, so a
        propose job in block mode cannot reach it (run 37522458757).
        The summary prints from prepare alone.
        """
        for job, expected in (("prepare", "true"), ("apply", "false")):
            with self.subTest(job=job):
                loaders = self.actions(
                    job, "lfreleng-actions/harden-runner-block-action"
                )
                self.assertEqual(len(loaders), 1)
                self.assertEqual(
                    loaders[0]["with"].get("allow_list_summary", "true"), expected
                )
                self.assertEqual(
                    loaders[0]["with"]["config"], "${{ inputs.egress_allow_config }}"
                )
                harden = self.actions(job, "step-security/harden-runner")
                self.assertEqual(len(harden), 1)
                self.assertEqual(
                    harden[0]["with"]["egress-policy"], "${{ inputs.egress_policy }}"
                )
        self.assertEqual(
            self.actions("propose", "lfreleng-actions/harden-runner-block-action"), []
        )
        harden = self.actions("propose", "step-security/harden-runner")
        self.assertEqual(len(harden), 1)
        self.assertEqual(harden[0]["with"]["egress-policy"], "audit")
        self.assertNotIn("allowed-endpoints", harden[0]["with"])

    def test_apply_can_report_when_propose_is_skipped_or_fails(self) -> None:
        """A status function overrides implicit success without allowing cancellation."""
        self.assert_expression(
            self.jobs["apply"]["if"],
            "!cancelled() && needs.prepare.result == 'success'",
        )
        for identity in ("after", "Build report"):
            with self.subTest(identity=identity):
                self.assert_expression(
                    self.step("apply", identity)["if"],
                    "!cancelled() && steps.verified.outcome == 'success'",
                )
        report = self.step("apply", "Build report")
        self.assert_expression(
            report["env"]["AFTER_OK"], "steps.after.outcome == 'success'"
        )
        self.assertEqual(report["env"]["PROPOSE_RESULT"], "${{ needs.propose.result }}")
        self.assertEqual(report["env"]["APPLY_RESULT"], "${{ steps.apply.outcome }}")
        self.assert_before("apply", "after", "Build report")


class PreflightContracts(WorkflowCase):
    """The run-time gate runs from pinned assets before any token exists."""

    def test_gate_runs_after_pinning_and_before_the_read_mint(self) -> None:
        """Contract tests, zizmor and the config check precede the mint."""
        self.assert_before(
            "prepare", "Pin assets commit", "Pre-flight: workflow contracts and audit"
        )
        self.assert_before(
            "prepare",
            "Pre-flight: workflow contracts and audit",
            "Pre-flight: configuration and credentials",
        )
        self.assert_before(
            "prepare",
            "Pre-flight: configuration and credentials",
            "Mint read-only App token",
        )
        run = self.step("prepare", "Pre-flight: workflow contracts and audit")["run"]
        self.assertIn("scripts/preflight.py workflow --root .", run)
        self.assertIn("cd triage-assets", run)

    def test_config_gate_sees_the_credentials_under_template_names(self) -> None:
        """Shape checks read the inputs the workflow was handed, nothing else."""
        step = self.step("prepare", "Pre-flight: configuration and credentials")
        self.assertEqual(
            step["env"]["BOT_APP_CLIENT_ID"], "${{ inputs.github_app_client_id }}"
        )
        self.assertEqual(
            step["env"]["BOT_APP_PRIVATE_KEY"], "${{ secrets.github_app_private_key }}"
        )
        self.assertIn("--config triage-assets/config/bot.json", step["run"])

    def test_minted_tokens_are_checked_for_identity(self) -> None:
        """Both mints hand their app-slug to the identity check before use."""
        read = self.step("prepare", "Pre-flight: App identity and token grants")
        self.assertEqual(
            read["env"]["MINTED_SLUG"], "${{ steps.app-token.outputs.app-slug }}"
        )
        self.assertEqual(
            read["env"]["GH_TOKEN"], "${{ steps.app-token.outputs.token }}"
        )
        self.assertIn("preflight.py token", read["run"])
        self.assert_before(
            "prepare",
            "Pre-flight: App identity and token grants",
            "Snapshot issues before the session",
        )
        write = self.step("apply", "Pre-flight: apply token identity")
        self.assertEqual(
            write["env"]["MINTED_SLUG"], "${{ steps.app-token.outputs.app-slug }}"
        )
        self.assert_before(
            "apply", "Pre-flight: apply token identity", "Apply triage proposal"
        )

    def test_zizmor_is_pinned(self) -> None:
        """The auditor the gate runs is an exact version."""
        self.assertRegex(
            self.step("prepare", "Install zizmor")["run"], r"zizmor==\d+\.\d+\.\d+"
        )

    def test_every_mint_owner_is_the_trusted_org_input(self) -> None:
        """owner is literally inputs.org on every create-github-app-token step."""
        mints = [
            (job, step)
            for job in self.jobs
            if "steps" in self.jobs[job]
            for step in self.actions(job, "actions/create-github-app-token")
        ]
        self.assertEqual({job for job, _ in mints}, {"prepare", "apply"})
        for job, step in mints:
            with self.subTest(job=job):
                self.assertEqual(step["with"]["owner"], "${{ inputs.org }}")
                self.assertEqual(
                    step["with"]["repositories"], "${{ inputs.repository }}"
                )


class SelfRepositoryCallTests(unittest.TestCase):
    """Check the local callee contract while actionlint lacks $/ support."""

    def test_self_references_resolve_and_match_callee_inputs(self) -> None:
        """Do not let the narrowly scoped parser exception hide a broken call."""
        for name in ("testing.yaml", "issues-triage-cron.yaml"):
            caller: dict[str, Any] = yaml.safe_load(
                (WORKFLOW.parent / name).read_text(encoding="utf-8")
            )
            for job in caller["jobs"].values():
                reference = job.get("uses", "")
                if not reference.startswith("$/"):
                    continue
                with self.subTest(caller=name, reference=reference):
                    target = ROOT / reference[2:]
                    self.assertEqual(target, WORKFLOW)
                    # BaseLoader preserves `on` as a string, unlike YAML 1.1.
                    callee: dict[str, Any] = yaml.load(
                        target.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
                    )
                    contract = callee["on"]["workflow_call"]
                    for section, passed in (("inputs", "with"), ("secrets", "secrets")):
                        declarations = contract[section]
                        supplied = job.get(passed, {})
                        self.assertIsInstance(supplied, dict)
                        self.assertLessEqual(set(supplied), set(declarations))
                        required = {
                            key
                            for key, value in declarations.items()
                            if value.get("required") == "true"
                        }
                        self.assertLessEqual(required, set(supplied))

    def test_every_bundled_call_runs_trusted_jobs_in_block_mode(self) -> None:
        """Each caller of the reusable workflow passes block and a pinned list.

        The reusable workflow forwards egress_policy to Prepare and Apply
        (Propose always audits), so the bundled callers are where block
        mode is chosen; a caller dropping to audit would leave the
        trusted, credential-holding jobs unrestricted.
        """
        calls = 0
        for name in ("testing.yaml", "issues-triage-cron.yaml"):
            caller: dict[str, Any] = yaml.safe_load(
                (WORKFLOW.parent / name).read_text(encoding="utf-8")
            )
            for job_name, job in caller["jobs"].items():
                if not str(job.get("uses", "")).startswith("$/"):
                    continue
                calls += 1
                with self.subTest(caller=name, job=job_name):
                    supplied = job["with"]
                    self.assertEqual(supplied.get("egress_policy"), "block")
                    self.assertRegex(
                        str(supplied.get("egress_allow_config", "")), r"^@[0-9a-f]{40}$"
                    )
        # Cron's triage job and testing's plumbing and dry-run jobs.
        self.assertEqual(calls, 3)


class WorkflowScriptTests(WorkflowCase):
    """Execute deterministic workflow shell steps without GitHub or credentials."""

    def test_cleanup_clears_spilled_output_without_following_symlinks(self) -> None:
        """Run the real script: it must clear scratch and reach nothing else."""
        scratch = self.root / "scratch"
        scratch.mkdir()
        home = self.root / "copilot-home"
        (home / "session").mkdir(parents=True)
        (home / "session" / "state.json").write_text("{}", encoding="utf-8")
        spilled = scratch / "1789719962183-copilot-tool-output-3626-abc.txt"
        spilled.write_text("issue bodies", encoding="utf-8")
        unrelated = scratch / "runner-owned.txt"
        unrelated.write_text("keep", encoding="utf-8")
        nested = scratch / "nested"
        nested.mkdir()
        deeper = nested / "9-copilot-tool-output-1-deep.txt"
        deeper.write_text("out of depth", encoding="utf-8")
        # A planted symlink matching the pattern must not redirect the
        # delete onto the file it points at.
        outside = self.root / "outside-target.txt"
        outside.write_text("must survive", encoding="utf-8")
        (scratch / "0-copilot-tool-output-link.txt").symlink_to(outside)
        artefacts = self.root / "artefacts"
        artefacts.mkdir()
        summary = artefacts / "session-summary.md"
        summary.write_text("proposal", encoding="utf-8")

        result = self.run_step(
            "propose",
            "Clear session scratch files",
            TMPDIR=str(scratch),
            COPILOT_HOME=str(home),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Cleared 1 spilled tool-output file(s)", result.stdout)
        self.assertFalse(spilled.exists())
        self.assertFalse(home.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue(deeper.exists())
        self.assertTrue(outside.exists())
        self.assertEqual(summary.read_text(encoding="utf-8"), "proposal")

    def test_cleanup_failure_surfaces_without_pipefail(self) -> None:
        """Actions runs an undeclared shell without pipefail.

        A piped find would hand its exit status to wc, so the step
        would report a clean cleanup and continue-on-error would have
        nothing to expose. Run it exactly as the runner would.
        """
        step = self.step("propose", "Clear session scratch files")
        self.assertNotIn("shell", step)
        result = self.run_step(
            "propose",
            "Clear session scratch files",
            TMPDIR=str(self.root / "absent-scratch"),
            COPILOT_HOME=str(self.root / "absent-home"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Cleared", result.stdout)

    def test_copilot_cli_installs_from_the_committed_lockfile(self) -> None:
        """Run the real install against the committed pin, with npm stubbed.

        npm ci is only a pin if it sees the lockfile: the files must be
        copied intact, npm must run in their directory with scripts off,
        and the CLI must reach PATH from there rather than globally.
        """
        (self.root / "triage-assets").symlink_to(ROOT)
        runner_temp = self.root / "runner-temp"
        runner_temp.mkdir()
        github_path = self.root / "github-path"
        npm_log = self.root / "npm-log"
        npm = self.root / "bin" / "npm"
        npm.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$PWD" "$@" > "$NPM_LOG"\n', encoding="utf-8"
        )
        npm.chmod(0o755)
        step = self.step("propose", "Install Copilot CLI")

        result = self.run_step(
            "propose",
            "Install Copilot CLI",
            **step["env"],
            RUNNER_TEMP=str(runner_temp),
            GITHUB_PATH=str(github_path),
            NPM_LOG=str(npm_log),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        dest = runner_temp / "copilot-cli"
        for name in ("package.json", "package-lock.json", ".npmrc"):
            self.assertEqual(
                (dest / name).read_bytes(),
                (ROOT / "tools" / "copilot-cli" / name).read_bytes(),
                name,
            )
        cwd, *arguments = npm_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(Path(cwd).resolve(), dest.resolve())
        self.assertEqual(
            arguments, ["ci", "--ignore-scripts", "--no-audit", "--no-fund"]
        )
        self.assertEqual(
            github_path.read_text(encoding="utf-8").splitlines(),
            [str(dest / "node_modules" / ".bin")],
        )

    bash: str

    @classmethod
    def setUpClass(cls) -> None:
        """Resolve runner-compatible Bash before the fixture replaces PATH."""
        bash = shutil.which("bash")
        if bash is None:
            raise unittest.SkipTest("inline workflow scripts require Bash 5+")
        result = subprocess.run(
            [bash, "--version"],
            env={"PATH": os.defpath},
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        version = re.search(r"version (\d+)", result.stdout)
        if version is None or int(version[1]) < 5:
            # macOS Bash 3.2 ignores errexit for a failing [[ ... ]] command.
            raise unittest.SkipTest("Bash 5+ is required to match ubuntu-latest")
        cls.bash = bash

    def setUp(self) -> None:
        """Isolate files and use the running Python interpreter, not runner tooling."""
        super().setUp()
        temporary = tempfile.TemporaryDirectory(prefix="triage-workflow-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        binaries = self.root / "bin"
        binaries.mkdir()
        (binaries / "python3").symlink_to(sys.executable)
        gh = binaries / "gh"
        gh.write_text(
            "#!/bin/sh\necho 'Unexpected GitHub call' >&2\nexit 99\n", encoding="utf-8"
        )
        gh.chmod(0o755)
        self.output = self.root / "github-output"
        self.summary = self.root / "step-summary"
        self.environment = {
            "PATH": str(binaries) + os.pathsep + os.defpath,
            "HOME": str(self.root),
            "GITHUB_OUTPUT": str(self.output),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def run_step(
        self, job: str, identity: str, **environment: str
    ) -> subprocess.CompletedProcess[str]:
        """Run the actual YAML body under the shell Actions would use.

        An undeclared shell runs as ``bash -e {0}``; ``shell: bash``
        adds ``pipefail``. Modelling the wrong one hides exactly the
        failures that survive into production, so honour the step.
        """
        step = self.step(job, identity)
        script: str = step["run"]
        self.assertNotIn(
            "${{", script, "inline scripts must receive expressions via env"
        )
        flags = ["-eo", "pipefail"] if step.get("shell") == "bash" else ["-e"]
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", *flags, "-c", script],
            cwd=self.root,
            env={**self.environment, **environment},
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def outputs(self) -> dict[str, str]:
        """Parse the single-line output protocol and reject duplicate output keys."""
        lines = self.output.read_text(encoding="utf-8").splitlines()
        values = dict(line.split("=", 1) for line in lines)
        self.assertEqual(len(lines), len(values))
        return values

    def install_evidence_tools(self) -> None:
        """Copy trusted scripts so no executed step can modify the real checkout."""
        scripts = self.root / "triage-assets" / "scripts"
        scripts.mkdir(parents=True)
        for name in (
            "bot_evidence.py",
            "bot_github.py",
            "triage_evidence.py",
            "triage_github.py",
            "triage_policy.py",
        ):
            shutil.copyfile(ROOT / "scripts" / name, scripts / name)

    def prepare_evidence(self) -> dict[str, str]:
        """Hash real prepared bytes with the workflow and simulate evidence download."""
        self.install_evidence_tools()
        prepared = self.root / "artefacts"
        prepared.mkdir()
        (prepared / "before.json").write_bytes(b'[{"number":1}]\n')
        (prepared / "excluded-repos.txt").write_bytes(b"restricted-repo\n")
        result = self.run_step("prepare", "digests")
        self.assertEqual(result.returncode, 0, result.stderr)
        hashes = self.outputs()
        prepared.rename(self.root / "evidence")
        return {"BEFORE_SHA": hashes["before"], "EXCLUSIONS_SHA": hashes["exclusions"]}

    def test_identity_includes_run_attempt_and_fresh_uuid_even_for_same_run(
        self,
    ) -> None:
        """Repeated reusable calls within one run/attempt still get distinct names."""
        namespaces: list[str] = []
        for run_id, attempt in (
            ("123456", "1"),
            ("123456", "1"),
            ("123456", "2"),
            ("987654", "1"),
        ):
            with self.subTest(
                run_id=run_id, attempt=attempt, invocation=len(namespaces)
            ):
                self.output.write_text("sentinel=preserved\n", encoding="utf-8")
                result = self.run_step(
                    "prepare", "identity", RUN_ID=run_id, RUN_ATTEMPT=attempt
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs = self.outputs()
                self.assertEqual(set(outputs), {"sentinel", "namespace"})
                self.assertEqual(outputs["sentinel"], "preserved")
                namespace = outputs["namespace"]
                prefix = f"{run_id}-{attempt}-"
                self.assertTrue(namespace.startswith(prefix), namespace)
                suffix = namespace.removeprefix(prefix)
                self.assertRegex(suffix, r"^[0-9a-f]{32}$")
                self.assertEqual(uuid.UUID(hex=suffix).version, 4)
                namespaces.append(namespace)
        self.assertEqual(len(set(namespaces)), len(namespaces))

    def test_packet_step_forwards_retriage_to_eligibility_filter(self) -> None:
        """Retriage must reach packet construction, not just the agent prompt."""
        scripts = self.root / "triage-assets" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "triage_evidence.py").write_text(
            "import json, sys\nfrom pathlib import Path\n"
            "Path('packet-args.json').write_text(json.dumps(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        step = self.step("prepare", "Prepare offline issue packet")
        self.assertEqual(step["env"]["RETRIAGE"], "${{ inputs.retriage }}")
        for retriage in ("true", "false"):
            with self.subTest(retriage=retriage):
                result = self.run_step(
                    "prepare", "Prepare offline issue packet", RETRIAGE=retriage
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = json.loads(
                    (self.root / "packet-args.json").read_text(encoding="utf-8")
                )
                self.assertEqual("--retriage" in arguments, retriage == "true")

    def test_prepare_agent_decision_respects_skip_retriage_and_pending(self) -> None:
        """Skip wins over retriage; only unlabelled issues count as pending."""
        jq = shutil.which("jq")
        if jq is None:
            self.skipTest("Prepare's inline pending calculation requires jq")
        (self.root / "bin" / "jq").symlink_to(jq)
        scripts = self.root / "triage-assets" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "snapshot.sh").write_text(
            '#!/bin/sh\nmkdir -p artefacts\nprintf "%s\\n" "$MOCK_SNAPSHOT" > "$1"\n',
            encoding="utf-8",
        )
        before = self.step("prepare", "before")
        self.assertEqual(before["env"]["SKIP_AGENT"], "${{ inputs.skip_agent }}")
        self.assertEqual(before["env"]["RETRIAGE"], "${{ inputs.retriage }}")
        self.assertEqual(
            self.jobs["prepare"]["outputs"]["run_agent"],
            "${{ steps.before.outputs.run_agent }}",
        )
        snapshots = {
            False: ("[]", '[{"labels":[{"name":"bug"}]}]'),
            True: (
                '[{"labels":[]}]',
                '[{"labels":[{"name":"bug"}]},{"labels":[]}]',
            ),
        }
        for skip, retriage, pending, expected in (
            ("false", "false", False, "false"),
            ("false", "false", True, "true"),
            ("false", "true", False, "true"),
            ("false", "true", True, "true"),
            ("true", "false", False, "false"),
            ("true", "false", True, "false"),
            ("true", "true", False, "false"),
            ("true", "true", True, "false"),
        ):
            for snapshot in snapshots[pending]:
                with self.subTest(skip=skip, retriage=retriage, snapshot=snapshot):
                    self.output.unlink(missing_ok=True)
                    result = self.run_step(
                        "prepare",
                        "before",
                        SKIP_AGENT=skip,
                        RETRIAGE=retriage,
                        MOCK_SNAPSHOT=snapshot,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.outputs(), {"run_agent": expected})
                    self.assertEqual(
                        (self.root / "artefacts" / "before.json").read_text(
                            encoding="utf-8"
                        ),
                        snapshot + "\n",
                    )

    def test_copilot_prefix_guard_runs_before_the_cli(self) -> None:
        """Token prefixes are screened locally; PAT scopes are not inferred or queried."""
        arguments = self.root / "copilot-args"
        copilot = self.root / "bin" / "copilot"
        copilot.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$@" > copilot-args\n',
            encoding="utf-8",
        )
        copilot.chmod(0o755)
        artefacts = self.root / "artefacts"
        artefacts.mkdir()
        (artefacts / "prompt.md").write_text("Offline test prompt", encoding="utf-8")
        for prefix, succeeds in (
            ("ghs_", False),
            ("ghp_", False),
            ("github_pat_", True),
        ):
            with self.subTest(prefix=prefix):
                arguments.unlink(missing_ok=True)
                result = self.run_step(
                    "propose",
                    "agent",
                    COPILOT_GITHUB_TOKEN=prefix + "test-only-not-a-real-token",
                    COPILOT_HOME=str(self.root / "copilot-home"),
                    MODEL="test-model",
                )
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                self.assertEqual(arguments.exists(), succeeds)
                if succeeds:
                    argv = arguments.read_text(encoding="utf-8").splitlines()
                    self.assertIn("--prompt=Offline test prompt", argv)
                    self.assertIn("--model=test-model", argv)
                else:
                    self.assertIn(
                        "::error::Use a model-only fine-grained Copilot PAT",
                        result.stdout,
                    )

    def test_model_input_is_checked_before_it_reaches_a_command_line(self) -> None:
        """Only a bare lower-case identifier may reach the CLI's --model flag."""
        for model, accepted in (
            ("claude-opus-5.5", True),
            ("gpt-6-astra", True),
            ("", False),
            ("Claude Opus 5.5", False),
            ("model --allow-all-tools", False),
            ("a;b", False),
        ):
            with self.subTest(model=model):
                result = self.run_step("prepare", "Check inputs", MODEL=model)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if not accepted:
                    self.assertIn("::error::model must be", result.stdout)

    def test_digest_script_hashes_exact_prepared_bytes(self) -> None:
        """Trusted outputs cover both snapshot and effective scope, including newlines."""
        prepared = self.root / "artefacts"
        prepared.mkdir()
        snapshot = b'[ {"number": 1} ]\r\n'
        exclusions = b"excluded-repo\n# scope\n"
        (prepared / "before.json").write_bytes(snapshot)
        (prepared / "excluded-repos.txt").write_bytes(exclusions)
        result = self.run_step("prepare", "digests")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.outputs(),
            {
                "before": hashlib.sha256(snapshot).hexdigest(),
                "exclusions": hashlib.sha256(exclusions).hexdigest(),
            },
        )

    def test_provenance_guard_accepts_only_complete_trusted_values(self) -> None:
        """Fail closed even when a missing SHA would otherwise select checkout HEAD."""
        valid = {
            "ASSETS_SHA": "a" * 40,
            "EVIDENCE_ID": "12345",
            "BEFORE_SHA": "b" * 64,
            "EXCLUSIONS_SHA": "c" * 64,
        }
        result = self.run_step("apply", "Require trusted provenance", **valid)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, value in valid.items():
            invalid: tuple[str, ...] = ("", " ", value + "\n")
            if name == "EVIDENCE_ID":
                invalid += ("0", "-1", "1,2", "triage-evidence-123-2")
            else:
                invalid += (value[:-1], value + "a", "g" * len(value), "main")
            for bad in invalid:
                with self.subTest(name=name, value=bad):
                    result = self.run_step(
                        "apply", "Require trusted provenance", **{**valid, name: bad}
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.output.exists())

    def test_propose_rejects_missing_trusted_checkout_sha(self) -> None:
        """The agent job also refuses GitHub checkout's empty-ref default."""
        for sha, succeeds in (("a" * 40, True), ("", False), ("main", False)):
            with self.subTest(sha=sha):
                result = self.run_step(
                    "propose", "Require pinned assets", ASSETS_SHA=sha
                )
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)

    def test_session_guard_rejects_missing_or_name_based_identity(self) -> None:
        """A successful proposal without a producer artifact ID is an error."""
        for identity, succeeds in (
            ("1234", True),
            ("", False),
            ("0", False),
            ("1,2", False),
            ("triage-session-123-2", False),
        ):
            with self.subTest(identity=identity):
                result = self.run_step(
                    "apply", "Require session artifact identity", SESSION_ID=identity
                )
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)

    def test_verified_evidence_is_copied_only_after_authentication(self) -> None:
        """Run the actual verify command and subsequent copy commands together."""
        hashes = self.prepare_evidence()
        result = self.run_step("apply", "verified", **hashes)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("before.json", "excluded-repos.txt"):
            self.assertEqual(
                (self.root / "artefacts" / name).read_bytes(),
                (self.root / "evidence" / name).read_bytes(),
            )
        self.assertEqual(
            {path.name for path in (self.root / "artefacts").iterdir()},
            {"before.json", "excluded-repos.txt"},
        )

    def test_forged_evidence_and_matching_sidecar_hash_never_get_copied(self) -> None:
        """Artifact replacement cannot authenticate itself or publish partial copies."""
        hashes = self.prepare_evidence()
        evidence = self.root / "evidence"
        for name in ("before.json", "excluded-repos.txt"):
            with self.subTest(name=name):
                path = evidence / name
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                sidecar = evidence / (name + ".sha256")
                sidecar.write_text(
                    hashlib.sha256(path.read_bytes()).hexdigest(), encoding="utf-8"
                )
                result = self.run_step("apply", "verified", **hashes)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("SHA-256 mismatch", result.stderr)
                self.assertFalse((self.root / "artefacts").exists())
                path.write_bytes(original)
                sidecar.unlink()

    def test_only_summary_crosses_from_untrusted_session(self) -> None:
        """Forged evidence and importable modules cannot overwrite trusted files."""
        hashes = self.prepare_evidence()
        result = self.run_step("apply", "verified", **hashes)
        self.assertEqual(result.returncode, 0, result.stderr)
        session = self.root / "untrusted-session"
        session.mkdir()
        summary = b"Untrusted proposal bytes; never execute them.\n"
        (session / "session-summary.md").write_bytes(summary)
        for name in (
            "before.json",
            "excluded-repos.txt",
            "bot_evidence.py",
            "bot_github.py",
            "triage_evidence.py",
            "triage_policy.py",
            "sitecustomize.py",
        ):
            (session / name).write_bytes(
                b"raise RuntimeError('Untrusted file executed')\n"
            )
        result = self.run_step("apply", "proposal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.root / "artefacts" / "session-summary.md").read_bytes(), summary
        )
        self.assertEqual(
            {path.name for path in (self.root / "artefacts").iterdir()},
            {"before.json", "excluded-repos.txt", "session-summary.md"},
        )
        for name in ("before.json", "excluded-repos.txt"):
            self.assertEqual(
                (self.root / "artefacts" / name).read_bytes(),
                (self.root / "evidence" / name).read_bytes(),
            )
        result = self.run_step("apply", "verified", **hashes)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_proposal_copy_is_bounded_and_rejects_nonregular_files(self) -> None:
        """Workflow wiring must use the bounded reader, not cp or a recursive copy."""
        self.install_evidence_tools()
        session = self.root / "untrusted-session"
        session.mkdir()
        source = session / "session-summary.md"
        destination = self.root / "artefacts" / "session-summary.md"
        for kind in ("missing", "oversized", "symlink", "directory"):
            with self.subTest(kind=kind):
                if kind == "oversized":
                    with source.open("wb") as stream:
                        stream.truncate(8 * 1024 * 1024 + 1)
                elif kind == "symlink":
                    target = self.root / "outside-summary"
                    target.write_bytes(b"Do not follow this link")
                    source.symlink_to(target)
                elif kind == "directory":
                    source.mkdir()
                result = self.run_step("apply", "proposal")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(destination.exists())
                if kind == "directory":
                    source.rmdir()
                else:
                    source.unlink(missing_ok=True)

    def test_report_uses_after_outcome_even_with_stale_or_missing_file(self) -> None:
        """Capture the real report command's argv rather than reimplement its branch."""
        scripts = self.root / "triage-assets" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "triage_report.py").write_text(
            "import json, pathlib, sys\n"
            "pathlib.Path('report-args.json').write_text(json.dumps(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        artefacts = self.root / "artefacts"
        artefacts.mkdir()
        after = artefacts / "after.json"
        for after_ok, exists, dry_run, propose_result in (
            ("false", True, "false", "failure"),
            ("false", False, "true", "skipped"),
            ("true", True, "true", "success"),
            ("true", False, "false", "success"),
        ):
            with self.subTest(after_ok=after_ok, exists=exists, dry_run=dry_run):
                after.unlink(missing_ok=True)
                if exists:
                    after.write_bytes(b"partial or stale snapshot")
                self.summary.write_text("", encoding="utf-8")
                result = self.run_step(
                    "apply",
                    "Build report",
                    AFTER_OK=after_ok,
                    DRY_RUN=dry_run,
                    PROPOSE_RESULT=propose_result,
                    APPLY_RESULT="skipped",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = json.loads(
                    (self.root / "report-args.json").read_text(encoding="utf-8")
                )
                expected = [
                    "--before",
                    "artefacts/before.json",
                    "--output-md",
                    "artefacts/triage-report.md",
                    "--output-json",
                    "artefacts/triage-report.json",
                ]
                if after_ok == "true":
                    expected += ["--after", "artefacts/after.json"]
                if dry_run == "true":
                    expected += ["--dry-run"]
                self.assertEqual(arguments, expected)
                self.assertIn(
                    f"Proposal job: {propose_result}; apply step: skipped",
                    self.summary.read_text(encoding="utf-8"),
                )


if __name__ == "__main__":
    unittest.main()
