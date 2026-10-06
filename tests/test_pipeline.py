# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline script pipeline; GitHub and Actions scheduling are not exercised."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

# PyYAML runs in the regression hook; the isolated checker uses its
# bundled stubs to stay within pre-commit.ci's environment size limit.
import yaml  # pyright: ignore[reportMissingModuleSource]

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = """{
  "issue": {"number": 1, "title": "Crash opening a file", "body": "Empty files crash.",
            "state": "open", "labels": [], "type": null},
  "labels": [{"name": "question", "description": "Question"},
             {"name": "bug", "description": "Defect"}],
  "types": [{"name": "Task", "is_enabled": true}, {"name": "Bug", "is_enabled": true}],
  "fields": [
    {"id": 20, "name": "Effort", "options": [{"id": 201, "name": "Large"}]},
    {"id": 10, "name": "Priority", "options": [{"id": 101, "name": "High"}]}],
  "values": [
    {"field_id": 20, "issue_field_name": "Effort", "value": "Large",
     "single_select_option": {"name": "Large"}},
    {"field_id": 10, "issue_field_name": "Priority", "value": null}]
}"""
FAKE_GH = r"""
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
raw = sys.stdin.read() if "--input" in args else None
with Path(os.environ["GH_LOG"]).open("a") as log:
    log.write(json.dumps({"argv": args, "input": raw}) + "\n")
path = Path(os.environ["GH_STATE"])
state = json.loads(path.read_text())
issue = state["issue"]
endpoint = "repos/owner/repo/issues/1"
write = False
pages = False
if args[:2] == ["search", "issues"]:
    # The snapshot fetches issues from public repositories alone.
    assert args[args.index("--visibility") + 1] == "public"
    result = [{
        **{key: issue[key] for key in ("number", "title", "labels")},
        "repository": {"name": "repo", "nameWithOwner": "owner/repo"},
        "url": "https://github.com/owner/repo/issues/1",
    }]
elif args[:5] == ["issue", "edit", "1", "--repo", "owner/repo"]:
    flag, value = args[5:]
    if flag == "--add-label":
        issue["labels"].extend({"name": name} for name in value.split(","))
    elif flag == "--type":
        issue["type"] = {"name": value}
    else:
        raise SystemExit(f"unexpected edit: {args!r}")
    write, result = True, {}
elif args[:1] == ["api"]:
    assert args[-2:] == ["--header", "X-GitHub-Api-Version: 2026-03-10"]
    args = args[:-2]
    if "--method" in args:
        method = args[args.index("--method") + 1]
        assert args == ["api", "--method", method,
                        endpoint + "/issue-field-values", "--input", "-"]
        assert method in ("POST", "PUT")
        if method == "PUT":
            state["values"] = []  # GitHub PUT replaces unrelated fields too.
        for value in json.loads(raw)["issue_field_values"]:
            field = next(f for f in state["fields"] if f["id"] == value["field_id"])
            state["values"] = [v for v in state["values"]
                               if v["field_id"] != value["field_id"]]
            state["values"].append({**value, "issue_field_name": field["name"],
                                   "single_select_option": {"name": value["value"]}})
        write, result = True, state["values"]
    elif args[1] == endpoint:
        result = issue if "--jq" not in args else {
            "pr": False, "state": issue["state"],
            "labels": [label["name"] for label in issue["labels"]],
        }
    else:
        routes = {
            "orgs/owner/issue-fields": state["fields"],
            "orgs/owner/issue-types": state["types"],
            "repos/owner/repo/labels": state["labels"],
            endpoint + "/issue-field-values": state["values"],
        }
        result, pages = routes[args[1]], True
else:
    raise SystemExit(f"unexpected gh command: {args!r}")
if write:
    path.write_text(json.dumps(state))
if pages:
    chunks = [result[:1], result[1:]]
    if "--paginate" not in args:
        print(json.dumps(chunks[0]))
    elif "--slurp" in args:
        print(json.dumps(chunks))
    else:
        print("\n".join(json.dumps(chunk) for chunk in chunks))
else:
    print(json.dumps(result))
"""


def read_json(path: Path) -> Any:
    """Read a pipeline artifact or simulated GitHub state."""
    return json.loads(path.read_bytes())


@unittest.skipUnless(
    shutil.which("bash") and shutil.which("jq"), "requires bash and jq"
)
class PipelineTests(unittest.TestCase):
    """Run workflow shell steps with real scripts and a stateful gh boundary."""

    def setUp(self) -> None:
        """Separate prepare/apply workspaces and allow no inherited credentials."""
        temporary = tempfile.TemporaryDirectory(prefix="triage-pipeline-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.prepare = self.root / "prepare"
        self.workspace = self.root / "apply"
        binaries = self.root / "bin"
        for directory in (self.prepare, self.workspace, binaries):
            directory.mkdir()
        for directory in (self.prepare, self.workspace):
            (directory / "triage-assets").symlink_to(ROOT, target_is_directory=True)
        # A closed PATH cannot fall through to a real gh, curl or other client.
        tools = "bash jq dirname mkdir sed tr mktemp rm mv cp".split()
        for name in tools:
            executable = shutil.which(name)
            assert executable is not None, f"requires {name}"
            (binaries / name).symlink_to(executable)
        (binaries / "python3").symlink_to(sys.executable)
        gh = binaries / "gh"
        gh.write_text(f"#!{sys.executable}\n{FAKE_GH}", encoding="utf-8")
        gh.chmod(0o755)
        self.state = self.root / "state.json"
        self.log = self.root / "gh.jsonl"
        self.evidence = self.workspace / "evidence"
        self.session = self.workspace / "untrusted-session"
        self.session.mkdir()
        self.artefacts = self.workspace / "artefacts"
        self.state.write_text(FIXTURE, encoding="utf-8")
        self.fixture: dict[str, Any] = read_json(self.state)
        self.original_state = self.state.read_bytes()
        self.environment = {
            "PATH": str(binaries),
            "HOME": str(self.root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "GH_STATE": str(self.state),
            "GH_LOG": str(self.log),
            "ORG": "owner",
            "REPOSITORY": "repo",
            "EXCLUDE_REPOS": " Private ",
            "SKIP_AGENT": "false",
            "RETRIAGE": "false",
            "GITHUB_OUTPUT": str(self.root / "prepare-outputs.txt"),
            "TRIAGE_ORG": "owner",
            "TRIAGE_REPOSITORY": "repo",
            "TRIAGE_EXCLUDE_FILE": "evidence/excluded-repos.txt",
            "TRIAGE_RETRIAGE": "false",
            "DRY_RUN": "false",
        }
        workflow: Any = yaml.safe_load(
            (ROOT / ".github/workflows/issues-triage.yaml").read_text(encoding="utf-8")
        )
        self.steps: dict[str, str] = {
            step["name"]: step["run"]
            for job in ("prepare", "apply")
            for step in workflow["jobs"][job]["steps"]
            if "run" in step
        }

    def run_steps(
        self, *names: str, cwd: Path | None = None, **environment: str
    ) -> subprocess.CompletedProcess[str]:
        """Execute checked-in workflow commands with runner-style fail-fast Bash."""
        return subprocess.run(
            [
                str(self.root / "bin/bash"),
                *shlex.split("--noprofile --norc -e -o pipefail -c"),
                "\n".join(self.steps[name] for name in names),
            ],
            cwd=cwd or self.workspace,
            env={**self.environment, **environment},
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )

    def assert_success(self, result: subprocess.CompletedProcess[str]) -> None:
        """Include real script diagnostics when a pipeline stage fails."""
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def calls(self) -> list[dict[str, Any]]:
        """Read every gh invocation, including failed or unexpected requests."""
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def writes(self) -> list[dict[str, Any]]:
        """Identify mutating CLI requests independently of fixture state changes."""
        return [
            call
            for call in self.calls()
            if call["argv"][:2] == ["issue", "edit"] or "--method" in call["argv"]
        ]

    def prepare_evidence(self) -> None:
        """Publish read-only evidence, retaining hashes outside the session artifact."""
        self.assert_success(
            self.run_steps(
                "Snapshot issues before the session",
                "Prepare offline issue packet",
                "Record evidence digests",
                cwd=self.prepare,
            )
        )
        outputs = dict(
            line.split("=", 1)
            for line in (self.root / "prepare-outputs.txt").read_text().splitlines()
        )
        self.assertEqual(outputs["run_agent"], "true")
        self.environment.update(
            BEFORE_SHA=outputs["before"], EXCLUSIONS_SHA=outputs["exclusions"]
        )
        shutil.copytree(self.prepare / "artefacts", self.evidence)
        self.evidence_bytes = {
            path.name: path.read_bytes() for path in self.evidence.iterdir()
        }
        for path in self.evidence.iterdir():
            path.chmod(0o444)
        self.assertEqual(self.state.read_bytes(), self.original_state)
        self.assertEqual(self.writes(), [])

    def write_summary(self, number: int = 1) -> bytes:
        """Supply an untrusted agent answer, not an imported Python collaborator."""
        proposal = {
            "proposals": [
                {
                    "repository": "owner/repo",
                    "issue": number,
                    "labels": ["bug"],
                    "priority": "High",
                    "type": "Bug",
                    "rationale": "Reproducible crash",
                }
            ]
        }
        summary = ("# Session\n\n```json\n" + json.dumps(proposal) + "\n```\n").encode()
        (self.session / "session-summary.md").write_bytes(summary)
        return summary

    def apply_pipeline(
        self, *, dry_run: bool = False
    ) -> subprocess.CompletedProcess[str]:
        """Only successful verification and bounded extraction may reach application."""
        return self.run_steps(
            "Verify evidence bytes",
            "Accept bounded proposal file",
            "Apply triage proposal",
            DRY_RUN=str(dry_run).lower(),
        )

    def test_dry_run_then_live_preserves_effort_and_writes_exactly(self) -> None:
        """Validate offline, then add labels/type/Priority without replacement."""
        self.prepare_evidence()
        packet = read_json(self.evidence / "issue-packet.json")["repositories"]
        self.assertEqual(len(packet), 1)
        self.assertEqual(packet[0]["repository"], "owner/repo")
        self.assertEqual(packet[0]["labels"], self.fixture["labels"])
        self.assertEqual(
            packet[0]["issues"], [{**self.fixture["issue"], "priority": None}]
        )
        self.assertEqual(self.evidence_bytes["excluded-repos.txt"], b"private\n")
        summary = self.write_summary(packet[0]["issues"][0]["number"])
        self.assert_success(self.apply_pipeline(dry_run=True))
        dry = read_json(self.artefacts / "apply-result.json")
        self.assertTrue(dry["dry_run"])
        self.assertEqual(
            dry["counts"], {"proposed": 1, "applied": 1, "rejected": 0, "failed": 0}
        )
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.state.read_bytes(), self.original_state)
        self.assertEqual((self.artefacts / "session-summary.md").read_bytes(), summary)
        self.assert_success(self.run_steps("Apply triage proposal"))
        live = read_json(self.artefacts / "apply-result.json")
        self.assertFalse(live["dry_run"])
        self.assertEqual(live["counts"], dry["counts"])
        self.assertEqual(live["applied"], dry["applied"])
        writes = self.writes()
        self.assertEqual(
            [call["argv"] for call in writes],
            [
                shlex.split(command)
                for command in (
                    "issue edit 1 --repo owner/repo --add-label bug",
                    "issue edit 1 --repo owner/repo --type Bug",
                    "api --method POST repos/owner/repo/issues/1/issue-field-values --input - "
                    "--header 'X-GitHub-Api-Version: 2026-03-10'",
                )
            ],
        )
        self.assertEqual([call["input"] for call in writes[:2]], [None, None])
        self.assertEqual(
            json.loads(writes[2]["input"]),
            {
                "issue_field_values": [{"field_id": 10, "value": "High"}],
            },
        )
        expected = json.loads(FIXTURE)
        expected["issue"].update(labels=[{"name": "bug"}], type={"name": "Bug"})
        expected["values"][1].update(
            value="High", single_select_option={"name": "High"}
        )
        self.assertEqual(read_json(self.state), expected)
        for name, content in self.evidence_bytes.items():
            self.assertEqual((self.evidence / name).read_bytes(), content)

    def test_invalid_summary_bytes_stop_before_any_apply_api_call(self) -> None:
        """Opaque extraction may copy invalid UTF-8, but application must fail safely."""
        self.prepare_evidence()
        calls = self.log.read_bytes()
        (self.session / "session-summary.md").write_bytes(
            b"\xff\n::error::injected\n##[error]injected"
        )
        result = self.apply_pipeline()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Could not read the agent's proposal", result.stderr)
        for unsafe in ("Traceback", "::", "##["):
            self.assertNotIn(unsafe, result.stdout + result.stderr)
        self.assertEqual(self.log.read_bytes(), calls)
        self.assertEqual(self.state.read_bytes(), self.original_state)
        self.assertFalse((self.artefacts / "apply-result.json").exists())

    def test_session_snapshot_cannot_authorize_an_unscanned_issue(self) -> None:
        """Only the bounded summary crosses from the session, never its forged scope."""
        self.prepare_evidence()
        forged = json.loads(self.evidence_bytes["before.json"])
        forged[0]["number"] = 99
        (self.session / "before.json").write_text(json.dumps(forged), encoding="utf-8")
        (self.session / "excluded-repos.txt").write_text("", encoding="utf-8")
        summary = self.write_summary(99)
        self.assert_success(self.apply_pipeline())
        result = read_json(self.artefacts / "apply-result.json")
        self.assertEqual(
            result["counts"],
            {
                "proposed": 1,
                "applied": 0,
                "rejected": 1,
                "failed": 0,
            },
        )
        self.assertIn(
            "absent from this run's snapshot", result["rejected"][0]["reason"]
        )
        self.assertEqual((self.artefacts / "session-summary.md").read_bytes(), summary)
        for name in ("before.json", "excluded-repos.txt"):
            self.assertEqual(
                (self.artefacts / name).read_bytes(), self.evidence_bytes[name]
            )
            self.assertEqual(
                (self.evidence / name).read_bytes(), self.evidence_bytes[name]
            )
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.state.read_bytes(), self.original_state)

    def test_changed_evidence_stops_pipeline_before_copy_or_api_writes(self) -> None:
        """Trusted prepare hashes reject altered snapshots and exclusion lists."""
        self.prepare_evidence()
        self.write_summary()
        calls = self.log.read_bytes()
        for name in ("before.json", "excluded-repos.txt"):
            with self.subTest(evidence=name):
                path = self.evidence / name
                path.chmod(0o644)
                path.write_bytes(self.evidence_bytes[name] + b"\n")
                result = self.apply_pipeline()
                path.write_bytes(self.evidence_bytes[name])
                path.chmod(0o444)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(f"SHA-256 mismatch for {name}", result.stderr)
                self.assertFalse(self.artefacts.exists())
                self.assertEqual(self.log.read_bytes(), calls)
                self.assertEqual(self.state.read_bytes(), self.original_state)


if __name__ == "__main__":
    unittest.main()
