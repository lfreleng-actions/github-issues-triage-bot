# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run the real snapshot script with a local gh stub and no GitHub access."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "snapshot.sh"


@unittest.skipUnless(
    shutil.which("bash") and shutil.which("jq"), "requires bash and jq"
)
class SnapshotTests(unittest.TestCase):
    """Exercise scope filtering, completeness and publication at the shell boundary."""

    def setUp(self) -> None:
        """Isolate files and substitute gh without inheriting credentials or shell hooks."""
        temporary = tempfile.TemporaryDirectory(prefix="triage-snapshot-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        binaries = self.root / "bin"
        binaries.mkdir()
        gh = binaries / "gh"
        gh.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$@" > "$MOCK_GH_ARGS"\n'
            'cat "$MOCK_GH_RESPONSE"\n'
            'exit "$MOCK_GH_STATUS"\n',
            encoding="utf-8",
        )
        gh.chmod(0o755)
        self.response = self.root / "response.json"
        self.arguments = self.root / "arguments.txt"
        self.output = self.root / "artefacts" / "before.json"
        self.exclusions = self.output.parent / "excluded-repos.txt"
        self.environment = {
            "PATH": str(binaries) + os.pathsep + os.environ.get("PATH", os.defpath),
            "HOME": str(self.root),
            "ORG": "owner",
            "MOCK_GH_ARGS": str(self.arguments),
            "MOCK_GH_RESPONSE": str(self.response),
        }

    @staticmethod
    def issue(repository: str, number: int = 1) -> dict[str, Any]:
        """Supply the search result fields used by filtering and downstream readers."""
        return {
            "repository": {"name": repository, "nameWithOwner": f"owner/{repository}"},
            "number": number,
            "title": "Example issue",
            "url": f"https://github.com/owner/{repository}/issues/{number}",
            "labels": [],
        }

    def run_snapshot(
        self, response: str, *, status: int = 0, **environment: str
    ) -> subprocess.CompletedProcess[str]:
        """Invoke the unmodified Bash script against one controlled gh response."""
        self.response.write_text(response, encoding="utf-8")
        return subprocess.run(
            ["bash", str(SCRIPT), str(self.output)],
            cwd=self.root,
            env={**self.environment, "MOCK_GH_STATUS": str(status), **environment},
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def assert_unpublished(self, result: subprocess.CompletedProcess[str]) -> None:
        """A failed first scan must leave neither evidence nor temporary output."""
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.exclusions.exists())
        self.assertEqual(list(self.output.parent.iterdir()), [])

    def test_zero_issues_publishes_empty_array(self) -> None:
        """An empty backlog is valid JSON evidence, not a query failure."""
        result = self.run_snapshot("[]")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text(encoding="utf-8")), [])
        self.assertEqual(self.exclusions.read_text(encoding="utf-8").strip(), "")
        self.assertIn("Snapshot: 0 open issue(s)", result.stdout)
        self.assertEqual(
            {path.name for path in self.output.parent.iterdir()},
            {"before.json", "excluded-repos.txt"},
        )

    def test_csv_exclusions_trim_and_ignore_case(self) -> None:
        """CSV scope names match GitHub identity regardless of whitespace or case."""
        allowed = self.issue("Allowed")
        result = self.run_snapshot(
            json.dumps([self.issue("SensitiveRepo"), self.issue("OTHER"), allowed]),
            EXCLUDE_REPOS="  sensitiverepo ,\tOther\r\n,  ",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text(encoding="utf-8")), [allowed])
        self.assertEqual(
            self.exclusions.read_text(encoding="utf-8").splitlines(),
            ["sensitiverepo", "other"],
        )

    def test_file_exclusions_trim_ignore_case_and_support_comments(self) -> None:
        """File and CSV exclusions share normalization; file comments stay supported."""
        source = self.root / "scope.txt"
        source.write_text(
            "# Scope\n  sensitiverepo  # inline comment\n\tOTHER\r\n  \n",
            encoding="utf-8",
        )
        allowed = self.issue("Allowed")
        result = self.run_snapshot(
            json.dumps([self.issue("SensitiveRepo"), self.issue("other"), allowed]),
            EXCLUDE_FILE=str(source),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text(encoding="utf-8")), [allowed])
        self.assertEqual(
            self.exclusions.read_text(encoding="utf-8").splitlines(),
            ["sensitiverepo", "other"],
        )

    def test_missing_explicit_exclusions_fail_before_gh(self) -> None:
        """A missing configured file cannot silently widen the scan."""
        result = self.run_snapshot("[]", EXCLUDE_FILE=str(self.root / "missing.txt"))
        self.assert_unpublished(result)
        self.assertFalse(self.arguments.exists())
        self.assertIn("EXCLUDE_FILE", result.stderr)

    def test_csv_override_does_not_require_exclusions_file(self) -> None:
        """A nonempty CSV remains authoritative over the configured file."""
        result = self.run_snapshot(
            json.dumps([self.issue("Excluded")]),
            EXCLUDE_REPOS="excluded",
            EXCLUDE_FILE=str(self.root / "missing.txt"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text(encoding="utf-8")), [])

    def test_failed_gh_never_publishes_partial_or_valid_output(self) -> None:
        """A nonzero gh exit vetoes even a complete-looking partial result array."""
        for response in ('[{"repository":', "[]", json.dumps([self.issue("Allowed")])):
            with self.subTest(response=response):
                result = self.run_snapshot(response, status=1)
                self.assert_unpublished(result)

    def test_failed_refresh_preserves_previous_evidence(self) -> None:
        """Publication is atomic: failure must not truncate an earlier snapshot."""
        self.output.parent.mkdir()
        previous = json.dumps([self.issue("Previous")]) + "\n"
        self.output.write_text(previous, encoding="utf-8")
        self.exclusions.write_text("previous-exclusion\n", encoding="utf-8")
        result = self.run_snapshot("[]", status=1, EXCLUDE_REPOS="new-exclusion")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(encoding="utf-8"), previous)
        self.assertEqual(
            self.exclusions.read_text(encoding="utf-8"), "previous-exclusion\n"
        )
        self.assertEqual(
            {path.name for path in self.output.parent.iterdir()},
            {"before.json", "excluded-repos.txt"},
        )

    def test_successful_gh_still_requires_one_json_array(self) -> None:
        """Empty, malformed, non-array and multiple-document responses fail closed."""
        for response in ("", "[", "null", "{}", "true", "[]\n[]"):
            with self.subTest(response=response):
                self.assert_unpublished(self.run_snapshot(response))

    def test_saturation_fails_before_excluding_repositories(self) -> None:
        """Filtering all 1000 results must not turn a truncated search into a no-op."""
        result = self.run_snapshot(
            json.dumps([self.issue("Excluded", number) for number in range(1, 1001)]),
            EXCLUDE_REPOS="excluded",
        )
        self.assert_unpublished(result)
        self.assertIn("1000", result.stderr)

    def test_below_saturation_is_publishable(self) -> None:
        """The conservative search-limit check still permits smaller results."""
        issues = [self.issue("Allowed", number) for number in range(1, 1000)]
        result = self.run_snapshot(json.dumps(issues))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text(encoding="utf-8")), issues)

    def test_repository_scope_reaches_gh_as_separate_arguments(self) -> None:
        """The real command keeps the owner, repository and result limit intact."""
        result = self.run_snapshot("[]", REPOSITORY="single-repo")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.arguments.read_text(encoding="utf-8").splitlines(),
            [
                "search",
                "issues",
                "--owner",
                "owner",
                "--state",
                "open",
                "--visibility",
                "public",
                "--limit",
                "1000",
                "--json",
                "repository,number,title,url,labels,createdAt,updatedAt",
                "--repo",
                "owner/single-repo",
            ],
        )

    def test_search_asks_for_public_repositories_alone(self) -> None:
        """Visibility is a server-side search filter evaluated at fetch time.

        The packet reaches a runner that audits egress rather than
        blocking it, so the snapshot fetches text the organisation
        already publishes and nothing else; filtering in the query
        leaves no window between a listing and the fetch.
        """
        result = self.run_snapshot("[]")
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.arguments.read_text(encoding="utf-8").splitlines()
        self.assertIn("--visibility", arguments)
        self.assertEqual(arguments[arguments.index("--visibility") + 1], "public")

    def test_hostile_issue_text_is_preserved_without_logging(self) -> None:
        """Runner-command-shaped issue text stays in the JSON, not the Actions log."""
        issue = self.issue("Allowed")
        issue["title"] = "##[error]untrusted ::add-mask::value"
        result = self.run_snapshot(json.dumps([issue]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text(encoding="utf-8")), [issue])
        self.assertNotIn(issue["title"], result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
