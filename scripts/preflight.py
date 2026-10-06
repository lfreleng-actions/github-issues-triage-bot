# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run-time checks that the trust boundary still holds before a job acts.

Every bot repository carries this file verbatim: it checks the shape
every bot shares, and knows nothing of what any one bot does.

The contract tests in ``tests/test_workflow.py`` run when a pull
request changes the workflow. A scheduled run executes whatever is on
the default branch, and nothing there re-checks the boundary before
the first App token is minted. This module does, from the pinned
assets checkout, so a merged drift in the workflow, the bot
configuration or the credentials fails the run closed instead of
running with it.

Four commands:

``workflow``   re-runs the workflow contract tests against the checked
               out workflow files and audits them with zizmor
``config``     checks ``config/bot.json`` and the credential shapes
``identity``   checks the App that minted a token is the configured one
``token``      checks a minted token cannot push to or administer a
               repository the token is scoped to

Each prints what it checked, one line per check, and nothing else:
no value a check read is ever echoed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any, cast

import bot_github as github

CLIENT_ID_RE = re.compile(r"^Iv[0-9A-Za-z]{18,}$")
# Assembled rather than written out: a literal PEM header in source
# trips the secret scanners this repository runs, and the markers are
# all the shape check needs.
PEM_HEAD = "-----BEGIN RSA " + "PRIVATE KEY-----"
PEM_TAIL = "-----END RSA " + "PRIVATE KEY-----"
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
ALLOW_CONFIG_RE = re.compile(r"^@[0-9a-f]{40}$")
MAX_CONFIG_BYTES = 64 * 1024
ZIZMOR_TIMEOUT = 300


class Drift(Exception):
    """The boundary no longer holds; the run must not continue."""


def say(check: str) -> None:
    """Record one passed check."""
    print(f"preflight: ok  {check}")


def load_config(path: Path) -> dict[str, Any]:
    """Read the bot configuration, refusing anything but a small object."""
    if not path.is_file():
        raise Drift(f"{path} is missing")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise Drift(f"{path} exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        parsed: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Drift(f"{path} is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise Drift(f"{path} is not an object")
    return cast("dict[str, Any]", parsed)


def check_config(path: Path) -> dict[str, Any]:
    """The bot configuration names one App slug and nothing unexpected."""
    config = load_config(path)
    slug = config.get("app_slug")
    if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug):
        raise Drift("config: app_slug is not a lower-case slug")
    unknown = set(config) - {"app_slug", "description"}
    if unknown:
        raise Drift(f"config: unexpected keys {sorted(unknown)}")
    say(f"config names app slug {slug}")
    return config


def check_credentials(client_id: str, private_key: str, copilot_token: str) -> None:
    """Each credential has the shape of the thing it claims to be.

    The private key is checked for PEM markers and a plausible length
    alone; it is never parsed, logged or compared.
    """
    if client_id and not CLIENT_ID_RE.fullmatch(client_id):
        raise Drift("credentials: BOT_APP_CLIENT_ID is not a GitHub App client id")
    if client_id and not private_key:
        raise Drift("credentials: client id is set but the private key is empty")
    if private_key:
        body = private_key.strip()
        if not (body.startswith(PEM_HEAD) and body.endswith(PEM_TAIL)):
            raise Drift("credentials: BOT_APP_PRIVATE_KEY is not a PEM RSA key")
        if not 1000 < len(body) < 8000:
            raise Drift("credentials: BOT_APP_PRIVATE_KEY has an implausible length")
    if copilot_token and not copilot_token.startswith("github_pat_"):
        raise Drift("credentials: copilot_token is not a fine-grained PAT")
    say("credential shapes")


def check_egress(policy: str, allow_config: str, allow_list: str) -> None:
    """Block mode has a pinned allow-list coordinate and a loaded list."""
    if policy not in ("audit", "block"):
        raise Drift(f"egress: policy {policy!r} is neither audit nor block")
    if policy == "block":
        if not ALLOW_CONFIG_RE.fullmatch(allow_config):
            raise Drift("egress: block mode needs a commit-pinned allow-list")
        if not allow_list.strip():
            raise Drift("egress: block mode but CONNECTION_ALLOW_LIST is empty")
    say(f"egress {policy}")


def check_live_skew(dry_run: bool, workflow_sha: str, assets_sha: str) -> None:
    """A live run executes the scripts of the commit its workflow came from."""
    if not dry_run and workflow_sha and workflow_sha != assets_sha:
        raise Drift("assets: live run with assets_ref differing from the workflow")
    say("assets match the workflow" if not dry_run else "dry run; assets skew allowed")


def run_contract_tests(root: Path) -> None:
    """Re-run the workflow contract tests against the checked-out files."""
    sys.path.insert(0, str(root / "tests"))
    suite = unittest.defaultTestLoader.loadTestsFromName("test_workflow")
    with open(os.devnull, "w", encoding="utf-8") as sink:
        result = unittest.TextTestRunner(stream=sink, verbosity=0).run(suite)
    if not result.wasSuccessful():
        failed = [str(case) for case, _ in result.failures + result.errors]
        raise Drift(f"workflow contracts failed: {failed[:5]}")
    say(f"{result.testsRun} workflow contract tests")


def run_zizmor(root: Path) -> None:
    """Audit the checked-out workflows; any finding is drift."""
    binary = shutil.which("zizmor")
    if binary is None:
        raise Drift("zizmor is not installed on the runner")
    proc = subprocess.run(
        [
            binary,
            "--persona",
            "auditor",
            "--no-progress",
            "--format",
            "json",
            str(root / ".github" / "workflows"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=ZIZMOR_TIMEOUT,
    )
    if proc.returncode not in (0, 11, 12, 13, 14):
        raise Drift(f"zizmor failed to run (exit {proc.returncode})")
    try:
        findings: Any = json.loads(proc.stdout or "[]")
    except ValueError as exc:
        raise Drift("zizmor produced unreadable output") from exc
    if not isinstance(findings, list):
        raise Drift("zizmor produced unreadable output")
    live = 0
    for finding in cast("list[Any]", findings):
        if not isinstance(finding, dict):
            continue
        if cast("dict[str, Any]", finding).get("ignored") is not True:
            live += 1
    if live:
        raise Drift(f"zizmor reported {live} finding(s)")
    say("zizmor audit clean")


def check_identity(expected_slug: str, minted_slug: str) -> None:
    """The App that minted the token is the one this pipeline is configured for.

    The key for a broader App wired into this workflow would still
    mint a working token; the slug the action returns is the one
    signal that says whose key it was.
    """
    if not minted_slug:
        raise Drift("identity: the token mint returned no app slug")
    if minted_slug != expected_slug:
        raise Drift(
            f"identity: token minted by {minted_slug}, expected {expected_slug}"
        )
    say(f"token minted by {minted_slug}")


def scoped_repository() -> str:
    """One repository the minted token can see, asked of the installation.

    A mint scoped to named repositories, or to a target organisation
    other than the caller's, cannot read the caller repository; the
    installation listing is in scope by construction, whatever the
    mint asked for.
    """
    data = github.api_object("installation/repositories?per_page=1")
    entries = data.get("repositories")
    if not isinstance(entries, list) or not entries:
        raise Drift("token: the installation grants access to no repository")
    first = cast("list[Any]", entries)[0]
    if not isinstance(first, dict):
        raise Drift("token: installation listing carried no repository object")
    return github.require_str(cast("dict[str, Any]", first), "full_name", "token")


def check_token_read_only(repository: str | None = None) -> None:
    """A read token must not be able to push to or administer a repository.

    Uses GH_TOKEN from the environment; the probe reads one repository
    the token is scoped to and inspects the permissions it holds there.
    """
    target = repository or scoped_repository()
    data = github.api_object(f"repos/{target}")
    perms = data.get("permissions")
    if not isinstance(perms, dict):
        raise Drift("token: repository reply carried no permissions")
    grants = cast("dict[str, Any]", perms)
    if grants.get("push") or grants.get("admin") or grants.get("maintain"):
        raise Drift("token: read token can push, maintain or administer")
    say(f"token is read-only on {target}")


def main(argv: list[str] | None = None) -> None:
    """Run the requested checks; any drift exits non-zero."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    workflow = commands.add_parser("workflow", help="contract tests and zizmor")
    workflow.add_argument("--root", type=Path, required=True)

    config = commands.add_parser("config", help="bot config, credentials, egress")
    config.add_argument("--config", type=Path, required=True)
    config.add_argument("--egress-policy", required=True)
    config.add_argument("--egress-allow-config", default="")
    config.add_argument("--dry-run", action="store_true")
    config.add_argument("--workflow-sha", default="")
    config.add_argument("--assets-sha", default="")

    identity = commands.add_parser("identity", help="minted app slug matches config")
    identity.add_argument("--config", type=Path, required=True)
    identity.add_argument("--minted-slug", required=True)

    token = commands.add_parser("token", help="minted token is read-only")
    token.add_argument("--repository", default=None)

    args = parser.parse_args(argv)
    try:
        if args.command == "workflow":
            run_contract_tests(args.root)
            run_zizmor(args.root)
        elif args.command == "config":
            check_config(args.config)
            check_credentials(
                os.environ.get("BOT_APP_CLIENT_ID", ""),
                os.environ.get("BOT_APP_PRIVATE_KEY", ""),
                os.environ.get("COPILOT_GITHUB_TOKEN", ""),
            )
            check_egress(
                args.egress_policy,
                args.egress_allow_config,
                os.environ.get("CONNECTION_ALLOW_LIST", ""),
            )
            check_live_skew(args.dry_run, args.workflow_sha, args.assets_sha)
        elif args.command == "identity":
            check_identity(str(check_config(args.config)["app_slug"]), args.minted_slug)
        else:
            check_token_read_only(args.repository)
    except Drift as exc:
        parser.exit(1, f"::error::preflight: {github.safe_message(exc)}\n")
    except (OSError, subprocess.SubprocessError, github.GitHubError) as exc:
        parser.exit(
            1, f"::error::preflight could not run: {github.safe_message(exc)}\n"
        )


if __name__ == "__main__":
    main()
