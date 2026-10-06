<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Setup

The pipeline uses three separate runners: trusted **Prepare**,
untrusted **Propose**, and trusted **Apply**. Prepare builds an
offline packet with issue bodies, existing labels, types and
priorities. Propose classifies that packet; Apply verifies evidence
and validates proposals before writing.

Propose runs the Copilot CLI with a fine-grained `copilot_token`
PAT for model access; [GITHUB.md](GITHUB.md) covers that
credential. Prepare and Apply use the GitHub App below.

## Shared prerequisites

### GitHub App for trusted reads and writes

Live runs require an organisation App. Public user-owned targets
require dry-run. Configure the App for the intended repositories:

<!-- markdownlint-disable MD013 -->

| Setting         | Value                                                                                                                  |
| --------------- | ---------------------------------------------------------------------------------------------------------------------- |
| App permissions | `issues: write` and `metadata: read` on repositories; `issue_fields: read` and `issue_types: read` on the organisation |
| Installation    | Target repositories; all repositories for an organisation-wide scan                                                    |
| Client id       | Passed as the `github_app_client_id` input                                                                             |
| Private key     | Passed as the `github_app_private_key` secret                                                                          |

<!-- markdownlint-enable MD013 -->

Prepare holds the private key and mints `issues: read` plus
`metadata: read` for snapshots and packet assembly. Apply verifies
the prepared evidence before minting its own token, including the
organisation definition reads. Its issue-write grant requires live
mode with a successful proposal job and accepted summary; all other
paths request `read`. Propose receives
neither the App key nor an installation token, including through
App-token post actions. Its job-native `GITHUB_TOKEN` has
`contents: read` and no other permissions.

Installation tokens expire after an hour. The `repository` input
also scopes both mints to that repository. Every bot repository in the
organisation names the credentials by role: `vars.BOT_APP_CLIENT_ID`
and `secrets.BOT_APP_PRIVATE_KEY`. Here they hold the **LF/RelEng
Issues Triage Bot** App, whose slug `config/bot.json` records.

Without App credentials, trusted jobs use their job-native token
for dry-run reads within its access; it does not grant organisation-wide
private access. Live mode refuses to start without an App client ID.
The current live App mint and field/type writes still need remote
validation; offline tests do not verify GitHub's permission handling.

### Where credentials live

Model credentials are repository secrets on the **calling**
repository, matching the name each guide gives. Organisation
secrets work too when more than one repository calls the
pipeline; the workflow sees nothing but the value handed to its
named secret input.

Copilot requires a personal fine-grained PAT with Copilot Requests
and no repository permissions. Caller-native `GITHUB_TOKEN`
authentication is no longer supported. The `github_pat_` prefix
check does not test the token remotely or prove the absence of
extra grants; the caller must review them. See [GITHUB.md](GITHUB.md).

The App key belongs in trusted jobs, never Propose. Treat `assets_repository`
and `assets_ref` as trusted code choices: Prepare resolves the ref
once, and downstream jobs use its commit SHA. Do not run unreviewed
assets with secrets.

## Validation

Start with the offline tests and the linting suite:

```bash
uv run python -B -m unittest discover -s tests -v
prek run --all-files
```

The workflow-contract tests use the PyYAML development dependency.
The local suite, three-job Copilot dry-run and both secretless PR
invocations passed; see
[Design §11](../development/DESIGN.md#11-rollout-and-validation)
for run evidence and limits.

For further validation, a maintainer can dispatch the agent against
a reviewed, trusted ref:

```bash
gh workflow run testing.yaml
```

This check uses `dry_run: true` and `retriage: true`. It can examine
labelled issues but does not guarantee eligible issues or non-empty
proposals. It passes no App credentials; live App token minting and
real writes remain untested and require a separate controlled
organisation-App run.
The Copilot step rejects a missing or non-PAT token before launching
the CLI; the prefix check does not test authentication.

Inspect all three artefacts:

- **Evidence, 7 days:** snapshot, normalized exclusions and offline
  issue packet when the agent runs. Prepare supplies the artefact ID
  and snapshot/exclusion digests directly to Apply.
- **Session, 7 days:** prompt, summary and Copilot logs. Apply extracts
  this separately and copies a bounded regular summary, excluding
    other files.
- **Results, 90 days:** verified before-state, available after-state,
  accepted summary, apply outcomes and diff report. Raw session logs
  stay out of this bundle. The report requires snapshot-step success
  before using after-state and observes labels, not priority/type.

## Scope, failures and recovery

A scan reaching the 1,000-result search cap fails visibly **before**
exclusion filtering. Restrict `repository` rather than accepting an
incomplete scan. Exclusions use repository names, trim whitespace,
ignore blank lines and normalize case. A non-empty `exclude_repos`
input overrides the bundled list; file-based lists allow `#` comments.

Live organisation configuration read failures are fatal. Dry-run
alone permits known endpoint absence or missing permission and
records unavailable priority/type values as dropped. Rate limits,
transient failures and unknown errors still fail. The applier refuses
an issue whose existing Priority it cannot resolve and skips any
issue with a Priority, including during retriage.

Workflow-level concurrency covers the full prepare/propose/apply
sequence of a live run per caller repository and target owner. GitHub
may supersede pending runs; `cancel-in-progress: false` is not a FIFO
queue. Dry runs write nothing and lock within their own caller run,
so this lock never makes them wait on or cancel live runs or other
runs' dry runs. A caller's own concurrency group applies first: keep
dry runs out of any group the caller shares with live runs, as the
bundled scheduled caller does.
Different callers targeting the same organisation need coordination.

A run/attempt/UUID namespace avoids reusable and matrix artefact
collisions without caller-supplied names. Downloads use producer IDs,
so rerunning Apply without its producers can reuse their available
evidence. Final result names append the current attempt.

Writes are nontransactional: a label change can succeed before a type
or Priority write fails. Cancellation does not undo completed writes,
and live checks do not prevent races with human edits. Inspect
`apply-result.json` and the current issue before targeted recovery.
Replay often needs `retriage: true` after labels have changed, but
must never overwrite a human Priority. There is no automatic rollback
or guarantee that rerunning will complete a partial application.

## Further reading

- [Design](../development/DESIGN.md) — the architecture, the
  containment model, and the reasoning behind the Copilot CLI
  integration
- [Repository README](https://github.com/lfreleng-actions/github-issues-triage#consuming-the-reusable-workflow)
  — calling the reusable workflow from another repository
