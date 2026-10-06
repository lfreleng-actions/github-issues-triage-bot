<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🏷️ GitHub Issues Triage

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![Source Code](https://img.shields.io/badge/GitHub-100000?logo=github&logoColor=white&color=blue)](https://github.com/lfreleng-actions/github-issues-triage) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lfreleng-actions/github-issues-triage/badge)](https://scorecard.dev/viewer/?uri=github.com/lfreleng-actions/github-issues-triage)
<!-- prettier-ignore-end -->

Scheduled AI triage of GitHub issues. A reusable workflow prepares
an offline issue packet, runs an agent to propose labels, priority
and type, then validates and applies those proposals on a separate
runner. Before/after snapshots record observed label changes;
session logs remain separate from the trusted report.

The weekday schedule runs **live**, applying validated labels, Priority
and Type. Manual dispatch and reusable-workflow defaults remain dry-run.

The agent session runs through the **Copilot CLI**, with a
fine-grained PAT for model access and no other credential.

## 📚 Documentation

<https://lfreleng-actions.github.io/github-issues-triage/>

Credential setup and validation steps live in
[`docs/setup/`](docs/setup/README.md). The
[design document](docs/development/DESIGN.md) covers the
architecture, containment model, and rollout plan in full.

## How it works

```text
prepare (trusted) -> propose (untrusted) -> apply (trusted)
  snapshot + packet    offline proposal     verify + check
  SHA + ID + digests ---------------------> write + report
```

Each job uses a separate runner:

1. **Prepare** holds the App key, mints a read token, captures the
   snapshot and resolves exclusions. It builds `issue-packet.json`
   with issue titles, bodies, existing labels, types and priorities,
   plus each repository's label vocabulary.
2. **Propose** reads the packet instead of querying GitHub issues.
   It receives no App key or installation token; its job-native
   `GITHUB_TOKEN` grants `contents: read` and no other permissions.
   The session skips when `skip_agent` is true, or when no unlabelled
   issues exist and `retriage` is false.
3. **Apply** gets the assets commit SHA, evidence artefact ID and
   snapshot/exclusion digests directly from Prepare. It checks out
   that commit, downloads evidence by ID and verifies its bytes
   before minting an App token. It extracts the session into a
   separate directory and copies a bounded, regular
   `session-summary.md` for proposal validation, excluding other files.
4. Writes require a successful proposal job and accepted summary.
   After evidence verification, Apply can still report a skipped or
   failed proposal job. Cancellation gates apply and reporting;
   the report requires snapshot-step success before using after-state.

Prepared evidence and session artefacts have **7-day retention**;
final results have **90-day retention**. Raw session logs and the
prompt stay in the session artefact, not the trusted report bundle.
Producer artefact IDs permit rerunning Apply without its producers
while their artefacts remain available. A run/attempt/UUID namespace
avoids collisions between reusable invocations and matrix calls;
result names add the current attempt. See [Design §12.7](docs/development/DESIGN.md).

Live runs hold one workflow-level lock across the whole pipeline per
caller repository and target owner. A lock keeps one pending run and a
newcomer cancels it, so this is not a FIFO queue. Dry runs write
nothing and lock within their own caller run, so this lock never makes
them cancel each other or a live run. A caller's own concurrency group
applies first: the bundled callers give dry dispatches groups of their
own, and other callers should keep dry runs out of shared groups too.
Different caller repositories targeting the same organisation need
external coordination.

## Consuming the reusable workflow

Other organisations can call the pipeline with their own credentials.
Public user-owned targets require dry-run:

<!-- markdownlint-disable MD013 -->

```yaml
jobs:
  triage:
    permissions:
      # Snapshot reads; label writes use the App token instead
      issues: read
      contents: read
    # Pin to an immutable release commit SHA; the tag rides along
    # as a comment. Never reference a mutable branch here: the
    # trusted jobs receive your App private key.
    # yamllint disable-line rule:line-length
    uses: lfreleng-actions/github-issues-triage/.github/workflows/issues-triage.yaml@<commit-sha>  # vX.Y.Z
    with:
      org: 'your-org'
      dry_run: true
      github_app_client_id: ${{ vars.YOUR_APP_CLIENT_ID }}
    secrets:
      copilot_token: ${{ secrets.COPILOT_CLI_TOKEN }}
      github_app_private_key: ${{ secrets.YOUR_APP_PRIVATE_KEY }}
```

<!-- markdownlint-enable MD013 -->

The assets checkout defaults to the called workflow's commit.
Prepare resolves any trusted `assets_ref` override once and pins
both downstream checkouts to the resulting SHA.

### Model credential

The Copilot CLI requires a **personal fine-grained PAT** with the
**Copilot Requests** account permission and **no repository
permissions**. Store it as `COPILOT_CLI_TOKEN`. Caller-native
`GITHUB_TOKEN` authentication is no longer supported; do not pass
that token as `copilot_token` or grant `copilot-requests`.

<!-- markdownlint-disable MD013 -->

```yaml
jobs:
  triage:
    permissions:
      issues: read
      contents: read

    # yamllint disable-line rule:line-length
    uses: lfreleng-actions/github-issues-triage/.github/workflows/issues-triage.yaml@<commit-sha>  # vX.Y.Z
    with:
      org: 'your-org'
      dry_run: true
    secrets:
      copilot_token: ${{ secrets.COPILOT_CLI_TOKEN }}
```

<!-- markdownlint-enable MD013 -->

The workflow checks for the `github_pat_` prefix. **That check
neither validates the token remotely nor proves it lacks extra
permissions.** The caller must provision and review its grants.
See [Copilot setup](docs/setup/GITHUB.md) for expiry, entitlement
and validation requirements.

Without App credentials, trusted jobs use their job-native token
for dry-run reads within its access. Live runs require an
organisation App with repository `issues: write`, `metadata: read`
and organisation `issue_fields: read`, `issue_types: read`.
Single-repository runs scope the installation token at mint time;
Propose never receives it.

### Inputs

<!-- markdownlint-disable MD013 -->

| Input | Default | Purpose |
| ----- | ------- | ------- |
| `org` | (required) | GitHub organisation or user to triage |
| `model` | `claude-opus-5.5` | Copilot CLI model identifier (`^[a-z0-9.-]+$`) |
| `dry_run` | `true` | Report intended labels; apply nothing |
| `retriage` | `false` | Re-examine issues that carry labels |
| `skip_agent` | `false` | Plumbing test: skip the agent session |
| `repository` | `''` | Restrict the scan to one repository |
| `exclude_repos` | `''` | Comma-separated repositories to skip |
| `egress_policy` | `audit` | harden-runner mode (`audit`/`block`) |
| `egress_allow_config` | `''` | `harden-runner-block-action` config coordinate |
| `github_app_client_id` | `''` | App auth; empty limits runs to dry-run |
| `assets_repository` | this repo | Source of the prompt and scripts |
| `assets_ref` | called workflow's commit | Ref of `assets_repository` to fetch |

| Secret | Required | Purpose |
| ------ | -------- | ------- |
| `copilot_token` | agent sessions | Fine-grained PAT (`github_pat_`) for Copilot Requests; no repository permissions |
| `github_app_private_key` | no | Pairs with `github_app_client_id` |

<!-- markdownlint-enable MD013 -->

## Workflows in this repository

<!-- markdownlint-disable MD013 -->

| Workflow | Purpose | Trigger |
| -------- | ------- | ------- |
| `issues-triage.yaml` | The reusable pipeline | `workflow_call` |
| `issues-triage-cron.yaml` | Org triage caller | 07:00 UTC weekdays / dispatch |
| `testing.yaml` | Secretless plumbing test / manual dry-run | Pull request / dispatch |
| `documentation.yaml` | Build and publish the docs site | Push to `main` / dispatch |
| `release.yaml` | Promote draft release on tag push | Tag push |

<!-- markdownlint-enable MD013 -->

## Safety model

- **Dry-run for manual and reusable defaults:** callers can check proposals
  without writing; the weekday schedule opts into live mode.
  The App token has issue-read access during dry-run or reporting
  without application; issue-write access requires live mode and
  proposal success.
- **App credentials stay in trusted jobs:** neither an App-token
  action nor its private-key-bearing post action runs in Propose.
  Job separation alone does not protect artefacts: Apply verifies
  evidence by producer ID and Prepare's digests, not by name or
  hashes supplied by the session.
- **Live checks before writes:** the applier checks scope, normalized
  exclusions, snapshot membership, current issue state and labels,
  repository label vocabulary, and organisation field/type options.
  An existing Priority takes the whole issue out of scope, even in
  retriage mode. `Urgent` belongs to humans.
- **Configuration failures are visible:** live organisation
  configuration read failures are fatal. Dry-run alone permits known
  endpoint absence or permission denial; outages, rate limits and
  unknown errors still fail. A search reaching 1,000 results fails
  before exclusions can hide truncation; restrict the scan.
- **Bounded processing:** at most 100 eligible issues per packet and
  100 entries per proposal. Larger batches fail before detail reads
  or writes rather than sampling. Narrow the repository or
  exclusions; this processing cap is separate from the search limit.
  Helper commands have a 60-second timeout; reads retry a transient
  failure twice, writes run once.
- **No transaction or race guarantee:** writes can succeed in part,
  and humans or other callers can change issues after validation.
  Recovery needs inspection and targeted action, often
  `retriage: true` after a partial label write. Never overwrite a
  human Priority to force replay; the workflow has no automatic rollback.
- **Untrusted sessions remain a risk:** tool approval rules and
  secret redaction are not a sandbox. The session may expose issue
  text, packet contents, model credentials and runtime credentials.
  Review PAT grants, artefact access and model data handling;
  a wrong label is not the worst possible outcome.
- **Egress control:** each runner uses harden-runner in audit or
  block mode. Audit records traffic; it does not block it.

## Development

Run the offline tests and linting suite:

```bash
uv run python -B -m unittest discover -s tests -v
prek run --all-files
```

The offline suite covers policy, GitHub adapters, evidence,
snapshots, report rendering and workflow contracts; workflow tests
use the PyYAML development dependency. The three-job dry-run, both
secretless PR invocations and the first live run all passed; see
[Design §11](docs/development/DESIGN.md#11-rollout-and-validation)
for run evidence and remaining gaps.

Build and preview the documentation site locally:

```bash
uv venv --python 3.13
uv pip install --require-hashes --requirement docs/requirements.txt
.venv/bin/mkdocs serve
```

The report generator has a strict type-checking gate
(`basedpyright`, see `pyproject.toml`) and the prompt document
passes the same prose linting as the rest of the repository.
