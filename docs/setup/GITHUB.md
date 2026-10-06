<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Copilot engine setup

The workflow installs Copilot CLI `1.0.80` from npm and invokes it
in programmatic mode. It reads an offline issue packet and emits
proposals; trusted jobs perform GitHub reads and writes.

<!-- markdownlint-disable MD013 -->

| Item            | Value                                                                 |
| --------------- | --------------------------------------------------------------------- |
| Secret          | `copilot_token`                                                       |
| Default model   | `claude-opus-5.5`                                                     |
| Harness         | `@github/copilot`, locked in `tools/copilot-cli/`                     |
| Session ceiling | The step timeout is 20 minutes                                        |
| Apply path      | Separate trusted runner; see [Design §12.7](../development/DESIGN.md) |

<!-- markdownlint-enable MD013 -->

## Authentication contract

Pass a **personal fine-grained PAT** with the **Copilot Requests**
account permission and **no repository permissions**. The workflow
sets it as `COPILOT_GITHUB_TOKEN` on the Copilot step.

**Caller-native `GITHUB_TOKEN` authentication is no longer supported.**
Do not pass `${{ secrets.GITHUB_TOKEN }}` as `copilot_token` or add
`copilot-requests` to the caller's permissions. Classic PATs and App
installation tokens are not supported model credentials here either.

The step checks for the `github_pat_` prefix before launching the
CLI. This rejects missing, native and classic tokens, but **does not
prove a PAT has no extra permissions or test it remotely**.
The caller must review its grants. A PAT with repository write
permissions would undermine the intended separation.

## Create and store the PAT

1. Open <https://github.com/settings/personal-access-tokens/new>.
2. Set **Resource owner** to your personal account so GitHub shows
   **Account permissions**.
3. Grant **Copilot Requests** and no repository permissions.
4. Choose an expiry, arrange rotation before that date, and copy
   the value without logging it.
5. Store it as the calling repository's Actions secret
   `COPILOT_CLI_TOKEN` under **Settings > Secrets and variables >
   Actions**.

The token owner needs an active Copilot entitlement and access to
the selected model. Usage draws on that person's entitlement; review
billing limits and model availability before scheduling runs.

## Caller example

This App-less example supports dry-run reads within the job token's
access. For organisation-wide private reads or live writes, add the
App credentials from [shared setup](README.md).

<!-- markdownlint-disable MD013 -->

```yaml
jobs:
  triage:
    permissions:
      issues: read
      contents: read
    # Replace with a reviewed release commit SHA, not a tag object.
    # yamllint disable-line rule:line-length
    uses: lfreleng-actions/github-issues-triage/.github/workflows/issues-triage.yaml@<commit-sha>  # vX.Y.Z
    with:
      org: 'your-org'
      dry_run: true
    secrets:
      copilot_token: ${{ secrets.COPILOT_CLI_TOKEN }}
```

<!-- markdownlint-enable MD013 -->

The reusable workflow gives Propose's job-native token
`contents: read` and no other permissions. No action in that job
receives the App key or an installation token. Prepare uses the App
to build the packet; Apply mints its token after verifying evidence.

Override the model with the `model` input, which defaults to
`claude-opus-5.5`. It must be a bare lower-case identifier; check
your entitlement before choosing another.

## Check before live use

The local suite tests contracts, not remote authentication or live
writes:

```bash
uv run python -B -m unittest discover -s tests -v
prek run --all-files
```

For further validation, a maintainer can run the manual dry-run
against a reviewed, trusted ref:

```bash
gh workflow run testing.yaml
```

The three-job dry-run and the first live run both passed;
see
[Design §11](../development/DESIGN.md#11-rollout-and-validation)
for run evidence and remaining gaps. The live run minted the
write-scoped token and applied labels, `Type` and `Priority`.
`testing.yaml` passes no App credentials and cannot verify writes.
Scheduled runs apply changes; disable the caller if problems arise.
Manual dispatch retains its dry-run default.

Inspect the preparation evidence, separate session artefact and
final results. Check proposal/apply outcomes alongside the label
diff: a failed apply can leave partial writes, and the report does
not observe priority/type changes. See shared setup for recovery.

## Containment and evidence

The session reads `issue-packet.json`, including issue bodies and
existing labels, types and priorities. “Offline” describes the
issue-data source, not a network-isolated runner: the model still
uses the network. Copilot allows `cat`/`jq` reads, denies `gh`/`git`
and the write tool, and disables built-in MCPs and custom
instructions. Those approval rules and secret redaction are not a
sandbox. Treat packet contents and session output as untrusted, and
review model data handling and artefact access.

Prepared evidence and session output have **7-day retention**.
The session artefact contains `prompt.md`, `session-summary.md`
and `copilot-logs/`. Apply extracts it into `untrusted-session/`,
then copies a regular, non-symlink summary of at most 8 MiB, excluding
other files. Raw logs never enter the trusted report bundle, with **90-day
retention**. The report does not ingest session logs for cost or
turn telemetry.

## Egress

`egress_policy` governs the trusted Prepare and Apply jobs; the
bundled callers run them in block mode behind the organisation
allow-list. The Propose job always audits: the model backend
(`api.githubcopilot.com:443` and its enterprise endpoint) is outside
that allow-list, and a session in block mode cannot start. Audit
records traffic without blocking it, and
[Design §7.1](../development/DESIGN.md#71-egress) states what that
exposes on the Propose runner and what bounds it. Adding the backend
to the organisation allow-list is the step that would let Propose
block too.

## Failure modes

<!-- markdownlint-disable MD013 -->

| Symptom                                | Check or recovery                                                                                                                 |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| PAT format guard fails                 | Supply a `github_pat_` PAT through `copilot_token`, then review its permissions.                                                  |
| CLI authentication or model failure    | Check expiry, Copilot Requests, owner entitlement and model access; prefix acceptance proves none of these.                       |
| Session tries to use `gh`              | The session must use the offline packet; do not add an App token to make the command work.                                        |
| Missing or malformed summary           | Inspect the separate session artefact; Apply must not consume failed-session proposals.                                           |
| Missing evidence ID or digest mismatch | Stop and investigate provenance; do not substitute an artefact with a matching name.                                              |
| Live configuration read failure        | Fix App access or the API failure; live mode must fail rather than drop unreadable configuration.                                 |
| Partial writes                         | Inspect current state and `apply-result.json`; use targeted recovery, often `retriage: true`, without overwriting human Priority. |

<!-- markdownlint-enable MD013 -->
