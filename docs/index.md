<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# GitHub Issues Triage

Scheduled AI triage of GitHub issues. A reusable workflow prepares
an offline issue packet, runs an agent to propose labels, priority
and type, then validates and applies proposals on a separate runner.
Snapshots and a diff report record observed label changes, not the
agent's claims.

## Harness

The agent runs through the Copilot CLI on an untrusted runner with
a fine-grained `copilot_token` PAT for model access and nothing
else; [GITHUB.md](setup/GITHUB.md) covers the credential. The
`model` input selects the model and defaults to `claude-opus-5.5`.

## How a run works

```text
prepare (trusted)
  | snapshot, exclusions, issue packet
  | commit SHA, evidence ID, digests
  v
propose (untrusted, separate runner)
  | offline proposal; no App key or installation token
  v
apply (trusted, separate runner)
  verify original evidence -> check proposal -> write -> report
```

Prepare reads issue bodies, existing labels, types and priorities
into the packet. Propose needs no GitHub issue API access; its
job-native `GITHUB_TOKEN` grants `contents: read` and no other
permissions. Apply takes
trusted provenance directly from Prepare, not through Propose.
It downloads the session into a separate directory and copies a
bounded regular summary for validation, excluding other files.

Prepared evidence and session artefacts have **7-day retention**.
Final results have **90-day retention** and exclude raw session
logs. Downloads use producer artefact IDs, so rerunning Apply without
its producers can reuse available evidence. A run/attempt/UUID namespace distinguishes
reusable and matrix invocations; final names add the current attempt.

Apply requires successful preparation and no cancellation. Writes
also require a successful proposal job and accepted summary. A
failed or skipped session can still get a report after evidence
verification; the report requires snapshot-step success before
using after-state. The report observes labels, not priority/type
changes; inspect `apply-result.json` for those outcomes.

## Where to start

- [Setup](setup/README.md) — App permissions, Copilot PAT and
  dry-run validation.
- [Design §12.7](development/DESIGN.md) — trust boundaries, failure
  handling and recovery.
- [Repository README](https://github.com/lfreleng-actions/github-issues-triage-bot#consuming-the-reusable-workflow)
  — caller examples and input reference.

## Safety model in brief

Dry-run is the default; live runs require an organisation App.
Public user-owned targets require dry-run. Copilot requires
Copilot Requests on a fine-grained PAT with no repository permissions;
the workflow rejects caller-native `GITHUB_TOKEN` for authentication.
A `github_pat_` prefix is not proof of the token's grants or validity.

The applier checks scope, exclusions, snapshot membership and live
issue state. It skips any issue with an existing Priority and
rejects agent proposals for `Urgent`. Live organisation configuration
read failures are fatal; dry-run alone allows known absence or
permission denial. A search reaching 1,000 results fails before
exclusion filtering can conceal truncation.

Workflow concurrency serializes all three jobs of a live run per
caller repository and target owner; dry runs lock within their
own caller run. Pending runs may supersede each other; there is
no FIFO queue or cross-caller lock. Writes are nontransactional and
live checks do not prevent races with human edits. Inspect partial
writes before targeted recovery; never overwrite human Priority to
force replay. Tool approval rules and redaction are not a sandbox.

The three-job Copilot dry-run and the first live run both passed;
see
[Design §11](development/DESIGN.md#11-rollout-and-validation)
for run evidence and remaining gaps.
