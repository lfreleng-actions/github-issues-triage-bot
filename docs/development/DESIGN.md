<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Design: Scheduled AI Triage of GitHub Issues

**Status:** Three-job pipeline live; first production write run passed
**Repository:** `lfreleng-actions/github-issues-triage`
**Author:** Matthew Watkins (AI-drafted, human-reviewed)
**Last updated:** 2026-09-18

This document describes the current workflow and helper scripts.
§12.7 defines the prepare/propose/apply trust boundary.
[§11](#11-rollout-and-validation) records validation evidence and
its limits. Copilot CLI is the harness; §12 describes it in
detail.

## 1. Problem Statement

Open issues across `lfreleng-actions` often arrive without labels.
The [security report](https://github.com/lfreleng-actions/github-security-report-action)
surfaces them as **Untriaged**, but manual triage does not keep pace
with new issues. Missing categories weaken release-drafter output,
maintainer filters and backlog reporting.

## 2. Goal

The scheduled caller runs at **07:00 UTC every weekday**. It scans
open issues, asks an agent to propose category labels, priority and
type, and delegates validation and writes to trusted code. Snapshots
and a diff report show observed label movement.

The schedule runs live, applying validated labels, Priority and
Type. Manual dispatch and reusable-workflow consumers keep their
dry-run defaults.

### Non-goals

- Closing, reopening or commenting on issues
- Editing titles or bodies
- Assigning people or milestones
- Triaging pull requests
- Creating repository labels or organisation field/type definitions
- Automatic rollback or transactional multi-field updates

## 3. Model Access

The workflow invokes Copilot CLI in programmatic mode with a
personal fine-grained PAT. It requires Copilot Requests and no
repository permissions. The workflow rejects caller-native
`GITHUB_TOKEN`, classic PATs and App installation tokens as model
credentials. See §12.3 and [Copilot setup](../setup/GITHUB.md).

The `model` input names the Copilot model the session uses and
defaults to `claude-opus-5.5`. Prepare rejects any value that is
not a bare lower-case identifier before it can reach the CLI's
command line.

## 4. Agent Harness

### 4.1 Selection

The workflow keeps the harness invocation inside Propose. Prepare,
policy validation, GitHub writes and reporting never read the
model or touch the CLI, so a harness change touches one job
alone. A bespoke model tool loop would duplicate the CLI; replacing
the pipeline with Agentic Workflows would be a separate
architectural decision.

### 4.2 Invocation contract

The agent reads `artefacts/issue-packet.json` and the assembled
policy prompt. It emits a summary containing a fenced JSON proposal.
It does not need GitHub issue API access or an App credential.

The CLI installs from a committed lockfile. Tool approval rules are
defence in depth, not a sandbox or proof that the session cannot
reach credentials. The trusted applier never executes
session-provided code.

### 4.3 Cost control

Prepare skips Propose when `skip_agent` is true, or when no unlabelled
issues exist and `retriage` is false. One session handles the
packet rather than one session per issue. The session has a
20-minute step timeout inside a 30-minute job.

## 5. GitHub Authentication and Permissions

### 5.1 A dedicated GitHub App

Live runs require an organisation App. Public user-owned targets
require dry-run. The App needs:

- Repository `issues: write` and `metadata: read`
- Organisation `issue_fields: read` and `issue_types: read`
- Installation access to the target repositories

Prepare and Apply alone receive the App private key. Prepare mints
issue-read access for snapshot and packet reads. Apply mints its own
token after evidence verification, with organisation definition
reads and an issue grant chosen for the path: `write` for live mode
with successful proposal/export gates, otherwise `read`.

A single-repository input scopes both installation tokens at mint
time. Tokens expire after an hour. The calling workflow names the
credentials by role, as every bot repository in the organisation
does: `vars.BOT_APP_CLIENT_ID` and `secrets.BOT_APP_PRIVATE_KEY`.
In this organisation the App behind them is **LF/RelEng Issues
Triage Bot**, whose slug `config/bot.json` records and the pre-flight
gate checks.

Without an App, trusted jobs use their job-native token for dry-run
reads within its access. That token does not grant organisation-wide
private access. Propose's job-native `GITHUB_TOKEN` has
`contents: read` and no other permissions. It has no App key,
installation token or App-token post action.

### 5.2 Model credentials are separate

The Copilot PAT is for model requests, not repository writes. Its
prefix does not prove its permissions; caller provisioning remains
part of the trust boundary. The workflow accepts no PAT substitute for the
App private-key secret.

## 6. Triage Policy

The policy lives in `prompt/triage.md`; deterministic checks live
in `scripts/triage_policy.py`.

| Label | Apply when the issue… |
| ----- | --------------------- |
| `bug` | reports incorrect behaviour |
| `feature` | requests new capability |
| `documentation` | concerns documentation or contributor guides |
| `code-quality` | concerns linting, typing, tests or hygiene |
| `CI` | concerns workflows, runners or pre-commit infrastructure |
| `chore` | tracks maintenance |
| `refactor` | requests restructuring without behaviour change |
| `breaking-change` | describes a compatibility break |
| `performance` | concerns speed or resource use |
| `question` | needs a human decision |

The applier enforces these rules:

- Propose existing taxonomy labels, with at most two effective
  taxonomy labels after application. Existing taxonomy labels count.
- Preserve human labels except the explicit `enhancement` to
  `feature` migration. `bug` and `feature` must not coexist.
- Skip labelled issues unless `retriage` is true.
- Skip the entire issue when it already has a Priority, regardless
  of retriage mode or an omitted priority proposal.
- Require priority and type keys; `null` expresses no proposal.
  Check non-null values against organisation definitions and type
  against the effective labels.
- Reserve `Urgent` for humans. An agent can propose `High` with
  `escalate: true`; escalation with another grade fails validation.
- Treat issue text and the agent's rationale as untrusted data.

Prompt instructions guide classification but do not establish a
security boundary. The applier validates proposals rather than
trusting the agent's account of what it did.

## 7. Workflow Design

```text
prepare: trusted runner, 15 minutes
  resolve assets -> snapshot -> packet -> publish evidence
       | SHA, evidence ID, digests            |
       |                                      v
       |                         propose: untrusted runner, 30 minutes
       |                           offline packet -> session artefact
       v                                      |
apply: trusted runner, 15 minutes <------------+
  verify evidence -> extract summary -> check -> write -> report
```

Workflow-level concurrency uses
`triage-pipeline-${{ github.repository }}-${{ inputs.org }}` with
`cancel-in-progress: false` for live runs. The lock covers the full
three-job sequence, not each stage independently. A group holds one
running and one pending run; a newcomer cancels the pending one, so
this is not a FIFO queue. Different caller repositories need external
coordination when targeting the same organisation. Concurrency does
not exclude human edits or unrelated automation.

Dry runs take `triage-dry-run-${{ github.run_id }}-${{ inputs.org }}`
instead. They mint no write token and skip every write, so they need
no protection from live runs. Sharing the live group let simultaneous
pull request checks cancel one another's pending plumbing
invocations, failing the Testing workflow. Invocations inside one
caller run still share a dry-run group, which is why the plumbing
matrix stops at two legs. A dry-run report can show a concurrent live
run's writes in its snapshot diff; `apply-result.json` records what
the run itself would apply.

A caller's workflow-level group applies before this lock, so the
guarantee above holds for this lock alone. The bundled callers keep
dry runs out of shared groups. The scheduled caller places dry
dispatches in `issues-triage-dry-run-${{ github.run_id }}`, so they
neither wait behind the schedule nor cancel a pending live run. The
Testing caller keys pull requests on their ref, so a new push
supersedes that pull request's older run, and gives each manual
dispatch its run ID, so one agent dry run never cancels another.

### 7.1 Egress

The trusted jobs, Prepare and Apply, run harden-runner in the mode
`egress_policy` names, `block` by default in the bundled callers,
and load the organisation allow-list first from the coordinate in
`egress_allow_config`. Propose always audits, because the Copilot
model backend (`api.githubcopilot.com` and its enterprise endpoint)
is outside the organisation allow-list and a session in block mode
cannot start. Audit records outbound calls without blocking them.

Audit mode is a deliberate, bounded exposure, not a claim that the
job holds nothing worth protecting. §12.2 names what sits on that
runner: the offline issue packet, the model PAT and the Actions
runtime token. A prompt-injected session could send any of them to
a host of its choosing. What bounds the damage is what each is
worth: the packet is text from public issues the organisation
already publishes; the PAT buys model requests on one person's
entitlement and grants no repository access; the runtime token
carries `contents: read` on this repository alone and expires with
the job. No credential on the Propose runner can write to any
repository, and §12.7 keeps every write behind evidence the trusted
jobs verify. The residual risks are model spend and disclosure of
public text, and the per-session timeout and the operator's spend
review are the controls for the first.

Block mode for Propose needs the model backend in the allow-list,
which the organisation has not added; adding it would narrow the
exposure to the backend itself and is the first item in §10.

The loader's pre hook runs in the two trusted jobs, with
`allow_list_summary` true in Prepare alone, so the shared allow-list
summary appears once. Propose loads no allow-list because it
enforces none.

### 7.2 Reporting and Run Artefacts

`snapshot.sh` captures repository, number, title, URL, labels and
timestamps. It validates a single JSON array and fails when search
returns 1,000 results, before exclusions can conceal truncation.
Restrict the scan rather than treating the cap as a complete result.

Search completeness and processing capacity are separate limits.
Preparation filters labelled issues unless retriaging, then refuses
more than 100 eligible targets before any per-issue API reads. Apply
refuses more than 100 proposal entries before configuration reads or
writes. Neither path samples a larger batch: use the
repository restriction or exclusions to narrow it. GitHub helper
commands time out after 60 seconds, and a read retries a transient
5xx or timeout twice before failing; a write runs once. Network
latency can still exhaust a job deadline, so these bounds are not a
completion-time guarantee.

Exclusions use repository names, trim whitespace, drop blank lines
and normalize case. File-based lists allow `#` comments; a non-empty
`exclude_repos` overrides the bundled list. Snapshot publication
uses temporary files so failed queries do not publish partial JSON.

The workflow keeps three artefacts with distinct lifetimes:

<!-- markdownlint-disable MD013 -->

| Artefact | Contents | Retention |
| -------- | -------- | --------- |
| `triage-evidence-<namespace>` | `before.json`, resolved `excluded-repos.txt`, `issue-packet.json` when Propose runs | 7 days |
| `triage-session-<namespace>-<current-attempt>` | `prompt.md`, `session-summary.md`, Copilot logs | 7 days |
| `issues-triage-<namespace>-<current-attempt>` | Verified before-state/exclusions, accepted summary, apply result, available after-state and diff report | 90 days |

<!-- markdownlint-enable MD013 -->

Raw session logs remain in the session artefact. Apply copies
the bounded summary, never logs, prompt or executable assets from
that directory. The accepted summary still contains untrusted text;
copying it does not endorse its claims.

The report requires after-snapshot step success before using
after-state; the existence of `after.json` does not suffice. Without
it, the report is incomplete. The diff observes labels, not
priority/type changes, and does not prove which actor caused a
change. `apply-result.json` records apply outcomes; session logs do
not feed the trusted report.

Session and result uploads use `always()`, but cancellation,
runner loss or upload failure can prevent preservation. Do not
promise a complete session log or evidence on every failure. Review
artefact access and model data handling: packets may include private
issue content, and logs can contain sensitive data despite redaction.

### 7.3 Modular consumption

The reusable workflow carries all three jobs. The thin scheduled
caller supplies triggers and organisation-specific credentials.
The repository README holds the input reference and pinned
caller examples; [setup](../setup/README.md) describes permissions.

Pin the called workflow to a reviewed commit SHA, not a tag object.
Assets default to the called workflow commit. Prepare resolves a
trusted `assets_ref` override once; both downstream jobs consume
its resolved SHA. If the workflow commit is unavailable, the caller
must supply a trusted ref. Neither Propose nor an artefact chooses
the applier's code revision.

## 8. Repository Layout

```text
.github/workflows/issues-triage.yaml       # three-job reusable workflow
.github/workflows/issues-triage-cron.yaml  # schedule and manual caller
.github/workflows/testing.yaml            # secretless PR / manual dry-run
prompt/triage.md                           # classification policy
config/excluded-repos.txt                  # bundled exclusions
scripts/snapshot.sh                       # bounded open-issue search
scripts/bot_github.py                      # shared gh plumbing (template)
scripts/bot_evidence.py                    # shared bounded reads, digests
scripts/artifact_fetch.py                  # shared, unused here (template)
scripts/preflight.py                       # shared App installation gate
scripts/ledger.py                          # shared, unused here (template)
scripts/triage_evidence.py                 # packet, verification, extraction
scripts/triage_policy.py                   # deterministic proposal checks
scripts/triage_github.py                   # triage-specific GitHub reads/writes
scripts/apply_triage.py                    # validation and apply outcomes
scripts/triage_report.py                   # snapshot diff and report
tests/                                    # offline regression tests
docs/                                     # MkDocs site and setup guides
```

Every bot carries five shared modules, copied verbatim from
`lfreleng-actions/bots-template`: `bot_github.py`, `bot_evidence.py`,
`artifact_fetch.py`, `preflight.py` and `ledger.py`. Triage calls
`bot_github`, `bot_evidence` and `preflight`. It has no per-target
memory, so `ledger.py` ships unused to keep the copied set whole;
`artifact_fetch.py` likewise, since Apply downloads the session
artefact whole and copies out nothing but its bounded summary.

PR plumbing skips the agent and passes no model or App secrets.
Manual agent validation must use a reviewed ref; a dry-run still
exposes its model credential to the chosen code.

## 9. Failure Modes and Mitigations

<!-- markdownlint-disable MD013 -->

| Failure | Handling |
| ------- | -------- |
| Search reaches 1,000 results | Fail before exclusions; restrict the scan. |
| Missing provenance, evidence or digest mismatch | Fail closed before App minting; never fall back to an artefact name. |
| Failed proposal job or missing export | Do not apply its proposal; report when verified evidence and cancellation gates permit. |
| Live organisation configuration read failure | Fail, including known missing permissions or endpoints. |
| Known configuration absence in dry-run | Permit recognized absence/permission denial alone; record dropped priority/type values. |
| Rate limit, outage or malformed API data | Operational failure, not a harmless proposal rejection. |
| Invalid or duplicate proposal | Reject it; malformed top-level proposal data fails the step. |
| Partial write or cancellation during writes | Inspect current state; targeted recovery, not automatic rollback. |
| Human edit after validation | A race remains; do not describe live reads or concurrency as atomic protection. |
| Prompt injection or secret exposure | No App credentials in Propose; keep provenance checks, review PAT grants and treat tool rules/redaction as defence in depth. |

<!-- markdownlint-enable MD013 -->

## 10. Open Questions

- Add the Copilot model backend to the organisation egress
  allow-list, so Propose can run in block mode and the exposure §7.1
  accepts narrows to the backend itself. That is an organisation
  change, outside this repository.
- Narrow the Apply job's write token to the repositories a validated
  proposal targets. Scoping requires naming repositories, and an
  org-wide scan names none, so the installation token reaches
  every repository. The applier already rejects out-of-scope
  targets, making this defence in depth rather than a new control;
  it touches the credential path, so treat it as its own change.
- Extend reporting if operators need observed priority/type changes;
  the current snapshot diff covers labels alone.
- Exercise partial-write recovery, rate-limit handling and a batch
  near the 100-issue cap; the first live run covered none of these.

## 11. Rollout and Validation

The local test suite covers policy, GitHub adapters, snapshot
failures, evidence integrity and workflow contracts, including
execution of embedded shell snippets with fakes. Workflow tests use
the PyYAML development dependency.

```bash
uv run python -B -m unittest discover -s tests -v
prek run --all-files
```

The [fork Copilot run][fork-validation] at the first consolidated
head, `a57aa2f`, completed with status `success`: Prepare, Propose,
Apply and all regression jobs passed with `dry_run: true`,
`retriage: true` and no App credentials. The [PR testing run][pr-validation]
also completed with status `success` for both the first and second secretless
invocations: Prepare and Apply succeeded, and Propose skipped in each.
Those invocations verified the absence of artefact-name collisions
between them. The fork result contains five accepted proposals with
no rejections or failures, and identical before/after snapshots.
Rerunning Apply reused the producer artefact IDs and published
a distinct attempt-2 report without repeating the model session.

[fork-validation]: https://github.com/modeseven-lfreleng-actions/github-issues-triage/actions/runs/35216029661
[pr-validation]: https://github.com/lfreleng-actions/github-issues-triage/actions/runs/35216002363

The [production dry-run][production-validation] also minted the
App's read-scoped token and validated 19 proposals with no rejected,
failed or dropped fields. Its snapshots were identical: it performed
no issue writes.

The [first live run][live-validation] then exercised the write path
end to end. Its Apply job minted `issues: write` alongside the
organisation `issue_fields` and `issue_types` reads, and applied all
19 proposals with none rejected, failed, dropped or escalated. The
snapshot diff recorded 19 changed issues, matching the
applied set, and left no unlabelled issues. Direct API reads afterwards
confirmed labels, `Type` and `Priority` on sampled issues. Apply took
83 seconds for 19 issues across 12 repositories.

That closes the untested path: live token minting, label
writes, and issue-field and type writes. It does not exercise partial
write recovery, rate-limit behaviour or a batch near the 100-issue
cap.

[production-validation]: https://github.com/lfreleng-actions/github-issues-triage/actions/runs/35318520607
[live-validation]: https://github.com/lfreleng-actions/github-issues-triage/actions/runs/35324225186

Scheduled runs now apply triage changes. To pause production if a run
reveals an operational problem, disable the scheduled caller:

```bash
gh workflow disable issues-triage-cron.yaml \
  --repo lfreleng-actions/github-issues-triage
```

Disabling future runs does not cancel an in-progress run or undo its
writes. Cancel an active run separately when needed, then inspect
partial application before retrying. Resolve the problem before
re-enabling the caller. Manual dispatch still defaults to dry-run.

The pinned token action forwards the organisation read grants through
`INPUT_PERMISSION-ISSUE-FIELDS` and `INPUT_PERMISSION-ISSUE-TYPES` in
its step environment. Version 3.2.0 does not declare corresponding
inputs; putting them in `with` creates main and post warnings. Keep
explicit repository permissions and proposal-success conditions.
Recheck this workaround on upgrades: declared input defaults
can overwrite the environment values.

## 12. GitHub Copilot

### 12.1 Harness

The workflow installs `@github/copilot` at `1.0.80` with Node 22 and
invokes `copilot --prompt`. `tools/copilot-cli/package-lock.json` pins
that version and every package beneath it by hash; the workflow runs
`npm ci --ignore-scripts` on it from the verified assets checkout.
The `model` input selects the model; the scheduled caller maps a
display name chosen on dispatch to its identifier.
CLI logs and the `--share` summary go to the separate session
artefact. The summary supplies the proposal; logs do not permit
writes.

### 12.2 Session containment

Propose offers Copilot shell tools, pre-approves `cat` and `jq`,
and denies `gh`, `git` and the write tool. It disables built-in
MCPs, custom-instruction loading and auto-update. It no longer seeds
a `gh` configuration with an App token.

An approval policy is not a sandbox. Shell reads and same-user
process access can expose data or credentials beyond the intended
packet. `--secret-env-vars=COPILOT_GITHUB_TOKEN` and log masking do
not guarantee secrecy after a value transformation.
Consider the model PAT, packet and Actions runtime credentials
exposed to the untrusted runner. A wrong label is not a worst-case
bound; model spend, data disclosure and artefact interference remain
risks. §12.7 protects the apply path without relying on those rules.

Run 35324225186 measured that boundary rather than assuming it. The
session ran `sed` and `grep`, which the allow list did not name, and
the CLI refused an unlisted `rm -f` of its own temporary file. So it
auto-approves commands it classifies as reads and requires an explicit
allow entry for the rest. The allow list now names the read utilities
the session needs, which changes no current behaviour and keeps the
run working if that classification tightens. The deny list still
overrides auto-approval for `gh`, `git` and the write tool.

That list holds `cat`, `jq`, `grep`, `head`, `tail` and `wc` alone.
`awk` and `sed` stay out despite the session reaching for `sed`:
`awk`'s `system()` runs arbitrary commands and GNU `sed`'s `w`
command writes files, so allowing either would grant a standing
bypass of those denials, because the shell tool sees the
interpreter's name and nothing beyond it. The CLI may still
auto-approve them as reads, which is this section's point: the gap
is the classifier's, and the workflow declines to widen it. `jq` can
read the environment, which is why `--secret-env-vars` covers the
model token and why no installation token reaches this job at all.

A later step clears the CLI's spilled tool output and its home
directory, so the session has no reason to attempt the cleanup its
policy refuses; a predictable refusal in the log is noise a real one
has to compete with. That step deletes rather than scrubs. `srm` is
absent from the runner image, `shred` documents its own dependence on
in-place overwrite that SSD wear-levelling breaks, and the same issue
bodies travel in the evidence artefact by design. Confidentiality of
issue content is a retention question, not an erasure one.

### 12.3 Authentication and billing

`copilot_token` must be a personal fine-grained PAT with Copilot
Requests and no repository permissions. The step sets
`COPILOT_GITHUB_TOKEN` and checks the `github_pat_` prefix. This is a
format guard, not remote validation or proof of missing extra grants.
The caller must provision and review the token's permissions.

Caller-native `GITHUB_TOKEN` is no longer supported as a model
credential. There is no caller-token permission-inheritance claim
in this design. Propose's own native token has `contents: read`
and no other permissions, independent of the model PAT.

The PAT owner needs Copilot entitlement and access to the selected
model. Usage draws on that entitlement; expiry, rotation and billing
limits need operational ownership. App installation tokens are not
an alternative model-authentication route in this workflow.

### 12.4 Validation work

See [§11](#11-rollout-and-validation) for the successful three-job
Copilot dry-run and remaining validation limits. Inspect proposal
outcomes and audit network endpoints for the pinned CLI.

### 12.5 Open questions

Measure classification quality and spend on a representative backlog.
The default model is a configuration choice, not evidence of the
cheapest or most accurate option. Remote live App minting and
writes remain pending (§10–§11).

### 12.6 Scheduled identity

The schedule applies changes. A dedicated App
handles trusted repository reads and writes; a separate personal PAT
handles model requests. Do not combine these roles by passing an App
key or repository-capable PAT to Propose. Rotate the model PAT before
expiry rather than treating prefix acceptance as a health check.

### 12.7 Prepare, propose and apply

#### Trusted preparation

Prepare runs on its own runner and holds the App key. Its issue-read
installation token scans issues and builds `issue-packet.json` from
eligible snapshot members, subject to the 100-issue processing cap
(§7.2). The packet includes issue titles, bodies, states,
existing labels, types and priorities, plus repository label names
and descriptions. Existing Priority values remain visible so the
agent can skip those issues. Packet reads do not mutate GitHub.

Prepare resolves the assets ref to a commit SHA and publishes these
job outputs: `assets_sha`, `evidence_id`, `before_sha256`,
`exclusions_sha256` and `namespace`. The digests cover the exact
bytes of `before.json` and `excluded-repos.txt`; they are not a claim
that every file in the evidence artefact has a separate trusted hash.

The namespace combines run ID, producer attempt and a fresh UUID.
It distinguishes reusable invocations and matrix calls automatically,
without asking callers to invent collision-free names.

#### Untrusted proposal runner

Propose checks out Prepare's SHA and downloads the packet using
Prepare's evidence ID. No action in this job receives the App key
or an installation token. It runs no App-token action that could expose the key
after the session. Its native `GITHUB_TOKEN` grants `contents: read`
and no other permissions. Copilot gets the PAT described in §12.3
for model access, without repository permissions.

Treat the session artefact and `session_id` output as untrusted data,
not code or evidence provenance. Runtime credentials may permit artefact
interference: a name alone does not authenticate an upload, and an
earlier upload is not immune merely because it preceded the agent.

#### Trusted application

Apply depends on both jobs but takes the assets SHA, evidence ID and
digests **directly from Prepare**, never through Propose or files in
the downloaded artefact. Missing or malformed provenance fails closed.
It checks out that SHA, downloads evidence by producer ID into
`evidence/`, and verifies snapshot/exclusion bytes against Prepare's
digests before copying them or minting any App token.

`scripts/triage_evidence.py` delegates to the shared
`bot_evidence.verify`, which checks bounded regular files without
following final symlinks: 16 MiB for the snapshot and 1 MiB for
exclusions. A forged sidecar digest or replacement artefact with the
same name cannot supply the trusted expected values. Missing or
expired producer evidence requires investigation or new preparation,
not a name-based fallback.

The session download goes into `untrusted-session/`, separate from
`evidence/`, `triage-assets/` and the report directory. The helper
copies a regular, non-symlink `session-summary.md` of at most
8 MiB. It ignores other session files, including forged snapshots,
Python modules and raw logs; none enters the trusted code path.
The applier then parses the summary's JSON as untrusted input.

Validation checks owner/repository scope, normalized exclusions,
snapshot membership, live issue kind/state/labels, label vocabulary,
priority/type options and classification consistency. It refuses
`Urgent` and skips any issue with an existing Priority. Unreadable
Priority is an operational failure, not an empty field.

Live organisation configuration read failures are fatal.
`--dry-run` alone allows known endpoint absence (404/410) or recognized
permission denial. Rate limits, unknown 403s, malformed responses
and transient failures still fail. When definitions are genuinely
absent, validation can drop unavailable priority/type values and
record why rather than inventing options.

#### Success gates and reporting

Apply requires successful preparation and no cancellation to start.
It can run after a skipped or failed proposal job to
report, but session download and extraction require proposal success.
The apply step requires proposal-job success and successful summary
extraction; normal step-success gating also requires provenance,
verification and token setup to succeed. Dry-run and reporting
without application must not mint an issue-write token.

After-snapshot and report steps require verified evidence and no
cancellation, even if application failed. Passing `--after` to the
report requires snapshot-step outcome `success`. A stale file is
not proof of a successful snapshot. It records proposal/apply status
and observed label movement, not raw session-log claims.

#### Reruns and partial writes

Evidence and session artefacts have 7-day retention; final results
have 90-day retention. Downloads use the IDs from their producing
jobs rather than reconstructing names from the current attempt.
This permits rerunning Apply without its producers when their outputs
and artefacts remain available. Session and final result names append
the current attempt
to Prepare's namespace, avoiding immutable-name conflicts on reruns.

This is replayable evidence, not transactional application. Labels,
type and Priority use separate requests; a later failure can leave
earlier writes in place. The workflow has no automatic rollback. Inspect
current state and `apply-result.json` before targeted recovery, often
with `retriage: true` after a label write. Never overwrite a human
Priority to force replay; the existing-Priority guard still applies.

The workflow lock serializes the full live sequence per caller
repository and owner (§7), but cannot exclude cross-caller or human
edits.
Fresh reads reduce stale decisions without eliminating the race
between validation and writes. Cancellation also cannot undo a
request that already succeeded.

### 12.8 The pre-flight gate

The contract tests in `tests/test_workflow.py` run when a pull
request changes the workflow. A scheduled run executes whatever is on
the default branch, and nothing in that path re-checks the boundary
before the first App token mint. `scripts/preflight.py` closes that:
it runs from the pinned assets checkout in Prepare, before any
`create-github-app-token` step, and fails the run closed on drift.

Before the read mint it re-runs the workflow contract tests and
`zizmor --persona auditor` against the checked-out workflow files,
checks `config/bot.json` names one lower-case App slug, checks each
credential has the shape of the thing it claims to be without
printing it, requires a commit-pinned and loaded allow-list in block
mode, and refuses a live run whose `assets_sha` differs from
`job.workflow_sha`. After the mint it compares the `app-slug` the
action returned with the configured slug, so another App's key wired
into this workflow fails rather than acts, and probes the token
against this repository to prove it holds no `push`, `maintain` or
`admin`. Apply repeats the identity check on its own token before the
one step that writes.

The same module, tests and step shape run in every bot repository of
the organisation; this repository's copy differs in the module it
imports for `gh` and the job names alone.
