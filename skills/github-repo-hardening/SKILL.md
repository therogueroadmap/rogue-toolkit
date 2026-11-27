---
name: github-repo-hardening
description: Use when the user asks to protect, harden or secure a GitHub repository ("protect this repo", "harden this repo", "set up branch protection / rulesets"), to set up a newly created repo like their others, to audit what a repo's GitHub security settings are missing, to enable secret scanning, Dependabot or CodeQL on a repo, or before making a private repo public. Not for security review of code or a diff, cleaning up a leaked secret, or setting up and debugging CI, releases or deployments.
---

# GitHub Repository Hardening

Audit first, show a plan that fits this repository, write only after the user approves it,
then measure again. Two failures matter most: locking people out of their own repository,
and calling a repository protected without having verified it.

## Requirements

- `gh` authenticated, with admin permission on the repository to apply changes.
- `python3`, or `python` where `python3` is missing or does not run (common on Windows).
- One repository per run: `owner/repo`, or the repository of the current directory. No local
  clone is needed; file changes go through the API.

## Step 1: Audit (read-only)

`audit.py` sits next to this file. Save its output in a temporary directory:

```bash
python3 "<skill-dir>/audit.py" owner/repo > before.json
python3 "<skill-dir>/audit.py" owner/repo --text
```

Use the audit instead of probing the API by hand: it covers every protection the same way
before and after. Each entry of `protections` is `ok`, `missing`, `partial` or
`unavailable`, with a reason. Exit code other than 0 means the repository cannot be read.

Report the context and the state of every protection, including open alert counts. Then
stop here when:

- the user asked only for an audit;
- `context.admin` is false (say which permission is needed);
- the repository is archived (nothing can be changed).

If `token.missing_scopes` lists `repo`, or `workflow` while workflow files need edits, ask
the user to run `gh auth refresh -h github.com -s repo,workflow` before applying.

`errors` lists calls that failed unexpectedly. Report those protections as unverified.

## Step 2: Plan

Present a numbered plan: what will change, and what is left out and why. Include the
maintainer count and chosen profile, the exact required check (or that there is none), the
tag patterns, the allowed actions, and the files the pull request will touch. Propose only
what is `missing` or `partial`.

### Decision rules

| Topic | Rule |
|---|---|
| Profile `solo` (one user with write access) | Pull request required, **0 approvals**, admin bypass limited to `pull_request` mode. |
| Profile `team` (two or more) | **1 approval**, no bypass. |
| Profile `unknown` | Ask how many people can write. Never assume one. |
| Deletion and force push on the default branch | Blocked, no bypass. |
| Required status check | Only `checks.recommended` or another entry of `checks.stable` (list the others). If none, require nothing and say so. Never a matrix job, even if it always passes. |
| Tags | Immutable only for `tags.suggested_patterns`. Never block updates of moving tags (`v1`, `latest`). No version tags: no tag rule. |
| Allowed actions | GitHub's own plus the ones the repository already uses. |
| Files (permissions, SHA pins, `dependabot.yml`, `SECURITY.md`) | One pull request from `chore/repo-hardening`. `SECURITY.md` only if none exists or is inherited. |
| Existing rulesets or classic protection | Do not duplicate or overwrite. Show the difference and propose only what is missing. Change a ruleset that this skill did not name only if the user asks. |
| Plan or visibility does not offer a feature | Leave it out and explain. It is not an error. |
| Fork or empty repository | Say so and apply only what fits. |

Check for conflicts and put them in the plan:

- A workflow that pushes to the default branch (`pushes commits or tags`) will be rejected by
  the pull request rule. Ask before adding it.
- A release workflow that moves tags will be rejected by the tag rule.
- Each workflow in `workflow_permissions.needs_review` may rely on the default write token.
  Propose concrete permissions for it, using the signal table in reference.md: a top-level
  `contents: read` plus job-level write scopes only on the jobs that need them (for example
  `contents: write` on the job that publishes a release). Apply a proposal only if the user
  approves it; otherwise leave that file unchanged. The default token becomes read-only only
  when every `needs_review` workflow has an approved proposal; if any is declined or
  undecided, keep the token as it is and say why. With approved proposals, switch it only
  after the pull request with those blocks is merged; with no `needs_review`, switch it in
  step 4.
- Stopping workflows from creating or approving pull requests is a separate setting. Apply it
  even when the token stays as it is, unless a workflow creates or approves pull requests.

The user may change any choice. Then ask them to pick a mode:

| Mode | Effect |
|---|---|
| **Confirm** | Apply settings by API and open the pull request. Merge nothing. |
| **Automatic** | Also merge the pull request this skill opened, once its checks pass. |
| **Audit only** | Stop now. |

**No write of any kind happens before the user approves the plan**, even if the request
already said "do it" or named a mode.

## Step 3: Apply, in this order

Calls, request bodies and verification commands are in [reference.md](reference.md). Read it
before the first write. Read each resource back after writing it.

1. Detection and repository settings by API.
2. File pull request. In automatic mode, wait for checks (15 minutes at most) and merge.
3. Rulesets. They come after the pull request so they do not gate it.
4. Default token, then Actions policy, verified by rerunning workflows that have no side
   effects. If a rerun fails, restore the previous Actions policy.
5. Verification.

Automatic mode does **not** merge when: the profile is `team` or `unknown` (a person must
review), any check fails or is still pending, or no check reports at all. Leave the pull
request open and say why. Never merge Dependabot or third-party pull requests.

If a write fails midway for a reason other than availability, stop, report what was applied
and what is pending, and do not roll back (the Actions policy is the only exception).
Running the skill again proposes only what is still missing.

## Step 4: Verify and report

Run `audit.py` again and report:

- before and after for every protection, from the two audit outputs;
- pull requests opened or merged (changes in an open pull request still show as `missing`);
- what depends on the user: pending review, `needs_review` workflows, open alerts, reruns
  that were not possible;
- recommendations: organization defaults and Actions policy, OpenSSF Scorecard for ongoing
  monitoring, `security-review` for code findings, rotating any leaked secret.

Say "protected" only for entries the second audit shows as `ok`.

## Boundaries

Do not change organization settings, process several repositories at once, fix the
vulnerabilities found, rewrite history, rotate secrets, or manage members, signing or 2FA.
**Never dismiss or close an alert.**

## Common mistakes

| Mistake | Do instead |
|---|---|
| Requiring an approval in a one-person repository | Use the `solo` profile; nobody can approve their own pull request. |
| `bypass_mode: always` for the admin | `pull_request`. |
| Requiring a matrix, path-filtered or push-only check | It may never report and blocks every merge. |
| Adding a read-only `permissions` block to a release workflow | Propose job-level write scopes; apply only on approval. |
| Merging with `--admin` to get past a rule or a failing check | Report the cause and leave it open. |
| Reporting success from the write responses | Run the audit again. |
