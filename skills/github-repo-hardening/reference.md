# Write calls, templates and verification

`O/R` is the repository, `BRANCH` its default branch. Keep every request body and saved
state in a temporary directory outside the user's project. Send bodies with
`--input file.json`: inline JSON breaks under shell quoting. In Git Bash, write endpoints
without a leading slash, and do not rely on doubled backslashes inside heredocs.

## 1. Detection and repository settings

| Protection key | Call | Verify |
|---|---|---|
| `secret_scanning`, `push_protection` | `gh api -X PATCH repos/O/R --input security.json` | `gh api repos/O/R --jq .security_and_analysis` |
| `delete_branch_on_merge` | `gh api -X PATCH repos/O/R -F delete_branch_on_merge=true` | `gh api repos/O/R --jq .delete_branch_on_merge` |
| `dependabot_alerts` | `gh api -X PUT repos/O/R/vulnerability-alerts` | `gh api -i repos/O/R/vulnerability-alerts` (204) |
| `dependabot_security_updates` (after alerts) | `gh api -X PUT repos/O/R/automated-security-fixes` | `gh api repos/O/R/automated-security-fixes` |
| `private_vulnerability_reporting` | `gh api -X PUT repos/O/R/private-vulnerability-reporting` | `gh api repos/O/R/private-vulnerability-reporting` |
| `codeql` | `gh api -X PATCH repos/O/R/code-scanning/default-setup -f state=configured` | `gh api repos/O/R/code-scanning/default-setup` (asynchronous: allow a few minutes) |

`security.json` (include only the keys the plan changes):

```json
{"security_and_analysis": {
  "secret_scanning": {"status": "enabled"},
  "secret_scanning_push_protection": {"status": "enabled"}
}}
```

Decide from the API message, not the status code. A 403, 404 or 422 whose message names the
plan, the visibility, Advanced Security or an organization policy means the feature is not
available: record the message and continue. Any other error (an invalid body, missing
permission, a rate limit) is a failed write: stop as `SKILL.md` says.

## 2. File changes, as one pull request

### Branch

```bash
gh pr list -R O/R --head chore/repo-hardening --state open --json number,url   # reuse if present
gh api repos/O/R/git/ref/heads/BRANCH --jq .object.sha
gh api -X POST repos/O/R/git/refs -f ref=refs/heads/chore/repo-hardening -f sha=SHA
```

If the branch exists without an open pull request, check
`gh api repos/O/R/compare/BRANCH...chore/repo-hardening --jq .ahead_by`. When it is `0`,
fast-forward it with `gh api -X PATCH repos/O/R/git/refs/heads/chore/repo-hardening -f sha=SHA`.
Otherwise it holds someone's commits: ask the user.

### Read and write a file

Read from the hardening branch, edit the bytes, and send them back with the blob `sha`
(omit `sha` for a new file). One commit per file. This script does both halves without
changing line endings:

```python
import base64, json, subprocess, sys

def gh(*args):
    done = subprocess.run(["gh", "api", *args], capture_output=True, check=True)
    return json.loads(done.stdout)

repo, path, message = sys.argv[1:4]
current = gh(f"repos/{repo}/contents/{path}?ref=chore/repo-hardening")
lines = base64.b64decode(current["content"]).decode("utf-8").splitlines(keepends=True)
# ... edit `lines` here ...
body = {"message": message, "branch": "chore/repo-hardening", "sha": current["sha"],
        "content": base64.b64encode("".join(lines).encode("utf-8")).decode()}
with open("body.json", "w", encoding="utf-8") as handle:
    json.dump(body, handle)
gh("-X", "PUT", f"repos/{repo}/contents/{path}", "--input", "body.json")
```

### Workflow permissions

Only for the paths in `workflow_permissions.add_read_only`. Insert before the top-level
`jobs:` line, using the file's own line ending:

```yaml
permissions:
  contents: read
```

Paths in `needs_review` show signs of writing (releases, comments, packages, pushes).
Never add the read-only block alone to them. Read the file, find the job behind each signal
and propose, as part of the plan, a top-level `contents: read` plus the job-level scopes
below. Apply the proposal only if the user approves it; a declined file stays unchanged and
the default token stays as it is.

| Signal | Job-level scopes to propose |
|---|---|
| publishes a release | `contents: write` |
| pushes commits or tags | `contents: write` (`create-pull-request`: also `pull-requests: write`) |
| writes with the gh CLI | `gh release`: `contents: write`; `gh pr`: `pull-requests: write`; `gh issue`/`gh label`: `issues: write` |
| comments, labels or scripts the API | `issues: write` and/or `pull-requests: write`, by what the step touches |
| publishes a package or image | GitHub Packages or GHCR: `packages: write`; external registry with its own secret: none; npm `--provenance`: `id-token: write` |
| deploys pages or uploads results | Pages: `pages: write` and `id-token: write`; SARIF or CodeQL: `security-events: write` |
| requests an OIDC token | `id-token: write` |
| calls the API with gh, uses the workflow token | Read the calls; propose only the scopes they need, or ask |

Example for a release job:

```yaml
permissions:
  contents: read
jobs:
  release:
    permissions:
      contents: write
```

A job-level block replaces the top-level one for that job, so list every scope the job
needs (keep `contents: read` if it only reads code). Do not promise the proposal is complete:
say it comes from heuristics and ask the user to confirm.

Signals are heuristics, so also read each file in `add_read_only` before editing it.

### Pin actions

For each entry in `pinned_actions.unpinned`, resolve the ref in the action's repository
(the first two path segments of the action):

```bash
gh api repos/A/B/git/ref/tags/REF --jq '.object | .type + " " + .sha'
# while the type is "tag" (annotated tag):
gh api repos/A/B/git/tags/SHA --jq '.object | .type + " " + .sha'
# on 404 the ref may be a branch: use its commit and warn the user
gh api repos/A/B/git/ref/heads/REF --jq .object.sha
```

Replace `uses: A/B/path@REF` with `uses: A/B/path@COMMIT_SHA # REF`, keeping the rest of
the line. Leave local (`./`), `docker://`, same-owner and already pinned references alone.

### `.github/dependabot.yml`

One block per ecosystem and directory from `dependabot_config.wanted` (new file) or
`uncovered` (append to the existing file without rewriting it):

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      github-actions:
        patterns: ["*"]
```

### `SECURITY.md`

Only when `security_policy` is `missing`. Use this text when private vulnerability
reporting reads back as enabled after step 1 (not merely planned):

```markdown
# Security Policy

## Supported versions

Only the latest released version receives security fixes.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: open the **Security** tab of this repository and
choose **Report a vulnerability**. The report stays private between you and the maintainers.

Include, when you can:

- the version, tag or commit affected;
- the steps to reproduce the problem, or a proof of concept;
- the impact you expect.

Please give the maintainers a reasonable time to publish a fix before disclosing it.
```

Where private reporting is not offered, ask the user for a contact and replace the second
paragraph of "Reporting a vulnerability" with it.

### Open, wait and merge

```bash
gh pr create -R O/R --head chore/repo-hardening --base BRANCH \
  --title "chore: harden repository settings" --body-file pr-body.md
timeout 900 gh pr checks NUMBER -R O/R --watch
```

Checks take a few seconds to register: on "no checks reported", wait and retry for up to
three minutes. In automatic mode only, and only for this pull request:

```bash
SHA=$(gh pr view NUMBER -R O/R --json headRefOid --jq .headRefOid)   # the head whose checks passed
gh pr merge NUMBER -R O/R --merge --match-head-commit "$SHA"   # or --squash / --rebase if merge commits are disabled
```

Never add `--admin` or `--auto`.

## 3. Rulesets

Create with `gh api -X POST repos/O/R/rulesets --input ruleset.json`. If a ruleset with the
same name exists, compare it and update with `gh api -X PUT repos/O/R/rulesets/ID --input ruleset.json`
(send the whole body). Put in each ruleset only the rules that nothing else already
enforces; skip a ruleset left with no rules.

**`hardening: default branch integrity`**

```json
{"name": "hardening: default branch integrity", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
 "bypass_actors": [],
 "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]}
```

**`hardening: pull request and checks`** (solo profile shown)

```json
{"name": "hardening: pull request and checks", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
 "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}],
 "rules": [
  {"type": "pull_request", "parameters": {
    "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": false,
    "require_code_owner_review": false, "require_last_push_approval": false,
    "required_review_thread_resolution": true}},
  {"type": "required_status_checks", "parameters": {
    "strict_required_status_checks_policy": false,
    "required_status_checks": [{"context": "STABLE_CHECK_NAME", "integration_id": 15368}]}}
 ]}
```

- Team profile: `"required_approving_review_count": 1` and `"bypass_actors": []`.
- `actor_id` 5 is the repository admin role. Use `bypass_mode` `pull_request`: `always`
  lets a sole admin push straight to the branch, which cancels the rule.
- Without a stable check, remove the whole `required_status_checks` rule.

**`hardening: immutable version tags`** (`include` comes from `tags.suggested_patterns`)

```json
{"name": "hardening: immutable version tags", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
 "bypass_actors": [],
 "rules": [{"type": "deletion"}, {"type": "update"}, {"type": "non_fast_forward"}]}
```

Before sending it, check that no pattern matches a tag in `tags.moving_tags`; add such tags
to `exclude` as `refs/tags/NAME`.

Verify:

```bash
gh api repos/O/R/rules/branches/BRANCH --jq '.[] | .type + " " + (.ruleset_id|tostring)'
gh api repos/O/R/rulesets/ID --jq '{name, enforcement, current_user_can_bypass}'
```

Expect `never` for integrity and tags, `pull_requests_only` for the solo pull request
ruleset. URL-encode a branch name that contains `/`.

## 4. Default token and Actions policy

### Default token (`default_token_permissions`)

The two fields are independent: send only the ones the plan changes.

```bash
gh api -X PUT repos/O/R/actions/permissions/workflow -f default_workflow_permissions=read
gh api -X PUT repos/O/R/actions/permissions/workflow -F can_approve_pull_request_reviews=false
gh api repos/O/R/actions/permissions/workflow   # verify
```

`can_approve_pull_request_reviews=false` also stops workflows from creating pull requests.

When `needs_review` is empty, switch the token in this step as usual. When the pull request
carries approved `permissions` proposals for `needs_review` workflows, send
`default_workflow_permissions=read` only after that pull request is merged: until then the
default branch still runs the old workflows, which rely on the write token. If it stays open
(confirm mode, `team` profile), leave the token as it is and tell the user to switch it after
merging, with the command above.

### Actions policy (`actions_policy`)

Save the current state first; it is needed to restore:

```bash
gh api repos/O/R/actions/permissions > policy-before.json
gh api repos/O/R/actions/permissions/selected-actions > selected-before.json   # only if "selected"
gh api -X PUT repos/O/R/actions/permissions -F enabled=true -f allowed_actions=selected
gh api -X PUT repos/O/R/actions/permissions/selected-actions --input selected.json
```

`selected.json` is `actions_policy.suggested`. When a selected list already exists, keep its
patterns and add the missing ones.

Verify by running again, for each workflow that has no side effects, its run on the current
head commit of the default branch (so it uses the merged workflow files). A workflow has no
side effects when its `write_signals` list is empty, or holds only `uses the workflow token`
and reading the file confirms that it only reads. If that run is still in progress, wait for
it; if the head commit has no successful run of the workflow, list it as "not verified".

```bash
HEAD=$(gh api repos/O/R/commits/BRANCH --jq .sha)
gh run list -R O/R --workflow FILE --commit "$HEAD" --status success --limit 1 --json databaseId,createdAt
gh run rerun RUN_ID -R O/R
gh run watch RUN_ID -R O/R --exit-status
```

Do not rerun a workflow that releases, publishes, deploys, pushes or comments: repeating it
repeats those effects. List it as "not verified" instead. Runs older than 30 days cannot be
rerun; list those too.

If a rerun fails after the restriction, restore and report the cause:

```bash
gh api -X PUT repos/O/R/actions/permissions --input policy-before.json
gh api -X PUT repos/O/R/actions/permissions/selected-actions --input selected-before.json   # only if it existed
```

If `policy-before.json` contains `selected_actions_url`, remove that key before sending it.
Actions called from inside a third-party composite action are invisible to the audit, and
are the usual cause of such a failure.
