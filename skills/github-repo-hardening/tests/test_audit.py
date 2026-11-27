"""Tests for audit.py with simulated API answers (no network)."""
import base64
import contextlib
import io
import json
import pathlib
import re
import subprocess
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import audit  # noqa: E402
import workflows  # noqa: E402

SHA = "a" * 40
CI = """\
name: ci
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@%s # v5
      - run: |
          echo "uses: not/an-action@v1"
          permissions: this is script text
""" % SHA
LOOSE = """\
name: release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: softprops/action-gh-release@v2
"""
LINT = """\
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/linter/run@feature/new-rules
      - uses: ./local
      - uses: docker://alpine:3
      - uses: acme/shared@v1
"""


def content(text):
    return {"content": base64.b64encode(text.encode()).decode()}


class FakeGh:
    def __init__(self, answers, auth="  - Token scopes: 'repo', 'workflow'", policy=True):
        self.answers, self.auth, self.policy = answers, auth, policy
        self.requested = []

    def get(self, endpoint):
        self.requested.append(endpoint)
        for key in (endpoint, endpoint.split("?")[0]):
            if key in self.answers:
                value = self.answers[key]
                if isinstance(value, audit.Result):
                    return value
                page = re.search("[?&]page=([0-9]+)", endpoint)
                if page and page.group(1) != "1":
                    return audit.Result(200, [])
                return audit.Result(200, value)
        return audit.Result(404, None, "Not Found")

    def graphql(self, query, variables):
        return audit.Result(200, {"data": {"repository": {"isSecurityPolicyEnabled": self.policy}}})

    def current_repo(self):
        return "acme/app"

    def auth_status(self):
        return self.auth


def user(push=True, kind="User"):
    return {"type": kind, "permissions": {"push": push}}


def check(name, conclusion="success", suite=1):
    return {"name": name, "conclusion": conclusion, "app": {"slug": "github-actions"},
            "check_suite": {"id": suite}}


def repo_answers(files=None, checks=None, **overrides):
    files = {".github/workflows/ci.yml": CI, "package.json": "{}"} if files is None else files
    checks = [check("build")] if checks is None else checks
    r = "repos/acme/app"
    answers = {
        r: {"full_name": "acme/app", "default_branch": "main", "visibility": "public", "size": 10,
            "owner": {"type": "Organization"}, "permissions": {"admin": True, "push": True},
            "delete_branch_on_merge": False, "archived": False, "fork": False,
            "security_and_analysis": {"secret_scanning": {"status": "disabled"},
                                      "secret_scanning_push_protection": {"status": "disabled"}}},
        f"{r}/git/trees/main": {"tree": [{"path": p, "type": "blob"} for p in files]},
        f"{r}/languages": {"JavaScript": 100},
        f"{r}/collaborators": [user(), user(push=False), user(kind="Bot")],
        f"{r}/tags": [],
        f"{r}/commits": [{"sha": "c1"}],
        f"{r}/actions/runs": {"workflow_runs": [{"check_suite_id": 1, "path": ".github/workflows/ci.yml"}]},
        f"{r}/commits/c1/check-runs": {"check_runs": checks},
        f"{r}/rulesets": [],
        f"{r}/rules/branches/main": [],
        f"{r}/branches/main/protection": audit.Result(404, None, "Branch not protected"),
        f"{r}/actions/permissions": {"enabled": True, "allowed_actions": "all"},
        f"{r}/actions/permissions/workflow": {"default_workflow_permissions": "write"},
        f"{r}/code-scanning/default-setup": {"state": "not-configured"},
        f"{r}/private-vulnerability-reporting": {"enabled": False},
        f"{r}/pulls": [],
    }
    for path, text in files.items():
        answers[f"{r}/contents/{path}"] = content(text)
    for key, value in overrides.items():
        answers[f"{r}/{key}" if key else r] = value
    return answers


def ruleset(ident, rules, target="branch", bypass=(), include=("~DEFAULT_BRANCH",), mine=None):
    return {"id": ident, "name": f"set {ident}", "target": target, "enforcement": "active",
            "conditions": {"ref_name": {"include": list(include), "exclude": []}},
            "rules": rules, "bypass_actors": list(bypass), "current_user_can_bypass": mine}


def with_rulesets(answers, *sets):
    r = "repos/acme/app"
    answers[f"{r}/rulesets"] = [{"id": s["id"]} for s in sets]
    effective = []
    for s in sets:
        answers[f"{r}/rulesets/{s['id']}"] = s
        if s["target"] == "branch":
            effective += [{**rule, "ruleset_id": s["id"]} for rule in s["rules"]]
    answers[f"{r}/rules/branches/main"] = effective
    return answers


def pr_rule(approvals):
    return {"type": "pull_request", "parameters": {"required_approving_review_count": approvals}}


ADMIN_ALWAYS = {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
ADMIN_PR = {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}


def run(answers, **kwargs):
    return audit.run_audit(FakeGh(answers, **kwargs), "acme/app")


def statuses(report):
    return {k: v["status"] for k, v in report["protections"].items()}


class UnprotectedRepo(unittest.TestCase):
    def setUp(self):
        self.report = run(repo_answers(), policy=False)

    def test_reports_missing_protections(self):
        found = statuses(self.report)
        for key in ("secret_scanning", "push_protection", "dependabot_alerts", "dependabot_config",
                    "codeql", "private_vulnerability_reporting", "security_policy", "branch_deletion",
                    "branch_force_push", "pull_request_required", "required_status_checks",
                    "actions_policy", "default_token_permissions", "delete_branch_on_merge"):
            self.assertEqual(found[key], "missing", key)
        self.assertEqual(found["tag_protection"], "unavailable")
        self.assertEqual(found["workflow_permissions"], "ok")
        self.assertEqual(found["pinned_actions"], "ok")
        self.assertEqual(self.report["errors"], [])

    def test_context(self):
        self.assertEqual(self.report["profile"]["name"], "solo")
        self.assertEqual(self.report["profile"]["admin_bypass"], "pull_request")
        self.assertEqual(self.report["checks"]["recommended"], "build")
        self.assertEqual(self.report["context"]["manifests"], [{"ecosystem": "npm", "directory": "/"}])


class Visibility(unittest.TestCase):
    def test_without_admin_nothing_hidden_is_called_missing(self):
        answers = repo_answers()
        info = answers["repos/acme/app"]
        info["permissions"] = {"admin": False, "push": True}
        del info["security_and_analysis"], info["delete_branch_on_merge"]
        for key in ("collaborators", "actions/permissions", "actions/permissions/workflow",
                    "private-vulnerability-reporting", "code-scanning/default-setup"):
            answers[f"repos/acme/app/{key}"] = audit.Result(403, None, "Must have admin rights")
        report = run(answers)
        found = statuses(report)
        for key in ("secret_scanning", "dependabot_alerts", "dependabot_security_updates",
                    "private_vulnerability_reporting", "branch_deletion", "actions_policy",
                    "default_token_permissions", "delete_branch_on_merge", "codeql"):
            self.assertEqual(found[key], "unavailable", key)
        self.assertEqual(report["profile"]["name"], "unknown")
        self.assertIsNone(report["profile"]["writers"])

    def test_private_repo_on_free_plan(self):
        blocked = audit.Result(403, None, "Upgrade to GitHub Pro or make this repository public")
        answers = repo_answers(**{"rulesets": blocked, "rules/branches/main": blocked,
                                  "branches/main/protection": blocked})
        answers["repos/acme/app"]["visibility"] = "private"
        report = run(answers)
        found = statuses(report)
        for key in ("branch_deletion", "pull_request_required", "required_status_checks",
                    "private_vulnerability_reporting"):
            self.assertEqual(found[key], "unavailable", key)
        self.assertIn("Upgrade", report["protections"]["branch_deletion"]["reason"])
        self.assertEqual(report["errors"], [])

    def test_unexpected_failures_are_listed_as_errors(self):
        report = run(repo_answers(**{"actions/permissions": audit.Result(502, None, "Bad Gateway")}))
        self.assertEqual(report["errors"][0]["status"], 502)
        self.assertIn("UNVERIFIED", audit.render_text(report))

    def test_rate_limit_is_an_error_even_with_403(self):
        limited = audit.Result(403, None, "API rate limit exceeded")
        report = run(repo_answers(**{"actions/permissions": limited}))
        self.assertEqual(len(report["errors"]), 1)

    def test_empty_repository(self):
        answers = repo_answers(files={}, **{"git/trees/main": audit.Result(409, None, "Git Repository is empty.")})
        report = run(answers)
        self.assertTrue(report["context"]["empty"])
        self.assertEqual(statuses(report)["branch_deletion"], "unavailable")
        self.assertEqual(statuses(report)["required_status_checks"], "unavailable")


class Profiles(unittest.TestCase):
    def protected(self, approvals, bypass, writers):
        answers = repo_answers(collaborators=[user()] * writers)
        with_rulesets(answers, ruleset(1, [pr_rule(approvals)], bypass=bypass))
        return statuses(run(answers))["pull_request_required"]

    def test_two_writers_make_a_team(self):
        report = run(repo_answers(collaborators=[user(), user()]))
        self.assertEqual((report["profile"]["name"], report["profile"]["required_approvals"]), ("team", 1))

    def test_solo(self):
        self.assertEqual(self.protected(0, [ADMIN_PR], 1), "ok")
        self.assertEqual(self.protected(0, [ADMIN_ALWAYS], 1), "partial")
        self.assertEqual(self.protected(1, [], 1), "partial")

    def test_team(self):
        self.assertEqual(self.protected(1, [], 2), "ok")
        self.assertEqual(self.protected(0, [], 2), "partial")
        self.assertEqual(self.protected(1, [ADMIN_PR], 2), "partial")

    def test_integrity_rules_must_not_be_bypassable(self):
        answers = repo_answers()
        with_rulesets(answers, ruleset(1, [{"type": "deletion"}], bypass=[ADMIN_ALWAYS]),
                      ruleset(2, [{"type": "non_fast_forward"}]))
        found = statuses(run(answers))
        self.assertEqual((found["branch_deletion"], found["branch_force_push"]), ("partial", "ok"))

    def test_classic_protection_counts(self):
        classic = {"enforce_admins": {"enabled": True}, "allow_deletions": {"enabled": False},
                   "allow_force_pushes": {"enabled": False},
                   "required_pull_request_reviews": {"required_approving_review_count": 0},
                   "required_status_checks": {"contexts": ["build"]}}
        found = statuses(run(repo_answers(**{"branches/main/protection": classic})))
        for key in ("branch_deletion", "branch_force_push", "pull_request_required", "required_status_checks"):
            self.assertEqual(found[key], "ok", key)

    def test_required_check_that_never_ran_is_flagged(self):
        rule = {"type": "required_status_checks",
                "parameters": {"required_status_checks": [{"context": "ghost"}]}}
        answers = with_rulesets(repo_answers(), ruleset(1, [rule]))
        item = run(answers)["protections"]["required_status_checks"]
        self.assertEqual(item["doubtful"], ["ghost"])


class Checks(unittest.TestCase):
    def classify(self, workflow, names, conclusion="success"):
        answers = repo_answers(files={".github/workflows/ci.yml": workflow},
                               checks=[check(n, conclusion) for n in names])
        result = run(answers)["checks"]
        return [c["name"] for c in result["stable"]], {c["name"]: c["reason"] for c in result["unstable"]}

    def test_matrix_jobs_are_never_required(self):
        text = """\
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        node: [20, 22]
    runs-on: ubuntu-latest
  named:
    name: build ${{ matrix.os }}
    strategy: {matrix: {os: [linux]}}
    runs-on: ${{ matrix.os }}
  done:
    needs: [test]
    runs-on: ubuntu-latest
"""
        stable, unstable = self.classify(text, ["test (20)", "test (22)", "build linux", "done"])
        self.assertEqual(stable, ["done"])
        self.assertEqual(set(unstable.values()), {"matrix job"})

    def test_reusable_workflow_check_name(self):
        text = "on: [push, pull_request]\njobs:\n  publishable:\n    uses: acme/shared/.github/workflows/x.yml@main\n"
        stable, unstable = self.classify(text, ["publishable / scan", "publishable / test (a)"])
        self.assertEqual(stable, ["publishable / scan"])
        self.assertIn("publishable / test (a)", unstable)

    def test_filtered_or_push_only_workflows(self):
        filtered = "on:\n  pull_request:\n    paths: ['src/**']\njobs:\n  build:\n    runs-on: x\n"
        self.assertIn("filtered", self.classify(filtered, ["build"])[1]["build"])
        push_only = "on: push\njobs:\n  build:\n    runs-on: x\n"
        self.assertIn("pull_request", self.classify(push_only, ["build"])[1]["build"])

    def test_flaky_check(self):
        answers = repo_answers(checks=[check("build"), check("build", "failure")])
        result = run(answers)["checks"]
        self.assertEqual(result["stable"], [])
        self.assertIsNone(result["recommended"])

    def test_other_apps_are_ignored(self):
        answers = repo_answers(checks=[{**check("vercel"), "app": {"slug": "vercel"}}])
        self.assertEqual(run(answers)["checks"]["stable"], [])


class Tags(unittest.TestCase):
    def test_moving_major_tags_are_left_out_of_the_pattern(self):
        tags = audit.analyze_tags(["v1", "v1.2.0", "v1.2.1", "latest"])
        self.assertEqual(tags["moving_tags"], ["v1"])
        self.assertEqual(tags["suggested_patterns"], ["refs/tags/v*.*.*"])
        self.assertEqual(tags["other_tags"], ["latest"])

    def test_short_tag_is_moving_only_when_it_follows_a_longer_one(self):
        names = ["v1.2", "v1.2.1", "1.0", "1.0.1"]
        shas = {"v1.2": "x", "v1.2.1": "x", "1.0": "a", "1.0.1": "b"}
        self.assertEqual(audit.analyze_tags(names, shas)["moving_tags"], ["v1.2"])

    def test_bypassable_rule_does_not_freeze_a_moving_tag(self):
        rules = [{"type": "deletion"}, {"type": "update"}]
        bot = ruleset(3, rules, target="tag", include=["~ALL"], bypass=[ADMIN_ALWAYS])
        strict = ruleset(4, rules, target="tag", include=["refs/tags/v*.*.*"])
        self.assertEqual(self.protection(["v1", "v1.0.0"], bot, strict)["status"], "ok")

    def test_patterns_follow_existing_tags(self):
        tags = audit.analyze_tags(["v1.0.0", "tool-v2.1.0", "3.0.0"])
        self.assertEqual(tags["suggested_patterns"],
                         ["refs/tags/*-v*", "refs/tags/[0-9]*", "refs/tags/v*"])

    def protection(self, names, *sets):
        answers = repo_answers(tags=[{"name": n} for n in names])
        with_rulesets(answers, *sets)
        return run(answers)["protections"]["tag_protection"]

    def test_states(self):
        rules = [{"type": "deletion"}, {"type": "update"}]
        full = ruleset(3, rules, target="tag", include=["refs/tags/v*"])
        self.assertEqual(self.protection(["v1.0.0"])["status"], "missing")
        self.assertEqual(self.protection(["v1.0.0"], full)["status"], "ok")
        self.assertEqual(self.protection(["v1.0.0", "x-v1.0.0"], full)["status"], "partial")
        self.assertEqual(self.protection(["v1", "v1.0.0"], full)["status"], "partial")
        self.assertEqual(self.protection(["nightly"])["status"], "unavailable")


class Files(unittest.TestCase):
    def setUp(self):
        self.report = run(repo_answers(files={
            ".github/workflows/ci.yml": CI, ".github/workflows/release.yml": LOOSE,
            ".github/workflows/lint.yml": LINT, "web/package.json": "{}",
            "web/node_modules/x/package.json": "{}",
            ".github/dependabot.yml": "version: 2\nupdates:\n  - package-ecosystem: github-actions\n"
                                      "    directory: /\n"}))

    def test_permissions_split_by_need(self):
        item = self.report["protections"]["workflow_permissions"]
        self.assertEqual(item["status"], "partial")
        self.assertEqual(item["add_read_only"], [".github/workflows/lint.yml"])
        self.assertEqual(item["needs_review"][0]["path"], ".github/workflows/release.yml")

    def test_unpinned_references(self):
        item = self.report["protections"]["pinned_actions"]
        self.assertEqual(sorted(u["ref"] for u in item["unpinned"]), [
            "actions/checkout@v4", "softprops/action-gh-release@v2",
            "some-org/linter/run@feature/new-rules"])

    def test_dependabot_coverage(self):
        item = self.report["protections"]["dependabot_config"]
        self.assertEqual(item["status"], "partial")
        self.assertEqual(item["uncovered"], [{"ecosystem": "npm", "directory": "/web"}])

    def test_allow_list_is_built_from_used_actions(self):
        suggested = self.report["protections"]["actions_policy"]["suggested"]
        self.assertEqual(suggested["patterns_allowed"],
                         ["acme/*", "softprops/action-gh-release@*", "some-org/linter/run@*"])

    def test_selected_policy_that_blocks_a_used_action(self):
        answers = repo_answers(files={".github/workflows/release.yml": LOOSE}, **{
            "actions/permissions": {"enabled": True, "allowed_actions": "selected"},
            "actions/permissions/selected-actions": {"github_owned_allowed": True, "patterns_allowed": []}})
        item = run(answers)["protections"]["actions_policy"]
        self.assertEqual(item["status"], "partial")
        self.assertEqual(item["uncovered"], ["softprops/action-gh-release@v2"])


class Privacy(unittest.TestCase):
    def test_leaked_secret_values_never_reach_the_report(self):
        leaked = "value-that-must-not-appear"
        alerts = [{"secret_type": "github_pat", "secret": leaked}]
        report = run(repo_answers(**{"secret-scanning/alerts": alerts}))
        self.assertEqual(report["alerts"]["secret_scanning"]["count"], 1)
        self.assertNotIn(leaked, json.dumps(report) + audit.render_text(report))

    def test_client_only_reads(self):
        done = subprocess.CompletedProcess([], 0, "{}", "")
        with mock.patch("subprocess.run", return_value=done) as called:
            audit.Gh().get("repos/acme/app")
        self.assertEqual(called.call_args[0][0][:4], ["gh", "api", "--method", "GET"])

    def test_client_reads_the_http_status(self):
        failed = subprocess.CompletedProcess([], 1, '{"message":"Not Found"}', "gh: Not Found (HTTP 404)")
        with mock.patch("subprocess.run", return_value=failed):
            result = audit.Gh().get("repos/acme/app")
        self.assertEqual((result.ok, result.status, result.message), (False, 404, "Not Found"))


class Scopes(unittest.TestCase):
    def test_missing_workflow_scope(self):
        self.assertEqual(audit.token_info("Token scopes: 'repo'", False)["missing_scopes"], ["workflow"])

    def test_unknown_scopes_are_not_reported_as_missing(self):
        for text in ("Logged in using GH_TOKEN", "- Token scopes: none"):
            self.assertIsNone(audit.token_info(text, True)["missing_scopes"])


class CommandLine(unittest.TestCase):
    def main(self, argv, gh):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            return audit.main(argv, gh), out.getvalue(), err.getvalue()

    def test_json_and_text(self):
        code, out, _ = self.main([], FakeGh(repo_answers()))
        self.assertEqual((code, json.loads(out)["repo"]), (0, "acme/app"))
        code, out, _ = self.main(["acme/app", "--text"], FakeGh(repo_answers()))
        self.assertIn("Stable checks: build", out)

    def test_no_access(self):
        self.assertEqual(self.main(["acme/app"], FakeGh({}))[0], 1)

    def test_bad_argument(self):
        self.assertEqual(self.main(["not-a-repo"], FakeGh({}))[0], 2)


class YamlReader(unittest.TestCase):
    def test_shapes(self):
        doc = workflows.parse_yaml(
            "a:\n- b: 1\n  c: [x, 'y, z']\n- |\n  text\nd:\n  e: ~\n  f:\n    plain value\n"
            "    continued\ng: [\n  h,\n  i ]\n\"on\": 'x # y' # comment\n")
        self.assertEqual(doc["a"][0], {"b": "1", "c": ["x", "y, z"]})
        self.assertEqual(doc["d"], {"e": None, "f": "plain value continued"})
        self.assertEqual(doc["g"], ["h", "i"])
        self.assertEqual(doc["on"], "x # y")

    def test_null_pull_request_is_not_a_filter(self):
        self.assertEqual(workflows.pull_request_state({"pull_request": None}), (True, False))
        doc = workflows.parse_yaml("on:\n  pull_request: ~\n")
        self.assertEqual(workflows.pull_request_state(doc["on"]), (True, False))

    def test_branch_filter_that_includes_the_default_branch_is_not_a_filter(self):
        state = workflows.pull_request_state
        self.assertEqual(state({"pull_request": {"branches": ["main"]}}, "main"), (True, False))
        self.assertEqual(state({"pull_request": {"branches": ["master", "develop"]}}, "master"), (True, False))
        self.assertEqual(state({"pull_request": {"branches": "main"}}, "main"), (True, False))
        self.assertEqual(state({"pull_request": {"branches": ["**"]}}, "main"), (True, False))
        self.assertEqual(state({"pull_request": {"branches": ["release/*"]}}, "release/1"), (True, False))
        self.assertEqual(state({"pull_request": {"branches-ignore": ["dev"]}}, "main"), (True, False))

    def test_branch_filter_that_may_exclude_the_default_branch_is_a_filter(self):
        state = workflows.pull_request_state
        self.assertEqual(state({"pull_request": {"branches": ["develop"]}}, "main"), (True, True))
        self.assertEqual(state({"pull_request": {"branches": ["main"]}}), (True, True))
        self.assertEqual(state({"pull_request": {"branches": ["*", "!main"]}}, "main"), (True, True))
        self.assertEqual(state({"pull_request": {"branches": ["release/*"]}}, "release/a/b"), (True, True))
        self.assertEqual(state({"pull_request": {"branches": ["ma?n"]}}, "main"), (True, True))
        self.assertEqual(state({"pull_request": {"branches-ignore": ["main"]}}, "main"), (True, True))
        self.assertEqual(state({"pull_request": {"branches": ["main"], "paths": ["src/**"]}}, "main"),
                         (True, True))

    def test_analyze_workflow_uses_the_default_branch(self):
        text = "on:\n  pull_request:\n    branches: [master]\njobs:\n  build:\n    runs-on: x\n"
        info = workflows.analyze_workflow(".github/workflows/ci.yml", text, "acme", "master")
        self.assertEqual((info["runs_on_pull_request"], info["pull_request_filtered"]), (True, False))

    def test_script_text_is_not_configuration(self):
        info = workflows.analyze_workflow(".github/workflows/ci.yml", CI, "acme")
        self.assertEqual([u["ref"] for u in info["uses"]], [f"actions/checkout@{SHA}"])

    def test_unreadable_file_is_flagged_and_still_scanned(self):
        text = "on: push\nx: &a [1]\ny: *a\njobs:\n  b:\n    steps:\n      - uses: o/r@v1\n"
        info = workflows.analyze_workflow(".github/workflows/ci.yml", text, "acme")
        self.assertFalse(info["parsed"])
        self.assertEqual(info["uses"][0]["ref"], "o/r@v1")


if __name__ == "__main__":
    unittest.main()
