#!/usr/bin/env python3
"""Read-only audit of the security settings of one GitHub repository.

Usage: audit.py [owner/repo] [--text]

Only GET requests and one GraphQL query are sent, through `gh`. Nothing is written.
Prints JSON (or a readable summary with --text). Exit codes: 0 audited, 1 the
repository cannot be read, 2 usage error or `gh` missing.
"""
import argparse
import base64
import json
import re
import subprocess
import sys
from fnmatch import fnmatchcase
from urllib.parse import quote

sys.dont_write_bytecode = True

from workflows import analyze_workflow, parse_yaml  # noqa: E402

RULESET_NAMES = (
    "hardening: default branch integrity",
    "hardening: pull request and checks",
    "hardening: immutable version tags",
)
HARDENING_BRANCH = "chore/repo-hardening"
EXPECTED_ERRORS = (403, 404, 409, 422)
ACTIONS_APP = "github-actions"
CHECK_COMMITS = 5
MAX_PAGES = 20
MANIFESTS = (
    ("package.json", "npm"), ("requirements*.txt", "pip"), ("pyproject.toml", "pip"), ("Pipfile", "pip"),
    ("setup.py", "pip"), ("uv.lock", "uv"), ("pom.xml", "maven"), ("build.gradle", "gradle"),
    ("build.gradle.kts", "gradle"), ("go.mod", "gomod"), ("Cargo.toml", "cargo"), ("Gemfile", "bundler"),
    ("composer.json", "composer"), ("pubspec.yaml", "pub"), ("Dockerfile", "docker"),
    ("docker-compose.yml", "docker-compose"), ("compose.yaml", "docker-compose"), ("*.csproj", "nuget"),
    ("*.tf", "terraform"), ("Package.swift", "swift"), ("mix.exs", "mix"), (".gitmodules", "gitsubmodule"),
)
VENDORED = re.compile(r"(^|/)(node_modules|vendor|third_party|dist|build|\.dart_tool|testdata|fixtures)/")
CODEQL_LANGUAGES = {
    "C", "C++", "C#", "Go", "Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Ruby", "Swift", "Rust",
}
VERSION_TAG = re.compile(r"^(?P<prefix>.*?[-_/@])?(?P<v>[vV])?(?P<numbers>\d+(?:\.\d+)*)(?P<suffix>[-+.].*)?$")
FAILED = ("failure", "timed_out", "startup_failure", "action_required")


# --------------------------------------------------------------------------- GitHub access

class Result:
    def __init__(self, status, data=None, message=""):
        self.status, self.data, self.message = status, data, message

    @property
    def ok(self):
        return 200 <= self.status < 300


class Gh:
    """Thin wrapper around the `gh` CLI. Replaced by a fake in the tests."""

    def _run(self, args):
        return subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")

    def _result(self, proc):
        try:
            data = json.loads(proc.stdout) if proc.stdout.strip() else None
        except ValueError:
            data = None
        if proc.returncode == 0:
            return Result(200, data)
        code = re.search(r"HTTP (\d{3})", proc.stderr)
        message = data.get("message") if isinstance(data, dict) else None
        return Result(int(code.group(1)) if code else 0, data, message or proc.stderr.strip())

    def get(self, endpoint):
        return self._result(self._run(["api", "--method", "GET", endpoint]))

    def graphql(self, query, variables):
        args = ["api", "graphql", "-f", f"query={query}"]
        for name, value in variables.items():
            args += ["-f", f"{name}={value}"]
        return self._result(self._run(args))

    def current_repo(self):
        proc = self._run(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"])
        return proc.stdout.strip() if proc.returncode == 0 else None

    def auth_status(self):
        proc = self._run(["auth", "status", "--active", "--hostname", "github.com"])
        if "unknown flag" in proc.stderr:
            proc = self._run(["auth", "status", "--hostname", "github.com"])
        return f"{proc.stdout}\n{proc.stderr}"


class Audit:
    def __init__(self, gh, repo):
        self.gh, self.repo = gh, repo
        self.errors = []

    def get(self, endpoint="", expected=EXPECTED_ERRORS):
        path = f"repos/{self.repo}" + (f"/{endpoint}" if endpoint else "")
        result = self.gh.get(path)
        limited = "rate limit" in result.message.lower()
        if not result.ok and (result.status not in expected or limited):
            self.errors.append({"endpoint": path, "status": result.status, "message": result.message})
        return result

    def pages(self, endpoint, key=None):
        """Return (items, failed result or None) across every page."""
        items = []
        joiner = "&" if "?" in endpoint else "?"
        for page in range(1, MAX_PAGES + 1):
            result = self.get(f"{endpoint}{joiner}per_page=100&page={page}")
            if not result.ok:
                return items, result
            chunk = (result.data or {}).get(key, []) if key else (result.data or [])
            items += chunk
            if len(chunk) < 100:
                break
        return items, None

    def file_text(self, path, ref):
        result = self.get(f"contents/{quote(path)}?ref={quote(ref, safe='')}")
        if not result.ok or not isinstance(result.data, dict):
            return None
        return base64.b64decode(result.data.get("content", "")).decode("utf-8", errors="replace")


def state(status, reason, **detail):
    return {"status": status, "reason": reason, **detail}


def unreadable(result, what):
    return state("unavailable", f"{what}: {result.message or 'no access'} (HTTP {result.status})")


# --------------------------------------------------------------------------- context

def token_info(auth_text, private):
    line = re.search(r"Token scopes:\s*(.*)", auth_text)
    scopes = re.findall(r"[\w:]+", line.group(1)) if line else []
    if not scopes or scopes == ["none"]:
        return {"scopes": None, "missing_scopes": None,
                "note": "scopes not reported (fine-grained or environment token): check write access by hand"}
    missing = []
    if "repo" not in scopes and (private or "public_repo" not in scopes):
        missing.append("repo")
    if "workflow" not in scopes:
        missing.append("workflow")
    return {"scopes": scopes, "missing_scopes": missing, "note": ""}


def maintainer_profile(audit):
    people, failed = audit.pages("collaborators?affiliation=all")
    if failed:
        return {"writers": None, "name": "unknown", "required_approvals": None, "admin_bypass": None,
                "note": f"collaborators cannot be listed (HTTP {failed.status}): ask the user"}
    writers = sum(1 for p in people if p.get("type") == "User" and p.get("permissions", {}).get("push"))
    if writers > 1:
        return {"writers": writers, "name": "team", "required_approvals": 1, "admin_bypass": None, "note": ""}
    if writers == 1:
        return {"writers": 1, "name": "solo", "required_approvals": 0, "admin_bypass": "pull_request", "note": ""}
    return {"writers": 0, "name": "unknown", "required_approvals": None, "admin_bypass": None,
            "note": "no user with write access was listed: ask the user"}


def detect_manifests(paths):
    found = set()
    for path in paths:
        if VENDORED.search(path):
            continue
        directory, _, name = path.rpartition("/")
        for pattern, ecosystem in MANIFESTS:
            if fnmatchcase(name, pattern):
                found.add((ecosystem, f"/{directory}"))
    # uv projects are managed by the uv ecosystem, not by pip.
    uv_dirs = {d for e, d in found if e == "uv"}
    return [{"ecosystem": e, "directory": d} for e, d in sorted(found) if not (e == "pip" and d in uv_dirs)]


def is_workflow_file(path):
    if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", path):
        return True
    return bool(re.match(r"^\.github/actions/(.+/)?action\.ya?ml$", path)) or path in ("action.yml", "action.yaml")


# --------------------------------------------------------------------------- checks

def match_job(check_name, jobs):
    """Return (job, reason it is not stable or None) for a check run name."""
    for job in jobs:
        if not job["reusable"] and check_name == job["name"]:
            return job, "matrix job" if job["matrix"] else None
    for job in jobs:
        label = job["name"]
        if job["reusable"] and check_name.startswith(f"{label} / "):
            if job["matrix"] or check_name.endswith(")"):
                return job, "matrix job"
            return job, None
    for job in jobs:
        if "${{" in job["name"]:
            pattern = ".*".join(re.escape(part) for part in re.split(r"\$\{\{.*?\}\}", job["name"]))
            if re.match(f"^{pattern}( .*)?$", check_name):
                return job, "matrix job" if job["matrix"] else "job name is computed at run time"
    for job in jobs:
        if job["matrix"] and check_name.startswith(f"{job['name']} ("):
            return job, "matrix job"
    return None, "cannot be mapped to a job in the workflow file"


def classify_checks(audit, branch, workflows):
    commits = audit.get(f"commits?sha={quote(branch, safe='')}&per_page={CHECK_COMMITS}")
    if not commits.ok:
        return {"stable": [], "unstable": [], "recommended": None,
                "note": f"commits cannot be read (HTTP {commits.status})"}
    seen, failed = {}, None
    for commit in (commits.data or [])[:CHECK_COMMITS]:
        sha = commit["sha"]
        runs, failed_runs = audit.pages(f"actions/runs?head_sha={sha}", "workflow_runs")
        checks, failed_checks = audit.pages(f"commits/{sha}/check-runs", "check_runs")
        failed = failed or failed_runs or failed_checks
        paths = {r.get("check_suite_id"): r.get("path", "").split("@")[0] for r in runs}
        for check in checks:
            if (check.get("app") or {}).get("slug") != ACTIONS_APP:
                continue
            entry = seen.setdefault(check["name"], {"conclusions": [], "paths": set()})
            entry["conclusions"].append(check.get("conclusion"))
            path = paths.get((check.get("check_suite") or {}).get("id"))
            if path:
                entry["paths"].add(path)
    by_path = {w["path"]: w for w in workflows}
    stable, unstable = [], []
    for name, entry in sorted(seen.items()):
        paths = sorted(entry["paths"])
        workflow = by_path.get(paths[0]) if len(paths) == 1 else None
        if "success" not in entry["conclusions"]:
            reason = "no successful run on the recent default-branch commits"
        elif any(c in FAILED for c in entry["conclusions"]):
            reason = "failed on a recent default-branch commit"
        elif len(paths) > 1:
            reason = "the same name comes from several workflows"
        elif workflow is None:
            reason = "not produced by a workflow file on the default branch"
        elif not workflow["parsed"]:
            reason = "the workflow file could not be parsed"
        elif not workflow["runs_on_pull_request"]:
            reason = "the workflow does not run on pull_request"
        elif workflow["pull_request_filtered"]:
            reason = "the pull_request trigger is filtered, so the check may never report"
        else:
            reason = match_job(name, workflow["jobs"])[1]
        if reason:
            unstable.append({"name": name, "reason": reason})
        else:
            stable.append({"name": name, "workflow": paths[0], "integration_id": 15368})
    note = f"some runs could not be read (HTTP {failed.status})" if failed else ""
    return {"stable": stable, "unstable": unstable,
            "recommended": stable[0]["name"] if stable else None, "note": note}


# --------------------------------------------------------------------------- tags

def analyze_tags(names, commits=None):
    """Split tags into fixed versions, moving aliases (`v1`, or `v1.2` that follows `v1.2.3`) and others."""
    commits = commits or {}
    parsed = {name: VERSION_TAG.match(name) for name in names}
    versions = [n for n, m in parsed.items() if m]
    moving = []
    for name in versions:
        match = parsed[name]
        parts = match.group("numbers").split(".")
        if match.group("suffix") or len(parts) > 2:
            continue
        follows = commits.get(name) is not None and any(
            other.startswith(f"{name}.") and commits.get(other) == commits[name] for other in versions)
        bare_major = len(parts) == 1 and (match.group("v") or any(o.startswith(f"{name}.") for o in versions))
        if follows or bare_major:
            moving.append(name)
    fixed = [n for n in versions if n not in moving]
    patterns = set()
    for name in fixed:
        match = parsed[name]
        prefix, letter = match.group("prefix") or "", match.group("v") or ""
        head = f"*{prefix[-1]}{letter}" if prefix else letter
        pattern = f"refs/tags/{head}*" if head else "refs/tags/[0-9]*"
        if any(fnmatchcase(f"refs/tags/{tag}", pattern) for tag in moving):
            # Require the dots, so the pattern does not freeze a moving tag.
            dots = ".*" * (len(match.group("numbers").split(".")) - 1)
            pattern = f"refs/tags/{head}*{dots}" if head else f"refs/tags/[0-9]*{dots}"
        patterns.add(pattern)
    return {
        "count": len(names),
        "version_tags": fixed,
        "moving_tags": moving,
        "other_tags": [n for n, m in parsed.items() if not m],
        "suggested_patterns": sorted(patterns),
    }


# --------------------------------------------------------------------------- rulesets

def read_rulesets(audit):
    listed, failed = audit.pages("rulesets?includes_parents=true")
    rulesets = []
    for item in listed:
        detail = audit.get(f"rulesets/{item['id']}")
        data = detail.data if detail.ok else item
        bypass = data.get("bypass_actors")
        rulesets.append({
            "id": item["id"],
            "name": data.get("name"),
            "target": data.get("target"),
            "enforcement": data.get("enforcement"),
            "source_type": data.get("source_type"),
            "conditions": data.get("conditions"),
            "rules": data.get("rules", []),
            "bypass_actors": bypass,
            "current_user_can_bypass": data.get("current_user_can_bypass"),
            "readable": detail.ok,
            "created_by_this_skill": data.get("name") in RULESET_NAMES,
        })
    return rulesets, failed


def bypass_of(ruleset):
    """Summarise who can skip a ruleset: 'none', 'pull_request', 'always' or 'unknown'."""
    if ruleset is None:
        return "unknown"
    actors = ruleset.get("bypass_actors")
    mine = ruleset.get("current_user_can_bypass")
    modes = {a.get("bypass_mode") for a in actors or []}
    if mine == "always" or modes & {"always", "exempt"}:
        return "always"
    if modes or mine == "pull_requests_only":
        return "pull_request"
    if actors is None and mine != "never":
        return "unknown"
    return "none"


def branch_sources(rules, rulesets, classic):
    """Map each rule type to the places that enforce it on the default branch."""
    by_id = {r["id"]: r for r in rulesets}
    sources = {}
    for rule in rules:
        ruleset = by_id.get(rule.get("ruleset_id"))
        sources.setdefault(rule["type"], []).append({
            "origin": f"ruleset '{ruleset['name']}'" if ruleset else f"ruleset {rule.get('ruleset_id')}",
            "bypass": bypass_of(ruleset),
            "parameters": rule.get("parameters") or {},
        })
    if classic:
        admins = classic.get("enforce_admins", {}).get("enabled", False)
        add = lambda kind, bypass, parameters: sources.setdefault(kind, []).append(
            {"origin": "classic branch protection", "bypass": bypass, "parameters": parameters})
        if not classic.get("allow_deletions", {}).get("enabled", False):
            add("deletion", "none", {})
        if not classic.get("allow_force_pushes", {}).get("enabled", False):
            add("non_fast_forward", "none", {})
        reviews = classic.get("required_pull_request_reviews")
        if reviews is not None:
            add("pull_request", "none" if admins else "always",
                {"required_approving_review_count": reviews.get("required_approving_review_count", 0)})
        checks = classic.get("required_status_checks")
        if checks is not None:
            contexts = checks.get("contexts") or [c["context"] for c in checks.get("checks", [])]
            add("required_status_checks", "none" if admins else "always",
                {"required_status_checks": [{"context": c} for c in contexts]})
    return sources


def integrity_state(sources, label):
    if not sources:
        return state("missing", f"the default branch allows {label}")
    if any(s["bypass"] == "none" for s in sources):
        return state("ok", f"{label} blocked", sources=sources)
    if all(s["bypass"] == "unknown" for s in sources):
        return state("ok", f"{label} blocked; bypass list not visible", sources=sources)
    return state("partial", f"{label} blocked, but some actors can bypass the rule", sources=sources)


def pull_request_state_of(sources, profile):
    if not sources:
        return state("missing", "changes can be pushed without a pull request")
    approvals = lambda s: s["parameters"].get("required_approving_review_count", 0)
    if profile["name"] == "solo":
        if any(approvals(s) > 0 and s["bypass"] == "none" for s in sources):
            return state("partial", "the only maintainer cannot satisfy the required approvals", sources=sources)
        if all(s["bypass"] == "always" for s in sources):
            return state("partial", "bypass mode 'always' lets the maintainer push directly", sources=sources)
    elif profile["name"] == "team":
        if not any(approvals(s) > 0 for s in sources):
            return state("partial", "no approval is required although several people can write", sources=sources)
        if not any(approvals(s) > 0 and s["bypass"] in ("none", "unknown") for s in sources):
            return state("partial", "the approval requirement has bypass actors", sources=sources)
    elif all(s["bypass"] == "always" for s in sources):
        return state("partial", "the pull request rule can always be bypassed", sources=sources)
    return state("ok", "pull request required", sources=sources)


def checks_rule_state(sources, checks):
    if not sources:
        if checks["recommended"]:
            return state("missing", f"no required status check; '{checks['recommended']}' is stable")
        return state("unavailable", "no stable check to require")
    required = sorted({c["context"] for s in sources
                       for c in s["parameters"].get("required_status_checks", [])})
    stable = {c["name"] for c in checks["stable"]}
    doubtful = [c for c in required if c not in stable]
    note = f"; not confirmed as stable: {', '.join(doubtful)}" if doubtful else ""
    if all(s["bypass"] == "always" for s in sources):
        return state("partial", f"required checks can always be bypassed{note}",
                     required=required, doubtful=doubtful, sources=sources)
    return state("ok", f"status checks required{note}", required=required, doubtful=doubtful, sources=sources)


def ref_matches(ref, conditions):
    names = (conditions or {}).get("ref_name", {})
    hit = lambda patterns: any(p == "~ALL" or fnmatchcase(ref, p) for p in patterns)
    return hit(names.get("include", [])) and not hit(names.get("exclude", []))


def tag_state(tags, rulesets, failed):
    if not tags["count"]:
        return state("unavailable", "the repository has no tags")
    if not tags["version_tags"]:
        return state("unavailable", "no fixed version tags (only moving or non-version tags)")
    if failed:
        return unreadable(failed, "rulesets cannot be read")
    active = [r for r in rulesets if r["target"] == "tag" and r["enforcement"] == "active"]

    def rules_on(tag, trusted=("none", "unknown", "pull_request", "always")):
        found = set()
        for ruleset in active:
            if ref_matches(f"refs/tags/{tag}", ruleset["conditions"]):
                if bypass_of(ruleset) in trusted:
                    found |= {r["type"] for r in ruleset["rules"]}
        return found

    needed = {"deletion", "update"}
    uncovered = [t for t in tags["version_tags"] if not needed <= rules_on(t, ("none", "unknown"))]
    # Only claim a tag is frozen when the bypass list is visible and empty.
    frozen = [t for t in tags["moving_tags"] if any(
        r["bypass_actors"] == [] and ref_matches(f"refs/tags/{t}", r["conditions"])
        and any(rule["type"] == "update" for rule in r["rules"]) for r in active)]
    listed = ", ".join(frozen[:5]) + (f" and {len(frozen) - 5} more" if len(frozen) > 5 else "")
    warning = f"; moving tags blocked from updating: {listed}" if frozen else ""
    if not uncovered:
        return state("partial" if frozen else "ok", f"version tags are immutable{warning}")
    touched = any(rules_on(t) & needed for t in tags["version_tags"])
    return state("partial" if touched else "missing",
                 f"{len(uncovered)} version tag(s) can be moved or deleted{warning}", uncovered=uncovered[:20])


# --------------------------------------------------------------------------- settings

def analysis_state(info, key, admin):
    block = info.get("security_and_analysis") or {}
    status = (block.get(key) or {}).get("status")
    if status == "enabled":
        return state("ok", "enabled")
    if status is None:
        why = "not offered for this plan or visibility" if admin else "reading it requires admin permission"
        return state("unavailable", why)
    note = "" if info.get("visibility") == "public" else \
        "; on a non-public repository it may require a paid plan"
    return state("missing", f"disabled{note}")


def toggle_state(result, admin, what, enabled=lambda data: True):
    """For endpoints that answer 404 when the feature is off."""
    if result.ok:
        return state("ok", "enabled") if enabled(result.data) else state("missing", "disabled")
    if result.status == 404 and admin:
        return state("missing", "disabled")
    return unreadable(result, f"{what} cannot be read")


def dependabot_file_state(audit, branch, paths, manifests, has_workflows):
    wanted = [(m["ecosystem"], m["directory"]) for m in manifests]
    if has_workflows:
        wanted.append(("github-actions", "/"))
    file = next((p for p in (".github/dependabot.yml", ".github/dependabot.yaml") if p in paths), None)
    listed = [{"ecosystem": e, "directory": d} for e, d in wanted]
    if not wanted:
        return state("unavailable", "no dependency manifest or workflow to update")
    if not file:
        return state("missing", "no dependabot.yml", wanted=listed)
    try:
        doc = parse_yaml(audit.file_text(file, branch) or "")
        configured = []
        for update in doc.get("updates") or []:
            directories = update.get("directories") or [update.get("directory") or "/"]
            directories = [directories] if isinstance(directories, str) else directories
            configured += [(update.get("package-ecosystem"), "/" + d.strip("/")) for d in directories]
    except (ValueError, AttributeError, TypeError, IndexError) as error:
        return state("partial", f"{file} exists but could not be parsed: {error}", wanted=listed)
    uncovered = [{"ecosystem": e, "directory": d} for e, d in wanted
                 if not any(e == ce and fnmatchcase(d, cd) for ce, cd in configured)]
    if uncovered:
        return state("partial", f"{file} does not cover every manifest", uncovered=uncovered)
    return state("ok", f"{file} covers the detected manifests")


def codeql_state(audit, languages, workflows):
    advanced = [w["path"] for w in workflows
                if any(u["ref"].startswith("github/codeql-action/analyze") for u in w["uses"])]
    if advanced:
        return state("ok", f"advanced setup in {', '.join(advanced)}")
    result = audit.get("code-scanning/default-setup")
    if result.ok and (result.data or {}).get("state") == "configured":
        return state("ok", "default setup configured")
    supported = sorted(set(languages) & CODEQL_LANGUAGES)
    if any(w["kind"] == "workflow" for w in workflows):
        supported.append("GitHub Actions")
    if not supported:
        return state("unavailable", "no language that CodeQL supports")
    if result.ok:
        return state("missing", "code scanning is not configured", languages=supported)
    return unreadable(result, "code scanning is not available")


def security_policy_state(audit, paths):
    local = next((p for p in paths if p.lower() in
                  ("security.md", ".github/security.md", "docs/security.md")), None)
    if local:
        return state("ok", f"policy in {local}")
    owner, name = audit.repo.split("/")
    result = audit.gh.graphql(
        "query($owner:String!,$name:String!){repository(owner:$owner,name:$name){isSecurityPolicyEnabled}}",
        {"owner": owner, "name": name})
    try:
        enabled = result.data["data"]["repository"]["isSecurityPolicyEnabled"]
    except (KeyError, TypeError):
        audit.errors.append({"endpoint": "graphql", "status": result.status, "message": result.message})
        return state("unavailable", "could not check for an inherited security policy")
    if enabled:
        return state("ok", "inherited from the owner's .github repository")
    return state("missing", "no security policy, local or inherited")


def workflow_file_states(workflows):
    if not workflows:
        none = state("unavailable", "no workflows")
        return none, none
    files = [w for w in workflows if w["kind"] == "workflow"]
    without = [w for w in files if not w["declares_permissions"]]
    if not files:
        permissions = state("unavailable", "no workflow files")
    elif not without:
        permissions = state("ok", "every workflow declares permissions")
    else:
        permissions = state(
            "missing" if len(without) == len(files) else "partial",
            f"{len(without)} workflow(s) declare no permissions",
            add_read_only=[w["path"] for w in without if not w["write_signals"]],
            needs_review=[{"path": w["path"], "signals": w["write_signals"]}
                          for w in without if w["write_signals"]])
    external = [(w["path"], u) for w in workflows for u in w["uses"]
                if u["kind"] in ("github", "third_party")]
    loose = [{"path": p, "ref": u["ref"]} for p, u in external if u["needs_pin"]]
    if not external:
        pins = state("unavailable", "no external actions")
    elif not loose:
        pins = state("ok", "external actions are pinned to a commit SHA")
    else:
        pins = state("missing" if len(loose) == len(external) else "partial",
                     f"{len(loose)} action reference(s) not pinned to a SHA", unpinned=loose)
    return permissions, pins


def allow_patterns(workflows, owner):
    patterns = set()
    for workflow in workflows:
        for use in workflow["uses"]:
            if use["kind"] == "same_owner":
                patterns.add(f"{use['action'].split('/')[0]}/*")
            elif use["kind"] == "third_party":
                patterns.add(f"{use['action']}@*")
    return sorted(patterns)


def actions_policy_state(audit, workflows, owner):
    result = audit.get("actions/permissions")
    suggested = {"github_owned_allowed": True, "verified_allowed": False,
                 "patterns_allowed": allow_patterns(workflows, owner)}
    if not result.ok:
        return unreadable(result, "the Actions policy cannot be read")
    current = result.data or {}
    if not current.get("enabled", True):
        return state("unavailable", "GitHub Actions is disabled", current=current)
    allowed = current.get("allowed_actions")
    if allowed == "local_only":
        return state("ok", "only the owner's actions are allowed", current=current)
    if allowed != "selected":
        return state("missing", "any action can run", current=current, suggested=suggested)
    selected = audit.get("actions/permissions/selected-actions")
    if not selected.ok:
        return unreadable(selected, "the selected actions cannot be read")
    data = selected.data or {}
    rules = data.get("patterns_allowed") or []
    uncovered = []
    for workflow in workflows:
        for use in workflow["uses"]:
            if use["kind"] in ("local", "docker", "same_owner"):
                continue
            if use["kind"] == "github" and data.get("github_owned_allowed"):
                continue
            hit = lambda p: fnmatchcase(use["ref"], p) or fnmatchcase(use["action"], p)
            blocked = any(hit(p[1:]) for p in rules if p.startswith("!"))
            if blocked or not any(hit(p) for p in rules if not p.startswith("!")):
                uncovered.append(use["ref"])
    detail = {"current": {**current, **data}, "suggested": suggested}
    if uncovered:
        return state("partial", "some actions in use do not match the allowed list "
                     "(verified creators may still cover them)", uncovered=sorted(set(uncovered)), **detail)
    return state("ok", "actions restricted to a selected list", **detail)


def token_permission_state(audit):
    result = audit.get("actions/permissions/workflow")
    if not result.ok:
        return unreadable(result, "the default token permissions cannot be read")
    data = result.data or {}
    problems = []
    if data.get("default_workflow_permissions") != "read":
        problems.append("the default token can write")
    if data.get("can_approve_pull_request_reviews"):
        problems.append("workflows can approve pull requests")
    if problems:
        return state("missing", "; ".join(problems), current=data)
    return state("ok", "read-only default token", current=data)


def open_alerts(audit):
    """Count open alerts. Alert contents, including leaked secrets, are never copied."""
    sources = {
        "secret_scanning": ("secret-scanning/alerts", lambda a: a.get("secret_type")),
        "code_scanning": ("code-scanning/alerts",
                          lambda a: (a.get("rule") or {}).get("security_severity_level")
                          or (a.get("rule") or {}).get("severity")),
        "dependabot": ("dependabot/alerts",
                       lambda a: (a.get("security_advisory") or {}).get("severity")),
    }
    report = {}
    for name, (endpoint, label) in sources.items():
        result = audit.get(f"{endpoint}?state=open&per_page=100")
        if not result.ok:
            report[name] = {"count": None, "reason": f"{result.message} (HTTP {result.status})"}
            continue
        alerts = result.data or []
        breakdown = {}
        for alert in alerts:
            key = str(label(alert) or "unknown")
            breakdown[key] = breakdown.get(key, 0) + 1
        report[name] = {"count": len(alerts), "truncated": len(alerts) == 100, "by_type": breakdown}
    return report


# --------------------------------------------------------------------------- audit

def run_audit(gh, repo):
    audit = Audit(gh, repo)
    answer = audit.get(expected=())
    if not answer.ok:
        raise LookupError(f"cannot read {repo}: {answer.message} (HTTP {answer.status})")
    info = answer.data
    repo = audit.repo = info.get("full_name", repo)
    owner = repo.split("/")[0]
    branch = info.get("default_branch") or "main"
    ref = quote(branch, safe="")
    permissions = info.get("permissions") or {}
    admin = bool(permissions.get("admin"))
    visibility = info.get("visibility") or ("private" if info.get("private") else "public")

    tree = audit.get(f"git/trees/{ref}?recursive=1")
    entries = (tree.data or {}).get("tree", []) if tree.ok else []
    paths = [e["path"] for e in entries if e.get("type") == "blob"]
    empty = tree.status == 409 or (not tree.ok and not info.get("size"))
    languages = audit.get("languages")
    languages = sorted(languages.data or {}) if languages.ok else []
    manifests = detect_manifests(paths)

    workflows = []
    for path in filter(is_workflow_file, paths):
        text = audit.file_text(path, branch)
        if text is None:
            audit.errors.append({"endpoint": path, "status": 0, "message": "file could not be read"})
            continue
        workflows.append(analyze_workflow(path, text, owner, branch))

    profile = maintainer_profile(audit)
    tag_list, tags_failed = audit.pages("tags")
    tags = analyze_tags([t["name"] for t in tag_list],
                        {t["name"]: (t.get("commit") or {}).get("sha") for t in tag_list})
    if empty:
        checks = {"stable": [], "unstable": [], "recommended": None, "note": "the repository is empty"}
    else:
        checks = classify_checks(audit, branch, workflows)

    rulesets, rulesets_failed = read_rulesets(audit)
    effective = audit.get(f"rules/branches/{ref}")
    protection = audit.get(f"branches/{ref}/protection")
    classic = protection.data if protection.ok else None
    sources = branch_sources((effective.data or []) if effective.ok else [], rulesets, classic)

    protections = {
        "secret_scanning": analysis_state(info, "secret_scanning", admin),
        "push_protection": analysis_state(info, "secret_scanning_push_protection", admin),
        "dependabot_alerts": toggle_state(audit.get("vulnerability-alerts"), admin, "Dependabot alerts"),
        "dependabot_security_updates": toggle_state(
            audit.get("automated-security-fixes"), admin, "security updates",
            lambda d: bool((d or {}).get("enabled"))),
    }
    protections["dependabot_config"] = dependabot_file_state(
        audit, branch, paths, manifests, any(w["kind"] == "workflow" for w in workflows))
    protections["codeql"] = codeql_state(audit, languages, workflows)
    if visibility != "public":
        protections["private_vulnerability_reporting"] = state("unavailable", "only offered on public repositories")
    else:
        result = audit.get("private-vulnerability-reporting")
        protections["private_vulnerability_reporting"] = toggle_state(
            result, admin, "private vulnerability reporting", lambda d: bool((d or {}).get("enabled")))
    protections["security_policy"] = security_policy_state(audit, paths)

    branch_rules = {
        "branch_deletion": lambda: integrity_state(sources.get("deletion"), "deletion"),
        "branch_force_push": lambda: integrity_state(sources.get("non_fast_forward"), "force pushes"),
        "pull_request_required": lambda: pull_request_state_of(sources.get("pull_request"), profile),
        "required_status_checks": lambda: checks_rule_state(sources.get("required_status_checks"), checks),
    }
    for key, evaluate in branch_rules.items():
        rule_type = {"branch_deletion": "deletion", "branch_force_push": "non_fast_forward",
                     "pull_request_required": "pull_request"}.get(key, key)
        if empty:
            protections[key] = state("unavailable", "the repository is empty")
        elif not effective.ok and rule_type not in sources:
            protections[key] = unreadable(effective, "branch rules are not available")
        else:
            protections[key] = evaluate()
            # Without admin rights, classic protection may exist and be invisible.
            if protections[key]["status"] == "missing" and not protection.ok and \
                    not (protection.status == 404 and admin):
                protections[key] = unreadable(protection, "classic branch protection cannot be read")

    if tags_failed:
        protections["tag_protection"] = unreadable(tags_failed, "tags cannot be read")
    else:
        protections["tag_protection"] = tag_state(tags, rulesets, rulesets_failed)
    protections["actions_policy"] = actions_policy_state(audit, workflows, owner)
    protections["default_token_permissions"] = token_permission_state(audit)
    protections["workflow_permissions"], protections["pinned_actions"] = workflow_file_states(workflows)
    cleanup = info.get("delete_branch_on_merge")
    if cleanup is None:
        protections["delete_branch_on_merge"] = state("unavailable", "reading it requires admin permission")
    else:
        protections["delete_branch_on_merge"] = \
            state("ok", "enabled") if cleanup else state("missing", "merged branches are kept")

    pulls = audit.get(f"pulls?state=open&head={quote(f'{owner}:{HARDENING_BRANCH}', safe='')}")
    pull = pulls.data[0] if pulls.ok and pulls.data else None

    return {
        "schema": 1,
        "repo": repo,
        "context": {
            "owner_type": (info.get("owner") or {}).get("type"),
            "visibility": visibility,
            "default_branch": branch,
            "archived": bool(info.get("archived")),
            "fork": bool(info.get("fork")),
            "empty": empty,
            "admin": admin,
            "push": bool(permissions.get("push")),
            "languages": languages,
            "manifests": manifests,
            "tree_truncated": bool((tree.data or {}).get("truncated")) if tree.ok else False,
        },
        "token": token_info(gh.auth_status(), visibility != "public"),
        "profile": profile,
        "workflows": workflows,
        "checks": checks,
        "tags": tags,
        "rulesets": rulesets,
        "classic_branch_protection": classic,
        "protections": protections,
        "alerts": open_alerts(audit),
        "hardening_pr": {"number": pull["number"], "url": pull["html_url"]} if pull else None,
        "errors": audit.errors,
    }


def render_text(report):
    context, profile = report["context"], report["profile"]
    flags = [k for k in ("archived", "fork", "empty", "tree_truncated") if context[k]]
    lines = [
        f"Repository: {report['repo']} ({context['visibility']}, {context['owner_type']}, "
        f"default branch {context['default_branch']}){' [' + ', '.join(flags) + ']' if flags else ''}",
        f"Admin permission: {'yes' if context['admin'] else 'no'}",
        f"Maintainers with write access: {profile['writers']} -> profile '{profile['name']}' {profile['note']}",
    ]
    token = report["token"]
    if token["missing_scopes"] is None:
        lines.append(f"Token scopes: unknown, {token['note']}")
    elif token["missing_scopes"]:
        lines.append(f"Token scopes missing: {', '.join(token['missing_scopes'])}")
    checks = report["checks"]
    lines.append(f"Stable checks: {', '.join(c['name'] for c in checks['stable']) or 'none'}")
    lines += [f"  not requirable: {c['name']} ({c['reason']})" for c in checks["unstable"][:10]]
    if len(checks["unstable"]) > 10:
        lines.append(f"  ... and {len(checks['unstable']) - 10} more (see the JSON output)")
    lines.append("")
    width = max(len(name) for name in report["protections"])
    for name, item in report["protections"].items():
        lines.append(f"{item['status']:<12}{name:<{width + 2}}{item['reason']}")
    lines.append("")
    for name, item in report["alerts"].items():
        count = "unknown" if item["count"] is None else f"{item['count']}{'+' if item['truncated'] else ''}"
        lines.append(f"Open {name} alerts: {count}")
    if report["hardening_pr"]:
        lines.append(f"Open hardening pull request: {report['hardening_pr']['url']}")
    for error in report["errors"]:
        lines.append(f"UNVERIFIED {error['endpoint']}: {error['message']} (HTTP {error['status']})")
    return "\n".join(lines)


def main(argv=None, gh=None):
    parser = argparse.ArgumentParser(description="Read-only audit of a GitHub repository's security settings.")
    parser.add_argument("repo", nargs="?", help="owner/repo (default: the repository of the current directory)")
    parser.add_argument("--text", action="store_true", help="readable summary instead of JSON")
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass
    gh = gh or Gh()
    try:
        repo = args.repo or gh.current_repo()
        if not repo or not re.match(r"^[\w.-]+/[\w.-]+$", repo):
            print("error: give the repository as owner/repo", file=sys.stderr)
            return 2
        report = run_audit(gh, repo)
    except FileNotFoundError:
        print("error: the GitHub CLI (gh) is not installed", file=sys.stderr)
        return 2
    except LookupError as error:
        print(f"error: {error}. Check `gh auth status`.", file=sys.stderr)
        return 1
    print(render_text(report) if args.text else json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
