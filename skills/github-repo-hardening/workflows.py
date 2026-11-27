"""Minimal reader for GitHub Actions YAML, using the standard library only.

It covers the YAML subset found in workflows, composite actions and dependabot.yml.
Anything it cannot read with confidence raises ValueError, so callers can treat the
file as unknown instead of guessing.
"""
import re

KEY = re.compile(r"""^(?:"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)'|([^'"\[\{].*?))\s*:(?:\s+(.*))?$""")
BLOCK = re.compile(r"^[|>][0-9+-]*$")
BLOCK_OPENER = re.compile(r"(?:^-|:)\s+(?:&\S+\s+)?[|>][0-9+-]*$")
QUOTED = re.compile(r"""^(?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*')$""")


def strip_comment(line):
    quote = None
    for i, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'" and (i == 0 or line[i - 1] in " :[{,-"):
            quote = char
        elif char == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def logical_lines(text):
    """Return [indent, content] pairs without comments, blanks or block scalar bodies."""
    lines, block_indent = [], None
    for raw in text.lstrip("﻿").splitlines():
        indent = len(raw) - len(raw.lstrip(" "))
        if block_indent is not None:
            if not raw.strip() or indent > block_indent:
                continue
            block_indent = None
        content = strip_comment(raw).strip()
        if not content or content in ("---", "..."):
            continue
        if raw[indent:indent + 1] == "\t":
            raise ValueError("tab indentation")
        lines.append([indent, content])
        if BLOCK_OPENER.search(content):
            # The body is indented deeper than the key, which may follow "- ".
            dashes = re.match(r"^(?:-\s+)*", content).group(0)
            is_bare_item = BLOCK.match(content[len(dashes):]) is not None
            block_indent = indent if is_bare_item else indent + len(dashes)
    return lines


def split_flow(body):
    items, depth, quote, current = [], 0, None, ""
    for char in body:
        if quote:
            quote = None if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == "," and depth == 0:
            items.append(current)
            current = ""
            continue
        current += char
    items.append(current)
    return [item.strip() for item in items if item.strip()]


def scalar(value):
    value = re.sub(r"^&\S+\s*", "", value.strip())
    if re.match(r"^\*[\w-]+$", value):
        raise ValueError("YAML aliases are not supported")
    if value.startswith("[") and value.endswith("]"):
        return [scalar(item) for item in split_flow(value[1:-1])]
    if value.startswith("{") and value.endswith("}"):
        result = {}
        for item in split_flow(value[1:-1]):
            key, _, val = item.partition(":")
            result[scalar(key)] = scalar(val)
        return result
    if QUOTED.match(value):
        return value[1:-1]
    if BLOCK.match(value):
        return ""
    return None if value in ("", "~", "null", "Null", "NULL") else value


def unbalanced(value):
    bare = re.sub(r""""(?:[^"\\]|\\.)*"|'(?:[^']|'')*'""", "", value)
    return bare.count("[") + bare.count("{") > bare.count("]") + bare.count("}")


def is_item(content):
    return content == "-" or content.startswith("- ")


def starts_scalar(line, parent_indent):
    """True when a key's value begins on the following line instead of being a nested block."""
    column, content = line
    if column <= parent_indent or is_item(content):
        return False
    return bool(QUOTED.match(content)) or not KEY.match(content)


def parse_block(lines, i, indent):
    is_list = is_item(lines[i][1])
    result = [] if is_list else {}
    while i < len(lines) and lines[i][0] == indent:
        content = lines[i][1]
        if is_list:
            if not is_item(content):
                break
            rest = content[1:].lstrip()
            if not rest:
                i += 1
                if i < len(lines) and lines[i][0] > indent:
                    value, i = parse_block(lines, i, lines[i][0])
                else:
                    value = None
            elif is_item(rest) or (KEY.match(rest) and not QUOTED.match(rest)):
                column = indent + len(content) - len(rest)
                lines[i] = [column, rest]
                value, i = parse_block(lines, i, column)
            else:
                value, i = parse_value(lines, i, indent, rest)
            result.append(value)
            continue
        match = KEY.match(content)
        if not match:
            raise ValueError(f"unreadable line: {content}")
        key = next(group for group in match.groups()[:3] if group is not None)
        rest = re.sub(r"^&\S+(\s+|$)", "", (match.group(4) or "").strip())
        if rest:
            result[key], i = parse_value(lines, i, indent, rest)
            continue
        i += 1
        nested = i < len(lines) and (
            lines[i][0] > indent or (lines[i][0] == indent and is_item(lines[i][1]))
        )
        if nested and starts_scalar(lines[i], indent):
            result[key], i = parse_value(lines, i, indent, lines[i][1])
        elif nested:
            result[key], i = parse_block(lines, i, lines[i][0])
        else:
            result[key] = None
    return result, i


def parse_value(lines, i, indent, rest):
    """Read a scalar or flow value, joining its continuation lines."""
    i += 1
    while i < len(lines) and lines[i][0] > indent:
        rest = f"{rest} {lines[i][1]}"
        i += 1
    if rest[:1] in ("[", "{"):
        while i < len(lines) and unbalanced(rest):
            rest = f"{rest} {lines[i][1]}"
            i += 1
    return scalar(rest), i


def parse_yaml(text):
    lines = logical_lines(text)
    if not lines:
        return {}
    result, end = parse_block(lines, 0, lines[0][0])
    if end != len(lines):
        raise ValueError(f"unreadable line: {lines[end][1]}")
    return result


SHA = re.compile(r"^[0-9a-f]{40}$")
USES_LINE = re.compile(r"""^\s*(?:-\s+)?uses\s*:\s*["']?([^\s"'#]+)""", re.MULTILINE)
PERMISSIONS_LINE = re.compile(r"^\s*permissions\s*:", re.MULTILINE)
WRITE_SIGNALS = {
    "publishes a release": r"action-gh-release|actions/create-release|ncipollo/release-action"
    r"|goreleaser|semantic-release",
    "writes with the gh CLI": r"\bgh\s+(release|pr|issue|label)\s+(create|upload|edit|comment|merge|close|review)",
    "calls the API with gh": r"\bgh\s+api\b",
    "pushes commits or tags": r"\bgit\s+push\b|git-auto-commit-action|create-pull-request",
    "publishes a package or image": r"\b(npm|pnpm|yarn|cargo)\s+publish\b|docker/login-action|\bdocker\s+push\b"
    r"|twine\s+upload|gh-action-pypi-publish|\bmvn\b.*\bdeploy\b|\bgradlew?\b.*\bpublish",
    "comments, labels or scripts the API": r"actions/github-script|peter-evans/|actions/stale|actions/labeler"
    r"|dependency-review-action",
    "deploys pages or uploads results": r"actions/deploy-pages|upload-sarif|codeql-action/(analyze|upload-sarif)",
    "requests an OIDC token": r"aws-actions/configure-aws-credentials|google-github-actions/auth|azure/login",
    "uses the workflow token": r"secrets\.GITHUB_TOKEN|\bgithub\.token\b",
}


def classify_uses(ref, owner):
    """Describe one `uses:` value relative to the repository owner."""
    if ref.startswith("./"):
        return {"ref": ref, "kind": "local", "needs_pin": False}
    if ref.startswith("docker://"):
        return {"ref": ref, "kind": "docker", "needs_pin": False}
    action, _, version = ref.partition("@")
    action_owner = action.split("/")[0].lower()
    if action_owner == owner.lower():
        kind = "same_owner"
    elif action_owner in ("actions", "github"):
        kind = "github"
    else:
        kind = "third_party"
    pinned = bool(SHA.match(version))
    return {
        "ref": ref,
        "kind": kind,
        "action": action,
        "version": version,
        "pinned": pinned,
        "needs_pin": not pinned and kind != "same_owner" and "${{" not in ref,
    }


def branch_pattern_matches(pattern, branch):
    """GitHub filter glob: `*` stops at `/`, `**` crosses it. Other special characters
    return None (unknown), so the caller stays conservative."""
    if any(c in pattern for c in "?+[]"):
        return None
    regex = "".join(".*" if part == "**" else "[^/]*" if part == "*" else re.escape(part)
                    for part in re.split(r"(\*\*|\*)", pattern))
    return re.fullmatch(regex, branch) is not None


def default_branch_targeted(config, default_branch):
    """True only when the base-branch filters certainly let pull requests into the default
    branch through. Patterns are applied in order and a `!` pattern removes matches."""
    if not default_branch:
        return False
    included = "branches" not in config
    if "branches" in config:
        patterns = config["branches"]
        for pattern in [patterns] if isinstance(patterns, str) else patterns or []:
            negated = str(pattern).startswith("!")
            match = branch_pattern_matches(str(pattern).lstrip("!"), default_branch)
            if match is None:
                return False
            if match:
                included = not negated
    ignored = config.get("branches-ignore")
    for pattern in [ignored] if isinstance(ignored, str) else ignored or []:
        match = branch_pattern_matches(str(pattern), default_branch)
        if match is None or match:
            return False
    return included


def pull_request_state(triggers, default_branch=None):
    """Return (runs on pull_request, is filtered so it may not run on every pull request
    into the default branch)."""
    if isinstance(triggers, str):
        return triggers == "pull_request", False
    if isinstance(triggers, list):
        return "pull_request" in triggers, False
    if not isinstance(triggers, dict) or "pull_request" not in triggers:
        return False, False
    config = triggers["pull_request"] or {}
    if not isinstance(config, dict):
        return True, True
    filtered = any(k in config for k in ("paths", "paths-ignore"))
    if "branches" in config or "branches-ignore" in config:
        filtered = filtered or not default_branch_targeted(config, default_branch)
    types = config.get("types")
    if types is not None:
        types = [types] if isinstance(types, str) else types
        filtered = filtered or not {"opened", "synchronize"} <= set(types)
    return True, filtered


def collect_uses(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uses" and isinstance(value, str):
                found.append(value)
            elif key not in ("with", "env"):
                collect_uses(value, found)
    elif isinstance(node, list):
        for item in node:
            collect_uses(item, found)


def analyze_workflow(path, text, owner, default_branch=None):
    code = "\n".join(strip_comment(line) for line in text.splitlines())
    info = {
        "path": path,
        "kind": "workflow" if path.startswith(".github/workflows/") else "composite_action",
        "parsed": True,
        "triggers": [],
        "runs_on_pull_request": False,
        "pull_request_filtered": False,
        "jobs": [],
        "write_signals": [label for label, rx in WRITE_SIGNALS.items() if re.search(rx, code)],
    }
    try:
        doc = parse_yaml(text)
        if not isinstance(doc, dict):
            raise ValueError("not a mapping")
        jobs = doc.get("jobs") or {}
        if info["kind"] == "workflow" and (not isinstance(jobs, dict) or not jobs):
            raise ValueError("no jobs mapping")
        triggers = doc.get("on")
        info["triggers"] = [triggers] if isinstance(triggers, str) else list(triggers or [])
        info["runs_on_pull_request"], info["pull_request_filtered"] = pull_request_state(
            triggers, default_branch)
        declares = "permissions" in doc
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                raise ValueError(f"job {job_id} is not a mapping")
            declares = declares or "permissions" in job
            strategy = job.get("strategy")
            info["jobs"].append({
                "id": job_id,
                "name": str(job.get("name") or job_id),
                "matrix": bool(strategy) and (not isinstance(strategy, dict) or "matrix" in strategy),
                "reusable": "uses" in job,
                "conditional": "if" in job,
            })
        refs = []
        collect_uses(doc, refs)
    except (ValueError, IndexError, RecursionError, TypeError, AttributeError) as error:
        info.update(parsed=False, parse_error=str(error), jobs=[])
        declares = bool(PERMISSIONS_LINE.search(code))
        refs = USES_LINE.findall(code)
    info["declares_permissions"] = declares
    info["uses"] = [classify_uses(ref, owner) for ref in dict.fromkeys(refs)]
    return info
