#!/bin/bash
# check-sync.sh (rogue-toolkit / version-maintenance)
# Pre-tool-use hook: blocks git commit if version files are out of sync.
# Receives Claude Code tool input as JSON on stdin.
# Register it with the matcher "Bash|PowerShell" to cover both shell tools.
#
# It checks the repository each commit runs in, not the shell's current folder:
# it follows cd, Set-Location and git -C in the command, then goes to the repo root.
# A folder it cannot resolve (for example cd "$VAR") is skipped, not blocked.
#
# BYPASS for automated processes:
#   Set env var SKIP_VERSION_SYNC=1 before committing, OR
#   prefix the git commit command with SKIP_VERSION_SYNC=1
#   Example: SKIP_VERSION_SYNC=1 git commit -m "chore: automated commit"
#   Used by: CI scripts, any automated pipeline

set -uo pipefail

# --- Respect automated bypass ---
if [ "${SKIP_VERSION_SYNC:-0}" = "1" ]; then
  exit 0
fi

TOOL_INPUT=$(cat 2>/dev/null || echo "{}")

# --- Fast exit: most shell calls have nothing to do with commits ---
case "$TOOL_INPUT" in
  *commit*) ;;
  *) exit 0 ;;
esac

# --- Find each git commit in the command ---
# First line: the session folder. Then one line per commit: the folders to enter, tab-separated.
TARGETS=$(printf '%s' "$TOOL_INPUT" | python3 -c '
import json, re, shlex, sys

try:
    data = json.loads(sys.stdin.buffer.read().decode("utf-8"))
except ValueError:
    sys.exit(0)
command = (data.get("tool_input") or {}).get("command") or data.get("command") or ""
if re.search(r"SKIP_VERSION_SYNC\s*=\s*[\"\x27]?1", command):
    sys.exit(0)

SEPARATORS = set(";&|\n")
CD_COMMANDS = {"cd", "chdir", "pushd", "set-location", "sl"}
GIT_COMMANDS = {"git", "git.exe"}
SHELL_COMMANDS = {"bash", "bash.exe", "sh", "sh.exe", "pwsh", "pwsh.exe", "powershell", "powershell.exe"}
ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")
PARSE_FAILED = []


def unquote(token):
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"\x27":
        return token[1:-1]
    return token


def split_segments(text):
    """Commands in text. Unbalanced quotes end the parse, keeping what came before them."""
    lexer = shlex.shlex(text, posix=False, punctuation_chars=";&|\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    segments, current = [], []
    try:
        for token in lexer:
            if set(token) <= SEPARATORS:
                segments.append(current)
                current = []
            else:
                current.append(token)
    except ValueError:
        PARSE_FAILED.append(text)
    segments.append(current)
    return segments


def commit_folders(args):
    """Folders from git -C if args run git commit, otherwise None."""
    folders, index = [], 0
    while index < len(args):
        arg = args[index]
        if arg == "-C" and index + 1 < len(args):
            folders.append(unquote(args[index + 1]))
            index += 2
        elif arg == "-c":
            index += 2
        elif arg.startswith("-"):
            index += 1
        else:
            return folders if unquote(arg) == "commit" else None
    return None


def normalize(word):
    """Drop the shell syntax around a word: (cd, $(git, x=$(git and a closing )."""
    return re.sub(r"^(?:[A-Za-z_]\w*=)?\$?\(+|\)+$", "", word)


def drop_assignments(words):
    """Remove prefixes like A=1 git. A quoted value (A="a b") spans several words."""
    if not words or not ASSIGNMENT.match(words[0]):
        return words
    for index, word in enumerate(words):
        if unquote(word).lower() in GIT_COMMANDS:
            return words[index:]
    while words and ASSIGNMENT.match(words[0]):
        words = words[1:]
    return words


def collect(text, chain, commits):
    for segment in split_segments(text):
        words = drop_assignments([word for word in map(normalize, segment) if word])
        if not words:
            continue
        name = unquote(words[0]).lower()
        if name in CD_COMMANDS:
            targets = [w for w in words[1:] if not w.startswith("-") and w.lower() != "/d"]
            if targets:
                chain.append(unquote(targets[0]))
        elif name in GIT_COMMANDS:
            folders = commit_folders(words[1:])
            if folders is not None:
                commits.append(chain + folders)
        elif name in SHELL_COMMANDS:
            for index, word in enumerate(words[1:-1], start=1):
                if word.lower() in ("-c", "-command"):
                    collect(unquote(words[index + 1]), list(chain), commits)
                    break


commits = []
chain = []
collect(command, chain, commits)
# Unbalanced quotes before the commit hide it from the parse: check the folder reached so far.
if PARSE_FAILED and not commits and re.search(r"\bgit\s+commit(\s|$)", command):
    commits.append(chain)

if commits:
    lines = [data.get("cwd") or ""] + ["\t".join(["."] + folders) for folders in commits]
    sys.stdout.buffer.write("\n".join(lines).encode("utf-8"))
' 2>/dev/null | tr -d '\r')

if [ -z "$TARGETS" ]; then
  exit 0
fi

# --- First version = "x" inside the TOML sections that match the given names ---
toml_version() {
  awk -v sections="^\\\\[($2)\\\\]" '
    /^\[/ { inside = ($0 ~ sections) }
    inside && /^version[[:space:]]*=[[:space:]]*"/ {
      sub(/^[^"]*"/, ""); sub(/".*/, ""); print; exit
    }
  ' "$1" 2>/dev/null
}

# --- Check one repository; expects the current folder to be its root ---
check_repo() {
  local VERSION="" MANIFEST=""

  if [ -f ".claude-plugin/plugin.json" ]; then
    MANIFEST=".claude-plugin/plugin.json"
    VERSION=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['version'])" 2>/dev/null || echo "")
  elif [ -f "plugin/.claude-plugin/plugin.json" ]; then
    MANIFEST="plugin/.claude-plugin/plugin.json"
    VERSION=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['version'])" 2>/dev/null || echo "")
  elif [ -f "package.json" ]; then
    MANIFEST="package.json"
    VERSION=$(python3 -c "import json; print(json.load(open('package.json'))['version'])" 2>/dev/null || echo "")
  elif [ -f "pubspec.yaml" ]; then
    MANIFEST="pubspec.yaml"
    VERSION=$(grep '^version:' pubspec.yaml | sed 's/version: *//; s/#.*//' | tr -d "\"'[:space:]" 2>/dev/null || echo "")
    # Flutter build number: 1.2.3+4 is released as 1.2.3
    VERSION="${VERSION%%+*}"
  elif [ -f "pyproject.toml" ]; then
    MANIFEST="pyproject.toml"
    VERSION=$(toml_version pyproject.toml 'project|tool\.poetry')
  elif [ -f "Cargo.toml" ]; then
    MANIFEST="Cargo.toml"
    # Ignores version.workspace = true and the version of a dependency table.
    VERSION=$(toml_version Cargo.toml 'package|workspace\.package')
  fi

  # No manifest found — skip check silently
  if [ -z "$VERSION" ] || [ -z "$MANIFEST" ]; then
    return 0
  fi

  local ISSUES=()

  if [ ! -f "CHANGELOG.md" ]; then
    ISSUES+=("CHANGELOG.md does not exist")
  elif ! grep -qF "[$VERSION]" CHANGELOG.md; then
    ISSUES+=("CHANGELOG.md has no entry for [$VERSION]")
  fi

  if [ -f "README.md" ] && ! grep -qF "$VERSION" README.md; then
    ISSUES+=("README.md does not mention $VERSION")
  fi

  # All in sync — allow commit
  if [ ${#ISSUES[@]} -eq 0 ]; then
    return 0
  fi

  # --- Block commit ---
  {
    echo ""
    echo "VERSION_SYNC_BLOCKED: commit blocked — version files are out of sync."
    echo "Repository: $(pwd)"
    echo "Manifest: $MANIFEST  (version: $VERSION)"
    echo ""
    for issue in "${ISSUES[@]}"; do
      echo "  ✗ $issue"
    done
    echo ""
    echo "Invoke the version-maintenance skill to resolve before committing."
    echo "It will update the files above to match version $VERSION."
    echo ""
  } >&2

  return 2
}

# --- Check the repository of each commit ---
SESSION_DIR=$(printf '%s\n' "$TARGETS" | sed -n 1p)
RESULT=0

while IFS= read -r LINE; do
  (
    if [ -n "$SESSION_DIR" ]; then
      cd "$SESSION_DIR" 2>/dev/null || true
    fi
    IFS=$'\t' read -ra FOLDERS <<< "$LINE"
    for FOLDER in "${FOLDERS[@]}"; do
      cd "${FOLDER/#\~/$HOME}" 2>/dev/null || exit 0
    done
    ROOT=$(git rev-parse --show-toplevel 2>/dev/null) && cd "$ROOT"
    check_repo
  ) || RESULT=2
done < <(printf '%s\n' "$TARGETS" | sed 1d)

exit $RESULT
