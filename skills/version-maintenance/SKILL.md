---
name: version-maintenance
description: Use when a git commit was blocked by VERSION_SYNC_BLOCKED, when bumping a version, updating a changelog, or preparing a release. Detects the project manifest (package.json, plugin.json, pubspec.yaml, pyproject.toml, Cargo.toml), applies version bump to manifest + CHANGELOG.md + README.md, and emits annotated git tag commands ready to copy-paste.
---

# Version Maintenance

Keep manifest, CHANGELOG.md, and README.md in sync. Run before every commit that changes functionality.

## Step 1 — Detect manifest and current version

Search in this order — use the first match:
1. `.claude-plugin/plugin.json` → `version` field (JSON)
2. `plugin/.claude-plugin/plugin.json` → `version` field (JSON)
3. `package.json` → `version` field (JSON)
4. `pubspec.yaml` → `version:` line
5. `pyproject.toml` → `version =` line under `[tool.poetry]` or `[project]`
6. `Cargo.toml` → `version =` line under `[package]`

If none found, ask the user which file contains the version.

## Step 2 — Determine version bump

If the user specified X.Y.Z or the hook output provided the current version, use it.
Otherwise ask:

> "What type of change is this?
> - **PATCH** — bug fix, prompt fix, config adjustment (no new features)
> - **MINOR** — new feature, new skill/endpoint/command (backward-compatible)
> - **MAJOR** — breaking change to public API, config format, or install layout"

Calculate new version from bump type. Preserve any custom suffix (-mvp, -alpha, -rc.N).

## Step 3 — Update manifest

Set the `version` field to the new version.

JSON manifest: `"version": "X.Y.Z"`
YAML (pubspec.yaml): `version: X.Y.Z`
TOML (pyproject.toml, Cargo.toml): `version = "X.Y.Z"`

## Step 4 — Update CHANGELOG.md

**If CHANGELOG.md does not exist:** create it:

```markdown
# Changelog

All notable changes are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

---

## [X.Y.Z] — YYYY-MM-DD

### Added | Changed | Fixed
- <describe what changed>
```

**If it exists:** insert a new section after `## [Unreleased]`:

```markdown
## [X.Y.Z] — YYYY-MM-DD

### Added | Changed | Fixed
- <describe what changed>

---
```

Use `### Fixed` for PATCH, `### Added` for MINOR, `### Changed` for MAJOR.
Ask for a one-line description if not already provided.
Update reference links at the bottom if they exist.

## Step 5 — Update README.md

Scan for the previous version string. Replace with the new version.
Common patterns: `> **Versión:** X.Y.Z`, `**version:** X.Y.Z`, badge URLs.
If no version mention found, skip silently.

## Step 6 — Emit git tag commands

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z: <one-line description>"
git push origin vX.Y.Z
```

**Hotfix series** (multiple PATCH in one session, shared commit):

```bash
SHA=$(git rev-parse HEAD)
git tag -a vX.Y.1 $SHA -m "Hotfix vX.Y.1: <description>"
git tag -a vX.Y.2 $SHA -m "Hotfix vX.Y.2: <description>"
git push origin --tags
```

## Step 7 — Summary

```
✅ Version bumped: OLD → NEW
Files updated:
  - <manifest>: version field
  - CHANGELOG.md: ## [NEW] — YYYY-MM-DD
  - README.md: version line updated  (or: no version mention, skipped)

Pending (run after commit):
  git tag -a vNEW -m "..."
  git push origin vNEW
```

## Edge cases

| Situation | Handling |
|---|---|
| Version mismatch between files | List all files + versions; ask which is authoritative |
| No CHANGELOG.md | Create from scratch (Step 4) |
| First release | Use v0.1.0 or ask; create complete CHANGELOG |
| Custom suffix (-mvp, -alpha) | Preserve; bump numeric part only |
| Multiple manifests (monorepo) | Ask which to bump; offer to bump all |
| Hook blocked but version looks correct | Investigate — likely CHANGELOG formatting issue |
| Automated commit (CI, scripts) | Set `SKIP_VERSION_SYNC=1` — hook exits 0 without blocking |

## Automated process integration

Any process that commits automatically must bypass the hook:

```bash
# Option A — env var in the process environment
export SKIP_VERSION_SYNC=1
git commit -m "chore: automated commit"

# Option B — inline prefix (without modifying the environment)
SKIP_VERSION_SYNC=1 git commit -m "chore: automated commit"
```

Version sync is the developer's responsibility at release time, not the agent's on individual commits.
