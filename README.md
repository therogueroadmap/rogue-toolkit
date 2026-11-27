# rogue-toolkit

Small standalone skills for Claude Code that I use in my own projects.

## Skills

| Skill | What it does |
|---|---|
| `version-maintenance` | Detects the project manifest (`package.json`, `plugin.json`, `pubspec.yaml`, `pyproject.toml`, `Cargo.toml`), bumps the version in the manifest, `CHANGELOG.md` and `README.md`, and prints annotated tag commands. `check-sync.sh` is an optional `PreToolUse` hook (matcher `Bash\|PowerShell`) that blocks a `git commit` when those files drift apart in the repository the commit runs in; the plugin does not register it, you wire it in your settings if you want it. |
| `github-repo-hardening` | Audits one GitHub repository with a read-only script, proposes a protection plan that fits it (maintainer count, stable checks, tags, actions in use) and, after you approve it, applies it with `gh`: detection settings, rulesets, Actions policy and one pull request for the file changes. It merges that pull request only in automatic mode and never dismisses alerts. |

Version 0.2.0.

## Install

From the [The Rogue Roadmap catalog](https://github.com/therogueroadmap/marketplace):

```text
/plugin marketplace add therogueroadmap/marketplace
/plugin install rogue-toolkit@therogueroadmap
```

## Requirements

- Claude Code.
- `bash` and `python3` for `check-sync.sh` (Git Bash on Windows).
- For `github-repo-hardening`: the GitHub CLI (`gh`) authenticated with admin permission on the repository, and `python3` or `python`.

## Status

Stable. More skills will join when they work without my private setup.

## License

MIT
