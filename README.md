# rogue-toolkit

Small standalone skills for Claude Code that I use in my own projects.

## Skills

| Skill | What it does |
|---|---|
| `version-maintenance` | Detects the project manifest (`package.json`, `plugin.json`, `pubspec.yaml`, `pyproject.toml`, `Cargo.toml`), bumps the version in the manifest, `CHANGELOG.md` and `README.md`, and prints annotated tag commands. `check-sync.sh` is an optional `PreToolUse` hook (matcher `Bash\|PowerShell`) that blocks a `git commit` when those files drift apart in the repository the commit runs in; the plugin does not register it, you wire it in your settings if you want it. |

Version 0.1.0.

## Install

From the [The Rogue Roadmap catalog](https://github.com/therogueroadmap/marketplace):

```text
/plugin marketplace add therogueroadmap/marketplace
/plugin install rogue-toolkit@therogueroadmap
```

## Requirements

- Claude Code.
- `bash` and `python3` for `check-sync.sh` (Git Bash on Windows).

## Status

Stable. More skills will join when they work without my private setup.

## License

MIT
