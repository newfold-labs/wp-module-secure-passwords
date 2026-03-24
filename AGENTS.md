# Agent guidance – wp-module-secure-passwords

This file gives AI agents a quick orientation to the repo. For full detail, see the **docs/** directory.

## What this project is

- **wp-module-secure-passwords** – Prevents passwords exposed in data breaches from being used and encourages better password hygiene. Registers with the Newfold Module Loader; no runtime Composer requires. Maintained by Newfold Labs.

- **Stack:** PHP 7.3+. No runtime Composer deps.

- **Architecture:** Registers with the loader; hooks into WordPress user/password flows. See docs/integration.md.

## Key paths

| Purpose | Location |
|---------|----------|
| Bootstrap | `bootstrap.php` |
| Includes | (see autoload) |
| Tests | `tests/` |

## Essential commands

```bash
composer install
composer run lint
composer run fix
composer run test
```

## Documentation

- **Full documentation** is in **docs/**. Start with **docs/index.md**.
- **CLAUDE.md** is a symlink to this file (AGENTS.md).

---

## Keeping documentation current

When you change code, features, or workflows, update the docs. Keep **docs/index.md** current: when you add, remove, or rename doc files, update the table of contents (and quick links if present). When cutting a release, update **docs/changelog.md**.
