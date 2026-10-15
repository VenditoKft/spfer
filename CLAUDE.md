# spfer

Go library for evaluating SPF records (`github.com/VenditoKft/spfer`).

## Commands

- `make test` / `make race` — run tests (without / with the race detector)
- `make check` — fmt + vet + race tests; same as CI. Run before committing.
- `make version` — show latest tag, commits since, and proposed next version
- `make publish` — tag and push a new version (`BUMP=major|minor|patch` or `VERSION=vX.Y.Z` to override). Only run when the user asks.

CI (`.github/workflows/test.yml`) runs vet and race tests on every PR and push to `main`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/). `scripts/version.sh` reads the prefixes to propose the next version, so they must be accurate:

```
<type>[(scope)][!]: <short imperative summary>

[optional body]

[BREAKING CHANGE: <what breaks and how to migrate>]
```

| Type | Use for | Version bump |
|---|---|---|
| `feat` | New public functionality | minor |
| `fix` | Bug fix | patch |
| `perf` | Performance improvement | patch |
| `refactor` | Code change with no behavior change | patch |
| `test` | Adding or fixing tests | patch |
| `docs` | Documentation only | patch |
| `build` / `ci` | Build system, Makefile, workflows | patch |
| `chore` | Maintenance, dependencies | patch |

- Any change that breaks the public API (removed/renamed exports, changed signatures or semantics) **must** add `!` after the type (e.g. `feat!: ...`) and a `BREAKING CHANGE:` footer. This triggers a major bump. From v2 onward, a major bump also needs `/vN` added to the module path in `go.mod`.
- Use `feat` only for user-visible additions to the library, not for tooling.
- Summary: lowercase, imperative ("add", not "added"), no trailing period, about 72 characters max.
- One logical change per commit.

Examples:

```
feat(macro): support %{h} macro expansion
fix: return permerror on duplicate redirect modifier
ci: add test workflow for pull requests
refactor!: rename Check to Evaluate

BREAKING CHANGE: Check is now Evaluate; update call sites.
```
