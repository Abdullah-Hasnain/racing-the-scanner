# Contributing

Three people, limited time, five machines. The goal is to never block each
other. Read this once before your first PR.

## Who owns what (avoid collisions)

| Area | Owner | Files |
|------|-------|-------|
| Memory + scanner | Khan (@khan-slayer) | `memory/**` |
| Scheduler sim + policies | Hasnain (@Abdullah-Hasnain) | `sim/**` |
| Detection + integration | Ibad (@vanodew1) | `detection/**`, `analysis/**` |

Shared files (`README.md`, `docs/**`, `.github/**`, root configs) change through
small PRs. If you need to touch another person's area, say so on the issue first.

## Branches

- One branch per issue, off `main`: `feat/<area>-<short>` or `fix/<area>-<short>`.
  Examples: `feat/sim-ocsvm-policy`, `feat/memory-v2-dwell`, `fix/detect-aggregator`.
- Never commit to `main` directly. `main` stays green (CI passing) at all times.

## Commits

- Small, focused commits. Present tense: "add OCSVM policy", not "added".
- Reference the issue: "add OCSVM policy (#12)".

## Pull requests

1. Push your branch and open a PR into `main`.
2. Fill the PR template; link the issue with "Closes #N".
3. CI must pass (lint + tests + C syntax-check).
4. One teammate reviews and approves.
5. Squash-merge. Delete the branch.

## Code standards

- Python: `ruff check .` must pass (run `ruff check --fix .` locally first).
  Keep the simulation CPU-only and dependency-light; GPU/torch code stays
  optional and guarded.
- New behavior gets a test under `sim/tests/` where practical. `make test` green.
- C: `make -C memory check` must pass (syntax). No hardcoded absolute paths.
- Do not commit data, results, figures, models, or `.env` (all gitignored).

## Definition of done

An issue is done when: the code is merged to `main`, CI is green, any new metric
writes a CSV that `analysis/make_graphs.py` can read, and the README or module
doc is updated if the interface changed.
