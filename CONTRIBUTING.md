# Contributing to SentinelScout

Thanks for your interest in contributing. This document covers what's
expected of a pull request, the coding style used in this repo, and the
current state of testing.

## Before You Start

- For anything beyond a small fix (new source integration, new CLI
  command, changes to correlation/scoring logic in `analyzer.py`), please
  open an issue first to discuss the approach.
- Never commit real API keys, `.env` files, or other credentials. Use
  `.env.example` as the template for any new configuration variables and
  keep secrets out of code, tests, and commit history.

## Development Setup

```bash
git clone https://github.com/glatinone/sentinelscout.git
cd sentinelscout
pip install -e ".[dev]"
```

This installs the package in editable mode along with the `dev` extras
(`ruff`, `pytest`, `pytest-asyncio`) declared in `pyproject.toml`.

## Coding Style

- Target Python 3.10+, matching `requires-python` in `pyproject.toml`.
- Lint with **ruff** before opening a PR:

  ```bash
  ruff check .
  ```

  CI runs `ruff check .` on every push and pull request; a PR with lint
  errors will fail CI. Ruff currently runs with its default rule set
  (there is no `[tool.ruff]` section in `pyproject.toml` yet) — if you
  add stricter or project-specific rules, do so in a dedicated PR with a
  clear description of what changed and why.
- Prefer small, focused modules consistent with the existing layout
  (`sentinelscout/sources/*.py` for individual OSINT source clients,
  `analyzer.py` for correlation/AI logic, `models.py` for shared data
  types).
- New source integrations should subclass `sentinelscout.sources.base.BaseSource`
  and follow the existing async `query()` pattern used by the other
  sources.
- Keep API-key handling consistent with `config.py` — read credentials
  through the existing config/`.env` loading path rather than adding new,
  ad hoc ways to read secrets.

## Testing Expectations

**There is currently no automated test suite in this repository** (no
`tests/` directory, no pytest configuration). CI reflects this honestly:
it lints the code and does a smoke import of every module, but it does
not run `pytest` against nonexistent tests.

Going forward, this is the expectation for new contributions, not a
description of existing coverage:

- **Any new feature, source integration, or correlation/scoring rule
  should come with a corresponding test.** `pytest` and `pytest-asyncio`
  are already declared as dev dependencies for this purpose — use them.
- Place new tests under a `tests/` directory (create it if it doesn't
  exist yet), mirroring the package layout, e.g.
  `tests/sources/test_virustotal.py` for `sentinelscout/sources/virustotal.py`.
  If you're the one setting this up for the first time, also consider
  wiring a `pytest` step into `.github/workflows/ci.yml` once real tests
  exist — the current workflow intentionally does not run pytest because
  there's nothing for it to run yet.
- Bug fixes should include a regression test that fails before the fix
  and passes after, where practical.
- Mock outbound HTTP calls to the third-party APIs (VirusTotal, OTX,
  Shodan, NVD, GitHub) rather than hitting live services in tests — this
  keeps CI deterministic and avoids burning API quota/keys.
- Until a real suite exists, at minimum verify manually that
  `sentinelscout --help` and the relevant CLI subcommand run without
  raising, and note in your PR description how you tested the change.

## Pull Request Requirements

Before opening a PR, make sure:

- [ ] The package still installs cleanly: `pip install -e ".[dev]"`.
- [ ] `ruff check .` passes with no errors.
- [ ] The package still imports cleanly (`python -c "import sentinelscout"`
      and any new modules you touched).
- [ ] New features, new sources, or new correlation rules include a test
      under `tests/` (see above). If you believe a test genuinely isn't
      feasible, say so explicitly in the PR description and explain why.
- [ ] No secrets, API keys, or `.env` files are included in the diff.
- [ ] The PR description explains *what* changed and *why*, and calls
      out any manual testing you did (especially while no automated
      suite exists).
- [ ] Documentation (`README.md`, `.env.example`, docstrings) is updated
      if you changed configuration, CLI behavior, or added a source.

Keep PRs scoped to a single logical change where possible — it's easier
to review and easier to bisect later if something breaks.
