@AGENTS.md

## Claude Code specific notes

- Commit only when the user asks, and never push unless asked. Do not add a `Co-Authored-By:` trailer, a "Generated
  with Claude Code" line or any other AI attribution to commit messages or pull request descriptions.
- Run tests with the checkout's venv: `.venv/bin/python -m pytest -q`.
- When this repository is open beside DeepSecrets in one window, DeepSecrets' own instructions apply to its files and
  these to this repository's; the two never import each other.
