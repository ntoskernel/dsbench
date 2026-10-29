# AGENTS.md

Instructions for AI coding agents working on dsbench, the benchmark harness for the DeepSecrets secrets scanner. Read
[README.md](README.md) first: it says what dsbench measures and how.

## Rules that are never bent

1. **Black box.** Never import `deepsecrets`. The scanner runs as a subprocess (`dsbench/tool.py`), and dsbench reads
   only its SARIF report (`dsbench/sarif.py`). A number that needs the scanner's internals belongs in DeepSecrets'
   own diagnostics, not here.
2. **No secret values in the repository.** Labels, raw findings, SARIF reports and the June dump hold real leaked
   credentials. They live in the bench home or the dataset directory only, and so does the June table: it holds no
   value, but its file names, lines and real-secret flags point at leaked credentials. Tests use synthetic values;
   `summary.md`, `metrics.json` and terminal output carry aggregates and never a value or a file name. Do not print a value from the bench home, even while debugging.
3. **Three places, kept apart.** The datasets and the bench home, the tool checkout and its cache, and this checkout
   (`dsbench/places.py`). Do not relax the overlap checks.
4. **Counting changes are versioned.** A change to what the `located` or `legacy` matcher accepts bumps its entry in
   `MATCHER_VERSIONS` (`dsbench/matcher.py`); metrics refuse pairs of another version, and a new `located` version
   locates the labels again. A change to the grouping or the fragment rule bumps `LABEL_POLICY_VERSION`
   (`dsbench/dataset.py`), which rebuilds a prepared dataset. The June view must keep reproducing June's own
   figures (`tests/test_june.py`) and June's per-(repository, value) recall of 93.10% (`tests/test_metrics.py`); both
   run when `DSBENCH_HOME` holds the June table and `DSBENCH_DATA` holds SecretBench, and skip otherwise.
5. **Quoted numbers come from the `all-files` profile.** It is the default; `scanner-defaults` measures a scope, not
   the scanner.

## Commands

```bash
python -m venv .venv && .venv/bin/pip install --constraint constraints.txt --editable '.[dev]'
.venv/bin/python -m pytest -q          # the whole suite, about 15 s; two June tests skip without the bench data
.venv/bin/black .                      # line length 120, quotes kept
dsbench doctor                         # with DSBENCH_DATA, DSBENCH_HOME, DSBENCH_TOOL_CWD, DSBENCH_CACHE set
```

A full SecretBench run is about 10 CPU-hours. Do not start one to check a change that the tests can check; when one is
needed, run it in the background and follow it with `dsbench watch`.

## Layout

| Module | What |
| --- | --- |
| `cli.py` | The command line; opens the store only in the commands that need it |
| `places.py`, `home.py` | The places and their separation; the bench home's layout |
| `store.py` | The DuckDB store (`bench.duckdb` in the bench home) and its bulk inserts |
| `dataset.py` | `prepare`: the CSV and the corpus listing into the store, the scanner's view of the corpus, candidate groups and fragments |
| `tool.py` | The scanner as a subprocess: command, profiles, version, commit, source digest, release trees and their venvs |
| `runner.py` | `run`: shards, the scheduler, timeouts and splits, ingestion, `--resume`, `progress.json` |
| `sarif.py` | Reading the scanner's SARIF report |
| `located.py` | Where a label and a finding sit in the text the scanner read; one file's pairs, in a worker process |
| `matcher.py` | Pairing findings with labels: `located` (the headline) and `legacy` (the June view); `MATCHER_VERSIONS` |
| `counting.py` | The `located` pairs per candidate group, per (repository, value) and per row, the reliability of each tier |
| `metrics.py` | Every view per confidence level, the June view included; `metrics.json`, `summary.md` |
| `doctor.py` | Readiness checks |
| `legacy/` | The June 2026 evaluation: reading its PostgreSQL dump (`pgcopy.py`, `preserve.py`) and the values-free table it leaves in the bench home (`june.py`) |

## Conventions

- Python 3.11+, black with line length 120 and `skip-string-normalization`, the standard library's `re`.
- Every module opens with a docstring that says what it does and why; comments are sparse and explain a reason.
- Dependencies are `duckdb` and `rapidfuzz` only. A new one is added to `pyproject.toml` and pinned in
  `constraints.txt`.
- Tests build their bench homes and corpora in `tmp_path`; the scanner in runner tests is `tests/fake_scanner.py`.

## Definition of done

1. `python -m pytest -q` passes and `black --check .` is clean.
2. No secret value, real file content or bench-home output in the diff.
3. If counting changed: the matcher version is bumped, the June tests still pass, and the change and its effect on a
   real run are stated.
4. Say plainly what changed, what was verified, and what was not.
