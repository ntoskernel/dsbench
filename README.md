# dsbench

A benchmark harness for [DeepSecrets](https://github.com/ntoskernel/deepsecrets), the offline secrets scanner. It runs
the scanner over a labelled corpus such as [SecretBench](https://github.com/setu1421/SecretBench) (Basak et al.,
*SecretBench: A Dataset of Software Secrets*, [arXiv:2303.06729](https://arxiv.org/abs/2303.06729)), matches what it
reports against the labels, and writes recall and precision per confidence level.

dsbench never imports DeepSecrets. It runs the scanner as a subprocess, as a user would, from the checkout or release
under test, and reads only its SARIF report.

## Principles

- **Black box.** The scanner runs with its own interpreter and dependencies; dsbench reads its report and nothing else.
- **Three places, kept apart.** The benchmark (the datasets, read only, and the bench home), the tool (the checkout
  under test and its cache) and dsbench itself. dsbench refuses to run when one sits inside another.
- **Private by default.** Labels and raw findings are real secrets. They live in the bench home, outside every
  repository. What dsbench writes for people to read (`summary.md`, `metrics.json`, the terminal) holds aggregates
  only, and nothing in this repository holds a secret value.
- **A benchmark scans every file.** The default profile, `all-files`, turns the scanner's built-in path exclusions off,
  so every labelled file counts. Quote numbers from it.
- **Runs are immutable.** Each run keeps its own rows in the store and its own directory. Changing the matcher or a
  metric re-counts stored results; nothing is scanned again.

## Requirements

- Python 3.11 or later on Linux (the runner uses process groups; other POSIX systems are untested).
- A DeepSecrets checkout, and an interpreter that holds its locked dependencies
  (`poetry install --no-root` in the checkout, or its development container).
- A labelled corpus in SecretBench's layout: `secretbench.csv` and the `Files/` directory it names. SecretBench is
  available from its authors on request.
- About 100 GB free for the bench home: a full SecretBench run keeps its raw findings and its shard directories.

## Install

```bash
python -m venv .venv
.venv/bin/pip install --constraint constraints.txt --editable '.[dev]'
```

`constraints.txt` pins every dependency, so two installs measure with the same code.

## Places

| Variable | What |
| --- | --- |
| `DSBENCH_DATA` | The datasets: `secretbench.csv` and `Files/`. Read only |
| `DSBENCH_HOME` | The bench home: the store (`bench.duckdb`), run directories, exports. Holds real secrets |
| `DSBENCH_TOOL_CWD` | The DeepSecrets checkout under test |
| `DSBENCH_CACHE` | Release trees extracted for `--tool-ref`, and a venv per lock to run them in |
| `DSBENCH_TOOL_PYTHON` | The scanner's interpreter. Default: `python3` on `PATH` outside dsbench's own venv |

`--data`, `--home` and the commands' `--tool-cwd` and `--cache` override them. `dsbench doctor` checks that each is
set, reachable and apart from the others, that the corpus is readable and that the scanner runs.

## Quick start

```bash
dsbench doctor                         # are the places, the data and the scanner ready?
dsbench prepare                        # load the labels and the corpus listing into the store
dsbench run --cores 16                 # scan every file, then match and count
dsbench watch                          # in another terminal: live progress and an ETA
dsbench status                         # datasets and runs
dsbench run --tool-ref v2.1.1          # a release's committed tree, in a venv from its own poetry.lock
dsbench run --resume <run_id>          # continue an interrupted run with its own scanner
dsbench match --run <run_id>           # pair findings with labels again (after a matcher change)
dsbench metrics --run <run_id>         # count again: metrics.json and summary.md
```

A run id is `<YYYYMMDD>-<HHMMSS>-<profile>`; `--label` names the build under test in the run's parameters.

## What a run does

`prepare` loads the CSV as given: problems in a row become recorded issues, never corrections. The scanner sees each
labelled file at its original repository path under a neutral directory (`r_<hash>/<path>`), because path-aware
scoring reads the path; unlabelled files stay flat.

`prepare` also groups the rows into candidate groups. A corpus labelled by regexes often labels one literal several
times, a token and its parts or one value under two rows, so rows of one file that start on the same line form one
group when their spans overlap or their normalised values are equal or one holds the other. A group with a real-secret
row is one real secret; a group of look-alike rows is one hard negative. A look-alike row that is a piece of a real
secret, by its comment ("Part of Slack Token") or because its value lies inside a real row's value in its group, is a
fragment. SecretBench has 95,992 groups (14,610 real, 81,382 hard negatives) and 1,149 fragment rows.

`run --tool-ref REF` scans the committed tree of a release or commit instead of a checkout: `git archive` extracts it
once into the cache, and it runs in a venv built once from that ref's own `poetry.lock` (its `main` group, every
package at its locked version and hash, installed by pip without resolving), since releases pin different
dependencies. Refs with the same lock share the venv.

`run` plans the files into shards, longest first: files over 5 MB alone, the rest packed to about equal cost. `--cores`
scanner processes run at once, each scanning one shard with `--process-count 1` in its own process group, with
`--report-diagnostics --disable-masking --outformat sarif`. A shard that fails or times out is split; a single file is
retried, then recorded with its status. Each shard's report is stored when the shard ends, so an interrupted run keeps
its finished work and `--resume` continues it. `progress.json` in the run directory says how far it is.

A run directory holds `shards/sNNNNN/{target/,report.sarif,scanner.log}`, `progress.json`, `metrics.json` and
`summary.md`.

## How findings are counted

**The June view.** In June 2026 DeepSecrets' maintainers evaluated the scanner against SecretBench and published the
figures in its README. dsbench reproduces that counting: per labelled row, without the 233 rows they flagged as wrong,
which leaves 14,847 secrets and 82,265 look-alikes. A row is found when a finding matches it under the `legacy` matcher:
the same start line, then equality, containment either way, or a fuzzy ratio of at least 90 between the two texts with
spaces and `. \ " ' - / +` removed. Precision is found secrets over found secrets plus charged look-alikes; findings
outside the labels never enter it.

Beside it, the same rows per (repository, value): one unit per repository, label and raw value, so copies of one
secret in many files count once.

Both are reported at each confidence level the scanner offers (`low`, `medium`, `high`, `very-high`), cutting one
`low` run by each finding's tier as the scanner itself reports it: the suffix of its rule id (`-LOW` to `-VERY-HIGH`;
`-INFO` marks a rejected candidate, in no named level), else, for a rule of fixed confidence, the `precision` of its
rule descriptor. A level therefore holds what that scanner version reports at that level, wherever its tiers start;
the numeric confidence is stored beside the tier.

Every stored pair carries the matcher's version; `metrics` refuses pairs from another version, so a matcher change
means `dsbench match` again, never a silent mix.

## The June 2026 table

The June view needs the labelled rows of that evaluation and June's own verdicts: the evaluation's row id, the CSV row
ids it stands for, the corpus file name, the line, whether the row is a real secret, the maintainers' `problem` flag,
whether the June scan found it, and a case label. `dsbench preserve --from-dump DUMP` exports them once from the
evaluation's PostgreSQL dump into the bench home (`legacy/<timestamp>/june_rows.csv.gz`); it needs `pg_restore` 17 or
later and no server. `dsbench june` then prints June's figures (93.38% recall, 66.65% precision).

The table holds no secret value, but it is not published: a file name, a line and the real-secret flag together point
at a leaked credential in a public repository. Without it, `metrics` counts everything except the June view.

## Development

```bash
.venv/bin/python -m pytest -q
.venv/bin/black .
```

The tests use synthetic data only; one calibration test also reads SecretBench when `DSBENCH_DATA` points at it, and
skips otherwise. Contributions must keep every secret value out of the repository, its tests and its history.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
