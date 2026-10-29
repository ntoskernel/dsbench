import csv
import json
import os
import sys
from pathlib import Path

import pytest

from dsbench import matcher, metrics, store
from dsbench.home import BenchHome
from dsbench.legacy import june
from dsbench.legacy.june import JuneRow

# (row_id, repo, file, line, value, label); rows 1 and 2 are one value in two files of one repository
LABELS = [
    (1, 'repo-a', 'f1', 1, 'Tq7XbR2mKp9L', True),
    (2, 'repo-a', 'f2', 1, 'Tq7XbR2mKp9L', True),
    (3, 'repo-b', 'f3', 1, 'Zx9Qm2Lp8Rt4', True),
    (4, 'repo-a', 'f1', 2, 'hello', False),
    (5, 'repo-a', 'f1', 3, 'world', False),
    (6, 'repo-b', 'f3', 4, 'Mk3Vb8Qw1Zr5', True),
    (7, 'repo-b', 'f3', 2, 'Zx9Qm2Lp8Rt4', False),
]
# (file, line, value, confidence, tier)
FINDINGS = [
    ('f1', 1, 'Tq7XbR2mKp9L', 10, 'very-high'),
    ('f3', 1, 'Zx9Qm2Lp8Rt4', 4, 'medium'),
    ('f1', 2, 'hello', 2, 'low'),
    ('f3', 2, 'Zx9Qm2Lp8Rt4', 7, 'high'),
    ('f9', 1, 'unlabelled', 10, 'very-high'),
]
ROWS = [
    JuneRow(row_id, (str(row_id),), file, line, label, 'not_a_secret' if row_id == 6 else None, False, None)
    for row_id, _, file, line, _, label in LABELS
]


@pytest.fixture
def con(home: BenchHome):
    with store.connect(home) as con:
        con.execute("INSERT INTO datasets (dataset_id, stats, created_at) VALUES ('d', '{\"rows\": 7}', now())")
        for file_id in ('f1', 'f2', 'f3', 'f9'):
            con.execute(
                'INSERT INTO files (dataset_id, file_id, size, view_path, labelled, scan_file_id) VALUES (?, ?, ?, ?, ?, ?)',
                ['d', file_id, 300_000 if file_id == 'f9' else 10, f'v/{file_id}', file_id != 'f9', file_id],
            )
        for row_id, repo, file_id, line, value, label in LABELS:
            con.execute(
                'INSERT INTO labels (dataset_id, row_id, repo, file_id, start_line, value, label, group_id, fragment) VALUES (?, ?, ?, ?, ?, ?, ?, ?, false)',
                ['d', row_id, repo, file_id, line, value, label, row_id],
            )
        params = {'cores': 2, 'segments': [{'wall_s': 90.0}], 'label': None}
        con.execute(
            "INSERT INTO runs (run_id, dataset_id, profile, params, status) VALUES ('r', 'd', 'all-files', ?, 'done')",
            [json.dumps(params)],
        )
        for i, (file_id, line, value, confidence, tier) in enumerate(FINDINGS, 1):
            con.execute(
                'INSERT INTO findings (run_id, finding_id, file_id, start_line, value, confidence, tier, rule_base) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                ['r', i, file_id, line, value, confidence, tier, 'S105'],
            )
        for file_id in ('f1', 'f2', 'f3', 'f9'):
            con.execute(
                "INSERT INTO artifacts (run_id, file_id, status, depth, errors) VALUES ('r', ?, 'ok', ?, 0)",
                [file_id, 'shallow' if file_id == 'f9' else 'deep'],
            )
        con.execute(
            "INSERT INTO shards (run_id, shard_id, n_files, status, cpu_s, wall_s) VALUES ('r', 's00001', 4, 'done', 7200, 60)"
        )
        matcher.match_run(con, home, 'r', ('legacy',))
        # the located pairs of this tiny corpus are the legacy ones
        con.execute(
            "INSERT INTO matches (run_id, matcher, matcher_version, finding_id, row_id, tier, encloses) "
            "SELECT run_id, 'located', ?, finding_id, row_id, 'exact', false FROM matches WHERE matcher = 'legacy'",
            [matcher.MATCHER_VERSIONS['located']],
        )
        yield con


def test_the_june_way_at_each_level(con):
    m = metrics.compute(con, 'r', rows=ROWS)
    counts = {
        level: (v['secrets'], v['secrets_found'], v['lookalikes'], v['lookalikes_found'])
        for level, v in m['june_way'].items()
    }
    assert counts == {'low': (3, 2, 3, 2), 'medium': (3, 2, 3, 1), 'high': (3, 1, 3, 1), 'very-high': (3, 1, 3, 0)}
    assert m['june_way']['medium']['precision'] == pytest.approx(2 / 3)
    assert m['june_way']['low']['all_secrets'] == 4  # the flagged row counts only over all rows
    assert m['findings']['by_level'] == {'low': 5, 'medium': 4, 'high': 3, 'very-high': 2}
    assert (m['findings']['in_labelled_files'], m['findings']['in_unlabelled_files']) == (4, 1)


def test_levels_follow_the_scanners_tiers_not_a_fixed_confidence(con):
    # a scanner whose medium starts at 5 reports confidence 4 as low: the medium cut must leave it out
    con.execute("UPDATE findings SET tier = 'low' WHERE confidence = 4")
    m = metrics.compute(con, 'r', rows=ROWS)
    assert m['june_way']['medium']['secrets_found'] == 1 and m['june_way']['low']['secrets_found'] == 2
    assert m['findings']['by_level']['medium'] == 3 and m['findings']['by_tier']['low'] == 2
    # a rejected candidate is in no named level
    con.execute("UPDATE findings SET tier = 'info' WHERE finding_id = 1")
    m = metrics.compute(con, 'r', rows=ROWS)
    assert m['findings']['by_level']['low'] == 4 and m['findings']['by_tier']['info'] == 1
    con.execute('UPDATE findings SET tier = NULL WHERE finding_id = 1')
    with pytest.raises(metrics.MetricsError):
        metrics.compute(con, 'r', rows=ROWS)


def test_per_repository_and_value_a_copy_counts_once(con):
    m = metrics.compute(con, 'r', rows=ROWS)
    low = m['per_repository_and_value']['low']
    # rows 1 and 2 are one unit, found through row 1; the same value labelled N elsewhere is a unit of its own
    assert (low['secrets'], low['secrets_found'], low['lookalikes'], low['lookalikes_found']) == (2, 2, 3, 2)
    assert low['recall'] == 1.0 and low['precision'] == 0.5
    assert m['per_repository_and_value']['very-high']['secrets_found'] == 1


def test_files_and_operations(con):
    m = metrics.compute(con, 'r', rows=ROWS)
    assert m['files']['status'] == {'ok': 4} and m['files']['to_scan'] == 4
    assert m['files']['depth']['over_tier'] == m['files']['depth']['over_tier_shallow'] == 1
    assert m['files']['depth']['within_tier'] == m['files']['depth']['within_tier_deep'] == 3
    assert m['operations']['cpu_h'] == 2.0 and m['operations']['wall_s'] == 90.0
    assert m['matching'] == {
        'legacy': {'version': 'legacy-1', 'pairs': 4, 'rows': 4},
        'located': {'version': 'located-1', 'pairs': 4, 'rows': 4},
    }


def test_the_located_headline_counts_groups_units_and_rows(con):
    loc = metrics.compute(con, 'r', rows=ROWS)['located']
    low = loc['per_group']['low']
    # groups are rows here: 4 real (rows 1, 2, 3, 6), 3 look-alikes; row 7's finding is a look-alike's only
    assert (low['secrets'], low['secrets_found'], low['lookalikes'], low['lookalikes_found']) == (4, 2, 3, 2)
    unit = loc['per_repository_and_value']['low']
    # rows 1 and 2 are one real unit; row 7 shares row 3's value in repo-b, so its unit is real, not a look-alike
    assert (unit['secrets'], unit['secrets_found'], unit['lookalikes'], unit['lookalikes_found']) == (3, 2, 2, 1)
    assert loc['per_row']['very-high']['secrets_found'] == 1 and loc['reliability']['medium']['real_groups'] == 1
    assert loc['extras']['low'] == {'in_labelled_files': 0, 'in_unlabelled_files': 1}


def test_pairs_from_another_matcher_version_are_refused(con):
    con.execute("UPDATE matches SET matcher_version = 'legacy-0' WHERE matcher = 'legacy'")
    with pytest.raises(metrics.MetricsError):
        metrics.compute(con, 'r', rows=ROWS)
    con.execute('DELETE FROM matches')
    with pytest.raises(metrics.MetricsError):
        metrics.compute(con, 'r', rows=ROWS)


def test_another_corpus_gets_no_june_view(con):
    other = [JuneRow(1, ('999',), 'x', 1, True, None, False, None)]
    m = metrics.compute(con, 'r', rows=other)
    assert m['june_way'] is None and m['june_rows_missing'] == 1
    assert 'Not applicable' in metrics.summary_markdown(m)


def test_the_written_reports_hold_aggregates_only(con, home: BenchHome, monkeypatch):
    monkeypatch.setattr(metrics.june, 'load_rows', lambda **kwargs: ROWS)
    m = metrics.write_metrics(con, home, 'r')
    written = (home.run_dir('r') / 'metrics.json').read_text() + (home.run_dir('r') / 'summary.md').read_text()
    for _, _, _, _, value, _ in LABELS:
        assert value not in written
    assert json.loads((home.run_dir('r') / 'metrics.json').read_text())['june_way'] == m['june_way']
    summary = (home.run_dir('r') / 'summary.md').read_text()
    assert '| low | 66.67% | 50.00% |' in summary and '## The June way per (repository, value)' in summary
    assert '## Per candidate group (`located` matcher)' in summary and '## Reliability of each tier' in summary


SECRETBENCH_CSV = Path(os.environ.get('DSBENCH_DATA', '/nonexistent')) / 'secretbench.csv'
JUNE_TABLE = june.latest_table(Path(os.environ.get('DSBENCH_HOME', '/nonexistent')) / 'legacy')


@pytest.mark.skipif(
    not SECRETBENCH_CSV.is_file() or JUNE_TABLE is None, reason='needs SecretBench and the June table (DSBENCH_*)'
)
def test_the_unit_view_gives_junes_own_published_figure():
    """The per-(repository, value) view keys the raw label value: on June's own rows that gives June's published
    93.10%, which any normalisation of the value lowers. Values are read into memory only."""
    csv.field_size_limit(sys.maxsize)
    with open(SECRETBENCH_CSV, newline='', encoding='utf-8') as f:
        label_of = {int(r['id']): (r['repo_name'], r['secret'][1:-1]) for r in csv.DictReader(f)}
    v = metrics.unit_view(june.load_rows(JUNE_TABLE), label_of, found=lambda row: row.is_ds_found)
    assert round(v['recall'], 4) == 0.9310


def test_without_a_june_table_everything_else_is_still_counted(con, home: BenchHome):
    m = metrics.compute(con, 'r', legacy_dir=home.legacy_dir)
    assert m['june_table'] is False and m['june_way'] is None and m['per_repository_and_value'] is None
    assert m['findings'] and 'no June table in this bench home' in metrics.summary_markdown(m)


def test_a_sample_run_counts_only_the_labels_of_its_files(con):
    params = {'cores': 2, 'segments': [], 'sample': {'n': 1, 'seed': 11, 'files': 1}}
    con.execute("UPDATE runs SET params = ? WHERE run_id = 'r'", [json.dumps(params)])
    con.execute("INSERT INTO shard_files (run_id, shard_id, file_id) VALUES ('r', 's00001', 'f1')")
    m = metrics.compute(con, 'r', rows=ROWS)
    low = m['located']['per_group']['low']
    # f1 holds row 1 (real, found) and rows 4 and 5 (look-alikes, row 4 charged)
    assert (low['secrets'], low['secrets_found'], low['lookalikes'], low['lookalikes_found']) == (1, 1, 2, 1)
    assert m['june_way'] is None and m['scope']['files'] == 1 and m['files']['to_scan'] == 1
    assert 'Not applicable: a sample run' in metrics.summary_markdown(m)


def test_the_summary_says_when_the_scanner_has_no_size_tier_and_when_a_run_was_resumed(con):
    con.execute('UPDATE artifacts SET depth = NULL')
    params = {'cores': 30, 'segments': [{'wall_s': 60.0}] * 3, 'resumed_with': [{'cores': 30}, {'cores': 12}]}
    con.execute("UPDATE runs SET params = ? WHERE run_id = 'r'", [json.dumps(params)])
    summary = metrics.summary_markdown(metrics.compute(con, 'r', rows=ROWS))
    assert 'The scanner reports no depth: it has no size tier.' in summary
    assert 'at `--cores 30` (resumed at 30, 12); wall 3.0 min over 3 segment(s)' in summary
