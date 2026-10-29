"""`compare` and the dark-matter overlay on synthetic runs."""

import json

import pytest

from dsbench import compare, darkmatter, store
from dsbench.home import BenchHome
from dsbench.matcher import MATCHER_VERSIONS

# (row_id, repo, file, value, label); one group per row
LABELS = [
    (1, 'repo-a', 'f1', 'Tq7XbR2mKp9L', True),
    (2, 'repo-a', 'f1', 'Zx9Qm2Lp8Rt4', True),
    (3, 'repo-a', 'f1', 'hello', False),
    (4, 'repo-b', 'f2', 'Mk3Vb8Qw1Zr5', True),
    (5, 'repo-b', 'f2', 'world', False),
]
# run -> (finding_id, file, value, tier, row paired or None)
FINDINGS = {
    'a': [
        (1, 'f1', 'Tq7XbR2mKp9L', 'very-high', 1),
        (2, 'f1', 'hello', 'low', 3),
        (3, 'f9', 'Wq2Er4Ty6Ui8', 'high', None),
    ],
    'b': [
        (1, 'f1', 'Tq7XbR2mKp9L', 'very-high', 1),
        (2, 'f1', 'Zx9Qm2Lp8Rt4', 'medium', 2),
        (3, 'f2', 'Mk3Vb8Qw1Zr5', 'high', 4),
        (4, 'f2', 'world', 'high', 5),
        (5, 'f9', 'Wq2Er4Ty6Ui8', 'high', None),
        (6, 'f9', 'placeholder-1', 'low', None),
    ],
}


@pytest.fixture
def con(home: BenchHome):
    with store.connect(home) as con:
        con.execute("INSERT INTO datasets (dataset_id, stats, created_at) VALUES ('d', '{}', now())")
        for file_id, repo in (('f1', 'repo-a'), ('f2', 'repo-b'), ('f9', None)):
            con.execute(
                'INSERT INTO files (dataset_id, file_id, repo, view_path, labelled, scan_file_id) VALUES (?, ?, ?, ?, ?, ?)',
                ['d', file_id, repo, f'v/{file_id}', repo is not None, file_id],
            )
        for row_id, repo, file_id, value, label in LABELS:
            con.execute(
                '''INSERT INTO labels (dataset_id, row_id, repo, file_id, start_line, value, label, group_id, fragment)
                   VALUES ('d', ?, ?, ?, 1, ?, ?, ?, false)''',
                [row_id, repo, file_id, value, label, row_id],
            )
        for run_id, findings in FINDINGS.items():
            params = {'label': f'build {run_id}', 'segments': []}
            con.execute(
                "INSERT INTO runs (run_id, dataset_id, tool_version, profile, params, status) VALUES (?, 'd', '9.9', 'all-files', ?, 'done')",
                [run_id, json.dumps(params)],
            )
            for fid, file_id, value, tier, row in findings:
                con.execute(
                    'INSERT INTO findings (run_id, finding_id, file_id, start_line, value, tier) VALUES (?, ?, ?, 1, ?, ?)',
                    [run_id, fid, file_id, value, tier],
                )
                if row is not None:
                    con.execute(
                        '''INSERT INTO matches (run_id, matcher, matcher_version, finding_id, row_id, encloses)
                           VALUES (?, 'located', ?, ?, ?, false)''',
                        [run_id, MATCHER_VERSIONS['located'], fid, row],
                    )
        yield con


def test_runs_are_counted_at_every_level_with_bootstrapped_differences(con, home: BenchHome):
    c = compare.compare(con, home, ['a', 'b'], name='t', samples=200)
    a, b = c['runs']
    assert (a['per_group']['low']['secrets_found'], a['per_group']['low']['lookalikes_found']) == (1, 1)
    assert (b['per_group']['low']['secrets_found'], b['per_group']['low']['lookalikes_found']) == (3, 1)
    assert b['per_group']['high']['secrets_found'] == 2 and b['per_group']['very-high']['secrets_found'] == 1
    assert b['difference_from_first']['per_group']['recall'] == pytest.approx(100 * (3 / 3 - 1 / 3), abs=0.01)
    low, high = b['difference_interval_95']['per_group']['recall']
    assert low <= high and c['dark_matter'] is None
    written = (home.root / 'comparisons').glob('*-t/compare.md')
    text = next(written).read_text()
    assert 'No dark-matter overlay' in text and 'Tq7XbR2mKp9L' not in text


def test_the_overlay_adds_judged_units_beyond_the_labels(con, home: BenchHome):
    key = darkmatter.unit_key(None, 'f9', 'Wq2Er4Ty6Ui8')
    noise = darkmatter.unit_key(None, 'f9', 'placeholder-1')
    darkmatter.write_overlay(
        home,
        [
            {'repo': key[0], 'value_sha256': key[1], 'verdict': 'live', 'source': 'test'},
            {'repo': noise[0], 'value_sha256': noise[1], 'verdict': 'placeholder', 'source': 'test'},
        ],
    )
    assert 'Wq2Er4Ty6Ui8' not in darkmatter.overlay_path(home).read_text()
    c = compare.compare(con, home, ['a', 'b'], name='dm', samples=50)
    a, b = c['runs']
    assert c['dark_matter'] == {'overlay_units': 2, 'pooled_secret_units': 1}
    # the live unit both runs report joins every recall's denominator: 3 labelled + 1 beyond
    dm = b['with_dark_matter']['low']
    assert (dm['secrets_found'], dm['lookalikes_found'], dm['beyond_noise']) == (4, 2, 1)
    assert dm['recall'] == 1.0 and a['with_dark_matter']['low']['recall'] == pytest.approx(2 / 4)
    assert b['reliability_beyond_labels']['high'] == {'secret': 1, 'noise': 0, 'secret_share': 1.0}
    assert (
        '## Per (repository, value) with the judged dark matter'
        in (home.root / 'comparisons')
        .joinpath(next(p.name for p in (home.root / 'comparisons').iterdir() if p.name.endswith('-dm')), 'compare.md')
        .read_text()
    )


def test_runs_of_different_scopes_or_one_run_are_refused(con, home: BenchHome):
    with pytest.raises(compare.CompareError):
        compare.compare(con, home, ['a'])
    con.execute("""UPDATE runs SET params = '{"sample": {"n": 1}}' WHERE run_id = 'b'""")
    con.execute("INSERT INTO shard_files (run_id, shard_id, file_id) VALUES ('b', 's1', 'f1')")
    with pytest.raises(compare.CompareError, match='different files'):
        compare.compare(con, home, ['a', 'b'])


def test_an_overlay_with_an_unknown_verdict_is_refused(home: BenchHome):
    darkmatter.overlay_path(home).write_text('repo,value_sha256,verdict,source,judged_at\nr,x,maybe,,\n')
    with pytest.raises(darkmatter.DarkMatterError):
        darkmatter.load_overlay(home)
