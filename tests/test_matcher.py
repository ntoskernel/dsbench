import pytest

from dsbench import matcher, store
from dsbench.home import BenchHome


@pytest.mark.parametrize(
    'label, finding, same',
    [
        ('Tq7XbR2mKp9L', 'Tq7XbR2mKp9L', True),
        # the June normalisation deletes space, newline, . \ " ' - / +
        ('Tq7X-bR2m/Kp9L', '"Tq7X bR2m.Kp9L"', True),
        ('ab+cd\\ef\nhi', "abcdefhi'", True),
        # containment either way
        ('Tq7XbR2mKp9L', 'token=Tq7XbR2mKp9L;', True),
        ('prefix-Tq7XbR2mKp9L-suffix', 'Tq7XbR2mKp9L', True),
        # with no minimum length: a finding that normalises to nothing is in every label
        ('Tq7XbR2mKp9L', '.-/', True),
        ('Tq7XbR2mKp9L', 'q', True),
        # otherwise a fuzzy ratio of 90 or more
        ('Tq7XbR2mKp9L', 'Tq7XbR2mKp9Z', True),  # 11 of 12: 91.7
        ('Tq7XbR2mKp9L', 'Tq7XbR2mKpZZ', False),  # 10 of 12: 83.3
        ('Tq7XbR2mKp9L', 'Zx9Qm2Lp8Rt4', False),
        # a tab survives the normalisation: no containment, and 88.9 is under 90
        ('ab\tcd', 'abcd', False),
    ],
)
def test_legacy_same(label, finding, same):
    assert matcher.legacy_same(label, finding) is same


def test_only_findings_on_the_labels_start_line_count():
    labels = [(1, 'f', 10, 'Tq7XbR2mKp9L')]
    assert matcher.match_legacy(labels, [(100, 'f', 11, 'Tq7XbR2mKp9L')]) == []
    assert matcher.match_legacy(labels, [(100, 'g', 10, 'Tq7XbR2mKp9L')]) == []
    assert matcher.match_legacy(labels, [(100, 'f', 10, 'Tq7XbR2mKp9L')]) == [(100, 1)]


def test_one_finding_credits_every_label_it_matches_and_every_pair_is_kept():
    labels = [(1, 'f', 3, 'Tq7XbR2mKp9L'), (2, 'f', 3, 'Tq7XbR2m'), (3, 'f', 3, 'Zx9Qm2Lp8Rt4')]
    findings = [(100, 'f', 3, 'Tq7XbR2mKp9L'), (101, 'f', 3, 'Tq7XbR2mKp9L-copy')]
    assert sorted(matcher.match_legacy(labels, findings)) == [(100, 1), (100, 2), (101, 1), (101, 2)]


def test_match_run_pairs_labels_of_an_alias_with_the_scanned_copy(home: BenchHome):
    with store.connect(home) as con:
        con.execute('''INSERT INTO files (dataset_id, file_id, view_path, scan_file_id) VALUES
               ('d', 'copy-a', 'r/a.py', 'copy-a'), ('d', 'copy-b', NULL, 'copy-a')''')
        con.execute(
            '''INSERT INTO labels (dataset_id, row_id, file_id, start_line, value) VALUES
               ('d', 1, 'copy-a', 2, 'Tq7XbR2mKp9L'), ('d', 2, 'copy-b', 2, 'Tq7XbR2mKp9L'), ('d', 3, 'copy-a', 9, 'x')'''
        )
        con.execute("INSERT INTO runs (run_id, dataset_id, params) VALUES ('r1', 'd', '{}')")
        con.execute('''INSERT INTO findings (run_id, finding_id, file_id, start_line, value, confidence) VALUES
               ('r1', 1, 'copy-a', 2, 'Tq7XbR2mKp9L', 10), ('r1', 2, 'copy-a', 5, 'other', 10)''')
        summary = matcher.match_run(con, home, 'r1', ('legacy',))['legacy']
        assert summary['pairs'] == 2 and summary['rows_matched'] == 2 and summary['findings_matched'] == 1
        assert matcher.match_run(con, home, 'r1', ('legacy',))['legacy']['pairs'] == 2  # again, replacing them
        rows = con.execute(
            'SELECT matcher, matcher_version, finding_id, row_id FROM matches ORDER BY row_id'
        ).fetchall()
    assert rows == [('legacy', 'legacy-1', 1, 1), ('legacy', 'legacy-1', 1, 2)]


def test_an_unknown_matcher_is_refused(home: BenchHome):
    with store.connect(home) as con, pytest.raises(matcher.MatcherError):
        matcher.match_run(con, home, 'r1', matchers='balanced')
