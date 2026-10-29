"""The `located` matcher's locating and pairing, on synthetic text."""

from pathlib import Path

import pytest

from dsbench import dataset, located, matcher, store
from dsbench.home import BenchHome
from helpers import csv_row, write_corpus

KEY = (
    '-----BEGIN RSA PRIVATE KEY-----\nTq7XbR2mKp9LZx9Qm2Lp8Rt4\nMk3Vb8Qw1Zr5Tq7XbR2mKp9L\n-----END RSA PRIVATE KEY-----'
)
TEXT = (
    'token = "Tq7XbR2mKp9L"\n'  # 1
    'other = "Zx9Qm2Lp8Rt4"  # and Tq7XbR2mKp9L again\n'  # 2
    'key = """\n' + KEY.replace('\n', '\n    ') + '\n"""\n'  # 3  # 4-7, indented  # 8
    'pem = "-----BEGIN RSA PRIVATE KEY-----\\nMk3Vb8Qw1Zr5\\n-----END RSA PRIVATE KEY-----"\n'  # 9
    'far = "Wq2Er4Ty6Ui8"\n'  # 10
)


@pytest.fixture
def text() -> located.Text:
    return located.Text(TEXT)


def label(t, value, line, col, end_line=None, end_col=None):
    return located.locate_label(t, value, line, end_line or line, col, end_col or col + len(value))


def test_a_label_is_located_exactly_or_moved_on_its_lines(text):
    s = label(text, 'Tq7XbR2mKp9L', 1, 10)
    assert (s.kind, TEXT[s.start : s.end]) == ('exact', 'Tq7XbR2mKp9L')
    s = label(text, 'Tq7XbR2mKp9L', 2, 1)  # on its line, at another column
    assert s.kind == 'moved' and text.line_of(s.start) == 2
    s = label(text, '"Zx9Qm2Lp8Rt4"\n', 2, 1)  # with its quotes and a trailing newline the file does not have there
    assert s.kind == 'moved' and TEXT[s.start : s.end] == '"Zx9Qm2Lp8Rt4"'


def test_a_reindented_key_is_located_with_whitespace_ignored(text):
    s = label(text, KEY, 4, 5, end_line=7, end_col=34)
    assert s.kind == 'reformed' and TEXT[s.start : s.end].startswith('-----BEGIN') and text.line_of(s.end) == 7


def test_a_value_on_other_lines_is_found_nearest_its_label(text):
    s = label(text, 'Wq2Er4Ty6Ui8', 3, 8)
    assert (s.kind, s.line_delta, text.line_of(s.start)) == ('elsewhere', 7, 10)


def test_a_value_not_in_the_file_falls_back_to_its_span_unless_it_is_a_transcription(text):
    s = label(text, 'Qq1Ww2Ee3Rr4', 10, 8)
    assert (s.kind, s.start, s.end) == ('span', text.offset(10, 8), text.offset(10, 20))
    assert label(text, '"Qq1Ww2Ee3Rr4"', 10, 7).kind == 'none'  # opens with a quote
    assert label(text, 'BEGIN\\nQq1Ww2Ee3Rr4', 9, 8).kind == 'none'  # an escaped newline
    assert label(text, 'Qq1Ww2Ee3Rr4', 99, 1).kind == 'none'  # its span is not in the file
    assert label(text, '', 1, 1).kind == 'none'


def test_a_finding_is_located_at_its_region_or_its_snippet_on_those_lines(text):
    assert located.locate_finding(text, 1, 1, 10, 22, 'Tq7XbR2mKp9L') == (9, 21)
    assert located.locate_finding(text, 2, 2, 1, 13, 'Zx9Qm2Lp8Rt4') == (32, 44)  # the region is off, the snippet not
    assert located.locate_finding(text, 1, 1, 1, 1, '') is None
    assert located.locate_finding(text, None, None, None, None, 'x') is None


def test_overlap_and_enclosure():
    assert located.overlap((0, 5), (4, 9)) and not located.overlap((0, 5), (5, 9))
    assert located.encloses((0, 10), (2, 5)) and not located.encloses((2, 5), (2, 5))
    assert not located.encloses((3, 10), (2, 5))


def test_value_forms():
    forms = located.value_forms('"a\\nb"\n')
    assert forms == ['"a\\nb"\n', '"a\\nb"', 'a\\nb', '"a\nb"\n', '"a\nb"', 'a\nb']


def test_match_run_locates_labels_once_and_pairs_overlapping_findings(tmp_path: Path, home: BenchHome):
    files = {'acme-app_c0_src__a.py': TEXT}
    rows = [
        csv_row(1, 'Tq7XbR2mKp9L', 'acme-app_c0_src__a.py', 1, 'Y', start_column=10, end_column=22),
        csv_row(
            2, 'Tq7X', 'acme-app_c0_src__a.py', 1, 'N', start_column=10, end_column=14, comment='Part of Slack Token'
        ),
        csv_row(3, 'Zx9Qm2Lp8Rt4', 'acme-app_c0_src__a.py', 2, 'N', start_column=10, end_column=22),
        csv_row(4, KEY, 'acme-app_c0_src__a.py', 4, 'Y', end_line=7, start_column=5, end_column=34),
    ]
    data = write_corpus(tmp_path / 'data', files, rows)
    with store.connect(home) as con:
        dataset_id, _ = dataset.prepare(con, home, data / 'secretbench.csv', data / 'Files')
        con.execute("INSERT INTO runs (run_id, dataset_id, params) VALUES ('r', ?, '{}')", [dataset_id])
        findings = [
            (1, 1, 1, 10, 22, 'Tq7XbR2mKp9L'),  # the token: rows 1 and 2
            (2, 2, 2, 10, 14, 'Zx9Q'),  # part of row 3
            (3, 5, 5, 5, 29, 'Tq7XbR2mKp9LZx9Qm2Lp8Rt4'),  # inside the key
            (4, 10, 10, 1, 4, 'far'),  # nothing labelled
        ]
        for fid, sl, el, sc, ec, value in findings:
            con.execute(
                '''INSERT INTO findings (run_id, finding_id, file_id, start_line, end_line, start_col, end_col, value)
                   VALUES ('r', ?, 'acme-app_c0_src__a.py', ?, ?, ?, ?, ?)''',
                [fid, sl, el, sc, ec, value],
            )
        summary = matcher.match_run(con, home, 'r', ('located',), processes=1)['located']
        assert summary['label_kinds'] == {'exact': 3, 'reformed': 1} and summary['pairs'] == 4
        pairs = con.execute(
            "SELECT finding_id, row_id, tier, encloses, matcher_version FROM matches WHERE matcher = 'located' ORDER BY 1, 2"
        ).fetchall()
        assert pairs == [
            (1, 1, 'exact', False, 'located-1'),
            (1, 2, 'exact', True, 'located-1'),
            (2, 3, 'exact', False, 'located-1'),
            (3, 4, 'reformed', False, 'located-1'),
        ]
        # the second time the labels come from the store, and only files with findings are read
        assert matcher.match_run(con, home, 'r', 'located', processes=2)['located']['pairs'] == 4
        assert con.execute('SELECT count(*) FROM label_spans').fetchone()[0] == 4
