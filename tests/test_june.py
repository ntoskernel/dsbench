import os
from pathlib import Path

import pytest

from dsbench.legacy import june


def row(june_id, valid, found, problem=None, case_type=None, csv_ids=None):
    return june.JuneRow(june_id, csv_ids or (str(june_id),), f'f{june_id}', 1, valid, problem, found, case_type)


def test_the_view_counts_clean_rows_and_charges_found_lookalikes():
    rows = [
        row(1, True, True),
        row(2, True, False),
        row(3, True, True, problem='not_a_secret'),  # out of the clean counts, still in the all-rows recall
        row(4, False, True),
        row(5, False, False),
        row(6, False, False),
    ]
    v = june.view(rows)
    assert (v['secrets'], v['secrets_found'], v['lookalikes'], v['lookalikes_found']) == (2, 1, 3, 1)
    assert v['recall'] == 0.5 and v['precision'] == 0.5 and v['fpr'] == pytest.approx(1 / 3)
    assert v['all_secrets'] == 3 and v['recall_all_rows'] == pytest.approx(2 / 3)
    assert v['f1'] == 0.5


def test_another_evaluation_is_counted_on_the_same_rows():
    rows = [row(1, True, False), row(2, False, True)]
    v = june.view(rows, found=lambda r: r.is_valid)
    assert v['recall'] == 1.0 and v['precision'] == 1.0 and v['fpr'] == 0.0


def test_the_table_is_read_from_the_latest_export_in_the_bench_home(tmp_path: Path):
    legacy = tmp_path / 'legacy'
    for stamp, rows in (('20261028-110354', [row(1, True, True)]), ('20261029-090000', [row(2, False, False)])):
        (legacy / stamp).mkdir(parents=True)
        june.write_rows(rows, legacy / stamp / june.TABLE)
    assert [r.june_id for r in june.load_rows(legacy_dir=legacy)] == [2]
    with pytest.raises(FileNotFoundError):
        june.load_rows(legacy_dir=tmp_path / 'empty')


def test_the_table_round_trips(tmp_path: Path):
    rows = [row(2, False, False, case_type='k'), row(1, True, True, problem='p', csv_ids=('1', '9'))]
    assert june.write_rows(rows, tmp_path / 't.csv.gz') == 2
    assert june.load_rows(tmp_path / 't.csv.gz') == sorted(rows, key=lambda r: r.june_id)


HOME_TABLE = june.latest_table(Path(os.environ.get('DSBENCH_HOME', '/nonexistent')) / 'legacy')


@pytest.mark.skipif(HOME_TABLE is None, reason="needs the bench home's June table (DSBENCH_HOME, `dsbench preserve`)")
def test_the_bench_homes_table_gives_junes_published_figures():
    """June 2026's own published figures, recomputed from the values-free table alone."""
    rows = june.load_rows(HOME_TABLE)
    v = june.view(rows)
    assert len(rows) == 97_345
    assert (v['secrets'], v['lookalikes']) == (14_847, 82_265)
    assert (v['secrets_found'], v['lookalikes_found']) == (13_864, 6_936)
    assert (round(v['recall'], 4), round(v['fpr'], 4), round(v['precision'], 4)) == (0.9338, 0.0843, 0.6665)
    assert (v['all_secrets'], round(v['recall_all_rows'], 4)) == (15_080, 0.9194)
    assert sum(r.problem is not None for r in rows) == 233
    assert sum(r.case_type is not None for r in rows) == 348
    assert len({r.case_type for r in rows} - {None}) == 16
    # June's unique index merged six CSV rows that repeat another's value on the same line
    assert sum(len(r.csv_ids) for r in rows) == 97_345 + 6
