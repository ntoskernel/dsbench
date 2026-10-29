import json
from pathlib import Path

import pytest

from dsbench import dataset, store
from dsbench.home import BenchHome
from helpers import csv_row, write_corpus

# a value longer than the csv module's default field limit (131,072 characters)
LONG = 'Q' * 140_000


def corpus(tmp_path: Path) -> Path:
    files = {
        'acme-app_c0ffee_src__config.py': 'token = "Tq7XbR2mKp9L"\nname = "hello"\n',
        'acme-app_c0ffee_tests__big.txt': LONG + '\n',
        'loose.txt': 'nothing\n',
        '.hidden': 'nothing\n',
    }
    rows = [
        csv_row(1, 'Tq7XbR2mKp9L', 'acme-app_c0ffee_src__config.py', 1, 'Y'),
        csv_row(2, 'hello', 'acme-app_c0ffee_src__config.py', 2, 'N', secret='"hello"'),
        csv_row(3, 'hello', 'acme-app_c0ffee_src__config.py', 2, 'N'),  # repeats row 2
        csv_row(4, LONG, 'acme-app_c0ffee_tests__big.txt', 1, 'Y'),
        csv_row(5, '--..--', 'acme-app_c0ffee_tests__big.txt', 1, 'N'),  # nothing left once normalised
        csv_row(6, 'gone', 'acme-app_c0ffee_lost.py', 1, 'N'),  # its file is not in the corpus
    ]
    return write_corpus(tmp_path / 'data', files, rows)


def prepared(home: BenchHome, data: Path, **kw):
    with store.connect(home) as con:
        dataset_id, stats = dataset.prepare(con, home, data / 'secretbench.csv', data / 'Files', **kw)
        files = {f['file_id']: f for f in store.fetch_dicts(con, 'SELECT * FROM files')}
        labels = {r['row_id']: r for r in store.fetch_dicts(con, 'SELECT * FROM labels')}
    return dataset_id, stats, files, labels


def test_prepare_loads_rows_as_given_with_views_and_issues(tmp_path: Path, home: BenchHome):
    dataset_id, stats, files, labels = prepared(home, corpus(tmp_path))
    assert dataset_id.startswith('secretbench-') and len(dataset_id) == len('secretbench-') + 12
    assert (stats['rows'], stats['rows_y'], stats['rows_n']) == (6, 2, 4)
    assert (stats['files'], stats['files_labelled'], stats['files_unlabelled']) == (4, 2, 2)
    assert stats['bytes'] == sum(p.stat().st_size for p in (tmp_path / 'data' / 'Files').iterdir())
    assert stats['labelled_files_missing'] == 1
    assert stats['issues'] == {'duplicate_row': 1, 'empty_value': 1, 'file_missing': 1, 'value_not_bracketed': 1}

    hashed = dataset.repo_dir('acme-app', 'c0ffee')
    assert files['acme-app_c0ffee_src__config.py']['view_path'] == f'{hashed}/src/config.py'
    assert files['loose.txt']['view_path'] == 'unlabelled/loose.txt'
    assert files['.hidden']['view_path'] == 'unlabelled/.hidden' and not files['.hidden']['labelled']
    assert labels[4]['value'] == LONG
    assert labels[2]['value'] == 'hello' and labels[2]['bracketed'] is False
    assert labels[3]['issues'] == 'duplicate_row' and labels[2]['issues'] == 'value_not_bracketed'
    assert labels[1]['repo'] == 'acme-app' and labels[1]['label'] is True and labels[1]['issues'] is None
    assert not list(home.tmp_dir.iterdir())


def test_the_same_data_is_one_dataset_until_forced(tmp_path: Path, home: BenchHome):
    data = corpus(tmp_path)
    first, _, _, _ = prepared(home, data)
    again, stats, _, _ = prepared(home, data)
    assert again == first and stats['already_prepared']
    rebuilt, stats, _, labels = prepared(home, data, force=True)
    assert rebuilt == first and 'already_prepared' not in stats and len(labels) == 6


def test_unwrap_takes_one_character_from_each_side():
    assert dataset.unwrap('[abc]') == ('abc', True)
    assert dataset.unwrap('"abc"') == ('abc', False)
    assert dataset.unwrap('[a]b]') == ('a]b', True)


def test_aliases_and_colliding_views():
    sizes = {'id_a': 10, 'id_b': 10, 'id_c': 11, 'id_d': 5, 'id_e': 5}
    rows = [
        {'file_id': 'id_a', 'repo': 'r', '_commit': 'c', '_path': 'x/app.py'},
        {'file_id': 'id_b', 'repo': 'r', '_commit': 'c', '_path': 'x/app.py'},  # the same file stored twice
        {'file_id': 'id_c', 'repo': 'r', '_commit': 'c', '_path': 'x/app.py'},  # a different file at that path
        {'file_id': 'id_d', 'repo': 'r', '_commit': 'c', '_path': 'lib'},  # a file where another one's directory is
        {'file_id': 'id_e', 'repo': 'r', '_commit': 'c', '_path': 'lib/inner.py'},
    ]
    files, counts = dataset.assign_views(sizes, rows)
    top = dataset.repo_dir('r', 'c')
    assert files['id_a']['view_path'] == f'{top}/x/app.py' and files['id_a']['scan_file_id'] == 'id_a'
    assert files['id_b']['view_path'] is None and files['id_b']['scan_file_id'] == 'id_a'
    assert files['id_c']['view_path'] == f'{top}~2/x/app.py'
    assert files['id_d']['view_path'] == f'{top}~2/lib' and files['id_e']['view_path'] == f'{top}/lib/inner.py'
    assert counts == {'aliases': 1, 'views_suffixed': 2}


def test_a_csv_without_the_needed_columns_is_refused(tmp_path: Path):
    path = tmp_path / 'bad.csv'
    path.write_text('id,secret\n1,[x]\n')
    with pytest.raises(dataset.DatasetError):
        dataset.read_rows(path)


def test_repeated_row_ids_are_refused(tmp_path: Path, home: BenchHome):
    rows = [csv_row(1, 'aa', 'acme-app_c0_a.py', 1, 'Y'), csv_row(1, 'bb', 'acme-app_c0_a.py', 2, 'N')]
    data = write_corpus(tmp_path / 'data', {'acme-app_c0_a.py': 'x\n'}, rows)
    with store.connect(home) as con, pytest.raises(dataset.DatasetError):
        dataset.prepare(con, home, data / 'secretbench.csv', data / 'Files')
    with store.connect(home) as con:
        assert con.execute('SELECT count(*) FROM datasets').fetchone()[0] == 0


def test_stats_are_stored_as_json(tmp_path: Path, home: BenchHome):
    dataset_id, stats, _, _ = prepared(home, corpus(tmp_path))
    with store.connect(home) as con:
        stored = json.loads(con.execute('SELECT stats FROM datasets').fetchone()[0])
    assert stored == stats
