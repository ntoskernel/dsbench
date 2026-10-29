import json
from datetime import datetime

import pytest

from dsbench import store
from dsbench.home import BenchHome


def test_connect_creates_every_table_and_is_idempotent(home: BenchHome):
    with store.connect(home) as con:
        tables = {t for (t,) in con.execute('SHOW TABLES').fetchall()}
    with store.connect(home) as con:
        assert {t for (t,) in con.execute('SHOW TABLES').fetchall()} == tables
    assert tables == {
        'datasets',
        'files',
        'labels',
        'runs',
        'shards',
        'shard_files',
        'artifacts',
        'findings',
        'matches',
        'errors',
    }
    with store.connect(home) as con:
        assert 'matcher_version' in store.table_columns(con, 'matches')
        assert 'depth' in store.table_columns(con, 'artifacts')


def test_a_read_only_store_must_exist(tmp_path):
    with pytest.raises(store.StoreError):
        store.connect(BenchHome(tmp_path / 'empty'), read_only=True)


def test_bulk_insert_round_trips_types_and_leaves_nothing_staged(home: BenchHome):
    rows = [
        {'run_id': 'r', 'finding_id': 1, 'file_id': 'a', 'confidence': 7, 'value': 'multi\nline "quoted" é'},
        {'run_id': 'r', 'finding_id': 2, 'file_id': 'b', 'start_line': 3},
    ]
    with store.connect(home) as con:
        assert store.bulk_insert(con, 'findings', rows, home.tmp_dir) == 2
        assert store.bulk_insert(con, 'findings', [], home.tmp_dir) == 0
        got = store.fetch_dicts(con, 'SELECT finding_id, confidence, value, start_line FROM findings ORDER BY 1')
    assert got == [
        {'finding_id': 1, 'confidence': 7, 'value': 'multi\nline "quoted" é', 'start_line': None},
        {'finding_id': 2, 'confidence': None, 'value': None, 'start_line': 3},
    ]
    assert not list(home.tmp_dir.iterdir())


def test_latest_dataset_and_runs_with_their_json(home: BenchHome):
    with store.connect(home) as con:
        with pytest.raises(store.StoreError):
            store.resolve_dataset(con, 'latest')
        for dataset_id, created in (('old', datetime(2026, 1, 1)), ('new', datetime(2026, 2, 1))):
            con.execute('INSERT INTO datasets (dataset_id, created_at) VALUES (?, ?)', [dataset_id, created])
        assert store.resolve_dataset(con, None) == 'new'
        assert store.resolve_dataset(con, 'old') == 'old'
        with pytest.raises(store.StoreError):
            store.resolve_dataset(con, 'gone')
        con.execute("INSERT INTO runs (run_id, params) VALUES ('r', ?)", [json.dumps({'label': 'nightly'})])
        assert store.get_run(con, 'r')['params'] == {'label': 'nightly'}
        with pytest.raises(store.StoreError):
            store.get_run(con, 'nope')
