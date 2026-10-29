import csv
import gzip
import json
from pathlib import Path

import duckdb

from dsbench.home import BenchHome
from dsbench.legacy import june, pgcopy, preserve

CSV_FIELDS = ['id', 'secret', 'file_identifier', 'start_line', 'label']

# synthetic stand-ins for the dump's tables; no value here is a real secret
# fmt: off
SECRETS = [
    {'id': '1', 'content': 'Tq7XbR2mKp9L', 'file': 'a.py', 'line_number': '3', 'is_extra': 'f', 'is_valid': 't',
     'problem': None, 'is_ds_found': 't', 'ds_case_type': None, 'extra': None},
    {'id': '2', 'content': 'example', 'file': 'a.py', 'line_number': '9', 'is_extra': 'f', 'is_valid': 'f',
     'problem': None, 'is_ds_found': 't', 'ds_case_type': 'placeholder', 'extra': None},
    {'id': '3', 'content': 'Zx9Qm2Lp8Rt4', 'file': 'b.py', 'line_number': '1', 'is_extra': 'f', 'is_valid': 't',
     'problem': 'not_a_secret', 'is_ds_found': 'f', 'ds_case_type': None, 'extra': None},
    {'id': '4', 'content': 'found-elsewhere', 'file': 'b.py', 'line_number': '7', 'is_extra': 't', 'is_valid': None,
     'problem': None, 'is_ds_found': 't', 'ds_case_type': None, 'extra': '{"conf": 7}'},
]
# fmt: on
CSV_ROWS = [
    ['10', '"Tq7XbR2mKp9L"', 'a.py', '3', 'Y'],
    ['11', '"Tq7XbR2mKp9L"', 'a.py', '3', 'Y'],  # a repeat June's unique index merged
    ['12', "'example'", 'a.py', '9', 'N'],
    ['13', '`Zx9Qm2Lp8Rt4`', 'b.py', '1', 'Y'],
    ['14', '"never-evaluated"', 'c.py', '2', 'N'],  # in a file June skipped
]
# fmt: off
COLUMNS = {
    'Secrets': [('id', 'integer'), ('content', 'character varying'), ('file', 'character varying'),
                ('line_number', 'integer'), ('is_extra', 'boolean'), ('is_valid', 'boolean'),
                ('problem', 'character varying'), ('is_ds_found', 'boolean'), ('ds_case_type', 'character varying'),
                ('extra', 'jsonb')],
    'FileReports': [('file', 'character varying'), ('processing_time', 'integer')],
    'secretbench': [('id', 'character varying(100)'), ('entropy', 'real')],
}
# fmt: on
TABLES = {
    'Secrets': SECRETS,
    'FileReports': [{'file': 'a.py', 'processing_time': '12'}, {'file': 'b.py', 'processing_time': None}],
    'secretbench': [{'id': '10', 'entropy': '3.5'}],
}


def write_csv(path: Path) -> Path:
    with open(path, 'w', newline='', encoding='utf-8') as f:
        out = csv.writer(f)
        out.writerow(CSV_FIELDS)
        out.writerows(CSV_ROWS)
    return path


def test_rows_map_to_csv_ids_by_file_line_and_value(tmp_path: Path):
    rows, report = preserve.map_rows(SECRETS, write_csv(tmp_path / 'sb.csv'))
    assert [(r.june_id, r.csv_ids) for r in rows] == [(1, ('10', '11')), (2, ('12',)), (3, ('13',))]
    assert report['extra_rows'] == 1 and report['unmapped_june_rows'] == 0 and report['label_disagreements'] == 0
    assert report['june_rows_for_several_csv_rows'] == 1
    assert report['csv_rows_absent'] == {'total': 1, 'by_label': {'N': 1}, 'files_by_label': {'Y': 0, 'N': 1}}


def test_preserve_writes_typed_parquet_the_values_free_table_and_the_baseline(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(pgcopy, 'table_columns', lambda pg_restore, dump: COLUMNS)
    monkeypatch.setattr(pgcopy, 'copy_rows', lambda pg_restore, dump, table: iter(TABLES[table]))
    dump = tmp_path / 'june.sql'
    dump.write_bytes(b'PGDMP')
    home = BenchHome(tmp_path / 'home').ensure()
    result = preserve.preserve(home, dump, write_csv(tmp_path / 'sb.csv'), 'pg_restore')

    out = Path(result['legacy_dir'])
    assert result['tables'] == {'FileReports': 2, 'Secrets': 4, 'secretbench': 1}
    with duckdb.connect() as con:
        secrets = con.execute(f"SELECT id, is_valid, extra FROM '{out / 'Secrets.parquet'}' ORDER BY id").fetchall()
        types = {name: kind for name, kind, *_ in con.execute(f"DESCRIBE '{out / 'Secrets.parquet'}'").fetchall()}
    assert secrets[0][:2] == (1, True) and json.loads(secrets[3][2]) == {'conf': 7}
    assert types['line_number'] == 'INTEGER' and types['is_extra'] == 'BOOLEAN'

    assert june.load_rows(legacy_dir=home.legacy_dir) == june.load_rows(out / june.TABLE)
    assert b'Tq7XbR2mKp9L' not in gzip.decompress((out / june.TABLE).read_bytes())  # ids, never values
    baseline = json.loads((out / 'legacy_baseline.json').read_text())
    assert baseline['june_view']['secrets'] == 1 and baseline['june_view']['recall'] == 1.0
    assert baseline['problems'] == {'not_a_secret': 1} and baseline['case_types'] == {'rows': 1, 'kinds': 1}
    assert (home.overlays_dir / 'sb_corrections.csv').read_text().splitlines()[1] == '3,13,b.py,1,not_a_secret'
    assert not list(home.tmp_dir.iterdir())
