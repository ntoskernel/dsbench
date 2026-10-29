"""`preserve --from-dump`: the June 2026 evaluation, exported once from its Postgres dump.

Into the bench home, under `legacy/<timestamp>/`: every table as Parquet (with values: the bench home is private),
`june_rows.csv.gz` and `legacy_baseline.json`; into `overlays/`, as ids, the two hand-made overlays of DeepSecrets'
maintainers: `sb_corrections.csv` (the 233 rows flagged with a problem) and `case_types_seed.csv` (the 348 case labels).
"""

import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import duckdb

from dsbench.home import BenchHome
from dsbench.legacy import june, pgcopy

TABLES = ('FileReports', 'Secrets', 'secretbench')
DUCK_TYPES = {
    'integer': 'INTEGER',
    'bigint': 'BIGINT',
    'smallint': 'SMALLINT',
    'boolean': 'BOOLEAN',
    'real': 'FLOAT',
    'double precision': 'DOUBLE',
    'json': 'JSON',
    'jsonb': 'JSON',
    'timestamp without time zone': 'TIMESTAMP',
}


def duck_type(pg_type: str) -> str:
    return DUCK_TYPES.get(pg_type.split('(')[0].strip(), 'VARCHAR')


def convert(value: Optional[str], duck: str):
    if value is None:
        return None
    if duck == 'BOOLEAN':
        return value == 't'
    if duck in ('INTEGER', 'BIGINT', 'SMALLINT'):
        return int(value)
    if duck in ('FLOAT', 'DOUBLE'):
        return float(value)
    if duck == 'JSON':
        return json.loads(value)
    return value


def export_table(
    pg_restore: str, dump: str, table: str, columns: List[Tuple[str, str]], parquet: Path, tmp_dir: Path, keep: bool
) -> Tuple[int, List[Dict[str, Optional[str]]]]:
    """Writes one table as Parquet; returns its row count and, when `keep`, its decoded text rows."""
    types = {name: duck_type(pg_type) for name, pg_type in columns}
    staged = tmp_dir / f'{table}.ndjson'
    kept: List[Dict[str, Optional[str]]] = []
    count = 0
    with open(staged, 'w', encoding='utf-8') as out:
        for row in pgcopy.copy_rows(pg_restore, dump, table):
            out.write(json.dumps({k: convert(v, types.get(k, 'VARCHAR')) for k, v in row.items()}) + '\n')
            count += 1
            if keep:
                kept.append(row)
    spec = '{' + ', '.join(f"'{name}': '{duck}'" for name, duck in types.items()) + '}'
    with duckdb.connect() as con:
        con.execute(
            f"COPY (SELECT * FROM read_json(?, format = 'newline_delimited', columns = {spec})) "
            f"TO '{parquet}' (FORMAT parquet)",
            [str(staged)],
        )
    staged.unlink()
    return count, kept


def unwrap(secret: str) -> str:
    """A CSV label's text: SecretBench wraps every value in one character on each side."""
    return secret[1:-1]


def map_rows(secrets: List[Dict[str, Optional[str]]], csv_path: Path) -> Tuple[List[june.JuneRow], Dict]:
    """June's labelled rows, each with the CSV rows it stands for, matched on file, line and value."""
    csv.field_size_limit(sys.maxsize)
    by_key: Dict[Tuple[str, int, str], List[str]] = defaultdict(list)
    csv_label: Dict[str, str] = {}
    csv_file: Dict[str, str] = {}
    with open(csv_path, newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            by_key[(r['file_identifier'], int(r['start_line']), unwrap(r['secret']))].append(r['id'])
            csv_label[r['id']] = r['label']
            csv_file[r['id']] = r['file_identifier']

    rows: List[june.JuneRow] = []
    unmapped = disagreeing = extras = 0
    for s in secrets:
        if s['is_extra'] == 't':
            extras += 1
            continue
        ids = tuple(by_key.get((s['file'], int(s['line_number']), s['content'] or ''), ()))
        unmapped += not ids
        is_valid = s['is_valid'] == 't'
        disagreeing += any((csv_label[i] == 'Y') != is_valid for i in ids)
        rows.append(
            june.JuneRow(
                june_id=int(s['id']),
                csv_ids=ids,
                file=s['file'],
                line=int(s['line_number']),
                is_valid=is_valid,
                problem=s['problem'] or None,
                is_ds_found=s['is_ds_found'] == 't',
                case_type=s['ds_case_type'] or None,
            )
        )

    covered = {i for row in rows for i in row.csv_ids}
    absent = [i for i in csv_label if i not in covered]
    report = {
        'labelled_rows': len(rows),
        'extra_rows': extras,
        'unmapped_june_rows': unmapped,
        'label_disagreements': disagreeing,
        'june_rows_for_several_csv_rows': sum(len(r.csv_ids) > 1 for r in rows),
        'csv_rows': len(csv_label),
        'csv_rows_absent': {
            'total': len(absent),
            'by_label': dict(Counter(csv_label[i] for i in absent)),
            'files_by_label': {
                label: len({csv_file[i] for i in absent if csv_label[i] == label}) for label in ('Y', 'N')
            },
        },
    }
    return rows, report


def _overlay(path: Path, rows: List[june.JuneRow], field: str) -> int:
    chosen = [r for r in rows if getattr(r, field)]
    with open(path, 'w', newline='', encoding='utf-8') as f:
        out = csv.writer(f)
        out.writerow(['june_id', 'csv_ids', 'file', 'line', field])
        for r in chosen:
            out.writerow([r.june_id, ';'.join(r.csv_ids), r.file, r.line, getattr(r, field)])
    return len(chosen)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def preserve(home: BenchHome, dump: Path, csv_path: Path, pg_restore: str) -> Dict:
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    out = home.legacy_dir / stamp
    out.mkdir(parents=True)
    columns = pgcopy.table_columns(pg_restore, str(dump))

    counts: Dict[str, int] = {}
    kept: Dict[str, List[Dict[str, Optional[str]]]] = {}
    for table in TABLES:
        counts[table], kept[table] = export_table(
            pg_restore, str(dump), table, columns[table], out / f'{table}.parquet', home.tmp_dir, table == 'Secrets'
        )

    rows, report = map_rows(kept['Secrets'], csv_path)
    june.write_rows(rows, out / june.TABLE)

    baseline = {
        'source': {'dump': str(dump), 'dump_sha256': sha256(dump), 'csv': str(csv_path), 'exported_at': stamp},
        'session': june.SESSION,
        'tables': counts,
        'rows': report,
        'problems': dict(Counter(r.problem for r in rows if r.problem)),
        'case_types': {
            'rows': sum(r.case_type is not None for r in rows),
            'kinds': len({r.case_type for r in rows} - {None}),
        },
        'june_view': june.view(rows),
    }
    (out / 'legacy_baseline.json').write_text(json.dumps(baseline, indent=2) + '\n')
    _overlay(home.overlays_dir / 'sb_corrections.csv', rows, 'problem')
    _overlay(home.overlays_dir / 'case_types_seed.csv', rows, 'case_type')
    baseline['legacy_dir'] = str(out)
    return baseline
