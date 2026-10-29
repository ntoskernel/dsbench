"""The store: one DuckDB file in the bench home, `bench.duckdb`, holding the prepared datasets, their labels, every run
and everything a run produced. Labels and findings carry real secret values, which is why the store lives in the bench
home and nowhere else.

Pairs carry `matches.matcher_version`, so pairs from another matcher version are never counted; `artifacts.depth`
is the size tier the scanner applied to a file; `errors` holds one row per error notification the scanner reported,
and `artifacts.errors` counts a file's notifications. `findings.tier` is the scanner's own tier for a finding and
`findings.tags` its `properties.tags` as a JSON list. `label_spans` is where the `located` matcher found each label
(per dataset, recomputed when that matcher's version changes); a `located` pair stores in `matches.tier` how its label
was located and in `matches.encloses` whether the finding covers the label and more. Columns added after a store was created arrive through
`MIGRATIONS`, which every writing connection applies. Bulk inserts go through NDJSON staged in the bench home's `tmp/`, which DuckDB reads in one pass
and dsbench deletes at once, since the rows can hold secrets."""

import json
import uuid
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import duckdb

from dsbench.home import BenchHome

DDL = [
    '''CREATE TABLE IF NOT EXISTS datasets (
        dataset_id VARCHAR PRIMARY KEY, adapter VARCHAR, labels_path VARCHAR, files_dir VARCHAR,
        fingerprint VARCHAR, created_at TIMESTAMP, stats JSON)''',
    # scan_file_id: the file actually scanned for this id (differs for files stored under two identifiers)
    '''CREATE TABLE IF NOT EXISTS files (
        dataset_id VARCHAR, file_id VARCHAR, size BIGINT, repo VARCHAR, commit_id VARCHAR, file_path VARCHAR,
        view_path VARCHAR, labelled BOOLEAN, scan_file_id VARCHAR, PRIMARY KEY (dataset_id, file_id))''',
    '''CREATE TABLE IF NOT EXISTS labels (
        dataset_id VARCHAR, row_id BIGINT, file_id VARCHAR, repo VARCHAR, value VARCHAR, bracketed BOOLEAN,
        start_line INTEGER, end_line INTEGER, start_col INTEGER, end_col INTEGER, label BOOLEAN,
        category VARCHAR, comment VARCHAR, is_multiline BOOLEAN, is_template BOOLEAN, in_url BOOLEAN,
        group_id BIGINT, fragment BOOLEAN, issues VARCHAR, PRIMARY KEY (dataset_id, row_id))''',
    '''CREATE TABLE IF NOT EXISTS runs (
        run_id VARCHAR PRIMARY KEY, dataset_id VARCHAR, tool_cmd VARCHAR, tool_cwd VARCHAR, tool_version VARCHAR,
        tool_commit VARCHAR, tool_digest VARCHAR, profile VARCHAR, params JSON, host JSON, diagnostics BOOLEAN,
        started_at TIMESTAMP, finished_at TIMESTAMP, status VARCHAR)''',
    '''CREATE TABLE IF NOT EXISTS shards (
        run_id VARCHAR, shard_id VARCHAR, n_files INTEGER, bytes BIGINT, est_cost DOUBLE, process_count INTEGER,
        status VARCHAR, attempts INTEGER, exit_code INTEGER, wall_s DOUBLE, cpu_s DOUBLE, max_rss_mb DOUBLE,
        started_at TIMESTAMP, finished_at TIMESTAMP, note VARCHAR, PRIMARY KEY (run_id, shard_id))''',
    '''CREATE TABLE IF NOT EXISTS shard_files (
        run_id VARCHAR, shard_id VARCHAR, file_id VARCHAR, view_path VARCHAR,
        PRIMARY KEY (run_id, shard_id, file_id))''',
    # one row per scanned file; status comes from the scanner's diagnostics, or from the harness (timeout, tool_error,
    # missing) when the scanner gave none
    '''CREATE TABLE IF NOT EXISTS artifacts (
        run_id VARCHAR, file_id VARCHAR, shard_id VARCHAR, status VARCHAR, scan_time_ms DOUBLE, skip_reason VARCHAR,
        errors INTEGER, depth VARCHAR, PRIMARY KEY (run_id, file_id))''',
    '''CREATE TABLE IF NOT EXISTS findings (
        run_id VARCHAR, finding_id BIGINT, file_id VARCHAR, shard_id VARCHAR, rule_id VARCHAR, rule_base VARCHAR,
        confidence INTEGER, start_line INTEGER, end_line INTEGER, start_col INTEGER, end_col INTEGER, value VARCHAR,
        fingerprint VARCHAR, tier VARCHAR, tags VARCHAR, PRIMARY KEY (run_id, finding_id))''',
    '''CREATE TABLE IF NOT EXISTS matches (
        run_id VARCHAR, matcher VARCHAR, matcher_version VARCHAR, finding_id BIGINT, row_id BIGINT, tier VARCHAR,
        line_delta INTEGER, encloses BOOLEAN, PRIMARY KEY (run_id, matcher, finding_id, row_id))''',
    # where the `located` matcher found each label, per matcher version; offsets into the text the scanner read
    '''CREATE TABLE IF NOT EXISTS label_spans (
        dataset_id VARCHAR, row_id BIGINT, matcher_version VARCHAR, kind VARCHAR, start_offset BIGINT,
        end_offset BIGINT, line_delta INTEGER, PRIMARY KEY (dataset_id, row_id))''',
    '''CREATE TABLE IF NOT EXISTS errors (
        run_id VARCHAR, shard_id VARCHAR, seq INTEGER, file_id VARCHAR, level VARCHAR, message VARCHAR,
        PRIMARY KEY (run_id, shard_id, seq))''',
]

# columns added after the first stores were created; each is idempotent
MIGRATIONS = [
    'ALTER TABLE findings ADD COLUMN IF NOT EXISTS tier VARCHAR',
    'ALTER TABLE findings ADD COLUMN IF NOT EXISTS tags VARCHAR',
    'ALTER TABLE matches ADD COLUMN IF NOT EXISTS encloses BOOLEAN',
]


class StoreError(Exception):
    pass


def connect(home: BenchHome, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    """The bench home's store, its tables created if missing. A read-only connection needs an existing store."""
    if read_only:
        if not home.db_path.exists():
            raise StoreError(f'No store at {home.db_path}: run `dsbench prepare` first')
        return duckdb.connect(str(home.db_path), read_only=True)
    con = duckdb.connect(str(home.db_path))
    for statement in DDL + MIGRATIONS:
        con.execute(statement)
    return con


def _jsonable(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def table_columns(con: duckdb.DuckDBPyConnection, table: str) -> Dict[str, str]:
    return {name: kind for name, kind, *_ in con.execute(f'DESCRIBE {table}').fetchall()}


def bulk_insert(con: duckdb.DuckDBPyConnection, table: str, rows: Iterable[Dict[str, Any]], tmp_dir: Path) -> int:
    """Inserts dicts keyed by column name (missing keys are NULL) through one staged NDJSON file."""
    columns = table_columns(con, table)
    staged = tmp_dir / f'{table}-{uuid.uuid4().hex}.ndjson'
    count = 0
    try:
        with open(staged, 'w', encoding='utf-8') as out:
            for row in rows:
                out.write(json.dumps({c: _jsonable(row.get(c)) for c in columns}) + '\n')
                count += 1
        if count:
            spec = '{' + ', '.join(f"'{name}': '{kind}'" for name, kind in columns.items()) + '}'
            con.execute(
                f"INSERT INTO {table} BY NAME SELECT * FROM read_json(?, format = 'newline_delimited', "
                f"columns = {spec}, maximum_object_size = 268435456)",
                [str(staged)],
            )
    finally:
        staged.unlink(missing_ok=True)
    return count


def fetch_dicts(con: duckdb.DuckDBPyConnection, sql: str, params: Optional[Sequence] = None) -> List[Dict[str, Any]]:
    cursor = con.execute(sql, list(params or []))
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def resolve_dataset(con: duckdb.DuckDBPyConnection, dataset: Optional[str]) -> str:
    """`latest` (or nothing) is the most recently prepared dataset."""
    if dataset and dataset != 'latest':
        if not con.execute('SELECT 1 FROM datasets WHERE dataset_id = ?', [dataset]).fetchone():
            raise StoreError(f'No dataset {dataset}')
        return dataset
    row = con.execute('SELECT dataset_id FROM datasets ORDER BY created_at DESC LIMIT 1').fetchone()
    if not row:
        raise StoreError('No dataset prepared yet: run `dsbench prepare`')
    return row[0]


def get_run(con: duckdb.DuckDBPyConnection, run_id: str) -> Dict[str, Any]:
    rows = fetch_dicts(con, 'SELECT * FROM runs WHERE run_id = ?', [run_id])
    if not rows:
        raise StoreError(f'No run {run_id}')
    run = rows[0]
    for key in ('params', 'host'):
        if isinstance(run.get(key), str):
            run[key] = json.loads(run[key])
    return run
