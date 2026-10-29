"""`prepare`: SecretBench into the store, as given.

The CSV is read with `csv.field_size_limit` raised (multi-line values are long) and every row is loaded unchanged:
problems become `issues` on the row (`value_not_bracketed`, `file_missing`, `duplicate_row`, `empty_value`), never
corrections. The label text is the CSV `secret` minus one wrapping character on each side, as June took it.

The scanner sees a view of the corpus, not its flat file names. A labelled file gets its repository path back under a
neutral directory, `r_<sha1(repo@commit)[:10]>/<file_path>`, because path-aware scoring (`/test/` in a path lowers a
variable's score) reads it: the layout is part of the measurement. Unlabelled files stay flat under `unlabelled/`. When
two identifiers would get the same view path, the alias rule applies: equal sizes mean one file stored twice, scanned
once (`scan_file_id` points at the copy that is scanned, and its labels keep their own id); different sizes keep both,
the second under `r_<hash>~2/`. A view path that is also a directory of another view path is moved the same way.

The dataset id is `secretbench-<12 hex>` of a digest of the CSV's bytes and the corpus listing (names and sizes), so
preparing the same data twice finds the existing dataset."""

import csv
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import duckdb

from dsbench.home import BenchHome
from dsbench.matcher import legacy_norm
from dsbench.store import bulk_insert

ADAPTER = 'secretbench'
UNLABELLED_DIR = 'unlabelled'
REQUIRED = [
    'id',
    'secret',
    'repo_identifier',
    'commit_id',
    'file_path',
    'start_line',
    'end_line',
    'start_column',
    'end_column',
    'label',
    'file_identifier',
]


class DatasetError(Exception):
    pass


def unwrap(secret: str) -> Tuple[str, bool]:
    """The label text, and whether the wrapper was the usual pair of brackets."""
    return secret[1:-1], secret[:1] == '[' and secret[-1:] == ']'


def repo_dir(repo: str, commit: str) -> str:
    return 'r_' + hashlib.sha1(f'{repo}@{commit}'.encode('utf-8')).hexdigest()[:10]


def _yn(value: Optional[str]) -> bool:
    return (value or '').strip().upper() == 'Y'


def _int(value: Optional[str], default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def corpus_sizes(files_dir: Path) -> Dict[str, int]:
    """Every regular file of the corpus directory (dot files included) and its size."""
    with os.scandir(files_dir) as entries:
        return {e.name: e.stat().st_size for e in entries if e.is_file(follow_symlinks=False)}


def fingerprint(csv_path: Path, sizes: Dict[str, int]) -> str:
    digest = hashlib.sha256()
    with open(csv_path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            digest.update(block)
    for name in sorted(sizes):
        digest.update(f'{name}\t{sizes[name]}\n'.encode('utf-8', 'surrogateescape'))
    return digest.hexdigest()


def read_rows(csv_path: Path) -> List[dict]:
    csv.field_size_limit(sys.maxsize)
    rows = []
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        missing = [c for c in REQUIRED if c not in (reader.fieldnames or [])]
        if missing:
            raise DatasetError(f'{csv_path} lacks the columns {", ".join(missing)}')
        for raw in reader:
            value, bracketed = unwrap(raw['secret'])
            start = _int(raw['start_line'])
            rows.append(
                {
                    'row_id': _int(raw['id']),
                    'file_id': raw['file_identifier'],
                    'repo': raw['repo_identifier'],
                    'value': value,
                    'bracketed': bracketed,
                    'start_line': start,
                    'end_line': max(_int(raw['end_line'], start), start),
                    'start_col': _int(raw['start_column']),
                    'end_col': _int(raw['end_column']),
                    'label': _yn(raw['label']),
                    'category': raw.get('category') or None,
                    'comment': raw.get('comment') or None,
                    'is_multiline': _yn(raw.get('is_multiline')),
                    'is_template': _yn(raw.get('is_template')),
                    'in_url': _yn(raw.get('in_url')),
                    '_commit': raw['commit_id'],
                    '_path': raw['file_path'],
                }
            )
    return rows


def _suffixed(view: str, n: int) -> str:
    head, sep, tail = view.partition('/')
    return f'{head}~{n}{sep}{tail}'


def assign_views(sizes: Dict[str, int], rows: List[dict]) -> Tuple[Dict[str, dict], Dict[str, int]]:
    """Each corpus file's entry in `files`, with its view path and the file actually scanned for it."""
    first: Dict[str, dict] = {}
    for row in rows:
        first.setdefault(row['file_id'], row)
    files: Dict[str, dict] = {}
    wanted: Dict[str, str] = {}
    for file_id in sorted(sizes):
        meta = first.get(file_id)
        if meta is None:
            files[file_id] = dict(file_id=file_id, repo=None, commit_id=None, file_path=None, labelled=False)
            wanted[file_id] = f'{UNLABELLED_DIR}/{file_id}'
        else:
            files[file_id] = dict(
                file_id=file_id, repo=meta['repo'], commit_id=meta['_commit'], file_path=meta['_path'], labelled=True
            )
            path = os.path.normpath(meta['_path'].replace('\\', '/')).lstrip('/')
            if path in ('', '.') or path.startswith('../'):
                path = file_id
            wanted[file_id] = f"{repo_dir(meta['repo'], meta['_commit'])}/{path}"

    counts = Counter()
    by_view: Dict[str, str] = {}
    for file_id in sorted(sizes):
        view: Optional[str] = wanted[file_id]
        scan_file_id = file_id
        if view in by_view:
            other = by_view[view]
            if sizes[other] == sizes[file_id]:
                scan_file_id, view = other, None
                counts['aliases'] += 1
            else:
                n = 2
                while _suffixed(view, n) in by_view:
                    n += 1
                view = _suffixed(view, n)
                counts['views_suffixed'] += 1
        if view is not None:
            by_view[view] = file_id
        files[file_id].update(size=sizes[file_id], view_path=view, scan_file_id=scan_file_id)

    # a view path cannot also be a directory of another one
    directories = {view.rsplit('/', 1)[0] for view in by_view if '/' in view}
    directories = {'/'.join(d.split('/')[: i + 1]) for d in directories for i in range(d.count('/') + 1)}
    for view in sorted(set(by_view) & directories):
        file_id = by_view.pop(view)
        n = 2
        while _suffixed(view, n) in by_view or _suffixed(view, n) in directories:
            n += 1
        moved = _suffixed(view, n)
        files[file_id]['view_path'], by_view[moved] = moved, file_id
        counts['views_suffixed'] += 1
    return files, dict(counts)


def tag_issues(rows: List[dict], sizes: Dict[str, int]) -> Counter:
    issues: Dict[int, List[str]] = defaultdict(list)
    dup = Counter((r['file_id'], r['value'], r['start_line']) for r in rows)
    seen = set()
    for row in rows:
        if not row['bracketed']:
            issues[row['row_id']].append('value_not_bracketed')
        if row['file_id'] not in sizes:
            issues[row['row_id']].append('file_missing')
        key = (row['file_id'], row['value'], row['start_line'])
        if dup[key] > 1:
            if key in seen:
                issues[row['row_id']].append('duplicate_row')
            seen.add(key)
        if not legacy_norm(row['value']):
            issues[row['row_id']].append('empty_value')
    tally = Counter()
    for row in rows:
        tags = issues.get(row['row_id'], [])
        row['issues'] = ','.join(tags) or None
        tally.update(tags)
    return tally


def prepare(
    con: duckdb.DuckDBPyConnection, home: BenchHome, csv_path: Path, files_dir: Path, force: bool = False
) -> Tuple[str, Dict]:
    """Loads the CSV and the corpus listing; returns the dataset id and its stats."""
    csv_path, files_dir = csv_path.resolve(), files_dir.resolve()
    sizes = corpus_sizes(files_dir)
    fp = fingerprint(csv_path, sizes)
    dataset_id = f'secretbench-{fp[:12]}'
    existing = con.execute('SELECT stats FROM datasets WHERE dataset_id = ?', [dataset_id]).fetchone()
    if existing and not force:
        return dataset_id, {**json.loads(existing[0]), 'already_prepared': True}

    rows = read_rows(csv_path)
    ids = Counter(r['row_id'] for r in rows)
    if any(n > 1 for n in ids.values()):
        raise DatasetError(f'{sum(n > 1 for n in ids.values())} row ids repeat in {csv_path}')
    files, view_counts = assign_views(sizes, rows)
    issues = tag_issues(rows, sizes)
    stats = {
        'rows': len(rows),
        'rows_y': sum(r['label'] for r in rows),
        'rows_n': sum(not r['label'] for r in rows),
        'files': len(sizes),
        'files_labelled': sum(f['labelled'] for f in files.values()),
        'files_unlabelled': sum(not f['labelled'] for f in files.values()),
        'files_scanned': sum(f['view_path'] is not None for f in files.values()),
        'bytes': sum(sizes.values()),
        'repositories': len({r['repo'] for r in rows}),
        'labelled_files_missing': len({r['file_id'] for r in rows} - set(sizes)),
        'aliases': view_counts.get('aliases', 0),
        'views_suffixed': view_counts.get('views_suffixed', 0),
        'issues': dict(sorted(issues.items())),
    }

    con.begin()
    try:
        for table in ('labels', 'files', 'datasets'):
            con.execute(f'DELETE FROM {table} WHERE dataset_id = ?', [dataset_id])
        con.execute(
            'INSERT INTO datasets VALUES (?, ?, ?, ?, ?, ?, ?)',
            [dataset_id, ADAPTER, str(csv_path), str(files_dir), fp, datetime.now(), json.dumps(stats)],
        )
        bulk_insert(con, 'files', ({'dataset_id': dataset_id, **f} for f in files.values()), home.tmp_dir)
        bulk_insert(con, 'labels', ({'dataset_id': dataset_id, **r} for r in rows), home.tmp_dir)
        con.commit()
    except BaseException:
        con.rollback()
        raise
    return dataset_id, stats
