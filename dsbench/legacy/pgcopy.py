"""Reading a pg_dump custom-format archive without a Postgres server. `pg_restore -s -f - DUMP` prints the DDL and
`pg_restore -a -t TABLE -f - DUMP` streams one table as COPY text, which this module decodes. The June archive is
format 1.16 (PostgreSQL 18), which needs pg_restore 17 or later: Debian bookworm's 15 refuses it, the PGDG
`postgresql-client-18` reads it."""

import os
import re
import shutil
import subprocess
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

MIN_MAJOR = 17
# where the PGDG packages put their binaries; PATH is tried after them
CANDIDATES = [f'/usr/lib/postgresql/{major}/bin/pg_restore' for major in (19, 18, 17)]

_ESCAPE = re.compile(r'\\(?:([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|(.))', re.DOTALL)
_SIMPLE = {'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v'}
_COPY_HEADER = re.compile(r'^COPY\s+(?:\w+\.)?"?([^"\s(]+)"?\s*\(([^)]*)\)\s+FROM\s+stdin;\s*$')
_CREATE = re.compile(r'^CREATE TABLE\s+(?:\w+\.)?"?([^"\s(]+)"?\s*\($')
_COLUMN = re.compile(r'^\s+"?([^"\s]+)"?\s+(.+?)(?:\s+CONSTRAINT\s.*|\s+DEFAULT\s.*|\s+NOT NULL)?,?$')


class PgRestoreError(Exception):
    pass


def major_version(binary: str) -> Optional[int]:
    try:
        out = subprocess.run([binary, '--version'], capture_output=True, text=True, timeout=30).stdout
    except OSError:
        return None
    found = re.search(r'\(PostgreSQL\)\s+(\d+)', out)
    return int(found.group(1)) if found else None


def find_pg_restore() -> Optional[str]:
    """The first pg_restore that reads format 1.16 archives, or None."""
    on_path = shutil.which('pg_restore')
    for binary in [*CANDIDATES, *([on_path] if on_path else [])]:
        if os.path.exists(binary) and (major_version(binary) or 0) >= MIN_MAJOR:
            return binary
    return None


def decode_field(raw: str) -> Optional[str]:
    """One COPY text field: `\\N` is NULL, backslash escapes are undone."""
    if raw == r'\N':
        return None
    if '\\' not in raw:
        return raw

    def unescape(m: re.Match) -> str:
        octal, hexa, char = m.groups()
        if octal is not None:
            return chr(int(octal, 8))
        if hexa is not None:
            return chr(int(hexa, 16))
        return _SIMPLE.get(char, char)

    return _ESCAPE.sub(unescape, raw)


def parse_copy(lines: Iterable[str]) -> Iterator[Tuple[List[str], List[Optional[str]]]]:
    """(columns, values) for every data row of the COPY blocks in a pg_restore text stream."""
    columns: Optional[List[str]] = None
    for line in lines:
        line = line.rstrip('\n')
        if columns is None:
            header = _COPY_HEADER.match(line)
            if header:
                columns = [c.strip().strip('"') for c in header.group(2).split(',')]
            continue
        if line == '\\.':
            columns = None
            continue
        values = [decode_field(field) for field in line.split('\t')]
        if len(values) != len(columns):
            raise PgRestoreError(f'COPY row with {len(values)} fields for {len(columns)} columns')
        yield columns, values


def copy_rows(pg_restore: str, dump: str, table: str) -> Iterator[Dict[str, Optional[str]]]:
    """Every row of one table as a dict of decoded text fields (None for NULL)."""
    with subprocess.Popen(
        [pg_restore, '-a', '-t', table, '-f', '-', dump], stdout=subprocess.PIPE, text=True, encoding='utf-8'
    ) as proc:
        for columns, values in parse_copy(proc.stdout):
            yield dict(zip(columns, values))
    if proc.returncode:
        raise PgRestoreError(f'pg_restore exited {proc.returncode} on table {table}')


def table_columns(pg_restore: str, dump: str) -> Dict[str, List[Tuple[str, str]]]:
    """Each table's columns and their Postgres types, from the archive's DDL."""
    ddl = subprocess.run([pg_restore, '-s', '-f', '-', dump], capture_output=True, text=True, check=True).stdout
    tables: Dict[str, List[Tuple[str, str]]] = {}
    current: Optional[str] = None
    for line in ddl.splitlines():
        start = _CREATE.match(line)
        if start:
            current = start.group(1)
            tables[current] = []
        elif current is not None and line.startswith(');'):
            current = None
        elif current is not None:
            column = _COLUMN.match(line)
            if column:
                tables[current].append((column.group(1), column.group(2).strip()))
    return tables
