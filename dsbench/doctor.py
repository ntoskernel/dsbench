"""`doctor`: whether this machine is ready to benchmark, place by place. A failure stops a run; a warning does not."""

import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from dsbench.legacy import june, pgcopy
from dsbench.places import Places, PlacesError, tool_python

OK, WARN, FAIL = 'ok', 'warn', 'FAIL'
MIN_FREE_GIB = 50


@dataclass
class Check:
    status: str
    name: str
    detail: str


def _writable(path: Path) -> bool:
    probe = path / f'.dsbench-{uuid.uuid4().hex}'
    try:
        probe.touch()
        probe.unlink()
        return True
    except OSError:
        return False


def check_places(places: Places) -> List[Check]:
    checks = []
    for name, path in places.named().items():
        if not path.is_dir():
            checks.append(Check(FAIL, name, f'{path} is not a directory'))
        else:
            checks.append(Check(OK, name, str(path)))
    for name in ('data', 'home', 'tool_cwd', 'cache'):
        if getattr(places, name) is None:
            checks.append(Check(FAIL, name, 'not set (argument or DSBENCH_* variable)'))
    for problem in places.overlaps():
        checks.append(Check(FAIL, 'apart', problem))
    return checks


def check_data(data: Path) -> List[Check]:
    checks = []
    labels = data / 'secretbench.csv'
    files = data / 'Files'
    checks.append(Check(OK if labels.is_file() else FAIL, 'labels', str(labels)))
    if files.is_dir():
        with os.scandir(files) as it:
            count = sum(1 for _ in it)
        checks.append(Check(OK, 'corpus', f'{files}: {count:,} entries'))
    else:
        checks.append(Check(FAIL, 'corpus', f'{files} is not a directory'))
    return checks


def check_home(home: Path) -> List[Check]:
    if not home.is_dir():
        return []
    checks = [Check(OK if _writable(home) else FAIL, 'home writable', str(home))]
    if (home / '.git').exists():
        checks.append(Check(FAIL, 'home private', f'{home} is a git repository; it will hold real secrets'))
    free = shutil.disk_usage(home).free / 2**30
    checks.append(Check(OK if free >= MIN_FREE_GIB else WARN, 'home disk', f'{free:,.0f} GiB free'))
    return checks


def check_tool(tool_cwd: Path, cache: Path) -> List[Check]:
    checks = []
    if cache.is_dir():
        checks.append(Check(OK if _writable(cache) else FAIL, 'cache writable', str(cache)))
    if not (tool_cwd / 'deepsecrets').is_dir():
        return checks + [Check(FAIL, 'tool', f'{tool_cwd} holds no deepsecrets/ package')]
    try:
        python = tool_python()
    except PlacesError as e:
        return checks + [Check(FAIL, 'tool python', str(e))]
    run = subprocess.run(
        [python, '-m', 'deepsecrets', '--help'], cwd=tool_cwd, capture_output=True, text=True, timeout=120
    )
    if run.returncode:
        detail = (run.stderr.strip().splitlines() or ['no output'])[-1]
        return checks + [Check(FAIL, 'tool', f'{python} -m deepsecrets --help exited {run.returncode}: {detail}')]
    head = subprocess.run(['git', '-C', str(tool_cwd), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True)
    dirty = subprocess.run(
        ['git', '-C', str(tool_cwd), 'status', '--porcelain', '--', 'deepsecrets'], capture_output=True, text=True
    )
    commit = head.stdout.strip() or 'no git'
    if dirty.stdout.strip():
        commit += '-dirty'
    checks.append(Check(OK, 'tool', f'{python} -m deepsecrets runs in {tool_cwd} at {commit}'))
    return checks


def check_legacy(home: Optional[Path]) -> List[Check]:
    checks = []
    binary = pgcopy.find_pg_restore()
    if binary:
        checks.append(Check(OK, 'pg_restore', f'{binary} (only `preserve` needs it)'))
    else:
        checks.append(Check(WARN, 'pg_restore', f'none of version {pgcopy.MIN_MAJOR}+; only `preserve` needs it'))
    table = june.latest_table(home / 'legacy') if home else None
    if table is None:
        return checks + [Check(WARN, 'june table', 'none in the bench home; `preserve --from-dump DUMP` writes it')]
    rows = june.load_rows(table)
    figures = june.view(rows)
    checks.append(
        Check(
            OK,
            'june table',
            f"{len(rows):,} rows; June's recall {figures['recall']:.2%}, precision {figures['precision']:.2%}",
        )
    )
    return checks


def run_doctor(places: Places) -> List[Check]:
    checks = check_places(places)
    if places.data and places.data.is_dir():
        checks += check_data(places.data)
    if places.home:
        checks += check_home(places.home)
    if places.tool_cwd and places.tool_cwd.is_dir() and places.cache:
        checks += check_tool(places.tool_cwd, places.cache)
    return checks + check_legacy(places.home)
