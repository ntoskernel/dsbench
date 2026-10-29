"""Dark matter: what scanners report outside the labels, and the verdicts that say what it is.

A finding paired with no label is an extra. Extras are counted per unit: one unit per repository and normalised value
(`counting.unit_value`), so a secret copied into many files of a repository is one unit. A file the dataset records
no repository for is its own pseudo-repository (`file:<id>`), so the same value in several such files is several
units.

The overlay is the judged part: `overlays/dark_matter_labels.csv` in the bench home, one verdict per unit, keyed by
the repository and the SHA-256 of the normalised value, so it holds no value and carries to every later run; only
units it does not know need judging. Its classes:

    live              a credential for a real system                                  secret in kind
    test_credential   real-looking, serves tests, examples, docs, local development   secret in kind
    copy_of_labelled  the same value is labelled Y elsewhere in the dataset          secret in kind
    publishable       public by design, or shipped inside client software            not a secret
    placeholder       a dummy or default value                                       not a secret
    not_secret        an identifier, hash, public key, data, UI text                 not a secret
    unclear           undecidable offline                                            left out"""

import csv
import hashlib
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import duckdb

from dsbench import counting
from dsbench.home import BenchHome

OVERLAY = 'dark_matter_labels.csv'
OVERLAY_FIELDS = ['repo', 'value_sha256', 'verdict', 'source', 'judged_at']
SECRET = ('live', 'test_credential', 'copy_of_labelled')
NOISE = ('publishable', 'placeholder', 'not_secret')
CLASSES = SECRET + NOISE + ('unclear',)

Unit = Tuple[str, str]


class DarkMatterError(Exception):
    pass


def value_sha256(normalised: str) -> str:
    return hashlib.sha256(normalised.encode('utf-8', 'surrogatepass')).hexdigest()


def unit_key(repo: Optional[str], file_id: str, value: Optional[str]) -> Unit:
    """A unit beyond the labels: its repository (or the file's pseudo-repository) and the hash of its value."""
    return (repo or f'file:{file_id}', value_sha256(counting.unit_value(value)))


def overlay_path(home: BenchHome) -> Path:
    return home.overlays_dir / OVERLAY


def load_overlay(home: BenchHome) -> Optional[Dict[Unit, str]]:
    """The judged units, or None when the bench home holds no overlay."""
    path = overlay_path(home)
    if not path.is_file():
        return None
    verdicts = {}
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row['verdict'] not in CLASSES:
                raise DarkMatterError(f"{path}: unknown verdict {row['verdict']!r}")
            verdicts[(row['repo'], row['value_sha256'])] = row['verdict']
    return verdicts


def write_overlay(home: BenchHome, rows: Iterable[Dict]) -> int:
    path = overlay_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_suffix('.tmp')
    count = 0
    with open(staged, 'w', newline='', encoding='utf-8') as f:
        out = csv.DictWriter(f, OVERLAY_FIELDS)
        out.writeheader()
        for row in sorted(rows, key=lambda r: (r['repo'], r['value_sha256'])):
            out.writerow({k: row.get(k) for k in OVERLAY_FIELDS})
            count += 1
    staged.replace(path)
    return count


def extra_units(
    con: duckdb.DuckDBPyConnection, run: Dict, rank_sql: str, scope: Optional[Set[str]] = None
) -> Dict[Unit, int]:
    """The run's units beyond the labels: each unpaired finding's unit, at the best tier rank that reports it."""
    rows = con.execute(
        f'''SELECT x.file_id, fl.repo, x.value, {rank_sql} FROM findings x
            JOIN files fl ON fl.dataset_id = ? AND fl.file_id = x.file_id
            WHERE x.run_id = ? AND x.finding_id NOT IN
                (SELECT finding_id FROM matches WHERE run_id = ? AND matcher = 'located')''',
        [run['dataset_id'], run['run_id'], run['run_id']],
    ).fetchall()
    units: Dict[Unit, int] = {}
    for file_id, repo, value, rank in rows:
        if rank is None or (scope is not None and file_id not in scope):
            continue
        key = unit_key(repo, file_id, value)
        units[key] = max(units.get(key, -1), rank)
    return units


def classify(units: Dict[Unit, int], overlay: Dict[Unit, str]) -> Dict[str, List[Unit]]:
    """The units in the overlay's terms: secret, noise, unclear or unjudged."""
    out: Dict[str, List[Unit]] = {'secret': [], 'noise': [], 'unclear': [], 'unjudged': []}
    for key in units:
        verdict = overlay.get(key)
        side = (
            'unjudged'
            if verdict is None
            else 'secret' if verdict in SECRET else 'noise' if verdict in NOISE else 'unclear'
        )
        out[side].append(key)
    return out
