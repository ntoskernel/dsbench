"""The June way of counting, from June's own rows.

June's database (`"Secrets"` in the June 2026 dump) holds one row per labelled SecretBench row it evaluated, keyed by
the corpus file name (the CSV's `file_identifier`) and the label's start line. The June view counts per labelled row:
no extras, and no row with a manual `problem` flag. That leaves 14,847 secrets and 82,265 look-alikes, and June's
published 93.38% is 13,864 of the 14,847.

`june_rows.csv.gz` is that table without a single value: June's id, the CSV row ids it stands for, the file, the line
and June's flags. `preserve --from-dump` writes it once into the bench home (`legacy/<timestamp>/`); after that neither
the dump nor Postgres tooling is needed. It stays in the bench home and is never shipped: values-free as it is, a file
name, a line and `is_valid` together point at a real leaked secret in a public repository. A row stands for more than one CSV row where the CSV repeats a value on the same line of a
file: June's unique index (`md5(content), file, line_number, is_extra`) kept one."""

import csv
import gzip
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

FIELDS = ['june_id', 'csv_ids', 'file', 'line', 'is_valid', 'problem', 'is_ds_found', 'case_type']
TABLE = 'june_rows.csv.gz'
# June's session: every labelled row of the dump belongs to it
SESSION = '1780485281'


@dataclass(frozen=True)
class JuneRow:
    june_id: int
    csv_ids: Tuple[str, ...]
    file: str
    line: int
    is_valid: bool
    problem: Optional[str]
    is_ds_found: bool
    case_type: Optional[str]

    @property
    def clean(self) -> bool:
        """Counted by the June view: DeepSecrets' maintainers flagged no problem on it."""
        return self.problem is None


def write_rows(rows: Iterable[JuneRow], path: Path) -> int:
    count = 0
    with gzip.open(path, 'wt', newline='', encoding='utf-8') as f:
        out = csv.writer(f)
        out.writerow(FIELDS)
        for row in sorted(rows, key=lambda r: r.june_id):
            out.writerow(
                [
                    row.june_id,
                    ';'.join(row.csv_ids),
                    row.file,
                    row.line,
                    int(row.is_valid),
                    row.problem or '',
                    int(row.is_ds_found),
                    row.case_type or '',
                ]
            )
            count += 1
    return count


def latest_table(legacy_dir: Path) -> Optional[Path]:
    """The table of the most recent `preserve` export under the bench home's `legacy/`, if there is one."""
    found = sorted(legacy_dir.glob(f'*/{TABLE}'))
    return found[-1] if found else None


def load_rows(path: Optional[Path] = None, legacy_dir: Optional[Path] = None) -> List[JuneRow]:
    """The table at `path`, else the latest export under `legacy_dir` (a bench home's `legacy/`)."""
    if path is None:
        path = latest_table(legacy_dir) if legacy_dir is not None else None
        if path is None:
            raise FileNotFoundError('no June table in the bench home: run `dsbench preserve --from-dump DUMP` once')
    with gzip.open(path, 'rt', newline='', encoding='utf-8') as f:
        return [
            JuneRow(
                june_id=int(r['june_id']),
                csv_ids=tuple(r['csv_ids'].split(';')) if r['csv_ids'] else (),
                file=r['file'],
                line=int(r['line']),
                is_valid=r['is_valid'] == '1',
                problem=r['problem'] or None,
                is_ds_found=r['is_ds_found'] == '1',
                case_type=r['case_type'] or None,
            )
            for r in csv.DictReader(f)
        ]


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def view(rows: Iterable[JuneRow], found: Optional[Callable[[JuneRow], bool]] = None) -> Dict[str, float]:
    """The June view of one evaluation. `found` says whether the evaluated scan found a row; by default June's own
    `is_ds_found`, which gives June's published figures."""
    found = found or (lambda row: row.is_ds_found)
    n = {'secrets': 0, 'secrets_found': 0, 'lookalikes': 0, 'lookalikes_found': 0, 'all_secrets': 0, 'all_found': 0}
    for row in rows:
        hit = found(row)
        if row.is_valid:
            n['all_secrets'] += 1
            n['all_found'] += hit
        if not row.clean:
            continue
        if row.is_valid:
            n['secrets'] += 1
            n['secrets_found'] += hit
        else:
            n['lookalikes'] += 1
            n['lookalikes_found'] += hit
    recall = _ratio(n['secrets_found'], n['secrets'])
    precision = _ratio(n['secrets_found'], n['secrets_found'] + n['lookalikes_found'])
    return {
        **n,
        'recall': recall,
        'precision': precision,
        'f1': _ratio(2 * recall * precision, recall + precision),
        'fpr': _ratio(n['lookalikes_found'], n['lookalikes']),
        'recall_all_rows': _ratio(n['all_found'], n['all_secrets']),
    }
