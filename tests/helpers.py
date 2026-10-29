"""Builders for a tiny SecretBench-shaped corpus. Every value is synthetic."""

import csv
from pathlib import Path
from typing import Dict, List

FAKE_SCANNER = Path(__file__).with_name('fake_scanner.py')
CSV_FIELDS = [
    'id',
    'secret',
    'repo_name',
    'domain',
    'commit_id',
    'file_path',
    'file_type',
    'start_line',
    'end_line',
    'start_column',
    'end_column',
    'committer_email',
    'commit_date',
    'label',
    'is_template',
    'in_url',
    'entropy',
    'character_set',
    'has_words',
    'length',
    'is_multiline',
    'category',
    'file_identifier',
    'repo_identifier',
    'comment',
]


def csv_row(row_id: int, value: str, file_id: str, line: int, label: str, repo: str = 'acme-app', **extra) -> Dict:
    commit, _, path = file_id.partition('_')[2].partition('_')
    row = {name: '' for name in CSV_FIELDS}
    row.update(
        id=row_id,
        secret=extra.pop('secret', f'[{value}]'),
        repo_name=repo.replace('-', '/', 1),
        commit_id=commit,
        file_path=extra.pop('file_path', path.replace('__', '/')),
        start_line=line,
        end_line=line,
        start_column=1,
        end_column=len(value) + 1,
        label=label,
        is_template='N',
        in_url='N',
        is_multiline='N',
        category='Other',
        file_identifier=file_id,
        repo_identifier=repo,
    )
    row.update(extra)
    return row


def write_corpus(root: Path, files: Dict[str, str], rows: List[Dict]) -> Path:
    """`root/Files/<id>` for each file and `root/secretbench.csv`."""
    (root / 'Files').mkdir(parents=True)
    for name, text in files.items():
        (root / 'Files' / name).write_text(text, encoding='utf-8')
    with open(root / 'secretbench.csv', 'w', newline='', encoding='utf-8') as f:
        out = csv.DictWriter(f, CSV_FIELDS)
        out.writeheader()
        out.writerows(rows)
    return root
