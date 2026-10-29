"""Pairing a run's findings with labelled rows.

One matcher so far, `legacy`, which reproduces the matching of the harness behind DeepSecrets' June 2026 evaluation
and serves the June view. For each label of a file it tries every finding of that file:

- the finding's start line must equal the label's `start_line`, so a multi-line label is matched on its first line;
- both texts lose every space, newline, `.`, `\\`, `"`, `'`, `-`, `/` and `+`;
- equality, or containment either way, is a match, with no minimum length (a finding that normalises to nothing
  credits every label on its line); otherwise `rapidfuzz.fuzz.ratio` of the two of 90 or more is.

That harness removed a matched finding only after every label of the file had been tried, so one finding can credit several
labels; here every accepted pair is stored. The label text is the CSV `secret` minus its wrapper (`dataset.unwrap`),
the finding's the SARIF snippet of an unmasked report. Labels of a file stored under two identifiers are matched
against the findings of the copy that was scanned.

`MATCHER_VERSIONS` stamps every stored pair; metrics refuse pairs from another version, so a change here means
`dsbench match` again, never a silent mix."""

from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

import duckdb
from rapidfuzz import fuzz

from dsbench.home import BenchHome
from dsbench.store import bulk_insert, get_run

MATCHER_VERSIONS = {'legacy': 'legacy-1'}
FUZZY_MIN = 90
_LEGACY_DROP = str.maketrans('', '', ' \n.\\"\'-/+')

# (row_id, scanned file, start line, text) and (finding_id, file, start line, text)
Label = Tuple[int, str, int, str]
Finding = Tuple[int, str, int, str]


class MatcherError(Exception):
    pass


def legacy_norm(text: str) -> str:
    return (text or '').translate(_LEGACY_DROP)


def legacy_same(label: str, finding: str) -> bool:
    a, b = legacy_norm(label), legacy_norm(finding)
    if a == b or a in b or b in a:
        return True
    return fuzz.ratio(a, b) >= FUZZY_MIN


def match_legacy(labels: Iterable[Label], findings: Iterable[Finding]) -> List[Tuple[int, int]]:
    """Every (finding_id, row_id) pair the June matcher accepts."""
    by_line: Dict[Tuple[str, int], List[Tuple[int, str]]] = defaultdict(list)
    for finding_id, file_id, line, text in findings:
        by_line[(file_id, line)].append((finding_id, text))
    pairs = []
    for row_id, file_id, line, value in labels:
        for finding_id, text in by_line.get((file_id, line), ()):
            if legacy_same(value, text):
                pairs.append((finding_id, row_id))
    return pairs


def match_run(con: duckdb.DuckDBPyConnection, home: BenchHome, run_id: str, matcher: str = 'legacy') -> Dict:
    """Stores the run's pairs for `matcher`, replacing earlier ones."""
    if matcher not in MATCHER_VERSIONS:
        raise MatcherError(f'unknown matcher {matcher!r}; known: {", ".join(MATCHER_VERSIONS)}')
    run = get_run(con, run_id)
    labels = con.execute(
        '''SELECT l.row_id, coalesce(f.scan_file_id, l.file_id), l.start_line, l.value
           FROM labels l LEFT JOIN files f ON f.dataset_id = l.dataset_id AND f.file_id = l.file_id
           WHERE l.dataset_id = ?''',
        [run['dataset_id']],
    ).fetchall()
    findings = con.execute(
        'SELECT finding_id, file_id, start_line, value FROM findings WHERE run_id = ?', [run_id]
    ).fetchall()
    pairs = match_legacy(labels, findings)
    version = MATCHER_VERSIONS[matcher]
    con.begin()
    try:
        con.execute('DELETE FROM matches WHERE run_id = ? AND matcher = ?', [run_id, matcher])
        bulk_insert(
            con,
            'matches',
            (
                {
                    'run_id': run_id,
                    'matcher': matcher,
                    'matcher_version': version,
                    'finding_id': finding_id,
                    'row_id': row_id,
                    'line_delta': 0,
                }
                for finding_id, row_id in pairs
            ),
            home.tmp_dir,
        )
        con.commit()
    except BaseException:
        con.rollback()
        raise
    return {
        'matcher': matcher,
        'matcher_version': version,
        'pairs': len(pairs),
        'rows_matched': len({r for _, r in pairs}),
        'findings_matched': len({f for f, _ in pairs}),
        'findings': len(findings),
        'labels': len(labels),
    }
