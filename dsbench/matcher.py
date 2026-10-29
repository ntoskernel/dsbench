"""Pairing a run's findings with labelled rows. Two matchers, each versioned.

`located` is the matcher behind dsbench's own numbers. The labelled value and the finding are both located in the
text of the file the scanner read (`located.py`), and a finding is paired with every label its span overlaps: no fuzzy
threshold, no line tolerance. Where each label sits depends only on the dataset, so it is computed once per dataset
and matcher version into `label_spans`; pairing a run then reads only the files that hold its findings. Each pair
records how its label was located and whether the finding encloses the label (covers it and more), which the
fragment rule in `metrics` needs.

`legacy` reproduces the matching of the harness behind DeepSecrets' June 2026 evaluation and serves the June view
only. For each label of a file it tries every finding of that file:

- the finding's start line must equal the label's `start_line`, so a multi-line label is matched on its first line;
- both texts lose every space, newline, `.`, `\\`, `"`, `'`, `-`, `/` and `+`;
- equality, or containment either way, is a match, with no minimum length (a finding that normalises to nothing
  credits every label on its line); otherwise `rapidfuzz.fuzz.ratio` of the two of 90 or more is.

That harness removed a matched finding only after every label of the file had been tried, so one finding can credit
several labels; here every accepted pair is stored. The label text is the CSV `secret` minus its wrapper
(`dataset.unwrap`), the finding's the SARIF snippet of an unmasked report.

Labels of a file stored under two identifiers are matched against the findings of the copy that was scanned.
`MATCHER_VERSIONS` stamps every stored pair; metrics refuse pairs from another version, so a change here means
`dsbench match` again, never a silent mix."""

import os
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import duckdb
from rapidfuzz import fuzz

from dsbench.home import BenchHome
from dsbench.located import match_file
from dsbench.store import bulk_insert, get_run

MATCHER_VERSIONS = {'legacy': 'legacy-1', 'located': 'located-2'}
MATCHERS = tuple(MATCHER_VERSIONS)
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


def default_processes() -> int:
    return max(1, min(16, len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else os.cpu_count() or 1))


def _map(jobs: Sequence, processes: int):
    if processes <= 1 or len(jobs) < 2:
        yield from map(match_file, jobs)
        return
    pool = ProcessPoolExecutor(processes)
    try:
        yield from pool.map(match_file, jobs, chunksize=8)
    finally:
        pool.shutdown()


def label_spans_ready(con: duckdb.DuckDBPyConnection, dataset_id: str) -> bool:
    versions = con.execute(
        'SELECT DISTINCT matcher_version FROM label_spans WHERE dataset_id = ?', [dataset_id]
    ).fetchall()
    return [v for (v,) in versions] == [MATCHER_VERSIONS['located']]


def match_located(
    con: duckdb.DuckDBPyConnection, home: BenchHome, run: Dict, processes: int
) -> Tuple[List[tuple], Dict[str, int]]:
    """The run's `located` pairs; locates the dataset's labels first when this matcher version has not."""
    dataset_id = run['dataset_id']
    files_dir = con.execute('SELECT files_dir FROM datasets WHERE dataset_id = ?', [dataset_id]).fetchone()[0]
    locate = not label_spans_ready(con, dataset_id)
    labels: Dict[str, List[tuple]] = defaultdict(list)
    if locate:
        rows = con.execute(
            '''SELECT coalesce(f.scan_file_id, l.file_id), l.row_id, l.value, l.start_line, l.end_line, l.start_col,
                      l.end_col
               FROM labels l LEFT JOIN files f ON f.dataset_id = l.dataset_id AND f.file_id = l.file_id
               WHERE l.dataset_id = ?''',
            [dataset_id],
        ).fetchall()
    else:
        rows = con.execute(
            '''SELECT coalesce(f.scan_file_id, l.file_id), s.row_id, s.kind, s.start_offset, s.end_offset, s.line_delta
               FROM label_spans s JOIN labels l ON l.dataset_id = s.dataset_id AND l.row_id = s.row_id
               LEFT JOIN files f ON f.dataset_id = l.dataset_id AND f.file_id = l.file_id
               WHERE s.dataset_id = ? AND s.start_offset IS NOT NULL''',
            [dataset_id],
        ).fetchall()
    for file_id, *rest in rows:
        labels[file_id].append(tuple(rest))
    findings: Dict[str, List[tuple]] = defaultdict(list)
    for file_id, *rest in con.execute(
        '''SELECT file_id, finding_id, start_line, end_line, start_col, end_col, value FROM findings
           WHERE run_id = ?''',
        [run['run_id']],
    ).fetchall():
        if file_id in labels:
            findings[file_id].append(tuple(rest))
    wanted = labels if locate else findings
    jobs = [(os.path.join(files_dir, f), labels[f], findings.get(f, []), locate) for f in sorted(wanted)]
    # the largest files first, so one of them does not finish last
    jobs.sort(key=lambda job: -(os.path.getsize(job[0]) if os.path.exists(job[0]) else 0))
    spans, pairs = [], []
    for file_spans, file_pairs in _map(jobs, processes):
        spans += file_spans
        pairs += file_pairs
    if locate:
        version = MATCHER_VERSIONS['located']
        con.begin()
        try:
            con.execute('DELETE FROM label_spans WHERE dataset_id = ?', [dataset_id])
            located_ids = {s[0] for s in spans}
            unread = [(row_id, 'none', None, None, 0) for rs in labels.values() for row_id, *_ in rs]
            bulk_insert(
                con,
                'label_spans',
                (
                    dict(
                        dataset_id=dataset_id,
                        row_id=row_id,
                        matcher_version=version,
                        kind=kind,
                        start_offset=start,
                        end_offset=end,
                        line_delta=delta,
                    )
                    for row_id, kind, start, end, delta in spans + [u for u in unread if u[0] not in located_ids]
                ),
                home.tmp_dir,
            )
            con.commit()
        except BaseException:
            con.rollback()
            raise
    kinds = dict(
        con.execute('SELECT kind, count(*) FROM label_spans WHERE dataset_id = ? GROUP BY 1', [dataset_id]).fetchall()
    )
    return pairs, kinds


def _store_pairs(con: duckdb.DuckDBPyConnection, home: BenchHome, run_id: str, matcher: str, pairs: List[Dict]) -> None:
    con.begin()
    try:
        con.execute('DELETE FROM matches WHERE run_id = ? AND matcher = ?', [run_id, matcher])
        bulk_insert(
            con,
            'matches',
            ({'run_id': run_id, 'matcher': matcher, 'matcher_version': MATCHER_VERSIONS[matcher], **p} for p in pairs),
            home.tmp_dir,
        )
        con.commit()
    except BaseException:
        con.rollback()
        raise


def match_run(
    con: duckdb.DuckDBPyConnection,
    home: BenchHome,
    run_id: str,
    matchers: Sequence[str] = MATCHERS,
    processes: Optional[int] = None,
) -> Dict[str, Dict]:
    """Stores the run's pairs for each matcher, replacing earlier ones; a summary per matcher."""
    if isinstance(matchers, str):
        matchers = (matchers,)
    unknown = [m for m in matchers if m not in MATCHER_VERSIONS]
    if unknown:
        raise MatcherError(f'unknown matcher {unknown[0]!r}; known: {", ".join(MATCHER_VERSIONS)}')
    run = get_run(con, run_id)
    n_findings = con.execute('SELECT count(*) FROM findings WHERE run_id = ?', [run_id]).fetchone()[0]
    n_labels = con.execute('SELECT count(*) FROM labels WHERE dataset_id = ?', [run['dataset_id']]).fetchone()[0]
    summaries = {}
    for matcher in matchers:
        extra: Dict = {}
        if matcher == 'legacy':
            labels = con.execute(
                '''SELECT l.row_id, coalesce(f.scan_file_id, l.file_id), l.start_line, l.value
                   FROM labels l LEFT JOIN files f ON f.dataset_id = l.dataset_id AND f.file_id = l.file_id
                   WHERE l.dataset_id = ?''',
                [run['dataset_id']],
            ).fetchall()
            findings = con.execute(
                'SELECT finding_id, file_id, start_line, value FROM findings WHERE run_id = ?', [run_id]
            ).fetchall()
            pairs = [{'finding_id': f, 'row_id': r, 'line_delta': 0} for f, r in match_legacy(labels, findings)]
        else:
            found, kinds = match_located(con, home, run, processes or default_processes())
            pairs = [
                {'finding_id': f, 'row_id': r, 'tier': kind, 'line_delta': delta, 'encloses': enc}
                for f, r, kind, delta, enc in found
            ]
            extra['label_kinds'] = dict(sorted(kinds.items()))
        _store_pairs(con, home, run_id, matcher, pairs)
        summaries[matcher] = {
            'matcher': matcher,
            'matcher_version': MATCHER_VERSIONS[matcher],
            'pairs': len(pairs),
            'rows_matched': len({p['row_id'] for p in pairs}),
            'findings_matched': len({p['finding_id'] for p in pairs}),
            'findings': n_findings,
            'labels': n_labels,
            **extra,
        }
    return summaries
