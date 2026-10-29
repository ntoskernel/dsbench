"""`metrics`: a run counted at each confidence level, into `metrics.json` and `summary.md`.

The headline is the `located` matcher's: per candidate group, per (repository, value) and per row, with the
reliability of each tier and the findings outside the labels (`counting.py`). Beside it, the June way.

The June view (`legacy/june.py`) takes June's own labelled rows (no extras, no row with a manual `problem` flag: 14,847
secrets and 82,265 look-alikes) and asks of each whether the run found it. Here a row is found at a level when one of
the CSV rows it stands for is paired by the `legacy` matcher with a finding whose tier is at least the level. The tier
is the scanner's own (`sarif.py`: the rule id's suffix, else the rule descriptor's `precision`), so a cut of a `low`
run gives the findings a scan at that level reports, whatever confidence that version's tiers start at (2.2.0's medium
starts at 3, 2.3's at 5). A rejected candidate (`info`) is in no named level. Beside it, the same rows per
(repository, value): one unit per repository, label and raw label value, found when any of its rows is, so copies of
one value do not multiply. The value is not normalised: keyed raw, June's own rows give June's published 93.10%,
while the `legacy` normalisation merges more and gives 92.61%. Precision in both is found secrets over found
secrets plus charged look-alikes; unlabelled findings never enter it.

`summary.md` and `metrics.json` hold aggregates only, never a value or a file name."""

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import duckdb

from dsbench import counting
from dsbench.counting import LEVELS, TIER_RANK
from dsbench.home import BenchHome
from dsbench.legacy import june
from dsbench.matcher import MATCHER_VERSIONS
from dsbench.runner import DEEP_MAX_SIZE, fill_tiers
from dsbench.sarif import TIERS
from dsbench.store import fetch_dicts, get_run


def rank_sql(column: str) -> str:
    """A finding's tier rank in SQL."""
    return f'CASE {column} ' + ' '.join(f"WHEN '{t}' THEN {r}" for t, r in TIER_RANK.items()) + ' END'


MATCHER = 'legacy'


class MetricsError(Exception):
    pass


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def check_tiers(con: duckdb.DuckDBPyConnection, run_id: str) -> None:
    untiered = con.execute('SELECT count(*) FROM findings WHERE run_id = ? AND tier IS NULL', [run_id]).fetchone()[0]
    if untiered:
        raise MetricsError(
            f'{run_id} has {untiered:,} findings without a tier and no shard report that names one; '
            f'run `dsbench match --run {run_id}` while its reports are in the run directory'
        )


def check_pairs(con: duckdb.DuckDBPyConnection, run_id: str, matcher: str) -> None:
    """Refuses pairs of another matcher version, and a run with findings but no pairs of this matcher."""
    versions = {
        v
        for (v,) in con.execute(
            'SELECT DISTINCT matcher_version FROM matches WHERE run_id = ? AND matcher = ?', [run_id, matcher]
        ).fetchall()
    }
    if versions - {MATCHER_VERSIONS[matcher]}:
        raise MetricsError(
            f'{run_id} has {matcher} pairs from {", ".join(sorted(versions))}, not {MATCHER_VERSIONS[matcher]}: '
            f'run `dsbench match --run {run_id}`'
        )
    if not versions and con.execute('SELECT count(*) FROM findings WHERE run_id = ?', [run_id]).fetchone()[0]:
        raise MetricsError(f'{run_id} has findings but no {matcher} pairs: run `dsbench match --run {run_id}`')


def row_tier(con: duckdb.DuckDBPyConnection, run_id: str, matcher: str = MATCHER) -> Dict[int, int]:
    """Each matched CSV row and the highest tier rank of a finding paired with it."""
    check_pairs(con, run_id, matcher)
    rank = rank_sql('f.tier')
    return dict(
        con.execute(
            f'''SELECT m.row_id, max({rank}) FROM matches m
               JOIN findings f ON f.run_id = m.run_id AND f.finding_id = m.finding_id
               WHERE m.run_id = ? AND m.matcher = ? GROUP BY m.row_id''',
            [run_id, matcher],
        ).fetchall()
    )


def found_at(best: Dict[int, int], level: str) -> Callable[[june.JuneRow], bool]:
    rank = TIER_RANK[level]

    def found(row: june.JuneRow) -> bool:
        return any(best.get(int(i), -1) >= rank for i in row.csv_ids)

    return found


def unit_view(
    rows: List[june.JuneRow], label_of: Dict[int, Tuple[str, str]], found: Callable[[june.JuneRow], bool]
) -> Dict[str, float]:
    """The June rows per (repository, value): a unit is found when any of its clean rows is."""
    units: Dict[Tuple[str, str, bool], bool] = {}
    for row in rows:
        if not row.clean or not row.csv_ids:
            continue
        repo, value = label_of[int(row.csv_ids[0])]
        key = (repo, value, row.is_valid)
        units[key] = units.get(key, False) or found(row)
    n = Counter()
    for (_, _, valid), hit in units.items():
        n['secrets' if valid else 'lookalikes'] += 1
        n['secrets_found' if valid else 'lookalikes_found'] += hit
    recall = _ratio(n['secrets_found'], n['secrets'])
    precision = _ratio(n['secrets_found'], n['secrets_found'] + n['lookalikes_found'])
    return {
        'secrets': n['secrets'],
        'secrets_found': n['secrets_found'],
        'lookalikes': n['lookalikes'],
        'lookalikes_found': n['lookalikes_found'],
        'recall': recall,
        'precision': precision,
        'f1': _ratio(2 * recall * precision, recall + precision),
    }


def _files(con: duckdb.DuckDBPyConnection, run: Dict) -> Dict:
    statuses = dict(
        con.execute('SELECT status, count(*) FROM artifacts WHERE run_id = ? GROUP BY 1', [run['run_id']]).fetchall()
    )
    tier = con.execute(
        '''SELECT count(*) FILTER (WHERE f.size > ?), count(*) FILTER (WHERE f.size > ? AND a.depth = 'shallow'),
                  count(*) FILTER (WHERE f.size <= ?), count(*) FILTER (WHERE f.size <= ? AND a.depth = 'deep'),
                  count(*) FILTER (WHERE a.depth IS NULL), sum(a.scan_time_ms), sum(a.errors)
           FROM artifacts a JOIN files f ON f.dataset_id = ? AND f.file_id = a.file_id WHERE a.run_id = ?''',
        [DEEP_MAX_SIZE] * 4 + [run['dataset_id'], run['run_id']],
    ).fetchone()
    expected = (
        con.execute('SELECT count(DISTINCT file_id) FROM shard_files WHERE run_id = ?', [run['run_id']]).fetchone()[0]
        or con.execute(
            'SELECT count(*) FROM files WHERE dataset_id = ? AND view_path IS NOT NULL', [run['dataset_id']]
        ).fetchone()[0]
    )
    return {
        'to_scan': expected,
        'artifacts': sum(statuses.values()),
        'status': dict(sorted(statuses.items())),
        'depth': {
            'tier_bytes': DEEP_MAX_SIZE,
            'over_tier': tier[0],
            'over_tier_shallow': tier[1],
            'within_tier': tier[2],
            'within_tier_deep': tier[3],
            'no_depth': tier[4],
        },
        'scan_time_s': round((tier[5] or 0) / 1000, 1),
        'error_notifications': int(tier[6] or 0),
    }


def _findings(con: duckdb.DuckDBPyConnection, run: Dict) -> Dict:
    by_tier = dict(
        con.execute('SELECT tier, count(*) FROM findings WHERE run_id = ? GROUP BY 1', [run['run_id']]).fetchall()
    )
    by_level = {
        level: sum(n for tier, n in by_tier.items() if TIER_RANK.get(tier, -1) >= TIER_RANK[level]) for level in LEVELS
    }
    labelled = con.execute(
        '''SELECT f.labelled, count(*) FROM findings x JOIN files f ON f.dataset_id = ? AND f.file_id = x.file_id
           WHERE x.run_id = ? GROUP BY 1''',
        [run['dataset_id'], run['run_id']],
    ).fetchall()
    rules = con.execute(
        'SELECT rule_base, count(*) FROM findings WHERE run_id = ? GROUP BY 1 ORDER BY 2 DESC, 1',
        [run['run_id']],
    ).fetchall()
    return {
        'by_level': by_level,
        'by_tier': {tier: by_tier.get(tier, 0) for tier in TIERS},
        'in_labelled_files': dict(labelled).get(True, 0),
        'in_unlabelled_files': dict(labelled).get(False, 0),
        'by_rule': dict(rules),
    }


def _operations(con: duckdb.DuckDBPyConnection, run: Dict) -> Dict:
    shards = con.execute(
        '''SELECT count(*), count(*) FILTER (WHERE status = 'done'), count(*) FILTER (WHERE status = 'split'),
                  count(*) FILTER (WHERE status = 'failed'), count(*) FILTER (WHERE status = 'done' AND n_files = 1),
                  sum(cpu_s), max(max_rss_mb), max(wall_s) FILTER (WHERE status = 'done')
           FROM shards WHERE run_id = ?''',
        [run['run_id']],
    ).fetchone()
    params = run['params']
    wall_s = sum(s.get('wall_s', 0) for s in params.get('segments', []))
    return {
        'cores': params.get('cores'),
        'resumed_cores': [r.get('cores') for r in params.get('resumed_with', [])],
        'shards': {'total': shards[0], 'done': shards[1], 'split': shards[2], 'failed': shards[3], 'solo': shards[4]},
        'wall_s': round(wall_s, 1),
        'cpu_s': round(shards[5] or 0, 1),
        'cpu_h': round((shards[5] or 0) / 3600, 2),
        'max_rss_mb': round(shards[6] or 0, 1),
        'longest_shard_s': round(shards[7] or 0, 1),
        'segments': len(params.get('segments', [])),
    }


def run_scope(con: duckdb.DuckDBPyConnection, run: Dict) -> Optional[set]:
    """The files a sample run scanned; None for a run of the whole dataset."""
    if not run['params'].get('sample'):
        return None
    return {
        f
        for (f,) in con.execute('SELECT DISTINCT file_id FROM shard_files WHERE run_id = ?', [run['run_id']]).fetchall()
    }


def located_view(con: duckdb.DuckDBPyConnection, run: Dict, scope: Optional[set]) -> Dict:
    check_pairs(con, run['run_id'], 'located')
    labels = counting.load_labels(con, run['dataset_id'], scope)
    kinds = dict(
        con.execute(
            'SELECT kind, count(*) FROM label_spans WHERE dataset_id = ? GROUP BY 1 ORDER BY 2 DESC',
            [run['dataset_id']],
        ).fetchall()
    )
    # a rejected candidate has no place in a numeric cut either: the scanner reports it only at `all`
    confidence = "CASE WHEN f.tier IS DISTINCT FROM 'info' THEN coalesce(f.confidence, 0) END"
    by_confidence = counting.count(
        labels, counting.located_pairs(con, run['run_id'], confidence), counting.CONFIDENCE_CUTS
    )
    return {
        'matcher': 'located',
        'version': MATCHER_VERSIONS['located'],
        'labels_located': kinds,
        **counting.count(labels, counting.located_pairs(con, run['run_id'], rank_sql('f.tier'))),
        'by_min_confidence': {
            'per_group': by_confidence['per_group'],
            'per_repository_and_value': by_confidence['per_repository_and_value'],
        },
        'extras': counting.extras(con, run, rank_sql('x.tier'), scope),
    }


def compute(
    con: duckdb.DuckDBPyConnection,
    run_id: str,
    rows: Optional[List[june.JuneRow]] = None,
    legacy_dir: Optional[Path] = None,
) -> Dict:
    run = get_run(con, run_id)
    check_tiers(con, run_id)
    scope = run_scope(con, run)
    headline = located_view(con, run, scope)
    june_table = True
    if rows is None:
        try:
            rows = june.load_rows(legacy_dir=legacy_dir)
        except FileNotFoundError:
            # no `preserve` export in this bench home: everything but the June view is still counted
            rows, june_table = [], False
    best = row_tier(con, run_id)
    label_of = {
        r['row_id']: (r['repo'], r['value'])
        for r in fetch_dicts(con, 'SELECT row_id, repo, value FROM labels WHERE dataset_id = ?', [run['dataset_id']])
    }
    ids = [int(i) for row in rows for i in row.csv_ids]
    missing = sum(i not in label_of for i in ids)
    june_way: Optional[Dict] = {}
    per_unit: Optional[Dict] = {}
    if missing or not june_table or scope is not None:
        # no June table, or not June's corpus: the June view would count a different set of rows
        june_way = per_unit = None
    else:
        for level in LEVELS:
            found = found_at(best, level)
            june_way[level] = june.view(rows, found=found)
            per_unit[level] = unit_view(rows, label_of, found)
    dataset = con.execute('SELECT stats FROM datasets WHERE dataset_id = ?', [run['dataset_id']]).fetchone()
    matching = {}
    for matcher in MATCHER_VERSIONS:
        pairs = con.execute(
            'SELECT count(*), count(DISTINCT row_id) FROM matches WHERE run_id = ? AND matcher = ?', [run_id, matcher]
        ).fetchone()
        matching[matcher] = {'version': MATCHER_VERSIONS[matcher], 'pairs': pairs[0], 'rows': pairs[1]}
    return {
        'computed_at': datetime.now().isoformat(timespec='seconds'),
        'run': {
            'run_id': run_id,
            'dataset_id': run['dataset_id'],
            'status': run['status'],
            'profile': run['profile'],
            'label': run['params'].get('label'),
            'tool': {
                'cwd': run['tool_cwd'],
                'ref': run['params'].get('tool_ref'),
                'version': run['tool_version'],
                'commit': run['tool_commit'],
                'digest': run['tool_digest'],
            },
            'started_at': str(run['started_at']),
            'finished_at': str(run['finished_at']),
        },
        'dataset': json.loads(dataset[0]) if dataset else None,
        'scope': {'sample': run['params'].get('sample'), 'files': len(scope) if scope is not None else None},
        'files': _files(con, run),
        'findings': _findings(con, run),
        'matching': matching,
        'levels': {'named': list(LEVELS), 'cut': 'by the scanner\'s own tier of each finding'},
        'located': headline,
        'june_table': june_table,
        'june_rows_missing': missing,
        'june_way': june_way,
        'per_repository_and_value': per_unit,
        'operations': _operations(con, run),
    }


def _pct(value: float) -> str:
    return f'{value:.2%}'


def _scores_table(view: Dict, findings: Optional[Dict] = None, fpr: bool = True) -> List[str]:
    head = '| Level | Recall | Precision | F1 |' + (' FPR |' if fpr else '') + ' Secrets found | Look-alikes charged |'
    rule = '| --- | ---: | ---: | ---: |' + (' ---: |' if fpr else '') + ' ---: | ---: |'
    if findings:
        head, rule = head + ' Findings |', rule + ' ---: |'
    lines = [head, rule]
    for level, v in view.items():
        lines.append(
            f"| {level} | {_pct(v['recall'])} | {_pct(v['precision'])} | {_pct(v['f1'])} |"
            + (f" {_pct(v['fpr'])} |" if fpr else '')
            + f" {v['secrets_found']:,} of {v['secrets']:,} | {v['lookalikes_found']:,} of {v['lookalikes']:,} |"
            + (f' {findings[level]:,} |' if findings else '')
        )
    return lines + ['']


def summary_markdown(m: Dict) -> str:
    run, files, ops, loc = m['run'], m['files'], m['operations'], m['located']
    tool = run['tool']
    scope = m.get('scope') or {}
    lines = [
        f"# {run['run_id']}",
        '',
        f"- Scanner: DeepSecrets {tool['version']} at {tool['commit'] or 'unknown commit'}"
        + (f" (ref `{tool['ref']}`)" if tool['ref'] else '')
        + f", source digest `{(tool['digest'] or '')[:12]}`",
        f"- Profile: `{run['profile']}`" + (f"; label: {run['label']}" if run['label'] else ''),
        f"- Dataset: `{run['dataset_id']}`; run status `{run['status']}`"
        + (
            f"; a sample of {scope['files']:,} files (`--sample {scope['sample']['n']} --seed {scope['sample']['seed']}`)"
            if scope.get('sample')
            else ''
        ),
        '- Matchers: ' + ', '.join(f"`{k}` version `{v['version']}`" for k, v in m['matching'].items()),
        '- Levels: each finding counted at its own tier as the scanner reports it (rule id suffix, else rule descriptor)',
        '',
        '## Files',
        '',
        f"{files['artifacts']:,} of {files['to_scan']:,} files have an artifact: "
        + ', '.join(f'{n:,} `{s}`' for s, n in files['status'].items())
        + '.',
        (
            'The scanner reports no depth: it has no size tier.'
            if files['depth']['no_depth'] == files['artifacts']
            else f"Size tier ({files['depth']['tier_bytes']:,} bytes): {files['depth']['over_tier_shallow']:,} of "
            f"{files['depth']['over_tier']:,} larger files `shallow`, {files['depth']['within_tier_deep']:,} of "
            f"{files['depth']['within_tier']:,} others `deep`."
        )
        + f" Error notifications: {files['error_notifications']:,}.",
        '',
        '## Per candidate group (`located` matcher)',
        '',
        *_scores_table(loc['per_group'], m['findings']['by_level']),
        '## Per (repository, value) (`located` matcher)',
        '',
        *_scores_table(loc['per_repository_and_value'], fpr=False),
        '## Per labelled row (`located` matcher, every row)',
        '',
        *_scores_table(loc['per_row']),
        '## By minimum confidence (2.3\'s `--min-confidence`; candidate groups, then (repository, value))',
        '',
        '| Confidence | Recall | Precision | F1 | Unit recall | Unit precision |',
        '| ---: | ---: | ---: | ---: | ---: | ---: |',
        *(
            f"| {c} | {_pct(g['recall'])} | {_pct(g['precision'])} | {_pct(g['f1'])} "
            f"| {_pct(u['recall'])} | {_pct(u['precision'])} |"
            for (c, g), u in zip(
                loc['by_min_confidence']['per_group'].items(),
                loc['by_min_confidence']['per_repository_and_value'].values(),
            )
        ),
        '',
        '## Reliability of each tier (candidate groups, at the best tier that found or charged them)',
        '',
        '| Tier | Real | Look-alikes | Share real |',
        '| --- | ---: | ---: | ---: |',
        *(
            f"| {tier} | {v['real_groups']:,} | {v['lookalike_groups']:,} | {_pct(v['secret_share'])} |"
            for tier, v in loc['reliability'].items()
        ),
        '',
        'Findings outside the labels: '
        + ', '.join(
            f"{level} {v['in_labelled_files'] + v['in_unlabelled_files']:,} "
            f"({v['in_unlabelled_files']:,} in unlabelled files)"
            for level, v in loc['extras'].items()
        )
        + '. Labels located: '
        + ', '.join(f'{k} {n:,}' for k, n in loc['labels_located'].items())
        + '.',
        '',
        '## The June way (per labelled row, `legacy` matcher)',
        '',
    ]
    if m['june_way'] is None:
        if scope.get('sample'):
            why = 'a sample run, while the June view counts every June row.'
        elif not m.get('june_table', True):
            why = 'no June table in this bench home (`dsbench preserve --from-dump DUMP` writes it).'
        else:
            why = f"{m['june_rows_missing']:,} CSV ids of June's rows are not labels of this dataset."
        lines += [f'Not applicable: {why}', '']
        return '\n'.join(lines + _operations_lines(ops))
    lines += _scores_table(m['june_way'], m['findings']['by_level'])
    lines += ['## The June way per (repository, value) (the same rows)', '']
    lines += _scores_table(m['per_repository_and_value'], fpr=False)
    return '\n'.join(lines + _operations_lines(ops))


def _operations_lines(ops: Dict) -> List[str]:
    shards = ops['shards']
    return [
        '## Operations',
        '',
        f"{shards['total']:,} shards ({shards['done']:,} done, {shards['solo']:,} of them single-file, "
        f"{shards['split']:,} split, {shards['failed']:,} failed) at `--cores {ops['cores']}`"
        + (f" (resumed at {', '.join(map(str, ops['resumed_cores']))})" if ops.get('resumed_cores') else '')
        + '; '
        f"wall {ops['wall_s'] / 60:,.1f} min over {ops['segments']} segment(s), scanner CPU {ops['cpu_h']:,.2f} h, "
        f"largest process {ops['max_rss_mb']:,.0f} MB, longest shard {ops['longest_shard_s'] / 60:,.1f} min. "
        'CPU is comparable only between runs on one machine with the same `--cores` and a quiet host.',
        '',
    ]


def write_metrics(con: duckdb.DuckDBPyConnection, home: BenchHome, run_id: str) -> Dict:
    fill_tiers(con, home, run_id)
    m = compute(con, run_id, legacy_dir=home.legacy_dir)
    run_dir = home.run_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / 'metrics.json').write_text(json.dumps(m, indent=2) + '\n')
    (run_dir / 'summary.md').write_text(summary_markdown(m))
    return m
