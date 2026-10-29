"""`compare`: several runs of one dataset head to head, builds of one scanner or different tools.

Every run is counted the way `metrics` counts it, with the `located` pairs at the matcher's current version: per
candidate group, per (repository, value) and per labelled row, at each named level (`low`, `medium`, `high`,
`very-high`), with the reliability of each tier. A tool without tiers reports everything at every level.

With a dark-matter overlay in the bench home (`darkmatter.py`), the per-(repository, value) view is also counted with
the judged units beyond the labels: a unit judged a secret in kind counts as a found secret for every run that reports
it, and one judged not a secret as a false positive. Recall then divides by the labelled real units plus every judged
secret unit any of the compared runs reports (a pooled denominator), unclear units are left out, and units the overlay
does not know are counted as unjudged beside the scores. The reliability table gains the share of secrets among each
tier's judged units.

Differences against the first run come with 95% intervals from a paired bootstrap over repositories: whole
repositories are resampled, so one repository's many copies of a secret move together. The bootstrap counts the
labels only. A comparison is written to `comparisons/<date>-<name>/` in the bench home, as aggregates only."""

import json
import random
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import duckdb

from dsbench import counting, darkmatter
from dsbench.counting import LEVELS, TIER_RANK
from dsbench.home import BenchHome
from dsbench.matcher import MATCHER_VERSIONS
from dsbench.metrics import check_pairs, check_tiers, rank_sql, run_scope
from dsbench.store import get_run

BOOTSTRAP = 1000
VIEWS = ('per_group', 'per_repository_and_value')


class CompareError(Exception):
    pass


def tool_name(run: Dict) -> str:
    kind = run['params'].get('tool_kind') or 'deepsecrets'
    names = {'deepsecrets': 'DeepSecrets', 'gitleaks': 'gitleaks', 'betterleaks': 'Betterleaks'}
    return f"{names.get(kind, kind)} {run['tool_version'] or ''}".strip()


def tiered(con: duckdb.DuckDBPyConnection, run_id: str) -> bool:
    return bool(
        con.execute(
            "SELECT count(*) FROM findings WHERE run_id = ? AND tier IN ('low', 'medium', 'high', 'very-high')",
            [run_id],
        ).fetchone()[0]
    )


def _f1(recall: float, precision: float) -> float:
    return 2 * recall * precision / (recall + precision) if recall + precision else 0.0


def _score(secrets: int, found: int, charged: int) -> Dict[str, float]:
    recall = found / secrets if secrets else 0.0
    precision = found / (found + charged) if found + charged else 0.0
    return {'recall': recall, 'precision': precision, 'f1': _f1(recall, precision)}


def with_dark_matter(labels_view: Dict, units: Dict, overlay: Dict, pooled_secret: int, rank: int) -> Dict[str, float]:
    """One run's per-unit scores at one level with the judged units beyond the labels."""
    sides = darkmatter.classify({k: r for k, r in units.items() if r >= rank}, overlay)
    found = labels_view['secrets_found'] + len(sides['secret'])
    charged = labels_view['lookalikes_found'] + len(sides['noise'])
    return {
        **_score(labels_view['secrets'] + pooled_secret, found, charged),
        'secrets_found': found,
        'lookalikes_found': charged,
        'beyond_secret': len(sides['secret']),
        'beyond_noise': len(sides['noise']),
        'beyond_unclear': len(sides['unclear']),
        'beyond_unjudged': len(sides['unjudged']),
    }


def _repo_counts(labels: counting.Labels, o: counting.Outcome, rank: int) -> Dict[str, Dict[str, List[int]]]:
    """Per repository: [secrets, found, look-alikes, charged] per group and per unit, at one rank."""
    out: Dict[str, Dict[str, List[int]]] = defaultdict(lambda: {v: [0, 0, 0, 0] for v in VIEWS})
    repo_of_group = {}
    for row, g in labels.group.items():
        repo_of_group.setdefault(g, labels.unit[row][0])
    for g, real in labels.real_group.items():
        c = out[repo_of_group[g]]['per_group']
        if real:
            c[0] += 1
            c[1] += o.group_found.get(g, -1) >= rank
        else:
            c[2] += 1
            c[3] += o.group_charged.get(g, -1) >= rank
    for u, real in labels.real_unit.items():
        c = out[u[0]]['per_repository_and_value']
        if real:
            c[0] += 1
            c[1] += o.unit_found.get(u, -1) >= rank
        else:
            c[2] += 1
            c[3] += o.unit_charged.get(u, -1) >= rank
    return out


def bootstrap(per_run: List[Dict[str, Dict[str, List[int]]]], samples: int, seed: int) -> Dict:
    """95% intervals of each run's difference from the first, in points, resampling repositories."""
    repos = sorted(set().union(*per_run))
    rng = random.Random(seed)
    diffs: Dict = {
        i: {v: {m: [] for m in ('recall', 'precision', 'f1')} for v in VIEWS} for i in range(1, len(per_run))
    }
    zero = [0, 0, 0, 0]
    for _ in range(samples):
        draw = rng.choices(repos, k=len(repos))
        for view in VIEWS:
            scored = []
            for counts in per_run:
                total = [0, 0, 0, 0]
                for repo in draw:
                    c = counts.get(repo, {}).get(view, zero)
                    for k in range(4):
                        total[k] += c[k]
                scored.append(_score(total[0], total[1], total[3]))
            for i in range(1, len(per_run)):
                for m in ('recall', 'precision', 'f1'):
                    diffs[i][view][m].append(100 * (scored[i][m] - scored[0][m]))
    out = {}
    for i, views in diffs.items():
        out[i] = {}
        for view, metrics in views.items():
            out[i][view] = {}
            for m, values in metrics.items():
                values.sort()
                out[i][view][m] = [
                    round(values[int(0.025 * len(values))], 2),
                    round(values[int(0.975 * len(values)) - 1], 2),
                ]
    return out


def compare(
    con: duckdb.DuckDBPyConnection,
    home: BenchHome,
    run_ids: Sequence[str],
    name: Optional[str] = None,
    samples: int = BOOTSTRAP,
    seed: int = 1,
) -> Dict:
    if len(run_ids) < 2:
        raise CompareError('compare needs two runs or more')
    runs = [get_run(con, r) for r in run_ids]
    if len({r['dataset_id'] for r in runs}) > 1:
        raise CompareError('the runs are of different datasets')
    scopes = [run_scope(con, r) for r in runs]
    if any(s != scopes[0] for s in scopes[1:]):
        raise CompareError('the runs scanned different files (a sample against a full run, or two samples)')
    for r in runs:
        check_tiers(con, r['run_id'])
        check_pairs(con, r['run_id'], 'located')
    labels = counting.load_labels(con, runs[0]['dataset_id'], scopes[0])
    overlay = darkmatter.load_overlay(home)
    results, per_run_low, extras = [], [], []
    for r in runs:
        pairs = counting.located_pairs(con, r['run_id'], rank_sql('f.tier'))
        counted = counting.count(labels, pairs)
        results.append(
            {
                'run_id': r['run_id'],
                'tool': tool_name(r),
                'commit': r['tool_commit'],
                'label': r['params'].get('label'),
                'tiered': tiered(con, r['run_id']),
                **{v: counted[v] for v in (*VIEWS, 'per_row', 'reliability')},
            }
        )
        per_run_low.append(_repo_counts(labels, counting.outcome(labels, pairs), TIER_RANK['low']))
        extras.append(darkmatter.extra_units(con, r, rank_sql('x.tier'), scopes[0]) if overlay is not None else {})
    dark = None
    if overlay is not None:
        pooled = set()
        for units in extras:
            pooled.update(darkmatter.classify(units, overlay)['secret'])
        dark = {'overlay_units': len(overlay), 'pooled_secret_units': len(pooled)}
        for result, units in zip(results, extras):
            result['with_dark_matter'] = {
                level: with_dark_matter(result['per_repository_and_value'][level], units, overlay, len(pooled), rank)
                for level, rank in counting.LEVEL_CUTS.items()
            }
            reliability = {}
            for tier in ('low', 'medium', 'high', 'very-high'):
                sides = darkmatter.classify({k: r for k, r in units.items() if r == TIER_RANK[tier]}, overlay)
                judged = len(sides['secret']) + len(sides['noise'])
                reliability[tier] = {
                    'secret': len(sides['secret']),
                    'noise': len(sides['noise']),
                    'secret_share': len(sides['secret']) / judged if judged else 0.0,
                }
            result['reliability_beyond_labels'] = reliability
    intervals = bootstrap(per_run_low, samples, seed)
    for i, result in enumerate(results[1:], 1):
        result['difference_from_first'] = {
            view: {
                m: round(100 * (result[view]['low'][m] - results[0][view]['low'][m]), 2)
                for m in ('recall', 'precision', 'f1')
            }
            for view in VIEWS
        }
        result['difference_interval_95'] = intervals[i]
    out = {
        'computed_at': datetime.now().isoformat(timespec='seconds'),
        'dataset_id': runs[0]['dataset_id'],
        'matcher': MATCHER_VERSIONS['located'],
        'scope': {'sample': runs[0]['params'].get('sample'), 'files': len(scopes[0]) if scopes[0] else None},
        'bootstrap': {'samples': samples, 'seed': seed, 'level': 'low', 'cluster': 'repository'},
        'dark_matter': dark,
        'runs': results,
    }
    where = home.root / 'comparisons' / f"{date.today().isoformat()}-{name or '-'.join(r['run_id'][:15] for r in runs)}"
    where.mkdir(parents=True, exist_ok=True)
    (where / 'compare.json').write_text(json.dumps(out, indent=2) + '\n')
    (where / 'compare.md').write_text(markdown(out))
    out['written_to'] = str(where)
    return out


def _pct(v: float) -> str:
    return f'{v:.2%}'


def markdown(c: Dict) -> str:
    runs = c['runs']
    lines = [f"# Comparison of {len(runs)} runs", '', f"Dataset `{c['dataset_id']}`, matcher `{c['matcher']}`.", '']
    for r in runs:
        lines.append(
            f"- `{r['run_id']}`: {r['tool']}"
            + (f" ({r['label']})" if r['label'] else '')
            + ('' if r['tiered'] else '; no tiers, every level the same')
        )
    for view, title in (('per_group', 'Per candidate group'), ('per_repository_and_value', 'Per (repository, value)')):
        lines += [
            '',
            f'## {title}',
            '',
            '| Level | Run | Recall | Precision | F1 | Found | Charged |',
            '| --- | --- | ---: | ---: | ---: | ---: | ---: |',
        ]
        for level in LEVELS:
            for r in runs:
                v = r[view][level]
                lines.append(
                    f"| {level} | {r['tool']} | {_pct(v['recall'])} | {_pct(v['precision'])} | {_pct(v['f1'])} "
                    f"| {v['secrets_found']:,} of {v['secrets']:,} | {v['lookalikes_found']:,} of {v['lookalikes']:,} |"
                )
    if len(runs) > 1:
        lines += ['', '## Differences from the first run, at low (points, 95% repository-bootstrap interval)', '']
        lines += ['| Run | View | Recall | Precision | F1 |', '| --- | --- | ---: | ---: | ---: |']
        for r in runs[1:]:
            for view in VIEWS:
                d, ci = r['difference_from_first'][view], r['difference_interval_95'][view]
                lines.append(
                    f"| {r['tool']} | {view} | "
                    + ' | '.join(
                        f"{d[m]:+.2f} [{ci[m][0]:+.2f}, {ci[m][1]:+.2f}]" for m in ('recall', 'precision', 'f1')
                    )
                    + ' |'
                )
    lines += [
        '',
        '## Reliability of each tier (labels)',
        '',
        '| Run | Tier | Real | Look-alikes | Share real |',
        '| --- | --- | ---: | ---: | ---: |',
    ]
    for r in runs:
        if r['tiered']:
            for tier, v in r['reliability'].items():
                lines.append(
                    f"| {r['tool']} | {tier} | {v['real_groups']:,} | {v['lookalike_groups']:,} | {_pct(v['secret_share'])} |"
                )
    if c['dark_matter']:
        lines += ['', '## Per (repository, value) with the judged dark matter', '']
        lines += [
            f"The overlay judges {c['dark_matter']['overlay_units']:,} units; the runs report {c['dark_matter']['pooled_secret_units']:,} judged secrets beyond the labels between them.",
            '',
        ]
        lines += [
            '| Level | Run | Recall | Precision | F1 | Secrets beyond | Noise beyond | Unjudged |',
            '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |',
        ]
        for level in LEVELS:
            for r in runs:
                v = r['with_dark_matter'][level]
                lines.append(
                    f"| {level} | {r['tool']} | {_pct(v['recall'])} | {_pct(v['precision'])} | {_pct(v['f1'])} "
                    f"| {v['beyond_secret']:,} | {v['beyond_noise']:,} | {v['beyond_unjudged']:,} |"
                )
        lines += [
            '',
            '| Run | Tier | Secrets beyond | Noise beyond | Share secret |',
            '| --- | --- | ---: | ---: | ---: |',
        ]
        for r in runs:
            if r['tiered']:
                for tier, v in r['reliability_beyond_labels'].items():
                    lines.append(
                        f"| {r['tool']} | {tier} | {v['secret']:,} | {v['noise']:,} | {_pct(v['secret_share'])} |"
                    )
    else:
        lines += ['', 'No dark-matter overlay in this bench home: the labels only.']
    return '\n'.join(lines) + '\n'
