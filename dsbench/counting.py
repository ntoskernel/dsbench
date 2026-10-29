"""Counting a run's `located` pairs: per candidate group (the headline), per (repository, value) and per labelled row,
at each confidence level, with the reliability of each tier and the findings outside the labels.

A real secret is found at a level when a finding of at least that tier is paired with one of its Y rows. A look-alike
is charged at a level when a finding of at least that tier is paired with one of its N rows and that finding is paired
with no Y row at all: a finding that reports a real secret is never a false positive, whatever else it overlaps. A
fragment (`dataset.py`) is not charged by a finding that encloses it, since such a finding reports the secret the
fragment is a piece of. Unlabelled findings ("extras") enter no precision.

- **Per candidate group.** A group with a Y row is a real secret, found when any of its Y rows is; a group of N rows is
  a hard negative, charged when any of its rows is.
- **Per (repository, value).** One unit per repository and value, so one secret copied into many files counts once.
  The value is normalised so that the forms one secret is written in are one unit: escaped `\\n`, `\\r` and `\\t`
  dropped, then whitespace, quotes, backticks, backslashes and `. - / +`. A unit is real when any of its rows is Y;
  it is found when one of its rows' groups is found, and a look-alike unit is charged when one of its rows' groups is
  charged. On SecretBench that gives 4,125 real units.
- **Per row.** Each CSV row as given, beside the June view's per-row count on June's own rows.

DeepSecrets 2.3 tags findings (`properties.tags`: `weak-password`, `test-context`, `publishable`) and can leave a tag
out with `--exclude-tags`. Each tag a run's findings carry gets two counts from the same pairs: what its findings reach
(the real groups they find and the look-alike groups they are charged for, as if they were the only findings), and
every view without them, which is what a scan with `--exclude-tags TAG` reports. With more than one tag, `all` leaves
every tagged finding out.

The reliability table is per tier rather than per level: each found real group and each charged look-alike group at
the best tier of the findings that found or charged it, and the share of real secrets among them.

A run of a sample counts only the labels of the files it scanned."""

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

import duckdb

from dsbench.sarif import TIERS

LEVELS = ('low', 'medium', 'high', 'very-high')
TIER_RANK = {tier: rank for rank, tier in enumerate(TIERS)}
# a scanner without tiers (gitleaks) reports every finding at every level
TIER_RANK['none'] = TIER_RANK['very-high']
_UNIT_DROP = str.maketrans('', '', ' \t\r\n"\'`.-/+\\')


def unit_value(value: Optional[str]) -> str:
    return (value or '').replace('\\n', '').replace('\\r', '').replace('\\t', '').translate(_UNIT_DROP)


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def scores(secrets: int, found: int, lookalikes: int, charged: int) -> Dict:
    recall, precision = _ratio(found, secrets), _ratio(found, found + charged)
    return {
        'secrets': secrets,
        'secrets_found': found,
        'lookalikes': lookalikes,
        'lookalikes_found': charged,
        'recall': recall,
        'precision': precision,
        'f1': _ratio(2 * recall * precision, recall + precision),
        'fpr': _ratio(charged, lookalikes),
    }


class Labels:
    """The labels in a run's scope: per row its group, label, fragment flag and unit."""

    def __init__(self, rows: Iterable[Tuple]) -> None:
        self.group: Dict[int, int] = {}
        self.real: Dict[int, bool] = {}
        self.fragment: Set[int] = set()
        self.unit: Dict[int, Tuple[str, str]] = {}
        real_group: Dict[int, bool] = defaultdict(bool)
        real_unit: Dict[Tuple[str, str], bool] = defaultdict(bool)
        for row_id, group_id, label, fragment, repo, value in rows:
            self.group[row_id] = group_id if group_id is not None else -row_id
            self.real[row_id] = bool(label)
            if fragment:
                self.fragment.add(row_id)
            self.unit[row_id] = (repo or '', unit_value(value))
            real_group[self.group[row_id]] |= bool(label)
            real_unit[self.unit[row_id]] |= bool(label)
        self.real_group = dict(real_group)
        self.real_unit = dict(real_unit)


def load_labels(con: duckdb.DuckDBPyConnection, dataset_id: str, scope: Optional[Set[str]] = None) -> Labels:
    rows = con.execute(
        '''SELECT l.row_id, l.group_id, l.label, l.fragment, l.repo, l.value, coalesce(f.scan_file_id, l.file_id)
           FROM labels l LEFT JOIN files f ON f.dataset_id = l.dataset_id AND f.file_id = l.file_id
           WHERE l.dataset_id = ?''',
        [dataset_id],
    ).fetchall()
    return Labels(r[:6] for r in rows if scope is None or r[6] in scope)


def located_pairs(con: duckdb.DuckDBPyConnection, run_id: str, rank_sql: str) -> List[Tuple[int, int, bool, int]]:
    """(finding_id, row_id, encloses, score) of every `located` pair; the score is the SQL expression given, the tier
    rank or the confidence."""
    return con.execute(
        f'''SELECT m.finding_id, m.row_id, coalesce(m.encloses, false), {rank_sql}
            FROM matches m JOIN findings f ON f.run_id = m.run_id AND f.finding_id = m.finding_id
            WHERE m.run_id = ? AND m.matcher = 'located\'''',
        [run_id],
    ).fetchall()


LEVEL_CUTS = {level: TIER_RANK[level] for level in LEVELS}
# 2.3's --min-confidence: every whole confidence from 0 to 10
CONFIDENCE_CUTS = {str(c): c for c in range(11)}


@dataclass
class Outcome:
    """Per row, group and unit, the best score at which it is found (real) or charged (look-alike)."""

    found: Dict[int, int]
    charged: Dict[int, int]
    group_found: Dict[int, int]
    group_charged: Dict[int, int]
    unit_found: Dict[Tuple[str, str], int]
    unit_charged: Dict[Tuple[str, str], int]


def outcome(labels: Labels, pairs: List[Tuple[int, int, bool, int]]) -> Outcome:
    """The counting rules: a finding paired with a Y row finds it; one paired with an N row charges it unless the same
    finding is paired with any Y row, or the row is a fragment the finding encloses."""
    pairs = [p for p in pairs if p[1] in labels.real and p[3] is not None]
    hits_real = {f for f, row, _, _ in pairs if labels.real[row]}
    found: Dict[int, int] = {}
    charged: Dict[int, int] = {}
    for f, row, enc, rank in pairs:
        if labels.real[row]:
            found[row] = max(found.get(row, -1), rank)
        elif f not in hits_real and not (row in labels.fragment and enc):
            charged[row] = max(charged.get(row, -1), rank)
    group_found: Dict[int, int] = {}
    group_charged: Dict[int, int] = {}
    for row, rank in found.items():
        g = labels.group[row]
        group_found[g] = max(group_found.get(g, -1), rank)
    for row, rank in charged.items():
        g = labels.group[row]
        if not labels.real_group[g]:
            group_charged[g] = max(group_charged.get(g, -1), rank)
    unit_found: Dict[Tuple[str, str], int] = {}
    unit_charged: Dict[Tuple[str, str], int] = {}
    for row, g in labels.group.items():
        u = labels.unit[row]
        if labels.real[row] and g in group_found:
            unit_found[u] = max(unit_found.get(u, -1), group_found[g])
        if not labels.real_unit[u] and g in group_charged:
            unit_charged[u] = max(unit_charged.get(u, -1), group_charged[g])
    return Outcome(found, charged, group_found, group_charged, unit_found, unit_charged)


def count(labels: Labels, pairs: List[Tuple[int, int, bool, int]], cuts: Optional[Dict[str, int]] = None) -> Dict:
    """Each view at each cut: a pair counts at a cut when its score (the finding's tier rank, or its confidence)
    reaches the cut. The reliability table needs tier ranks, so it comes only with the level cuts."""
    by_tier = cuts is None
    cuts = LEVEL_CUTS if cuts is None else cuts
    o = outcome(labels, pairs)
    found, charged = o.found, o.charged
    group_found, group_charged, unit_found, unit_charged = o.group_found, o.group_charged, o.unit_found, o.unit_charged
    pairs = [p for p in pairs if p[1] in labels.real and p[3] is not None]

    n_rows = Counter(labels.real.values())
    n_groups = Counter(labels.real_group.values())
    n_units = Counter(labels.real_unit.values())

    def at(best: Dict, rank: int) -> int:
        return sum(1 for r in best.values() if r >= rank)

    views: Dict = {'per_group': {}, 'per_repository_and_value': {}, 'per_row': {}}
    for level, rank in cuts.items():
        views['per_group'][level] = scores(
            n_groups[True], at(group_found, rank), n_groups[False], at(group_charged, rank)
        )
        views['per_repository_and_value'][level] = scores(
            n_units[True], at(unit_found, rank), n_units[False], at(unit_charged, rank)
        )
        views['per_row'][level] = scores(n_rows[True], at(found, rank), n_rows[False], at(charged, rank))
    if not by_tier:
        return views
    reliability = {}
    for tier in TIERS[1:]:
        rank = TIER_RANK[tier]
        real = sum(1 for r in group_found.values() if r == rank)
        lookalike = sum(1 for r in group_charged.values() if r == rank)
        reliability[tier] = {
            'real_groups': real,
            'lookalike_groups': lookalike,
            'secret_share': _ratio(real, real + lookalike),
        }
    return {**views, 'reliability': reliability, 'paired_findings': len({p[0] for p in pairs})}


def extras(con: duckdb.DuckDBPyConnection, run: Dict, rank_sql: str, scope: Optional[Set[str]] = None) -> Dict:
    """Findings paired with no label, per level, in labelled and in unlabelled files."""
    rows = con.execute(
        f'''SELECT x.file_id, fl.labelled, {rank_sql} FROM findings x
            JOIN files fl ON fl.dataset_id = ? AND fl.file_id = x.file_id
            WHERE x.run_id = ? AND x.finding_id NOT IN
                (SELECT finding_id FROM matches WHERE run_id = ? AND matcher = 'located')''',
        [run['dataset_id'], run['run_id'], run['run_id']],
    ).fetchall()
    out = {}
    for level in LEVELS:
        rank = TIER_RANK[level]
        kept = [
            labelled
            for file_id, labelled, r in rows
            if r is not None and r >= rank and (scope is None or file_id in scope)
        ]
        out[level] = {'in_labelled_files': sum(kept), 'in_unlabelled_files': len(kept) - sum(kept)}
    return out


def finding_tags(con: duckdb.DuckDBPyConnection, run_id: str) -> Dict[int, FrozenSet[str]]:
    """The tags of every tagged finding of a run."""
    tags = {}
    for finding_id, raw in con.execute(
        'SELECT finding_id, tags FROM findings WHERE run_id = ? AND tags IS NOT NULL', [run_id]
    ).fetchall():
        names = frozenset(str(t) for t in json.loads(raw) if t)
        if names:
            tags[finding_id] = names
    return tags


def tag_views(labels: Labels, pairs: List[Tuple[int, int, bool, int]], tags: Dict[int, FrozenSet[str]]) -> Dict:
    """Per tag: its findings, what they reach, and every view without them (`--exclude-tags`)."""
    names = sorted({t for ts in tags.values() for t in ts})
    views = {}
    for name in names + (['all'] if len(names) > 1 else []):
        tagged = {f for f, ts in tags.items() if name == 'all' or name in ts}
        reach = count(labels, [p for p in pairs if p[0] in tagged])
        without = count(labels, [p for p in pairs if p[0] not in tagged])
        views[name] = {
            'findings': len(tagged),
            'reach': {
                view: {
                    level: {'real': v['secrets_found'], 'lookalike': v['lookalikes_found']}
                    for level, v in reach[view].items()
                }
                for view in ('per_group', 'per_repository_and_value')
            },
            'without': {view: without[view] for view in ('per_group', 'per_repository_and_value')},
        }
    return views
