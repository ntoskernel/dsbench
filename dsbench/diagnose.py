"""`diagnose`: why a run missed what it missed and reported what it reported, from the scanner's own tracer.

DeepSecrets ships a replay tool in its source tree, `python -m deepsecrets.diagnostics trace` (from commit 1e66e7a;
not in v2.1.1 or older, and not in the wheels). Given labelled spans, it replays each file through the scan pipeline
and says, stage by stage, where a value was lost or what reported it. dsbench still never imports DeepSecrets: it
runs the tracer as a subprocess of the measured tree, with the run's interpreter.

The tree must be the one the run measured. Its source digest (`tool.source_digest`) is compared with the digest the
run recorded, and a tree that changed since is refused: a trace of other code explains nothing about this run. The
tracer's own package is outside that digest, so its digest is recorded beside the traces.

Cases, one per candidate group, at the `low` level and with the `located` matcher's pairs:

    miss       every real group the run did not find (its first Y row)
    lookalike  every hard-negative group the run was charged for (its first charged row)
    contrast   a seeded sample of found real groups, so a pattern among misses can be told from one among all
    extra      a seeded sample of findings that match no label

The tracer sees each file at its view path (a symlink tree under the run's private directory), as the scanner did,
with `--no-path-exclusions` when the run's profile scans every file and the scanner's default `--deep-max-size`. Cases
and traces hold real values and stay in `runs/<id>/private/diagnosis/`; `diagnosis.json` and what `diagnose` prints are
aggregates: verdicts per kind, the misses' loss funnel, the regex-candidate rules that rejected labelled values
(de-duplicated by span and rule, since one candidate can be recorded once per pass), and a rule ledger from the
tracer's single-rule counterfactuals: the rules without which a found secret would be lost (`carried`), a charged
look-alike would be dropped (`blamed`) or a missed secret would be found (`blocked`)."""

import hashlib
import json
import os
import random
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import duckdb

from dsbench import counting
from dsbench.home import BenchHome
from dsbench.matcher import MATCHER_VERSIONS
from dsbench.metrics import check_pairs, rank_sql, run_scope
from dsbench.runner import DEEP_MAX_SIZE
from dsbench.store import get_run
from dsbench.tool import PACKAGE, Tool, profile_scans_every_file, source_digest

# trace schemas this module reads: 5 (2.2.0) and 6 (2.3: tags in evaluations, candidates and findings)
SCHEMAS = (5, 6)
TRACER = 'diagnostics'
DEFAULTS = {'contrast': 2000, 'extras': 1000, 'seed': 1, 'max_file_mb': 20.0}


class DiagnoseError(Exception):
    pass


def diagnosis_dir(home: BenchHome, run_id: str) -> Path:
    return home.run_dir(run_id) / 'private' / 'diagnosis'


def tracer_digest(cwd: Path) -> Optional[str]:
    package = cwd / PACKAGE / TRACER
    if not package.is_dir():
        return None
    digest = hashlib.sha256()
    for path in sorted(p for p in package.rglob('*') if p.is_file() and '__pycache__' not in p.parts):
        digest.update(path.relative_to(package).as_posix().encode() + b'\0' + path.read_bytes() + b'\0')
    return digest.hexdigest()


def recorded_tool(run: Dict) -> Tool:
    """The scanner the run measured, refused unless its tree still has the recorded digest and holds the tracer."""
    cwd = Path(run['tool_cwd'] or '')
    if not (cwd / PACKAGE).is_dir():
        raise DiagnoseError(f'{cwd} holds no {PACKAGE}/ package')
    digest = source_digest(cwd)
    if run['tool_digest'] and digest != run['tool_digest']:
        raise DiagnoseError(
            f"the tree at {cwd} no longer has the digest {run['run_id']} recorded "
            f"({(digest or '')[:12]} against {run['tool_digest'][:12]}): diagnose a run of a committed tree"
        )
    if tracer_digest(cwd) is None:
        raise DiagnoseError(f'{cwd} has no {PACKAGE}/{TRACER} tracer (source trees from commit 1e66e7a have one)')
    cmd = json.loads(run['tool_cmd'])
    if cmd[1:] != ['-W', 'ignore', '-m', PACKAGE]:
        raise DiagnoseError(f"{run['run_id']} ran a custom command; diagnose needs the scanner's interpreter")
    return Tool(
        cmd=tuple(cmd),
        cwd=cwd,
        profile=run['profile'],
        version=run['tool_version'],
        commit=run['tool_commit'],
        digest=digest,
        ref=run['params'].get('tool_ref'),
    )


# ---------------------------------------------------------------- cases
def _first(rows: Iterable[int]) -> int:
    return min(rows)


def pick_cases(
    con: duckdb.DuckDBPyConnection, run: Dict, contrast: int, extras: int, seed: int
) -> List[Tuple[str, str, int]]:
    """(kind, case id, source id): a label row for misses, look-alikes and contrast, a finding for extras."""
    check_pairs(con, run['run_id'], 'located')
    scope = run_scope(con, run)
    labels = counting.load_labels(con, run['dataset_id'], scope)
    pairs = counting.located_pairs(con, run['run_id'], rank_sql('f.tier'))
    low = counting.TIER_RANK['low']
    o = counting.outcome(labels, [p for p in pairs if p[3] is not None and p[3] >= low])
    rows_of: Dict[int, List[int]] = defaultdict(list)
    for row, g in labels.group.items():
        rows_of[g].append(row)
    picked = []
    for g in sorted(rows_of):
        if labels.real_group[g] and g not in o.group_found:
            picked.append(('miss', f'miss:{g}', _first(r for r in rows_of[g] if labels.real[r])))
        elif not labels.real_group[g] and g in o.group_charged:
            picked.append(('lookalike', f'lookalike:{g}', _first(r for r in rows_of[g] if r in o.charged)))
    found = sorted(o.group_found)
    for g in random.Random(seed).sample(found, min(contrast, len(found))):
        picked.append(('contrast', f'contrast:{g}', _first(r for r in rows_of[g] if r in o.found)))
    paired = {p[0] for p in pairs}
    unpaired = sorted(
        f
        for f, file_id, tier in con.execute(
            'SELECT finding_id, file_id, tier FROM findings WHERE run_id = ?', [run['run_id']]
        ).fetchall()
        if f not in paired and tier != 'info' and (scope is None or file_id in scope)
    )
    for f in random.Random(seed).sample(unpaired, min(extras, len(unpaired))):
        picked.append(('extra', f'extra:{f}', f))
    return picked


def write_cases(
    con: duckdb.DuckDBPyConnection, run: Dict, picked: List[Tuple[str, str, int]], out_dir: Path
) -> Tuple[Path, Dict[str, str]]:
    """cases.jsonl for the tracer, and each case's kind. Each traced file is linked at its view path."""
    files_dir = Path(
        con.execute('SELECT files_dir FROM datasets WHERE dataset_id = ?', [run['dataset_id']]).fetchone()[0]
    )
    view = dict(
        con.execute(
            'SELECT file_id, view_path FROM files WHERE dataset_id = ? AND view_path IS NOT NULL', [run['dataset_id']]
        ).fetchall()
    )
    labels = {
        r[0]: r[1:]
        for r in con.execute(
            '''SELECT l.row_id, coalesce(f.scan_file_id, l.file_id), l.start_line, l.end_line, l.start_col, l.end_col,
                      l.value
               FROM labels l LEFT JOIN files f ON f.dataset_id = l.dataset_id AND f.file_id = l.file_id
               WHERE l.dataset_id = ? AND l.row_id IN (SELECT unnest(?))''',
            [run['dataset_id'], [s for k, _, s in picked if k != 'extra']],
        ).fetchall()
    }
    findings = {
        r[0]: r[1:]
        for r in con.execute(
            '''SELECT finding_id, file_id, start_line, end_line, start_col, end_col, value FROM findings
               WHERE run_id = ? AND finding_id IN (SELECT unnest(?))''',
            [run['run_id'], [s for k, _, s in picked if k == 'extra']],
        ).fetchall()
    }
    target = out_dir / 'target'
    shutil.rmtree(target, ignore_errors=True)
    kinds = {}
    path = out_dir / 'cases.jsonl'
    with open(path, 'w', encoding='utf-8') as out:
        for kind, case_id, source in picked:
            file_id, line, end_line, start_col, end_col, value = (findings if kind == 'extra' else labels)[source]
            if file_id not in view or line is None:
                continue
            link = target / view[file_id]
            if not link.is_symlink():
                link.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(files_dir / file_id, link)
            case = {
                'case_id': case_id,
                'path': str(link),
                'relative_path': view[file_id],
                'line': line,
                'end_line': end_line or line,
                'start_col': start_col or 1,
                'end_col': end_col or 1,
                'value': value or '',
            }
            out.write(json.dumps(case) + '\n')
            kinds[case_id] = kind
    return path, kinds


def run_tracer(tool: Tool, cases: Path, traces: Path, processes: int, max_file_mb: float) -> None:
    args = [
        tool.cmd[0],
        '-W',
        'ignore',
        '-m',
        f'{PACKAGE}.{TRACER}',
        'trace',
        '--cases',
        str(cases),
        '--out',
        str(traces),
        '--processes',
        str(processes),
        '--max-file-mb',
        str(max_file_mb),
        '--deep-max-size',
        str(DEEP_MAX_SIZE),
    ]
    if profile_scans_every_file(tool.profile):
        args.append('--no-path-exclusions')
    with open(traces.with_name('tracer.log'), 'wb') as log:
        done = subprocess.run(args, cwd=tool.cwd, env=tool.env(), stdout=log, stderr=subprocess.STDOUT)
    if done.returncode:
        raise DiagnoseError(f'the tracer exited {done.returncode}; see {traces.with_name("tracer.log")}')


# ---------------------------------------------------------------- analysis
def category(verdict: Dict) -> str:
    """A verdict without its case-specific detail (rule ids, sizes, totals)."""
    stage, component, detail = verdict.get('stage'), verdict.get('component'), verdict.get('detail') or ''
    if stage == 'reported':
        return f'reported by the {component.replace("_", " ")}'
    if stage == 'tier':
        return 'size tier, the lexer would have found it' if 'would have detected' in detail else 'size tier'
    if stage == 'evaluation':
        return {
            'regex_candidate_evaluator': 'regex candidate rejected',
            'variable_evaluator': 'scored not dangerous',
            'semantic_engine': 'no entropy score and no password-like name (S106 gate)',
        }.get(component, f'evaluation: {component}')
    if stage == 'gate':
        return f'gate: {detail}'
    if stage in ('detection', 'emission', 'post_filter', 'token', 'lexer', 'label'):
        return f'{stage}: {detail}'
    if stage == 'selection':
        return 'excluded path'
    return stage or 'no verdict'


def analyse(traces: Iterable[Dict], kinds: Dict[str, str]) -> Dict:
    verdicts: Dict[str, Counter] = defaultdict(Counter)
    schemas = Counter()
    rejected_by: Dict[str, Counter] = defaultdict(Counter)
    ledger = {'carried': Counter(), 'blamed': Counter(), 'blocked': Counter()}
    reported_excluded = Counter()
    traced = Counter()
    for t in traces:
        kind = kinds.get(str(t.get('case_id')))
        if kind is None:
            continue
        schemas[t.get('schema')] += 1
        traced[kind] += 1
        verdict = t.get('verdict') or {}
        verdicts[kind][category(verdict)] += 1
        if verdict.get('stage') == 'reported' and (t.get('selection') or {}).get('excluded_by'):
            reported_excluded[kind] += 1
        seen = set()
        for c in t.get('candidate_evaluation') or []:
            key = (tuple(c.get('span') or ()), c.get('rule'))
            if key not in seen:
                seen.add(key)
                rejected_by[kind][str(c.get('reason') or c.get('rule'))] += 1
        for e in t.get('evaluations') or []:
            for rule, dangerous in (e.get('dangerous_without') or {}).items():
                if kind == 'contrast' and e.get('dangerous') and not dangerous:
                    ledger['carried'][rule] += 1
                elif kind == 'lookalike' and e.get('dangerous') and not dangerous:
                    ledger['blamed'][rule] += 1
                elif kind == 'miss' and not e.get('dangerous') and dangerous:
                    ledger['blocked'][rule] += 1
    unknown = sorted(s for s in schemas if s not in SCHEMAS)
    if unknown:
        raise DiagnoseError(f'trace schema {unknown} is not one dsbench reads ({", ".join(map(str, SCHEMAS))})')
    return {
        'traced': dict(traced),
        'verdicts': {k: dict(v.most_common()) for k, v in sorted(verdicts.items())},
        'reported_in_excluded_files': dict(reported_excluded),
        'rejected_by_candidate_rule': {k: dict(v.most_common(15)) for k, v in sorted(rejected_by.items())},
        'ledger': {k: dict(v.most_common(15)) for k, v in ledger.items()},
        'schemas': {str(k): v for k, v in schemas.items()},
    }


def read_traces(path: Path) -> Iterable[Dict]:
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def diagnose(
    con: duckdb.DuckDBPyConnection,
    home: BenchHome,
    run_id: str,
    processes: int = 8,
    contrast: int = DEFAULTS['contrast'],
    extras: int = DEFAULTS['extras'],
    seed: int = DEFAULTS['seed'],
    max_file_mb: float = DEFAULTS['max_file_mb'],
    reuse_traces: bool = False,
) -> Dict:
    run = get_run(con, run_id)
    out_dir = diagnosis_dir(home, run_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    traces_path = out_dir / 'traces.jsonl'
    meta_path = out_dir / 'meta.json'
    if reuse_traces:
        if not traces_path.is_file() or not meta_path.is_file():
            raise DiagnoseError(f'no stored traces for {run_id}; run `dsbench diagnose --run {run_id}` once')
        meta = json.loads(meta_path.read_text())
        kinds = {}
        with open(out_dir / 'cases.jsonl', encoding='utf-8') as f:
            for line in f:
                case_id = json.loads(line)['case_id']
                kinds[case_id] = case_id.split(':', 1)[0]
    else:
        tool = recorded_tool(run)
        picked = pick_cases(con, run, contrast, extras, seed)
        cases_path, kinds = write_cases(con, run, picked, out_dir)
        started = datetime.now()
        run_tracer(tool, cases_path, traces_path, processes, max_file_mb)
        meta = {
            'run_id': run_id,
            'traced_at': started.isoformat(timespec='seconds'),
            'trace_s': round((datetime.now() - started).total_seconds(), 1),
            'tool': {'cwd': str(tool.cwd), 'commit': tool.commit, 'digest': tool.digest},
            'tracer_digest': tracer_digest(tool.cwd),
            'matcher': MATCHER_VERSIONS['located'],
            'options': {'contrast': contrast, 'extras': extras, 'seed': seed, 'max_file_mb': max_file_mb},
            'cases': dict(Counter(kinds.values())),
        }
        meta_path.write_text(json.dumps(meta, indent=2) + '\n')
    result = {**meta, **analyse(read_traces(traces_path), kinds)}
    (out_dir / 'diagnosis.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
