"""dsbench's command line. The store is opened only by the commands that need it, and `status` falls back to a
run's `progress.json` while a run holds the store's write lock."""

import argparse
import json
import signal
import sys
import time
from collections import deque
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

import duckdb

from dsbench import __version__
from dsbench.compare import CompareError
from dsbench.darkmatter import DarkMatterError
from dsbench.dataset import DatasetError
from dsbench.diagnose import DiagnoseError
from dsbench.doctor import FAIL, run_doctor
from dsbench.home import HomeError, resolve_home
from dsbench.legacy import june, pgcopy
from dsbench.matcher import MatcherError
from dsbench.metrics import MetricsError
from dsbench.places import PlacesError, resolve_places
from dsbench.thirdparty import ThirdPartyError
from dsbench.runner import DEFAULT_SEED, RunError, RunOptions
from dsbench.store import StoreError
from dsbench.tool import DEFAULT_PROFILE, PROFILE_ALIASES, PROFILES, ToolError

# `watch` measures its rate over the progress it saw in this window
WATCH_WINDOW_S = 180


def _percent(value: float) -> str:
    return f'{value:.2%}'


def cmd_doctor(args) -> int:
    places = resolve_places(data=args.data, home=args.home, tool_cwd=args.tool_cwd, cache=args.cache)
    checks = run_doctor(places)
    width = max(len(c.name) for c in checks)
    for c in checks:
        print(f'{c.status:<5} {c.name:<{width}}  {c.detail}')
    failed = sum(c.status == FAIL for c in checks)
    print(f'\n{"not ready" if failed else "ready"}: {failed} failed')
    return 1 if failed else 0


def cmd_preserve(args) -> int:
    from dsbench.legacy.preserve import preserve

    pg_restore = args.pg_restore or pgcopy.find_pg_restore()
    if not pg_restore:
        print(
            f'preserve: no pg_restore of version {pgcopy.MIN_MAJOR}+ (the PGDG postgresql-client-18)', file=sys.stderr
        )
        return 1
    places = resolve_places(data=args.data)
    csv_path = Path(args.csv) if args.csv else (places.data / 'secretbench.csv' if places.data else None)
    if csv_path is None or not csv_path.is_file():
        print('preserve: no labels CSV; pass --csv or set DSBENCH_DATA', file=sys.stderr)
        return 1
    result = preserve(resolve_home(args.home), Path(args.from_dump), csv_path, pg_restore)
    rows, view = result['rows'], result['june_view']
    print(f"exported {result['tables']} into {result['legacy_dir']}")
    print(
        f"June rows: {rows['labelled_rows']:,} labelled, {rows['extra_rows']:,} extras, {rows['unmapped_june_rows']} unmapped"
    )
    print(f"CSV rows absent from June: {rows['csv_rows_absent']}")
    print(
        f"June view: recall {_percent(view['recall'])} ({view['secrets_found']:,}/{view['secrets']:,}), "
        f"FPR {_percent(view['fpr'])}, precision {_percent(view['precision'])}, "
        f"all-rows recall {_percent(view['recall_all_rows'])}"
    )
    return 0


def cmd_june(args) -> int:
    if args.table:
        rows = june.load_rows(Path(args.table))
    else:
        rows = june.load_rows(legacy_dir=resolve_home(args.home).legacy_dir)
    v = june.view(rows)
    print(f'{len(rows):,} June rows; {v["secrets"]:,} clean secrets, {v["lookalikes"]:,} look-alikes')
    print(f'recall    {_percent(v["recall"])}  ({v["secrets_found"]:,} found)')
    print(f'precision {_percent(v["precision"])}  ({v["lookalikes_found"]:,} look-alikes charged)')
    print(f'FPR       {_percent(v["fpr"])}')
    print(f'F1        {_percent(v["f1"])}')
    print(f'recall over all {v["all_secrets"]:,} secrets {_percent(v["recall_all_rows"])}')
    return 0


def cmd_prepare(args) -> int:
    from dsbench.dataset import prepare
    from dsbench.store import connect

    places = resolve_places(data=args.data)
    csv_path = Path(args.csv) if args.csv else (places.data / 'secretbench.csv' if places.data else None)
    files_dir = Path(args.files) if args.files else (places.data / 'Files' if places.data else None)
    if csv_path is None or not csv_path.is_file() or files_dir is None or not files_dir.is_dir():
        print('prepare: pass --csv and --files, or set DSBENCH_DATA', file=sys.stderr)
        return 1
    home = resolve_home(args.home)
    with connect(home) as con:
        dataset_id, stats = prepare(con, home, csv_path, files_dir, force=args.force)
    state = 'already prepared' if stats.get('already_prepared') else 'prepared'
    print(f'{dataset_id} {state}')
    print(
        f"rows      {stats['rows']:,} ({stats['rows_y']:,} Y, {stats['rows_n']:,} N) in {stats['repositories']:,} repositories"
    )
    print(
        f"files     {stats['files']:,} ({stats['files_labelled']:,} labelled, {stats['files_unlabelled']:,} not), "
        f"{stats['bytes'] / 1e9:,.3f} GB; {stats['files_scanned']:,} to scan"
    )
    print(
        f"aliases   {stats['aliases']}, view paths moved {stats['views_suffixed']}, labelled files missing {stats['labelled_files_missing']}"
    )
    print(
        f"groups    {stats['groups']:,} ({stats['groups_real']:,} real, {stats['groups_hard_negative']:,} hard negatives); "
        f"{stats['fragment_rows']:,} fragment rows"
    )
    print('issues    ' + (', '.join(f'{k} {v:,}' for k, v in stats['issues'].items()) or 'none'))
    return 0


def _interrupt(signum, frame):
    raise KeyboardInterrupt


def cmd_run(args) -> int:
    opts = RunOptions(
        cores=args.cores, shard_timeout=args.shard_timeout, solo_timeout=args.solo_timeout, attempts=args.attempts
    )
    home = resolve_home(args.home)
    previous = signal.signal(signal.SIGTERM, _interrupt)
    try:
        return _run(args, opts, home)
    finally:
        signal.signal(signal.SIGTERM, previous)


def _run(args, opts: RunOptions, home) -> int:
    from dsbench.runner import Runner
    from dsbench.store import connect, resolve_dataset
    from dsbench.places import tool_python
    from dsbench.tool import check_module, ensure_venv, extract_ref, resolve_thirdparty, resolve_tool

    with connect(home) as con:
        if args.resume:
            runner = Runner.resume(con, home, args.resume, opts)
        else:
            places = resolve_places(tool_cwd=args.tool_cwd, cache=args.cache)
            python = None
            if args.tool != 'deepsecrets':
                if places.cache is None:
                    print(f'run: --tool {args.tool} needs the cache (--cache) it was fetched into', file=sys.stderr)
                    return 1
                tool = resolve_thirdparty(args.tool, places.cache, args.profile)
            elif args.tool_ref:
                if places.cache is None or places.tool_cwd is None:
                    print('run: --tool-ref needs the repository (--tool-cwd) and the cache (--cache)', file=sys.stderr)
                    return 1
                cwd = extract_ref(places.tool_cwd, args.tool_ref, places.cache)
                if not args.tool_cmd:
                    print(f'[run] the venv of {args.tool_ref}, from its {cwd.name}/poetry.lock ...', flush=True)
                    python = ensure_venv(cwd, places.cache, tool_python())
            else:
                cwd = places.tool_cwd or Path.cwd()
            if args.tool == 'deepsecrets':
                tool = resolve_tool(cwd, args.tool_cmd, args.profile, args.tool_ref, python=python)
                check_module(tool)
            runner = Runner.create(
                con,
                home,
                resolve_dataset(con, args.dataset),
                tool,
                opts,
                label=args.label,
                sample=(args.sample, args.seed) if args.sample else None,
                labelled_only=args.labelled_only,
            )
        t = runner.tool
        name = 'DeepSecrets' if t.kind == 'deepsecrets' else t.kind
        print(
            f'[run] {runner.run_id}: {name} {t.version}'
            + (f' at {t.commit}' if t.commit else '')
            + f' in {t.cwd}, profile {t.profile}, '
            f'{len(runner.queue):,} shards for {runner.total_files - runner.tally.files_done:,} files, '
            f'--cores {opts.cores}',
            flush=True,
        )
        try:
            result = runner.execute()
        except KeyboardInterrupt:
            print(f'[run] interrupted; continue with `dsbench run --resume {runner.run_id}`', file=sys.stderr)
            return 130
        print(
            f"[run] {result['status']}: {result['files_done']:,} files, {result['findings']:,} findings, "
            f"{result['done']:,} shards done, {result['split']} split, {result['failed']} failed, "
            f"scanner CPU {result['cpu_s'] / 3600:,.2f} h",
            flush=True,
        )
        if args.no_analyze:
            return 0 if result['status'] == 'done' else 1
        _analyze(con, home, runner.run_id)
    return 0 if result['status'] == 'done' else 1


def _analyze(con, home, run_id: str, matchers=None, processes: Optional[int] = None) -> None:
    from dsbench.matcher import MATCHERS, match_run
    from dsbench.metrics import write_metrics

    for m in match_run(con, home, run_id, matchers or MATCHERS, processes).values():
        kinds = m.get('label_kinds')
        print(
            f"[match] {m['matcher']} ({m['matcher_version']}): {m['pairs']:,} pairs, "
            f"{m['rows_matched']:,} rows, {m['findings_matched']:,} of {m['findings']:,} findings"
            + (f"; labels located {', '.join(f'{k} {n:,}' for k, n in kinds.items())}" if kinds else '')
        )
    _print_metrics(write_metrics(con, home, run_id), home.run_dir(run_id))


def _print_metrics(m: dict, run_dir: Path) -> None:
    files, loc = m['files'], m['located']
    print(
        f"files: {files['artifacts']:,} of {files['to_scan']:,}; "
        + ', '.join(f'{s} {n:,}' for s, n in files['status'].items())
    )
    print('located, per candidate group, then per (repository, value):')
    for level in loc['per_group']:
        g, u = loc['per_group'][level], loc['per_repository_and_value'][level]
        print(
            f"  {level:<9} recall {_percent(g['recall'])} ({g['secrets_found']:,}), precision {_percent(g['precision'])} "
            f"({g['lookalikes_found']:,} charged), F1 {_percent(g['f1'])} | "
            f"recall {_percent(u['recall'])} ({u['secrets_found']:,}), precision {_percent(u['precision'])}"
        )
    if m['june_way'] is None:
        why = 'a sample run' if (m.get('scope') or {}).get('sample') else "June's rows are not this dataset's labels"
        print(f'June view: not applicable, {why}')
        print(f'written: {run_dir / "metrics.json"}, {run_dir / "summary.md"}')
        return
    print('June way, then per (repository, value):')
    for level in m['june_way']:
        v, u = m['june_way'][level], m['per_repository_and_value'][level]
        print(
            f"  {level:<9} recall {_percent(v['recall'])} ({v['secrets_found']:,}), precision {_percent(v['precision'])} "
            f"({v['lookalikes_found']:,} charged), F1 {_percent(v['f1'])} | "
            f"recall {_percent(u['recall'])}, precision {_percent(u['precision'])}"
        )
    print(f'written: {run_dir / "metrics.json"}, {run_dir / "summary.md"}')


def cmd_match(args) -> int:
    from dsbench.store import connect

    home = resolve_home(args.home)
    with connect(home) as con:
        _analyze(con, home, args.run, None if args.matcher == 'all' else (args.matcher,), args.processes)
    return 0


def cmd_metrics(args) -> int:
    from dsbench.metrics import write_metrics
    from dsbench.store import connect

    home = resolve_home(args.home)
    with connect(home) as con:
        _print_metrics(write_metrics(con, home, args.run), home.run_dir(args.run))
    return 0


def cmd_diagnose(args) -> int:
    from dsbench.diagnose import diagnose
    from dsbench.store import connect

    home = resolve_home(args.home)
    with connect(home) as con:
        d = diagnose(
            con,
            home,
            args.run,
            processes=args.processes,
            contrast=args.contrast,
            extras=args.extras,
            seed=args.seed,
            max_file_mb=args.max_file_mb,
            reuse_traces=args.reuse_traces,
        )
    print(f"traced {', '.join(f'{n:,} {k}' for k, n in d['traced'].items())} (schema {', '.join(d['schemas'])})")
    for kind in ('miss', 'lookalike'):
        verdicts = d['verdicts'].get(kind, {})
        if verdicts:
            print(f'{kind}, by the first stage that explains it:')
            for name, n in verdicts.items():
                print(f'  {n:>6,}  {name}')
    print(f'written: {home.run_dir(args.run) / "private" / "diagnosis" / "diagnosis.json"}')
    return 0


def cmd_compare(args) -> int:
    from dsbench.compare import compare
    from dsbench.store import connect

    home = resolve_home(args.home)
    with connect(home) as con:
        c = compare(con, home, args.runs, name=args.name, samples=args.bootstrap, seed=args.seed)
    print('per candidate group, then per (repository, value), at low:')
    for r in c['runs']:
        g, u = r['per_group']['low'], r['per_repository_and_value']['low']
        print(
            f"  {r['tool']:<22} recall {_percent(g['recall'])}, precision {_percent(g['precision'])} | "
            f"recall {_percent(u['recall'])}, precision {_percent(u['precision'])}"
        )
    print(f"written: {c['written_to']}/compare.json, compare.md")
    return 0


def _progress_path(home, run_id: Optional[str]) -> Optional[Path]:
    """The run's progress.json, or else the most recently updated one of a running run, or else of any run."""
    if run_id:
        path = home.run_dir(run_id) / 'progress.json'
        return path if path.is_file() else None
    found = sorted(home.runs_dir.glob('*/progress.json'), key=lambda p: p.stat().st_mtime, reverse=True)
    running = [p for p in found if json.loads(p.read_text()).get('status') == 'running']
    return (running or found or [None])[0]


def watch_lines(p: Dict, samples: Deque[Tuple[float, int, int]]) -> List[str]:
    """The view of one progress.json; `samples` are (monotonic time, files done, shards done) seen so far. The ETA
    counts shards, which the planner gives roughly equal cost, not files, which come largest first."""
    files, shards = p['files'], p['shards']
    share = files['done'] / files['total'] if files['total'] else 0.0
    total_shards = shards['done'] + shards['running'] + shards['queued']
    lines = [
        f"dsbench run {p['run_id']}  {p['status']}  (--cores {p.get('cores', '?')}, updated {p['updated_at'][11:]})",
        f"files     [{'#' * round(share * 40):<40}] {share:6.1%}  {files['done']:,} of {files['total']:,}",
        f"shards    {shards['done']:,} of {total_shards:,} done, {shards['running']} running, {shards['queued']:,} queued"
        f" | {shards['failed']} failed, {shards['split']} split, {shards['retried']} retried",
        f"findings  {p['findings']:,}   cpu {p['cpu_s'] / 3600:.2f} h   elapsed {p['elapsed_s'] / 60:.1f} min"
        '   (since this session started)',
        'statuses  ' + (', '.join(f'{s} {n:,}' for s, n in p.get('statuses', {}).items()) or '-'),
    ]
    first, last = samples[0], samples[-1]
    span = last[0] - first[0]
    if p['status'] != 'running':
        lines.append(f"stopped: {p['status']}")
    elif span < 20 or last[2] == first[2]:
        lines.append('rate      measuring...')
    else:
        shard_rate = (last[2] - first[2]) / span
        eta = (shards['running'] / 2 + shards['queued']) / shard_rate
        lines.append(
            f"rate      {(last[1] - first[1]) / span:,.0f} files/s, {shard_rate * 60:,.1f} shards/min"
            f" over the last {span / 60:.1f} min   ETA ~{eta / 60:,.0f} min"
        )
    return lines


def cmd_watch(args) -> int:
    home = resolve_home(args.home)
    path = _progress_path(home, args.run)
    if path is None:
        print('watch: no run with a progress.json', file=sys.stderr)
        return 1
    samples: Deque[Tuple[float, int, int]] = deque()
    clear = sys.stdout.isatty() and not args.once
    try:
        while True:
            p = json.loads(path.read_text())
            now = time.monotonic()
            samples.append((now, p['files']['done'], p['shards']['done']))
            while now - samples[0][0] > WATCH_WINDOW_S:
                samples.popleft()
            print(('\033[H\033[2J' if clear else '') + '\n'.join(watch_lines(p, samples)), flush=True)
            if args.once or p['status'] != 'running':
                return 0
            time.sleep(args.every)
    except KeyboardInterrupt:
        return 0


def cmd_darkmatter(args) -> int:
    from dsbench import darkmatter
    from dsbench.metrics import rank_sql
    from dsbench.store import connect

    home = resolve_home(args.home)
    if args.dm_command == 'import':
        result = darkmatter.import_verdicts(home, Path(args.csv), args.source, Path(args.units) if args.units else None)
        print(
            f"imported {', '.join(f'{v} {n:,}' for v, n in result['imported'].items()) or 'nothing'}; "
            f"the overlay holds {result['overlay_units']:,} units"
        )
        return 0
    with connect(home) as con:
        s = darkmatter.export(con, home, args.runs, rank_sql('x.tier'), name=args.name, per_sheet=args.per_sheet)
    print(
        f"{s['units']:,} units beyond the labels from {s['findings']:,} findings; per run: "
        + ', '.join(f'{r} {n:,}' for r, n in s['units_per_run'].items())
    )
    print('settled: ' + ', '.join(f'{k} {n:,}' for k, n in sorted(s['settled'].items())))
    print(f"{s['sheets']} review sheets; written: {s['written_to']}")
    return 0


def cmd_tools(args) -> int:
    from dsbench import thirdparty

    places = resolve_places(cache=args.cache)
    if places.cache is None:
        print('tools: pass --cache or set DSBENCH_CACHE', file=sys.stderr)
        return 1
    unknown = [n for n in args.names if n not in thirdparty.RELEASES]
    if unknown:
        print(f'tools: unknown {", ".join(unknown)}; known: {", ".join(thirdparty.RELEASES)}', file=sys.stderr)
        return 1
    for name in args.names or list(thirdparty.RELEASES):
        where = thirdparty.fetch(name, places.cache)
        marker = json.loads((where / thirdparty.MARKER).read_text())
        print(f"{name} {marker['version']}: {where} (archive {marker['sha256'][:12]}, verified)")
    return 0


def cmd_status(args) -> int:
    from dsbench.store import connect

    home = resolve_home(args.home)
    try:
        con = connect(home, read_only=True)
    except duckdb.IOException:
        print('the store is locked by a running dsbench; progress of the runs:')
        for progress in sorted(home.runs_dir.glob('*/progress.json')):
            p = json.loads(progress.read_text())
            if p['status'] == 'running':
                print(
                    f"  {p['run_id']}: {p['files']['done']:,} of {p['files']['total']:,} files, "
                    f"{p['shards']['running']} shards running, {p['shards']['queued']:,} queued, "
                    f"{p['findings']:,} findings, {p['elapsed_s'] / 60:,.1f} min, updated {p['updated_at']}"
                )
        return 0
    with con:
        print('datasets:')
        for dataset_id, created, stats in con.execute(
            'SELECT dataset_id, created_at, stats FROM datasets ORDER BY created_at'
        ).fetchall():
            s = json.loads(stats)
            print(f"  {dataset_id}  {created:%Y-%m-%d %H:%M}  {s['rows']:,} rows, {s['files']:,} files")
        print('runs:')
        for run_id, status, version, commit, params, files, findings in con.execute(
            '''SELECT r.run_id, r.status, r.tool_version, r.tool_commit, r.params,
                      (SELECT count(*) FROM artifacts a WHERE a.run_id = r.run_id),
                      (SELECT count(*) FROM findings f WHERE f.run_id = r.run_id)
               FROM runs r ORDER BY r.started_at'''
        ).fetchall():
            label = json.loads(params).get('label')
            kind = json.loads(params).get('tool_kind') or 'deepsecrets'
            name = {'deepsecrets': 'DeepSecrets', 'betterleaks': 'Betterleaks'}.get(kind, kind)
            print(
                f"  {run_id}  {status:<11} {name} {version} at {commit}  {files:,} files, {findings:,} findings"
                + (f'  [{label}]' if label else '')
            )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='dsbench', description='Benchmark DeepSecrets as a black box.')
    parser.add_argument('--version', action='version', version=f'dsbench {__version__}')
    parser.add_argument('--home', help='bench home (default: $DSBENCH_HOME)')
    parser.add_argument('--data', help='datasets directory (default: $DSBENCH_DATA)')
    sub = parser.add_subparsers(dest='command', required=True)

    doctor = sub.add_parser('doctor', help='check the places, the data, the tool and the legacy table')
    doctor.add_argument('--tool-cwd', help='the scanner checkout (default: $DSBENCH_TOOL_CWD)')
    doctor.add_argument('--cache', help='venvs and release trees (default: $DSBENCH_CACHE)')
    doctor.set_defaults(func=cmd_doctor)

    preserve = sub.add_parser('preserve', help="export the June 2026 Postgres dump into the bench home")
    preserve.add_argument('--from-dump', required=True, help='the pg_dump custom-format archive')
    preserve.add_argument('--csv', help='the labels (default: $DSBENCH_DATA/secretbench.csv)')
    preserve.add_argument('--pg-restore', help='pg_restore 17 or later (default: found automatically)')
    preserve.set_defaults(func=cmd_preserve)

    june_cmd = sub.add_parser('june', help="June's own figures, from the bench home's values-free June table")
    june_cmd.add_argument('--table', help="a june_rows.csv.gz (default: the bench home's latest export)")
    june_cmd.set_defaults(func=cmd_june)

    prepare_cmd = sub.add_parser('prepare', help='load the labels and the corpus listing into the store')
    prepare_cmd.add_argument('--csv', help='the labels (default: $DSBENCH_DATA/secretbench.csv)')
    prepare_cmd.add_argument('--files', help='the corpus directory (default: $DSBENCH_DATA/Files)')
    prepare_cmd.add_argument('--force', action='store_true', help='rebuild a dataset prepared before')
    prepare_cmd.set_defaults(func=cmd_prepare)

    run = sub.add_parser('run', help='scan a dataset with the scanner under test, then match and count')
    run.add_argument('--dataset', default='latest', help='a dataset id (default: the latest prepared)')
    run.add_argument(
        '--tool-cwd', help='the scanner checkout, or the repository of --tool-ref (default: $DSBENCH_TOOL_CWD)'
    )
    run.add_argument(
        '--tool',
        default='deepsecrets',
        choices=['deepsecrets', 'gitleaks', 'betterleaks'],
        help='the scanner: DeepSecrets (default), or a release fetched with `dsbench tools fetch`',
    )
    run.add_argument('--tool-cmd', help='the scanner command (default: python -W ignore -m deepsecrets)')
    run.add_argument(
        '--tool-ref',
        help="scan a ref's committed tree, extracted into $DSBENCH_CACHE/trees/, in a venv from that ref's poetry.lock",
    )
    run.add_argument('--cache', help='venvs and release trees (default: $DSBENCH_CACHE)')
    run.add_argument(
        '--profile',
        default=DEFAULT_PROFILE,
        choices=[*PROFILES, *PROFILE_ALIASES],
        help='all-files (default; the only profile whose numbers are quoted) or scanner-defaults',
    )
    run.add_argument('--cores', type=int, default=16, help='scanner processes at once (default: 16)')
    run.add_argument('--shard-timeout', type=float, default=3600, help='seconds for a packed shard (default: 3600)')
    run.add_argument('--solo-timeout', type=float, default=4 * 3600, help='seconds for one file (default: 14400)')
    run.add_argument('--attempts', type=int, default=2, help='tries for a single file before giving up (default: 2)')
    run.add_argument('--label', help='a free-text name for the build, kept in the run\'s params')
    run.add_argument('--sample', type=int, metavar='N', help='scan N labelled files drawn with --seed')
    run.add_argument(
        '--seed', type=int, default=DEFAULT_SEED, help='the sample\'s seed (default: 11, the reference sample)'
    )
    run.add_argument('--labelled-only', action='store_true', help='leave out the files without a label')
    run.add_argument('--resume', metavar='RUN', help='continue an interrupted run with its own scanner')
    run.add_argument('--no-analyze', action='store_true', help='scan only; match and metrics later')
    run.set_defaults(func=cmd_run)

    match = sub.add_parser('match', help="pair a run's findings with the labels, then count")
    match.add_argument('--run', required=True)
    match.add_argument(
        '--matcher',
        default='all',
        choices=['all', 'located', 'legacy'],
        help='which pairs to store again (default: all)',
    )
    match.add_argument('--processes', type=int, help='processes that read the corpus for `located` (default: up to 16)')
    match.set_defaults(func=cmd_match)

    metrics = sub.add_parser('metrics', help="count a run's stored pairs: metrics.json and summary.md")
    metrics.add_argument('--run', required=True)
    metrics.set_defaults(func=cmd_metrics)

    diag = sub.add_parser('diagnose', help="trace a run's misses and charged look-alikes through the scanner's tracer")
    diag.add_argument('--run', required=True)
    diag.add_argument('--processes', type=int, default=8, help='tracer processes (default: 8)')
    diag.add_argument('--contrast', type=int, default=2000, help='found real groups to trace for contrast')
    diag.add_argument('--extras', type=int, default=1000, help='unlabelled findings to trace')
    diag.add_argument('--seed', type=int, default=1, help='the seed of both samples (default: 1)')
    diag.add_argument('--max-file-mb', type=float, default=20.0, help='larger files are not traced (default: 20)')
    diag.add_argument('--reuse-traces', action='store_true', help='analyse the stored traces again without tracing')
    diag.set_defaults(func=cmd_diagnose)

    cmp = sub.add_parser('compare', help='runs of one dataset head to head: every level, the reliability table')
    cmp.add_argument('runs', nargs='+', metavar='RUN', help='two runs or more; differences are taken from the first')
    cmp.add_argument('--name', help='the comparison\'s name in comparisons/<date>-<name>/')
    cmp.add_argument('--bootstrap', type=int, default=1000, help='repository-bootstrap samples (default: 1000)')
    cmp.add_argument('--seed', type=int, default=1, help='the bootstrap seed (default: 1)')
    cmp.set_defaults(func=cmd_compare)

    dm = sub.add_parser('darkmatter', help='units beyond the labels: export them for judging, import verdicts')
    dm_sub = dm.add_subparsers(dest='dm_command', required=True)
    dm_export = dm_sub.add_parser('export', help='units, evidence, rule verdicts and masked review sheets')
    dm_export.add_argument('--runs', nargs='+', required=True, metavar='RUN')
    dm_export.add_argument('--name', help="the export's name in darkmatter/<date>-<name>/")
    dm_export.add_argument('--per-sheet', type=int, default=100, help='units per review sheet (default: 100)')
    dm_export.set_defaults(func=cmd_darkmatter)
    dm_import = dm_sub.add_parser('import', help='merge verdicts into the overlay')
    dm_import.add_argument('csv', help="an export's rules.csv, or its filled verdicts-template.csv")
    dm_import.add_argument('--source', required=True, help='who or what gave the verdicts')
    dm_import.add_argument('--units', help="the export's units.jsonl, to resolve a template's unit ids")
    dm_import.set_defaults(func=cmd_darkmatter)

    tools = sub.add_parser('tools', help='other scanners: fetch the pinned gitleaks and Betterleaks releases')
    tools_sub = tools.add_subparsers(dest='tools_command', required=True)
    fetch = tools_sub.add_parser('fetch', help='download, verify and unpack into $DSBENCH_CACHE/tools/')
    fetch.add_argument('names', nargs='*', metavar='NAME', help='gitleaks, betterleaks (default: both)')
    fetch.add_argument('--cache', help='where to keep them (default: $DSBENCH_CACHE)')
    fetch.set_defaults(func=cmd_tools)

    status = sub.add_parser('status', help='datasets and runs')
    status.set_defaults(func=cmd_status)

    watch = sub.add_parser('watch', help="a live view of a run's progress, until it stops")
    watch.add_argument('--run', help='a run id (default: the running run, else the latest)')
    watch.add_argument('--every', type=float, default=5.0, help='seconds between redraws (default: 5)')
    watch.add_argument('--once', action='store_true', help='print the view once and exit')
    watch.set_defaults(func=cmd_watch)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (
        HomeError,
        PlacesError,
        StoreError,
        DatasetError,
        ToolError,
        RunError,
        MatcherError,
        MetricsError,
        DiagnoseError,
        CompareError,
        DarkMatterError,
        ThirdPartyError,
    ) as e:
        print(f'dsbench: {e}', file=sys.stderr)
        return 1
