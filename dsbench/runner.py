"""`run`: one scan of a prepared dataset by the scanner under test, in shards.

Files are planned longest-first by an estimate from their size: every file over 5 MB
gets a shard of its own, the rest are packed into shards of about equal estimated cost (at most 2,000 files each), and
the shards are queued most expensive first. `--cores` scanner processes run at once, each a shard scanned with
`--process-count 1` in its own process group, so `--cores` is exactly the number of busy scanners. A shard that times
out or fails is split in two; a single file is tried again, then recorded with the harness's own status (`timeout` or
`tool_error`). There is no memory admission: the scanner's size tier (since 2.2) keeps a worker's memory bounded.

A shard's directory is `runs/<run_id>/shards/sNNNNN/` with `target/` (symlinks at the view paths into the corpus),
`report.sarif` and `scanner.log`. Its report is ingested in one transaction when it finishes, so a run interrupted at
any point keeps every finished shard, and `--resume` scans only the files without an artifact, with the run's own
scanner (refusing one whose source digest changed). `progress.json` in the run directory says how far a run is."""

import json
import os
import platform
import shlex
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, IO, List, Optional, Tuple

import duckdb

from dsbench.home import BenchHome
from dsbench.sarif import TIER_SUFFIXES, Report, SarifError, read_report
from dsbench.store import bulk_insert, fetch_dicts, get_run
from dsbench.tool import Tool, resolve_tool

SOLO_BYTES = 5_000_000
MAX_FILES = 2_000
# the scanner's default size tier: a file up to it gets the lexer, which costs far more per byte than the regex rules
DEEP_MAX_SIZE = 250_000
DEEP_WEIGHT = 8
# a per-file floor, so thousands of tiny files are not planned as free
MIN_COST = 20_000
SHARDS_PER_CORE = 12
PROGRESS_EVERY_S = 10.0


class RunError(Exception):
    pass


@dataclass
class RunOptions:
    cores: int = 16
    shard_timeout: float = 3600.0
    solo_timeout: float = 4 * 3600.0
    attempts: int = 2
    solo_bytes: int = SOLO_BYTES
    max_files: int = MAX_FILES
    poll_s: float = 0.25

    def params(self) -> Dict:
        return {
            'cores': self.cores,
            'shard_timeout': self.shard_timeout,
            'solo_timeout': self.solo_timeout,
            'attempts': self.attempts,
            'solo_bytes': self.solo_bytes,
            'max_files': self.max_files,
        }


def cost(size: int) -> int:
    return size * (DEEP_WEIGHT if size <= DEEP_MAX_SIZE else 1) + MIN_COST


def plan(files: List[dict], cores: int, solo_bytes: int = SOLO_BYTES, max_files: int = MAX_FILES) -> List[List[dict]]:
    """Shards of files (dicts with `file_id`, `view_path`, `size`), most expensive first."""
    ordered = sorted(files, key=lambda f: (-f['size'], f['file_id']))
    solo = [[f] for f in ordered if f['size'] > solo_bytes]
    rest = [f for f in ordered if f['size'] <= solo_bytes]
    groups = list(solo)
    if rest:
        total = sum(cost(f['size']) for f in rest)
        budget = max(total / max(cores * SHARDS_PER_CORE, 1), cost(rest[0]['size']))
        current: List[dict] = []
        spent = 0
        for f in rest:
            if current and (spent + cost(f['size']) > budget or len(current) >= max_files):
                groups.append(current)
                current, spent = [], 0
            current.append(f)
            spent += cost(f['size'])
        groups.append(current)
    return sorted(groups, key=lambda g: -sum(cost(f['size']) for f in g))


def split(files: List[dict]) -> List[List[dict]]:
    """Two halves of about equal estimated cost."""
    halves: Tuple[List[dict], List[dict]] = ([], [])
    spent = [0, 0]
    for f in sorted(files, key=lambda f: -f['size']):
        side = 0 if spent[0] <= spent[1] else 1
        halves[side].append(f)
        spent[side] += cost(f['size'])
    return [h for h in halves if h]


@dataclass
class PlannedShard:
    shard_id: str
    files: List[dict]
    attempts: int = 0

    @property
    def bytes(self) -> int:
        return sum(f['size'] for f in self.files)

    @property
    def est_cost(self) -> int:
        return sum(cost(f['size']) for f in self.files)


@dataclass
class Running:
    shard: PlannedShard
    proc: subprocess.Popen
    started: float
    timeout: float
    log: IO[bytes]


@dataclass
class Tally:
    done: int = 0
    split: int = 0
    failed: int = 0
    retried: int = 0
    files_done: int = 0
    findings: int = 0
    cpu_s: float = 0.0
    unknown_uris: int = 0
    statuses: Dict[str, int] = field(default_factory=dict)


def new_run_id(profile: str, now: Optional[datetime] = None) -> str:
    return f"{(now or datetime.now()).strftime('%Y%m%d-%H%M%S')}-{profile}"


def host_info(tool: Tool) -> Dict:
    info = {
        'hostname': socket.gethostname(),
        'cpus': os.cpu_count(),
        'cpus_usable': len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else os.cpu_count(),
        'platform': platform.platform(),
    }
    try:
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.startswith('model name'):
                info['cpu_model'] = line.split(':', 1)[1].strip()
                break
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemTotal:'):
                info['mem_gib'] = round(int(line.split()[1]) / 2**20, 1)
                break
    except OSError:
        pass
    try:
        done = subprocess.run([tool.cmd[0], '--version'], capture_output=True, text=True, timeout=60)
        info['tool_python'] = (done.stdout or done.stderr).strip() or None
    except OSError:
        info['tool_python'] = None
    return info


def _write_json(path: Path, data: Dict) -> None:
    staged = path.with_suffix('.tmp')
    staged.write_text(json.dumps(data, indent=2, default=str) + '\n')
    staged.replace(path)


class Runner:
    def __init__(
        self, con: duckdb.DuckDBPyConnection, home: BenchHome, run: Dict, tool: Tool, opts: RunOptions
    ) -> None:
        self.con, self.home, self.run, self.tool, self.opts = con, home, run, tool, opts
        self.run_id = run['run_id']
        self.run_dir = home.run_dir(self.run_id)
        files_dir = con.execute('SELECT files_dir FROM datasets WHERE dataset_id = ?', [run['dataset_id']]).fetchone()
        self.files_dir = Path(files_dir[0])
        last_shard = con.execute(
            "SELECT max(CAST(substr(shard_id, 2) AS INTEGER)) FROM shards WHERE run_id = ?", [self.run_id]
        ).fetchone()[0]
        self.next_shard = (last_shard or 0) + 1
        last_finding = con.execute('SELECT max(finding_id) FROM findings WHERE run_id = ?', [self.run_id]).fetchone()[0]
        self.next_finding = (last_finding or 0) + 1
        self.tally = Tally()
        self.queue: List[PlannedShard] = []
        self.total_files = 0

    # ------------------------------------------------------------------ creating and resuming
    @classmethod
    def create(
        cls,
        con: duckdb.DuckDBPyConnection,
        home: BenchHome,
        dataset_id: str,
        tool: Tool,
        opts: RunOptions,
        label: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> 'Runner':
        run_id = run_id or new_run_id(tool.profile)
        if con.execute('SELECT 1 FROM runs WHERE run_id = ?', [run_id]).fetchone() or home.run_dir(run_id).exists():
            raise RunError(f'run {run_id} exists already')
        params = {**opts.params(), 'label': label, 'tool_ref': tool.ref, 'resumed_with': [], 'segments': []}
        con.execute(
            '''INSERT INTO runs (run_id, dataset_id, tool_cmd, tool_cwd, tool_version, tool_commit, tool_digest,
                   profile, params, host, diagnostics, started_at, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?, 'running')''',
            [
                run_id,
                dataset_id,
                json.dumps(list(tool.cmd)),
                str(tool.cwd),
                tool.version,
                tool.commit,
                tool.digest,
                tool.profile,
                json.dumps(params),
                json.dumps(host_info(tool)),
                datetime.now(),
            ],
        )
        home.run_dir(run_id).mkdir(parents=True)
        runner = cls(con, home, get_run(con, run_id), tool, opts)
        files = fetch_dicts(
            con,
            'SELECT file_id, view_path, size FROM files WHERE dataset_id = ? AND view_path IS NOT NULL',
            [dataset_id],
        )
        runner.queue = runner._register(plan(files, opts.cores, opts.solo_bytes, opts.max_files))
        runner.total_files = len(files)
        return runner

    @classmethod
    def resume(cls, con: duckdb.DuckDBPyConnection, home: BenchHome, run_id: str, opts: RunOptions) -> 'Runner':
        run = get_run(con, run_id)
        recorded_cmd = shlex.join(json.loads(run['tool_cmd']))
        tool = resolve_tool(Path(run['tool_cwd']), recorded_cmd, run['profile'], run['params'].get('tool_ref'))
        if run['tool_digest'] and tool.digest != run['tool_digest']:
            raise RunError(f'the scanner in {tool.cwd} changed since {run_id} started (source digest differs)')
        con.begin()
        # a finished shard was ingested whole; anything else is scanned again
        con.execute(
            """DELETE FROM artifacts WHERE run_id = ? AND status IN ('timeout', 'tool_error')""",
            [run_id],
        )
        con.execute(
            """UPDATE shards SET status = 'abandoned' WHERE run_id = ? AND status IN ('pending', 'running', 'failed')""",
            [run_id],
        )
        params = run['params']
        params.setdefault('resumed_with', []).append(
            {'at': datetime.now().isoformat(timespec='seconds'), **opts.params()}
        )
        con.execute(
            "UPDATE runs SET params = ?, status = 'running', finished_at = NULL WHERE run_id = ?",
            [json.dumps(params), run_id],
        )
        con.commit()
        runner = cls(con, home, get_run(con, run_id), tool, opts)
        todo = fetch_dicts(
            con,
            '''SELECT f.file_id, f.view_path, f.size FROM files f
               WHERE f.dataset_id = ? AND f.view_path IS NOT NULL
                 AND f.file_id NOT IN (SELECT file_id FROM artifacts WHERE run_id = ?)''',
            [run['dataset_id'], run_id],
        )
        runner.queue = runner._register(plan(todo, opts.cores, opts.solo_bytes, opts.max_files))
        runner.total_files = con.execute(
            'SELECT count(*) FROM files WHERE dataset_id = ? AND view_path IS NOT NULL', [run['dataset_id']]
        ).fetchone()[0]
        runner.tally.files_done = runner.total_files - len(todo)
        return runner

    def _register(self, groups: List[List[dict]]) -> List[PlannedShard]:
        shards = []
        for files in groups:
            shards.append(PlannedShard(f's{self.next_shard:05d}', files))
            self.next_shard += 1
        if not shards:
            return []
        bulk_insert(
            self.con,
            'shards',
            (
                {
                    'run_id': self.run_id,
                    'shard_id': s.shard_id,
                    'n_files': len(s.files),
                    'bytes': s.bytes,
                    'est_cost': s.est_cost,
                    'process_count': 1,
                    'status': 'pending',
                    'attempts': 0,
                }
                for s in shards
            ),
            self.home.tmp_dir,
        )
        bulk_insert(
            self.con,
            'shard_files',
            (
                {'run_id': self.run_id, 'shard_id': s.shard_id, 'file_id': f['file_id'], 'view_path': f['view_path']}
                for s in shards
                for f in s.files
            ),
            self.home.tmp_dir,
        )
        return shards

    # ------------------------------------------------------------------ the loop
    def _shard_dir(self, shard_id: str) -> Path:
        return self.run_dir / 'shards' / shard_id

    def _launch(self, shard: PlannedShard) -> Running:
        shard_dir = self._shard_dir(shard.shard_id)
        target = shard_dir / 'target'
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        for f in shard.files:
            link = target / f['view_path']
            link.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(self.files_dir / f['file_id'], link)
        report = shard_dir / 'report.sarif'
        report.unlink(missing_ok=True)
        log = open(shard_dir / 'scanner.log', 'wb')
        proc = subprocess.Popen(
            self.tool.args(target, report, 1),
            cwd=self.tool.cwd,
            env=self.tool.env(),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        shard.attempts += 1
        self.con.execute(
            "UPDATE shards SET status = 'running', attempts = ?, started_at = ? WHERE run_id = ? AND shard_id = ?",
            [shard.attempts, datetime.now(), self.run_id, shard.shard_id],
        )
        timeout = self.opts.solo_timeout if len(shard.files) == 1 else self.opts.shard_timeout
        return Running(shard, proc, time.monotonic(), timeout, log)

    def execute(self) -> Dict:
        segment_start, wall_start = datetime.now(), time.monotonic()
        running: Dict[int, Running] = {}
        last_progress = 0.0
        status = 'interrupted'
        try:
            while self.queue or running:
                while self.queue and len(running) < self.opts.cores:
                    job = self._launch(self.queue.pop(0))
                    running[job.proc.pid] = job
                for pid, job in list(running.items()):
                    reaped, wait_status, usage = os.wait4(pid, os.WNOHANG)
                    timed_out = False
                    if reaped == 0:
                        if time.monotonic() - job.started <= job.timeout:
                            continue
                        _kill_group(pid)
                        reaped, wait_status, usage = os.wait4(pid, 0)
                        timed_out = True
                    del running[pid]
                    job.proc.returncode = os.waitstatus_to_exitcode(wait_status)
                    requeue = self._finish(job, job.proc.returncode, usage, timed_out)
                    self.queue = sorted(self.queue + requeue, key=lambda s: -s.est_cost)
                if time.monotonic() - last_progress >= PROGRESS_EVERY_S:
                    self._progress(running, wall_start)
                    last_progress = time.monotonic()
                time.sleep(self.opts.poll_s)
            status = 'done' if not self.tally.failed else 'incomplete'
        finally:
            for pid, job in running.items():
                _kill_group(pid)
                try:
                    os.wait4(pid, 0)
                except ChildProcessError:
                    pass
                job.log.close()
                self.con.execute(
                    "UPDATE shards SET status = 'pending', note = 'interrupted' WHERE run_id = ? AND shard_id = ?",
                    [self.run_id, job.shard.shard_id],
                )
            self._close(status, segment_start, time.monotonic() - wall_start)
            self._progress({}, wall_start, final=status)
        return {'run_id': self.run_id, 'status': status, **self.tally.__dict__}

    def _close(self, status: str, segment_start: datetime, wall_s: float) -> None:
        run = get_run(self.con, self.run_id)
        params = run['params']
        params.setdefault('segments', []).append(
            {'started_at': segment_start.isoformat(timespec='seconds'), 'wall_s': round(wall_s, 1), 'status': status}
        )
        self.con.execute(
            'UPDATE runs SET status = ?, finished_at = ?, params = ? WHERE run_id = ?',
            [status, datetime.now(), json.dumps(params), self.run_id],
        )

    def _progress(self, running: Dict[int, Running], wall_start: float, final: Optional[str] = None) -> None:
        t = self.tally
        _write_json(
            self.run_dir / 'progress.json',
            {
                'run_id': self.run_id,
                'status': final or 'running',
                'updated_at': datetime.now().isoformat(timespec='seconds'),
                'elapsed_s': round(time.monotonic() - wall_start, 1),
                'cores': self.opts.cores,
                'files': {'done': t.files_done, 'total': self.total_files},
                'shards': {
                    'done': t.done,
                    'running': len(running),
                    'queued': len(self.queue),
                    'split': t.split,
                    'retried': t.retried,
                    'failed': t.failed,
                },
                'findings': t.findings,
                'cpu_s': round(t.cpu_s, 1),
                'statuses': t.statuses,
            },
        )

    # ------------------------------------------------------------------ one finished shard
    def _finish(self, job: Running, exit_code: int, usage, timed_out: bool) -> List[PlannedShard]:
        job.log.close()
        shard = job.shard
        wall = time.monotonic() - job.started
        cpu = usage.ru_utime + usage.ru_stime
        rss_mb = usage.ru_maxrss / 1024
        self.tally.cpu_s += cpu
        failure: Optional[str] = None
        report: Optional[Report] = None
        if timed_out:
            failure = f'timeout after {job.timeout:.0f} s'
        elif exit_code != 0:
            failure = f'exit {exit_code}'
        else:
            try:
                report = read_report(self._shard_dir(shard.shard_id) / 'report.sarif')
            except SarifError as e:
                failure = f'report unreadable: {e}'
        measured = [exit_code, wall, cpu, rss_mb, datetime.now()]
        if failure is None:
            self._ingest(shard, report, measured)
            return []
        update = '''UPDATE shards SET status = ?, note = ?, exit_code = ?, wall_s = ?, cpu_s = coalesce(cpu_s, 0) + ?,
                        max_rss_mb = greatest(coalesce(max_rss_mb, 0), ?), finished_at = ?
                    WHERE run_id = ? AND shard_id = ?'''
        if len(shard.files) > 1:
            self.con.execute(update, ['split', failure, *measured, self.run_id, shard.shard_id])
            self.tally.split += 1
            return self._register(split(shard.files))
        if shard.attempts < self.opts.attempts:
            self.con.execute(update, ['pending', failure, *measured, self.run_id, shard.shard_id])
            self.tally.retried += 1
            return [shard]
        harness_status = 'timeout' if timed_out else 'tool_error'
        self.con.begin()
        self.con.execute(update, ['failed', failure, *measured, self.run_id, shard.shard_id])
        self.con.execute(
            'INSERT INTO artifacts (run_id, file_id, shard_id, status, errors) VALUES (?, ?, ?, ?, 0)',
            [self.run_id, shard.files[0]['file_id'], shard.shard_id, harness_status],
        )
        self.con.commit()
        self.tally.failed += 1
        self.tally.files_done += 1
        self.tally.statuses[harness_status] = self.tally.statuses.get(harness_status, 0) + 1
        return []

    def _ingest(self, shard: PlannedShard, report: Report, measured: list) -> None:
        by_view = {f['view_path']: f['file_id'] for f in shard.files}
        unknown = 0
        errors_by_file: Dict[str, int] = {}
        errors = []
        for seq, n in enumerate(report.notifications):
            file_id = by_view.get(n.uri or '')
            if file_id:
                errors_by_file[file_id] = errors_by_file.get(file_id, 0) + 1
            errors.append(
                {
                    'run_id': self.run_id,
                    'shard_id': shard.shard_id,
                    'seq': seq,
                    'file_id': file_id,
                    'level': n.level,
                    'message': n.message,
                }
            )
        artifacts = {}
        for a in report.artifacts:
            file_id = by_view.get(a.uri)
            if file_id is None:
                unknown += 1
                continue
            artifacts[file_id] = {
                'run_id': self.run_id,
                'file_id': file_id,
                'shard_id': shard.shard_id,
                'status': a.status,
                'scan_time_ms': a.scan_time_ms,
                'skip_reason': a.skip_reason,
                'depth': a.depth,
                'errors': errors_by_file.get(file_id, 0),
            }
        for f in shard.files:
            artifacts.setdefault(
                f['file_id'],
                {'run_id': self.run_id, 'file_id': f['file_id'], 'shard_id': shard.shard_id, 'status': 'missing'},
            )
        findings = []
        for r in report.results:
            file_id = by_view.get(r.uri)
            if file_id is None:
                unknown += 1
                continue
            findings.append(
                {
                    'run_id': self.run_id,
                    'finding_id': self.next_finding + len(findings),
                    'file_id': file_id,
                    'shard_id': shard.shard_id,
                    'rule_id': r.rule_id,
                    'rule_base': r.rule_base,
                    'confidence': r.confidence,
                    'start_line': r.start_line,
                    'end_line': r.end_line,
                    'start_col': r.start_col,
                    'end_col': r.end_col,
                    'value': r.value,
                    'fingerprint': r.fingerprint,
                    'tier': r.tier,
                    'tags': json.dumps(r.tags) if r.tags is not None else None,
                }
            )
        note = f'{unknown} report entries outside the shard' if unknown else None
        self.con.begin()
        try:
            bulk_insert(self.con, 'artifacts', artifacts.values(), self.home.tmp_dir)
            bulk_insert(self.con, 'findings', findings, self.home.tmp_dir)
            bulk_insert(self.con, 'errors', errors, self.home.tmp_dir)
            self.con.execute(
                '''UPDATE shards SET status = 'done', note = ?, exit_code = ?, wall_s = ?,
                       cpu_s = coalesce(cpu_s, 0) + ?, max_rss_mb = greatest(coalesce(max_rss_mb, 0), ?),
                       finished_at = ?
                   WHERE run_id = ? AND shard_id = ?''',
                [note, *measured, self.run_id, shard.shard_id],
            )
            if self.run.get('tool_version') is None and report.tool_version:
                self.con.execute(
                    'UPDATE runs SET tool_version = ? WHERE run_id = ?', [report.tool_version, self.run_id]
                )
                self.run['tool_version'] = report.tool_version
            self.con.commit()
        except BaseException:
            self.con.rollback()
            raise
        self.next_finding += len(findings)
        t = self.tally
        t.done += 1
        t.files_done += len(shard.files)
        t.findings += len(findings)
        t.unknown_uris += unknown
        for a in artifacts.values():
            t.statuses[a['status']] = t.statuses.get(a['status'], 0) + 1


def fill_tiers(con: duckdb.DuckDBPyConnection, home: BenchHome, run_id: str) -> int:
    """Tiers for findings stored before dsbench kept them: from the rule id's suffix, else from the rule descriptors of
    the shard reports still in the run directory. Returns how many findings are left without a tier."""
    cases = ' '.join(f"WHEN rule_id LIKE '%{suffix}' THEN '{suffix[1:].lower()}'" for suffix in TIER_SUFFIXES)
    con.execute(
        f'UPDATE findings SET tier = CASE {cases} END WHERE run_id = ? AND tier IS NULL',
        [run_id],
    )
    left = con.execute(
        'SELECT rule_id, min(shard_id) FROM findings WHERE run_id = ? AND tier IS NULL GROUP BY 1', [run_id]
    ).fetchall()
    reports: Dict[str, Dict[str, str]] = {}
    for rule_id, shard_id in left:
        if shard_id not in reports:
            try:
                reports[shard_id] = read_report(home.run_dir(run_id) / 'shards' / shard_id / 'report.sarif').rule_tiers
            except SarifError:
                reports[shard_id] = {}
        tier = reports[shard_id].get(rule_id)
        if tier:
            con.execute(
                'UPDATE findings SET tier = ? WHERE run_id = ? AND rule_id = ? AND tier IS NULL',
                [tier, run_id, rule_id],
            )
    return con.execute('SELECT count(*) FROM findings WHERE run_id = ? AND tier IS NULL', [run_id]).fetchone()[0]


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
