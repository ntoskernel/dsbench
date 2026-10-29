from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dsbench.places import DSBENCH_ROOT, resolve_places


class HomeError(Exception):
    pass


@dataclass(frozen=True)
class BenchHome:
    """Private working area: the DuckDB store, per-run shard targets and reports, overlays, legacy exports."""

    root: Path

    @property
    def db_path(self) -> Path:
        return self.root / 'bench.duckdb'

    @property
    def runs_dir(self) -> Path:
        return self.root / 'runs'

    @property
    def overlays_dir(self) -> Path:
        return self.root / 'overlays'

    @property
    def legacy_dir(self) -> Path:
        return self.root / 'legacy'

    @property
    def tmp_dir(self) -> Path:
        return self.root / 'tmp'

    def run_dir(self, run_id: str) -> Path:
        return self.runs_dir / run_id

    def ensure(self) -> 'BenchHome':
        for path in (self.root, self.runs_dir, self.overlays_dir, self.legacy_dir, self.tmp_dir):
            path.mkdir(parents=True, exist_ok=True)
        return self


def resolve_home(path: Optional[str]) -> BenchHome:
    places = resolve_places(home=path)
    if places.home is None:
        raise HomeError('No bench home: pass --home or set DSBENCH_HOME to a directory outside every repository')
    if places.home.is_relative_to(DSBENCH_ROOT) or (places.home / '.git').exists():
        raise HomeError(f'Bench home {places.home} is a repository or inside dsbench; it holds real secrets')
    problems = places.overlaps()
    if problems:
        raise HomeError('; '.join(problems))
    return BenchHome(root=places.home).ensure()
