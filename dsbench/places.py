"""The three places a benchmark touches, kept apart: the benchmark (the datasets, read only, and the bench home), the
tool (the checkout under test and its cache) and dsbench itself. Labels and raw findings are real secrets, so the bench
home may sit inside no repository, and none of the places may sit inside another."""

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# the dsbench checkout this package was loaded from
DSBENCH_ROOT = Path(__file__).resolve().parents[1]

ENV = {
    'data': 'DSBENCH_DATA',
    'home': 'DSBENCH_HOME',
    'tool_cwd': 'DSBENCH_TOOL_CWD',
    'cache': 'DSBENCH_CACHE',
}


class PlacesError(Exception):
    pass


@dataclass(frozen=True)
class Places:
    data: Optional[Path]
    home: Optional[Path]
    tool_cwd: Optional[Path]
    cache: Optional[Path]
    dsbench: Path = DSBENCH_ROOT

    def named(self) -> Dict[str, Path]:
        pairs = {'data': self.data, 'home': self.home, 'tool_cwd': self.tool_cwd, 'cache': self.cache}
        return {name: path for name, path in {**pairs, 'dsbench': self.dsbench}.items() if path is not None}

    def overlaps(self) -> List[str]:
        """Every pair of places where one is the other or sits inside it."""
        named = list(self.named().items())
        found = []
        for i, (a, pa) in enumerate(named):
            for b, pb in named[i + 1 :]:
                if pa == pb or pa.is_relative_to(pb) or pb.is_relative_to(pa):
                    found.append(f'{a} ({pa}) and {b} ({pb}) overlap')
        return found

    def require_apart(self) -> 'Places':
        problems = self.overlaps()
        if problems:
            raise PlacesError('; '.join(problems))
        return self


def resolve_places(**given: Optional[str]) -> Places:
    """Each place from its argument, else its environment variable, else unset."""
    paths = {}
    for name, var in ENV.items():
        raw = given.get(name) or os.environ.get(var)
        paths[name] = Path(raw).expanduser().resolve() if raw else None
    return Places(**paths)


def tool_python() -> str:
    """The interpreter that runs the scanner: DSBENCH_TOOL_PYTHON, else python3 on PATH outside dsbench's own venv
    (typically the system interpreter of a container that holds the checkout's locked dependencies)."""
    explicit = os.environ.get('DSBENCH_TOOL_PYTHON')
    if explicit:
        return explicit
    own_bin = str(Path(sys.prefix) / 'bin')
    path = os.pathsep.join(d for d in os.environ.get('PATH', '').split(os.pathsep) if d and d != own_bin)
    found = shutil.which('python3', path=path) or shutil.which('python', path=path)
    if not found:
        raise PlacesError('No python3 for the scanner on PATH; set DSBENCH_TOOL_PYTHON')
    return found
