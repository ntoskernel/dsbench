"""A stand-in for gitleaks and Betterleaks: `dir TARGET --config C --report-path R ...`, a JSON report like theirs.

Every `name = "value"` line is a finding of rule `generic-api-key`, whose match is the whole assignment and whose secret
is the value; columns are 1-based and inclusive, plus `--shift` (gitleaks reports one more). `version` and `config
show` answer as the real binaries do. A file that is a symlink is reported as such, as the real tools resolve it."""

import json
import os
import re
import sys

ASSIGNMENT = re.compile(r'\w+ = "([^"]*)"')
VERSION = os.environ.get('FAKE_LEAKS_VERSION', '8.30.1')
SHIFT = int(os.environ.get('FAKE_LEAKS_SHIFT', '1'))


def main(argv):
    if argv[:1] == ['version']:
        print(VERSION)
        return 0
    if argv[:2] == ['config', 'show']:
        print(
            "title = 'x'\nprefilter = '''\nmatchesAny(attributes[\"path\"], [`node_modules`])\n'''\n\n[[rules]]\nid = 'r'\nregex = '''x'''"
        )
        return 0
    assert argv[0] == 'dir' and os.environ.get('GOMAXPROCS') == '1'
    target, report = argv[1], argv[argv.index('--report-path') + 1]
    assert os.path.isfile(argv[argv.index('--config') + 1])
    found = []
    for root, _, names in os.walk(target):
        for name in sorted(names):
            path = os.path.join(root, name)
            assert not os.path.islink(path), 'dsbench must give these tools copies'
            with open(path, encoding='utf-8') as f:
                for number, line in enumerate(f.read().splitlines(), 1):
                    for m in ASSIGNMENT.finditer(line):
                        found.append(
                            {'RuleID': 'generic-api-key', 'File': path, 'StartLine': number, 'EndLine': number,
                             'StartColumn': m.start() + 1 + SHIFT, 'EndColumn': m.end() + SHIFT, 'Match': m.group(0),
                             'Secret': m.group(1), 'Fingerprint': f'{path}:{number}', 'Tags': [],
                             'Attributes': {'confidence': 'medium'} if SHIFT == 0 else {}}
                        )  # fmt: skip
    with open(report, 'w') as f:
        json.dump(found or None, f)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
