"""A stand-in for DeepSecrets with the same command line and SARIF contract, for testing the runner without it.

Every `name = "value"` line is a finding, at the confidence of a trailing `# conf=N` (10 without one). A file whose
text holds HANG makes the scan sleep, one holding CRASH makes it exit 3, and files over 100 bytes are `shallow`."""

import argparse
import json
import os
import re
import sys
import time

ASSIGNMENT = re.compile(r'(\w+) = "([^"]*)"(?:\s*# conf=(\d+))?')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--target-dir', required=True)
    parser.add_argument('--outfile', required=True)
    parser.add_argument('--outformat')
    parser.add_argument('--process-count')
    parser.add_argument('--excluded-paths', nargs='*')
    parser.add_argument('--report-diagnostics', action='store_true')
    parser.add_argument('--disable-masking', action='store_true')
    args = parser.parse_args()

    results, artifacts, notifications = [], [], []
    for root, _, names in os.walk(args.target_dir):
        for name in sorted(names):
            path = os.path.join(root, name)
            uri = os.path.relpath(path, args.target_dir)
            with open(path, encoding='utf-8') as f:
                text = f.read()
            if 'HANG' in text:
                time.sleep(60)
            if 'CRASH' in text:
                return 3
            if 'NOTE' in text:
                notifications.append(
                    {'message': {'text': 'Error during fetching file contents'}, 'level': 'error',
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': uri, 'uriBaseId': '%SRCROOT%'}}}]}
                )  # fmt: skip
            for number, line in enumerate(text.splitlines(), 1):
                for m in ASSIGNMENT.finditer(line):
                    confidence = int(m.group(3) or 10)
                    tier = (
                        'VERY-HIGH'
                        if confidence >= 9
                        else 'HIGH' if confidence >= 6 else 'MEDIUM' if confidence >= 3 else 'LOW'
                    )
                    region = {
                        'startLine': number, 'endLine': number, 'startColumn': m.start(2) + 1,
                        'endColumn': m.end(2) + 1, 'snippet': {'text': m.group(2)},
                    }  # fmt: skip
                    results.append(
                        {'ruleId': f'S105-{tier}', 'level': 'error', 'properties': {'confidence': confidence},
                         'message': {'text': 'Secret in code'}, 'partialFingerprints': {'dsfpx/v1': f'{uri}|{m.group(2)}'},
                         'locations': [{'physicalLocation': {'artifactLocation': {'uri': uri, 'uriBaseId': '%SRCROOT%'},
                                                             'region': region}}]}
                    )  # fmt: skip
            artifacts.append(
                {'location': {'uri': uri, 'uriBaseId': '%SRCROOT%'}, 'length': os.path.getsize(path),
                 'properties': {'status': 'ok', 'scanTimeMs': 1.5,
                                'depth': 'shallow' if os.path.getsize(path) > 100 else 'deep'}}
            )  # fmt: skip
    run = {'tool': {'driver': {'name': 'DeepSecrets', 'semanticVersion': '9.9.9', 'rules': []}}, 'results': results}
    if args.report_diagnostics:
        run['artifacts'] = artifacts
        run['invocations'] = [{'executionSuccessful': True, 'toolExecutionNotifications': notifications}]
    with open(args.outfile, 'w', encoding='utf-8') as f:
        json.dump({'runs': [run], 'version': '2.1.0'}, f)
    return 0


if __name__ == '__main__':
    sys.exit(main())
