#!/usr/bin/env python3
"""Audit the full resolver lockfile; fail on advisories in any compiled workspace graph.

Cargo.lock includes inactive optional SQLx MySQL/RSA packages. Do not suppress their
advisory globally: derive the compiled graph each run, including build/dev deps and
all platforms. cargo-deny independently audits the selected feature graph in CI.
"""
import json
import subprocess
import sys

result = subprocess.run(['cargo', 'audit', '--json'], capture_output=True, text=True)
try:
    report = json.loads(result.stdout)
except (ValueError, TypeError):
    print('Advisory database audit failed; no valid report.', file=sys.stderr)
    sys.exit(1)
if 'vulnerabilities' not in report or report.get('error'):
    print('Advisory database audit failed.', file=sys.stderr)
    sys.exit(1)
graph = subprocess.run(['cargo', 'tree', '--locked', '--workspace', '--target', 'all',
    '--edges', 'normal,build,dev', '--prefix', 'none', '--format', '{p}', '--no-dedupe'],
    capture_output=True, text=True, check=True)
active = set()
for line in graph.stdout.splitlines():
    fields = line.split()
    if len(fields) > 1 and fields[1].startswith('v'):
        active.add((fields[0], fields[1][1:]))
failures = 0
findings = report['vulnerabilities'].get('list', [])
for warnings in report.get('warnings', {}).values():
    findings.extend(warnings)
for finding in findings:
    package = finding.get('package', {})
    identity = (package.get('name'), package.get('version'))
    compiled = identity in active
    advisory = finding.get('advisory', {})
    print('{}: {} {} {} — {}'.format('FAIL compiled' if compiled else 'INFO inactive lockfile entry',
        *identity, advisory.get('id', 'warning'), advisory.get('title', 'dependency warning')))
    failures += int(compiled)
if result.returncode and not findings:
    print('Audit exited unsuccessfully without an explained finding.', file=sys.stderr)
    sys.exit(1)
print('Compiled dependency advisory check: {}'.format('FAILED' if failures else 'PASS'))
sys.exit(bool(failures))
