#!/usr/bin/env python3
"""Bounded actual loopback HTTP measurements with exclusively owned disposable data."""
import argparse
from pathlib import Path
import sys

from authentication_benchmark.http_run import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new private results directory')
    parser.add_argument('--repetitions', type=int, choices=range(1, 6), default=3)
    arguments = parser.parse_args()
    try:
        run(arguments.output, arguments.repetitions)
    except Exception:
        print('Owned HTTP benchmark failed; inspect the categorical receipt.', file=sys.stderr)
        return 1
    print('Owned HTTP benchmark completed; see results.json in the requested directory.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
