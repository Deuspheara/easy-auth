"""Finite Docker operations; never format container output on a failure."""
import json
import subprocess


def run(arguments, *, environment=None, timeout=120):
    result = subprocess.run(["docker", *arguments], env=environment, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise ValueError("Docker release verification operation failed")
    return result.stdout


def inspect(identifier):
    values = json.loads(run(["inspect", identifier]))
    if len(values) != 1:
        raise ValueError("unexpected Docker inspection result")
    return values[0]
