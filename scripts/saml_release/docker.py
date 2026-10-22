"""Finite Docker operations; never format container output on a failure."""
import json
import subprocess


def run(arguments, *, environment=None, timeout=120):
    result = subprocess.run(["docker", *arguments], env=environment, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        operation = arguments[0] if arguments[0] in {
            "run", "compose", "inspect", "create", "start", "export", "save", "rm"} else "operation"
        if operation == "compose":
            operation += "/" + next((value for value in arguments if value in {
                "create", "ps", "down"}), "operation")
        if operation == "run" and "nginx" in arguments:
            operation += "/proxy-configuration"
        category = next((value for value in ("permission denied", "unknown flag", "not found",
                                             "no such file", "invalid mount", "not a directory")
                         if value in result.stderr.lower()), "unspecified")
        # Only fixed labels and the numeric exit code; never argv, env, raw stderr,
        # assertion text or credential-bearing container output.
        raise ValueError(f"Docker release {operation} failed: exit={result.returncode}, category={category}")
    return result.stdout


def inspect(identifier):
    values = json.loads(run(["inspect", identifier]))
    if len(values) != 1:
        raise ValueError("unexpected Docker inspection result")
    return values[0]
