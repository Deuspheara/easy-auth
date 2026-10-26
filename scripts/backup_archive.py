#!/usr/bin/env python3
"""Private age archive operations; database execution remains a separate operator step."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from operational_recovery.encrypted_archives.cipher import ArchiveCipher


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # Invalid arguments can contain credentials pasted accidentally. Never
        # reflect argparse's foreign values in an operational diagnostic.
        raise ValueError("invalid backup command; run --help")


def arguments():
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    for name in ("keygen", "encrypt", "decrypt"):
        command = commands.add_parser(name)
        command.add_argument("--tool-directory", type=Path, required=True)
        if name in ("keygen", "decrypt"):
            command.add_argument("--identity", type=Path, required=True)
        if name in ("encrypt", "decrypt"):
            command.add_argument("--output", type=Path, required=True)
        if name == "encrypt":
            command.add_argument("--recipient", required=True)
        if name == "decrypt":
            command.add_argument("--input", type=Path, required=True)
            command.add_argument("--expected-sha256", required=True)
    return parser.parse_args()


def main():
    options = arguments()
    cipher = ArchiveCipher(options.tool_directory)
    if options.command == "keygen":
        result = dict(status="identity_created", recipient=cipher.new_identity(options.identity))
    elif options.command == "encrypt":
        if sys.stdin.isatty():
            raise ValueError("a PostgreSQL custom archive stream is required")
        result = dict(status="encrypted", ciphertext_sha256=cipher.encrypt(
            sys.stdin.buffer, options.output, options.recipient))
    else:
        cipher.decrypt(options.input, options.output, options.identity, options.expected_sha256)
        result = dict(status="decrypted_quarantine", plaintext_released_to_database=False)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status="failed", category=type(error).__name__)), file=sys.stderr)
        raise SystemExit(1) from None
