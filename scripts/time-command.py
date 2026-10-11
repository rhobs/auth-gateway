#!/usr/bin/env python3
"""Run one command and record its wall time in a JSON stage file."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timings-file", required=True, type=Path)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--capture-output", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    return args


def save_timing(path: Path, stage: str, duration: float, exit_code: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, object] = {"schemaVersion": 1, "stages": {}}
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schemaVersion") != 1:
            raise ValueError(f"unsupported timing file format: {path}")
        if not isinstance(data.get("stages"), dict):
            raise ValueError(f"timing file has no stages object: {path}")

    stages = data["stages"]
    assert isinstance(stages, dict)
    stages[stage] = {"durationSeconds": duration, "exitCode": exit_code}

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=path.name + ".",
            delete=False,
        ) as temporary_file:
            json.dump(data, temporary_file, indent=2, sort_keys=True)
            temporary_file.write("\n")
            temporary_path = Path(temporary_file.name)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def main() -> int:
    args = parse_args()
    started = time.perf_counter()
    exit_code = 0
    try:
        if args.capture_output:
            completed = subprocess.run(args.command, check=False, capture_output=True, text=True)
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
        else:
            completed = subprocess.run(args.command, check=False)
        exit_code = completed.returncode
    except OSError as error:
        print(f"could not run {args.command[0]}: {error}", file=sys.stderr)
        exit_code = 127

    duration = time.perf_counter() - started
    try:
        save_timing(args.timings_file, args.stage, duration, exit_code)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"could not write timing for {args.stage}: {error}", file=sys.stderr)
        return 1

    print(f"stage timing {args.stage}: {duration:.3f}s", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
