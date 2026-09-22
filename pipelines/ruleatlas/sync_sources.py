#!/usr/bin/env python3
"""Sync curated RuleAtlas sources (sigma + splunk) into a local data directory."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_SOURCES = ("sigma", "splunk")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _ensure_ruleatlas() -> str:
    exe = shutil.which("ruleatlas")
    if exe:
        return exe
    # try python -m ruleatlas
    try:
        subprocess.run(
            [sys.executable, "-m", "ruleatlas", "--help"],
            check=True,
            capture_output=True,
        )
        return f"{sys.executable} -m ruleatlas"
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise SystemExit(
            "RuleAtlas is not installed. From the repo root run:\n"
            "  pip install -r pipelines/ruleatlas/requirements.txt\n"
            f"Detail: {e}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sync RuleAtlas public sources")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=_repo_root() / "data" / "ruleatlas",
        help="Local RuleAtlas index/cache directory (gitignored)",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        default=list(DEFAULT_SOURCES),
        help="Source IDs to sync (default: sigma splunk)",
    )
    parser.add_argument(
        "--transport",
        choices=["archive", "files", "git"],
        default="archive",
    )
    args = parser.parse_args(argv)

    args.data_dir.mkdir(parents=True, exist_ok=True)
    cmd_base = _ensure_ruleatlas()
    if cmd_base.endswith("-m ruleatlas"):
        prefix = [sys.executable, "-m", "ruleatlas"]
    else:
        prefix = [cmd_base]

    cmd = [
        *prefix,
        "--data-dir",
        str(args.data_dir),
        "sync",
        *args.sources,
        "--transport",
        args.transport,
    ]
    print("Running:", " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
