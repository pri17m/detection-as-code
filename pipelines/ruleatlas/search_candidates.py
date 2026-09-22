#!/usr/bin/env python3
"""Search RuleAtlas index and export normalized DaC candidates."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from normalize import normalize_many, write_candidates

# Seed queries for CloudTrail-first + Windows shortlist validation
DEFAULT_QUERIES = [
    "aws:cloudtrail",
    "eventName ConsoleLogin MFAUsed",
    "sessionCredentialFromConsole",
    "ec2RoleDelivery",
    "ListFoundationModels",
    "AssumeRole recipientAccountId",
    "T1078.004",
    "T1548.005",
    "T1059.001",
    "sysmon EncodedCommand",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _ruleatlas_prefix() -> list[str]:
    if shutil.which("ruleatlas"):
        return ["ruleatlas"]
    try:
        subprocess.run(
            [sys.executable, "-m", "ruleatlas", "--help"],
            check=True,
            capture_output=True,
        )
        return [sys.executable, "-m", "ruleatlas"]
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise SystemExit(
            "RuleAtlas is not installed. pip install -r pipelines/ruleatlas/requirements.txt\n"
            f"Detail: {e}"
        )


def search_one(
    *,
    data_dir: Path,
    query: str,
    method: str,
    source: str,
    limit: int,
) -> list[dict]:
    prefix = _ruleatlas_prefix()
    cmd = [
        *prefix,
        "--data-dir",
        str(data_dir),
        "search",
        query,
        "--method",
        method,
        "--limit",
        str(limit),
    ]
    if source:
        cmd.extend(["--source", source])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(proc.returncode)
    raw = proc.stdout.strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "records", "hits", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        # single record
        if "title" in data or "logic" in data:
            return [data]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Search RuleAtlas and export candidates")
    parser.add_argument("--data-dir", type=Path, default=_repo_root() / "data" / "ruleatlas")
    parser.add_argument("--query", action="append", help="Search query (repeatable)")
    parser.add_argument("--method", choices=["keyword", "attack", "hybrid"], default="hybrid")
    parser.add_argument("--source", default="", help="Optional source filter (sigma, splunk)")
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument(
        "--out",
        type=Path,
        default=_repo_root() / "content" / "validation" / "candidates.json",
    )
    parser.add_argument(
        "--seeds",
        action="store_true",
        help="Use built-in CloudTrail-first + Windows seed queries",
    )
    args = parser.parse_args(argv)

    queries = list(args.query or [])
    if args.seeds or not queries:
        queries = list(DEFAULT_QUERIES)

    all_records: list[dict] = []
    for q in queries:
        print(f"search: {q!r}", file=sys.stderr)
        try:
            hits = search_one(
                data_dir=args.data_dir,
                query=q,
                method=args.method,
                source=args.source,
                limit=args.limit,
            )
        except SystemExit:
            raise
        except Exception as e:
            print(f"warn: search failed for {q!r}: {e}", file=sys.stderr)
            continue
        print(f"  hits={len(hits)}", file=sys.stderr)
        all_records.extend(hits)

    candidates = normalize_many(all_records)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_candidates(candidates, str(args.out))
    print(f"Wrote {len(candidates)} candidates → {args.out}")
    return 0


if __name__ == "__main__":
    # Ensure local imports work when run as a script
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    raise SystemExit(main())
