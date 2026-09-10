#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _iter_detection_files(detections_root: Path) -> Iterable[Path]:
    for p in sorted(detections_root.rglob("*.y*ml")):
        if p.name.startswith("."):
            continue
        yield p


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _normalize(path: Path, obj: Any) -> List[Dict[str, Any]]:
    if obj is None:
        return []
    if isinstance(obj, dict):
        return [obj]
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    return []


def build_coverage(detections_root: Path) -> Dict[str, Any]:
    tech_to_rules: Dict[str, List[str]] = defaultdict(list)
    platform_counts: Dict[str, int] = defaultdict(int)
    total = 0
    mapped = 0

    for p in _iter_detection_files(detections_root):
        for det in _normalize(p, _load_yaml(p)):
            did = det.get("id")
            if not isinstance(did, str):
                continue
            total += 1
            for plat in det.get("platforms", []) or []:
                if isinstance(plat, str):
                    platform_counts[plat] += 1

            mitre = det.get("mitre") or {}
            techniques = mitre.get("techniques") if isinstance(mitre, dict) else None
            if isinstance(techniques, list) and any(isinstance(t, str) for t in techniques):
                mapped += 1
                for t in techniques:
                    if isinstance(t, str):
                        tech_to_rules[t].append(did)

    for t in list(tech_to_rules.keys()):
        tech_to_rules[t] = sorted(set(tech_to_rules[t]))

    out = {
        "summary": {
            "detections_total": total,
            "detections_with_mitre": mapped,
            "detections_with_mitre_percent": round((mapped / total * 100.0), 2) if total else 0.0,
            "unique_techniques": len(tech_to_rules),
            "platform_counts": dict(sorted(platform_counts.items())),
        },
        "techniques": dict(sorted(tech_to_rules.items())),
    }
    return out


def main() -> int:
    root = _repo_root()
    detections_root = root / "detections"
    out_path = root / "content" / "mitre" / "coverage.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    coverage = build_coverage(detections_root)
    out_path.write_text(json.dumps(coverage, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"Wrote {out_path} ({coverage['summary']['unique_techniques']} techniques)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

