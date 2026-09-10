#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml
from jsonschema import Draft202012Validator


RE_FORBIDDEN_INDEX = re.compile(r"(?i)(^|\s|\||\()index\s*=")
RE_SPLUNK_SOURCETYPE = re.compile(r"(?i)\bsourcetype\s*=")


@dataclass(frozen=True)
class DetectionFile:
    path: Path
    detections: List[Dict[str, Any]]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_schema(schema_path: Path) -> Dict[str, Any]:
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to parse YAML: {path}: {e}") from e


def _iter_detection_files(detections_root: Path) -> Iterable[Path]:
    for p in sorted(detections_root.rglob("*.y*ml")):
        if p.name.startswith("."):
            continue
        yield p


def _normalize_file(path: Path, obj: Any) -> DetectionFile:
    if obj is None:
        return DetectionFile(path=path, detections=[])
    if isinstance(obj, dict):
        return DetectionFile(path=path, detections=[obj])
    if isinstance(obj, list):
        out: List[Dict[str, Any]] = []
        for i, item in enumerate(obj):
            if not isinstance(item, dict):
                raise ValueError(f"{path}: list item {i} is not an object")
            out.append(item)
        return DetectionFile(path=path, detections=out)
    raise ValueError(f"{path}: YAML must be an object or list of objects")


def _validate_schema(validator: Draft202012Validator, det: Dict[str, Any], *, path: Path) -> List[str]:
    errors = []
    for err in sorted(validator.iter_errors(det), key=lambda e: e.json_path):
        loc = err.json_path or "$"
        errors.append(f"{path}: {loc}: {err.message}")
    return errors


def _validate_mitre_minimums(det: Dict[str, Any], *, path: Path) -> List[str]:
    errors: List[str] = []
    mitre = det.get("mitre")
    if not isinstance(mitre, dict):
        return errors
    techniques = mitre.get("techniques")
    if not isinstance(techniques, list) or not any(isinstance(t, str) for t in techniques):
        errors.append(f"{path}: mitre.techniques: must include at least one ATT&CK technique id")
    return errors


def _validate_portability(det: Dict[str, Any], *, path: Path) -> List[str]:
    errors: List[str] = []
    platforms = det.get("platforms", [])
    query = (det.get("query") or {}) if isinstance(det.get("query"), dict) else {}

    # Forbid index= across all query strings we store (Splunk portability guarantee).
    for k, q in query.items():
        if not isinstance(q, str):
            continue
        if RE_FORBIDDEN_INDEX.search(q):
            errors.append(
                f"{path}: query.{k}: contains forbidden 'index=' (use sourcetype-only; index is deploy-time config)"
            )

    # Splunk-specific: if a Splunk query is present, require sourcetype= in SPL.
    if "splunk" in platforms and "splunk" in query:
        spl = query.get("splunk", "")
        if isinstance(spl, str) and not RE_SPLUNK_SOURCETYPE.search(spl):
            errors.append(f"{path}: query.splunk: missing required 'sourcetype=' constraint")

    return errors


def _validate_id_uniqueness(detections: Iterable[Tuple[Path, Dict[str, Any]]]) -> List[str]:
    seen: Dict[str, Path] = {}
    errors: List[str] = []
    for p, d in detections:
        did = d.get("id")
        if not isinstance(did, str):
            continue
        if did in seen:
            errors.append(f"{p}: duplicate id '{did}' (also in {seen[did]})")
        else:
            seen[did] = p
    return errors


def main() -> int:
    root = _repo_root()
    detections_root = root / "detections"
    schema_path = root / "schemas" / "detection.schema.json"
    if not schema_path.exists():
        print(f"Missing schema: {schema_path}", file=sys.stderr)
        return 2
    if not detections_root.exists():
        print(f"Missing detections directory: {detections_root}", file=sys.stderr)
        return 2

    schema = _load_schema(schema_path)
    validator = Draft202012Validator(schema)

    all_errors: List[str] = []
    flattened: List[Tuple[Path, Dict[str, Any]]] = []

    for path in _iter_detection_files(detections_root):
        obj = _load_yaml(path)
        df = _normalize_file(path, obj)
        if not df.detections:
            all_errors.append(f"{path}: empty detection file")
            continue
        for det in df.detections:
            flattened.append((path, det))
            all_errors.extend(_validate_schema(validator, det, path=path))
            all_errors.extend(_validate_mitre_minimums(det, path=path))
            all_errors.extend(_validate_portability(det, path=path))

    all_errors.extend(_validate_id_uniqueness(flattened))

    if all_errors:
        print("\n".join(all_errors), file=sys.stderr)
        return 1

    print(f"OK: validated {len(flattened)} detections from {detections_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

