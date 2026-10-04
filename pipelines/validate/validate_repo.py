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


RE_FORBIDDEN_INDEX = re.compile(r"(?i)(^|\s|\||\()index\s*=")  # strict ban, case-insensitive
RE_SPLUNK_SOURCETYPE = re.compile(
    r"(?i)(\bsourcetype\s*=|`(windows_security|windows_system|windows_powershell_operational|windows_powershell_classic|windows_sysmon)`)"
)

REQUIRED_WINDOWS_SOURCETYPE_MACROS = {
    "windows_security",
    "windows_system",
    "windows_powershell_operational",
    "windows_powershell_classic",
    "windows_sysmon",
}


def _is_windows_splunk_sourcetype(value: str) -> bool:
    # Windows family sourcetypes per telemetry contract.
    return (
        value.startswith("WinEventLog")
        or value.startswith("XmlWinEventLog")
        or value == "sysmon"
        or value.startswith("sysmon:")
    )


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


def _load_sourcetype_contract(sourcetype_map_path: Path) -> tuple[list[str], set[str]]:
    obj = _load_yaml(sourcetype_map_path)
    if not isinstance(obj, dict):
        raise ValueError(f"{sourcetype_map_path}: expected YAML object")

    allowed = obj.get("allowed_sourcetypes")
    if not isinstance(allowed, list) or not all(isinstance(x, str) for x in allowed):
        raise ValueError(f"{sourcetype_map_path}: missing/invalid 'allowed_sourcetypes' (must be a list of strings)")

    # Optional: some repos also carry a macro->sourcetype expansion map under "canonical".
    canonical = obj.get("canonical")
    if isinstance(canonical, dict):
        for _, v in canonical.items():
            if isinstance(v, list):
                allowed.extend([x for x in v if isinstance(x, str)])

    macros = obj.get("macros")
    if not isinstance(macros, dict):
        raise ValueError(f"{sourcetype_map_path}: missing/invalid 'macros' map")
    missing = sorted([m for m in REQUIRED_WINDOWS_SOURCETYPE_MACROS if m not in macros])
    if missing:
        raise ValueError(f"{sourcetype_map_path}: missing required macro(s): {', '.join(missing)}")

    allowed_sourcetype_macros = obj.get("allowed_sourcetype_macros")
    if allowed_sourcetype_macros is None:
        allowed_macros = set(REQUIRED_WINDOWS_SOURCETYPE_MACROS)
    elif isinstance(allowed_sourcetype_macros, list) and all(isinstance(x, str) for x in allowed_sourcetype_macros):
        allowed_macros = set(allowed_sourcetype_macros)
    else:
        raise ValueError(f"{sourcetype_map_path}: invalid 'allowed_sourcetype_macros' (must be a list of strings)")

    ci = obj.get("ci")
    if not isinstance(ci, dict) or ci.get("reject_hardcoded_index") is not True:
        raise ValueError(f"{sourcetype_map_path}: ci.reject_hardcoded_index must be true")

    return [x for x in allowed if isinstance(x, str)], allowed_macros


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


def _validate_sourcetypes_allowlist(
    det: Dict[str, Any],
    *,
    allowed_sourcetypes: list[str],
    allowed_macros: set[str],
    path: Path,
) -> List[str]:
    errors: List[str] = []
    sts = det.get("sourcetypes")
    if not isinstance(sts, list):
        return errors
    exact = {x for x in allowed_sourcetypes if "*" not in x}
    globs = [x for x in allowed_sourcetypes if "*" in x]
    glob_res = []
    for g in globs:
        # simple glob: * matches any chars
        pat = "^" + re.escape(g).replace("\\*", ".*") + "$"
        glob_res.append(re.compile(pat))

    for st in sts:
        if not isinstance(st, str):
            continue
        # Telemetry canonical allowlist is Windows-focused; other platform packs may define
        # their own portable sourcetypes (e.g., Falcon/MDE stubs) that are not part of the
        # Windows telemetry contract. Enforce allowlist strictly for Windows-family sourcetypes
        # and for allowlisted macro keys.
        if st not in allowed_macros and not _is_windows_splunk_sourcetype(st):
            continue
        if st in allowed_macros:
            continue
        if st in exact:
            continue
        if any(r.match(st) for r in glob_res):
            continue
        errors.append(f"{path}: sourcetypes: '{st}' not in allowed_sourcetypes (config/sourcetype_map.yaml)")
    return errors


def _validate_platform_query_match(det: Dict[str, Any], *, path: Path) -> List[str]:
    errors: List[str] = []
    platforms = det.get("platforms", [])
    query = det.get("query")
    sigma = det.get("sigma")

    query_obj = query if isinstance(query, dict) else {}
    has_sigma = isinstance(sigma, dict) and isinstance(sigma.get("path"), str) and len(sigma.get("path")) >= 5

    def _require_query(platform: str, key: str) -> None:
        qv = query_obj.get(key)
        if not isinstance(qv, str) or not qv.strip():
            errors.append(f"{path}: platforms includes '{platform}' but query.{key} is missing/empty")

    if isinstance(platforms, list):
        if "splunk" in platforms:
            # Splunk requires query.splunk unless a Sigma source is present.
            if not has_sigma:
                _require_query("splunk", "splunk")
        if "defender" in platforms:
            _require_query("defender", "defender")
        if "crowdstrike" in platforms:
            _require_query("crowdstrike", "crowdstrike")

    return errors


def _validate_portability(det: Dict[str, Any], *, path: Path) -> List[str]:
    errors: List[str] = []
    platforms = det.get("platforms", [])
    query = (det.get("query") or {}) if isinstance(det.get("query"), dict) else {}

    # Hardcoded index= ban (strict, case-insensitive) across all query strings.
    for k, q in query.items():
        if not isinstance(q, str):
            continue
        if RE_FORBIDDEN_INDEX.search(q):
            errors.append(
                f"{path}: query.{k}: contains forbidden 'index=' (detections must be org-portable; index is deploy-time config)"
            )

    # Splunk SPL portability: if a Splunk query is present, require sourcetype= constraint.
    if isinstance(platforms, list) and "splunk" in platforms and "splunk" in query:
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


def _validate_catalog_fields(
    flattened: List[Tuple[Path, Dict[str, Any]]],
    *,
    root: Path,
) -> List[str]:
    """Enforce telemetry catalog membership for Windows + CloudTrail required_fields."""
    catalog_path = root / "content" / "telemetry" / "catalog.json"
    if not catalog_path.exists():
        return [f"Missing telemetry catalog: {catalog_path}"]

    # Import sibling module when running as a script
    validate_dir = Path(__file__).resolve().parent
    if str(validate_dir) not in sys.path:
        sys.path.insert(0, str(validate_dir))
    from telemetry_catalog import TelemetryCatalog  # noqa: WPS433
    from validate_fields import validate_detection  # noqa: WPS433

    catalog = TelemetryCatalog.load(catalog_path)
    errors: List[str] = []
    for path, det in flattened:
        rv = validate_detection(det, catalog, path=path)
        if not rv.in_scope:
            continue
        unknown_required = [
            f.name for f in rv.fields if f.status == "unknown" and f.source == "required_fields"
        ]
        if unknown_required:
            errors.append(
                f"{path}: required_fields not in telemetry catalog: {', '.join(unknown_required)}"
            )
    return errors


def main() -> int:
    root = _repo_root()
    detections_root = root / "detections"
    schema_path = root / "schemas" / "detection.schema.json"
    sourcetype_map_path = root / "config" / "sourcetype_map.yaml"

    if not schema_path.exists():
        print(f"Missing schema: {schema_path}", file=sys.stderr)
        return 2
    if not detections_root.exists():
        print(f"Missing detections directory: {detections_root}", file=sys.stderr)
        return 2
    if not sourcetype_map_path.exists():
        print(f"Missing sourcetype map: {sourcetype_map_path}", file=sys.stderr)
        return 2

    schema = _load_schema(schema_path)
    validator = Draft202012Validator(schema)
    allowed_sourcetypes, required_macros = _load_sourcetype_contract(sourcetype_map_path)

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
            all_errors.extend(
                _validate_sourcetypes_allowlist(
                    det,
                    allowed_sourcetypes=allowed_sourcetypes,
                    allowed_macros=required_macros,
                    path=path,
                )
            )
            all_errors.extend(_validate_platform_query_match(det, path=path))
            all_errors.extend(_validate_portability(det, path=path))

    all_errors.extend(_validate_id_uniqueness(flattened))
    all_errors.extend(_validate_catalog_fields(flattened, root=root))

    if all_errors:
        print("\n".join(all_errors), file=sys.stderr)
        return 1

    print(f"OK: validated {len(flattened)} detections from {detections_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

