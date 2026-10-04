#!/usr/bin/env python3
"""Deterministic + optional Jev validation of detection tables/fields against the telemetry catalog."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

from telemetry_catalog import TelemetryCatalog, load_default_catalog

# SPL / Sigma noise that is not a telemetry field
_SPL_KEYWORDS = {
    "search",
    "where",
    "stats",
    "table",
    "eval",
    "rename",
    "fields",
    "sort",
    "dedup",
    "bin",
    "timechart",
    "chart",
    "transaction",
    "join",
    "append",
    "lookup",
    "inputlookup",
    "outputlookup",
    "makeresults",
    "mvexpand",
    "mvcombine",
    "spath",
    "rex",
    "regex",
    "replace",
    "coalesce",
    "if",
    "case",
    "match",
    "like",
    "isnull",
    "isnotnull",
    "typeof",
    "tonumber",
    "tostring",
    "strftime",
    "strptime",
    "relative_time",
    "true",
    "false",
    "null",
    "and",
    "or",
    "not",
    "in",
    "by",
    "as",
    "count",
    "values",
    "list",
    "dc",
    "sum",
    "avg",
    "min",
    "max",
    "earliest",
    "latest",
    "first_seen",
    "last_seen",
    "mvindex",
    "split",
    "lower",
    "upper",
    "len",
    "substr",
    "trim",
    "cidrmatch",
    # metadata / non-event fields
    "sourcetype",
    "source",
    "index",
    "host",
    "linecount",
    "punct",
    "timestamp",
}

_RE_MACRO = re.compile(r"`([a-zA-Z_][a-zA-Z0-9_]*)`")
_RE_SOURCETYPE = re.compile(r"(?i)\bsourcetype\s*=\s*([`\"']?)([^`\"'\s\|\)\(]+)\1")
_RE_FIELD_EQ = re.compile(
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_\-]*)*)\s*(?:=|!=|IN\b)"
)
_RE_QUOTED_FIELD = re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_\-]*)*)['\"]")
_RE_SIGMA_FIELD = re.compile(r"(?m)^\s{2,}([A-Za-z_][A-Za-z0-9_]*(?:\|[a-z]+)?)\s*:")


QUESTION_SET_VERSION = "field_grounding.v1"
JEV_MODEL = "jev-1.13.0"


@dataclass
class FieldFinding:
    name: str
    status: str  # valid | alias | unknown | invalid
    canonical: Optional[str] = None
    source: str = "required_fields"  # required_fields | query | sigma


@dataclass
class TableFinding:
    name: str
    status: str  # valid | unknown
    table_id: Optional[str] = None


@dataclass
class RuleValidation:
    id: str
    title: str
    path: Optional[str]
    families: List[str]
    in_scope: bool
    tables: List[TableFinding] = field(default_factory=list)
    fields: List[FieldFinding] = field(default_factory=list)
    verdict: str = "SKIP"  # PASS | FAIL | NEEDS_REVIEW | TELEMETRY_GAP | SKIP
    reasons: List[str] = field(default_factory=list)
    content_hash: str = ""
    jev: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _content_hash(parts: Sequence[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def extract_from_spl(query: str) -> Tuple[Set[str], Set[str]]:
    tables: Set[str] = set()
    fields: Set[str] = set()
    if not query:
        return tables, fields
    for m in _RE_MACRO.finditer(query):
        tables.add(m.group(1))
    for m in _RE_SOURCETYPE.finditer(query):
        tables.add(m.group(2))
    for m in _RE_FIELD_EQ.finditer(query):
        name = m.group("field")
        if name.lower() in _SPL_KEYWORDS or name.startswith("_"):
            continue
        # skip eval LHS that are clearly local (heuristic: snake without dots and assigned after eval)
        fields.add(name)
    return tables, fields


def extract_from_sigma(text: str) -> Tuple[Set[str], Set[str]]:
    tables: Set[str] = set()
    fields: Set[str] = set()
    try:
        obj = yaml.safe_load(text)
    except Exception:
        return tables, fields
    if not isinstance(obj, dict):
        return tables, fields
    logsource = obj.get("logsource") if isinstance(obj.get("logsource"), dict) else {}
    for key in ("product", "service", "category"):
        val = logsource.get(key)
        if isinstance(val, str) and val:
            tables.add(val)
    detection = obj.get("detection")
    if isinstance(detection, dict):
        for _k, block in detection.items():
            if _k == "condition" or not isinstance(block, dict):
                continue
            for fname in block.keys():
                if not isinstance(fname, str):
                    continue
                base = fname.split("|", 1)[0]
                if base.lower() in {"selection", "filter"}:
                    continue
                fields.add(base)
    return tables, fields


def _normalize_detection(obj: Any) -> List[Dict[str, Any]]:
    if obj is None:
        return []
    if isinstance(obj, dict):
        return [obj]
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    return []


def _sourcetypes_of(det: Dict[str, Any]) -> List[str]:
    sts = det.get("sourcetypes") or []
    return [s for s in sts if isinstance(s, str)]


def validate_detection(
    det: Dict[str, Any],
    catalog: TelemetryCatalog,
    *,
    path: Optional[Path] = None,
    logic_override: Optional[str] = None,
) -> RuleValidation:
    did = str(det.get("id") or path or "unknown")
    title = str(det.get("title") or "")
    sourcetypes = _sourcetypes_of(det)
    families = sorted(catalog.families_for_sourcetypes(sourcetypes))
    in_scope = catalog.in_scope(sourcetypes)

    query_obj = det.get("query") if isinstance(det.get("query"), dict) else {}
    spl = logic_override
    if spl is None and isinstance(query_obj.get("splunk"), str):
        spl = query_obj["splunk"]

    extracted_tables: Set[str] = set(sourcetypes)
    extracted_fields: Set[str] = set()
    for rf in det.get("required_fields") or []:
        if isinstance(rf, str) and rf.strip():
            extracted_fields.add(rf.strip())

    field_sources: Dict[str, str] = {f: "required_fields" for f in extracted_fields}

    if isinstance(spl, str):
        t2, f2 = extract_from_spl(spl)
        extracted_tables |= t2
        for f in f2:
            extracted_fields.add(f)
            field_sources.setdefault(f, "query")

    sigma = det.get("sigma")
    if isinstance(sigma, dict) and isinstance(sigma.get("path"), str) and path is not None:
        # sigma path is relative to repo; skip if missing
        pass

    content_hash = _content_hash(
        [
            did,
            title,
            spl or "",
            ",".join(sorted(extracted_tables)),
            ",".join(sorted(extracted_fields)),
            str(catalog.version),
            QUESTION_SET_VERSION,
        ]
    )

    result = RuleValidation(
        id=did,
        title=title,
        path=str(path) if path else None,
        families=families,
        in_scope=in_scope,
        content_hash=content_hash,
    )

    if not in_scope:
        result.verdict = "SKIP"
        result.reasons.append("sourcetypes outside Windows/CloudTrail catalog MVP")
        return result

    table_ids: List[str] = []
    for tname in sorted(extracted_tables):
        # skip bare collapsed WinEventLog without channel when other macros present
        tr = catalog.resolve_table(tname)
        if tr:
            result.tables.append(TableFinding(name=tname, status="valid", table_id=tr.id))
            table_ids.append(tr.id)
        else:
            # ignore pure SPL noise macros that are not telemetry (rare)
            low_name = tname.lower().strip("`")
            if low_name in _SPL_KEYWORDS or low_name.endswith("_filter"):
                continue
            result.tables.append(TableFinding(name=tname, status="unknown", table_id=None))

    # Prefer family tables when sourcetypes resolved
    if not table_ids and families:
        table_ids = [tid for tid, t in catalog.tables.items() if t.family in families]

    unknown_fields = 0
    alias_fields = 0
    for fname in sorted(extracted_fields):
        # Only enforce metadata required_fields strictly; query-extracted use softer path
        source = field_sources.get(fname, "query")
        status, canonical = catalog.resolve_field(fname, table_ids=table_ids or None)
        if status == "unknown":
            # Query tokens that look like local eval vars (no dot, not in required_fields) → skip
            if source == "query" and "." not in fname and fname not in (det.get("required_fields") or []):
                # still record lightly as skipped noise
                continue
            unknown_fields += 1
            result.fields.append(
                FieldFinding(name=fname, status="unknown", canonical=None, source=source)
            )
        elif status == "alias":
            alias_fields += 1
            result.fields.append(
                FieldFinding(name=fname, status="alias", canonical=canonical, source=source)
            )
        else:
            result.fields.append(
                FieldFinding(name=fname, status="valid", canonical=canonical, source=source)
            )

    unknown_tables = [t for t in result.tables if t.status == "unknown"]
    unknown_required = [
        f for f in result.fields if f.status == "unknown" and f.source == "required_fields"
    ]

    if unknown_required or any(
        t.status == "unknown" and any(h in t.name.lower() for h in ("cloudtrail", "winevent", "sysmon", "windows_"))
        for t in unknown_tables
    ):
        result.verdict = "TELEMETRY_GAP"
        if unknown_required:
            result.reasons.append(
                "unknown required_fields: " + ", ".join(f.name for f in unknown_required)
            )
        if unknown_tables:
            result.reasons.append(
                "unknown tables: " + ", ".join(t.name for t in unknown_tables)
            )
    elif unknown_fields or alias_fields:
        result.verdict = "NEEDS_REVIEW"
        if alias_fields:
            result.reasons.append(f"{alias_fields} alias field(s) need confirmation")
        if unknown_fields:
            result.reasons.append(f"{unknown_fields} unknown query field(s)")
    else:
        result.verdict = "PASS"
        result.reasons.append("all tables/fields resolved in catalog")

    return result


def _tables_from_logsource(logsource: Dict[str, Any]) -> Set[str]:
    tables: Set[str] = set()
    if not isinstance(logsource, dict):
        return tables
    product = str(logsource.get("product") or "").lower()
    service = str(logsource.get("service") or "").lower()
    category = str(logsource.get("category") or "").lower()
    if service == "cloudtrail" or (product == "aws" and service == "cloudtrail"):
        tables.add("aws:cloudtrail")
    if product == "cloudtrail":
        tables.add("aws:cloudtrail")
    if product == "windows":
        if service in {"sysmon", "sysmon-operational"} or category == "process_creation":
            tables.add("windows_sysmon" if service.startswith("sysmon") else "windows_security")
        elif service in {"security", "system", "powershell", "powershell-classic"}:
            mapping = {
                "security": "windows_security",
                "system": "windows_system",
                "powershell": "windows_powershell_operational",
                "powershell-classic": "windows_powershell_classic",
            }
            tables.add(mapping.get(service, "windows_security"))
        else:
            tables.add("windows_security")
    if product == "sysmon" or service == "sysmon":
        tables.add("windows_sysmon")
    return tables


def _tables_from_telemetry(telemetry: Dict[str, Any]) -> Set[str]:
    tables: Set[str] = set()
    if not isinstance(telemetry, dict):
        return tables
    product = str(telemetry.get("product") or "").lower()
    service = str(telemetry.get("service") or "").lower()
    if product or service:
        tables |= _tables_from_logsource({"product": product, "service": service})
    for ds in telemetry.get("data_source") or []:
        if not isinstance(ds, str):
            continue
        dsl = ds.lower()
        if "cloudtrail" in dsl:
            tables.add("aws:cloudtrail")
        if "sysmon" in dsl:
            tables.add("windows_sysmon")
        if "windows security" in dsl or "wineventlog:security" in dsl:
            tables.add("windows_security")
    return tables


def validate_candidate(candidate: Dict[str, Any], catalog: TelemetryCatalog) -> RuleValidation:
    """Validate a RuleAtlas-normalized candidate object."""
    logic = str(candidate.get("logic") or "")
    low = logic.lower()
    language = str(candidate.get("language") or "").lower()
    logsource = candidate.get("logsource") if isinstance(candidate.get("logsource"), dict) else {}
    telemetry = candidate.get("telemetry") if isinstance(candidate.get("telemetry"), dict) else {}

    is_sigma = (
        language == "sigma"
        or "logsource:" in low
        or logic.lstrip().startswith("title:")
        or logic.lstrip().startswith("detection:")
    )

    tables: Set[str] = set()
    fields: Set[str] = set()
    tables |= _tables_from_logsource(logsource)
    tables |= _tables_from_telemetry(telemetry)

    if is_sigma:
        t2, fields = extract_from_sigma(logic)
        tables |= t2
        # RuleAtlas often ships detection-only YAML; recover platform from content.
        if "eventsource" in low and "cloudtrail.amazonaws.com" in low:
            tables.add("aws:cloudtrail")
        if "sysmon" in low:
            tables.add("windows_sysmon")
        elif "eventid" in low or "eventcode" in low:
            if "windows" in low or "security" in low or not tables:
                tables.add("windows_security")
        # Drop sigma product/service tokens that are not catalog table names once mapped.
        tables = {
            t
            for t in tables
            if catalog.resolve_table(t) is not None
            or t in {"aws:cloudtrail", "windows_security", "windows_sysmon", "windows_system"}
        }
        det = {
            "id": candidate.get("id") or candidate.get("content_hash") or "candidate",
            "title": candidate.get("title") or "",
            "sourcetypes": sorted(tables),
            "required_fields": sorted(fields),
            "query": {},
        }
        return validate_detection(det, catalog, logic_override="")

    tables_spl, fields = extract_from_spl(logic)
    tables |= tables_spl
    if (
        "aws:cloudtrail" in low
        or "`aws_cloudtrail`" in low
        or "`cloudtrail`" in low
        or "cloudtrail.amazonaws.com" in low
    ):
        tables.add("aws:cloudtrail")
    elif "useridentity." in low and "eventname" in low:
        tables.add("aws:cloudtrail")
    if "sysmon" in low:
        tables.add("windows_sysmon")
    if "wineventlog:security" in low or "windows_security" in low:
        tables.add("windows_security")

    det = {
        "id": candidate.get("id") or candidate.get("content_hash") or "candidate",
        "title": candidate.get("title") or "",
        "sourcetypes": sorted(tables),
        "required_fields": sorted(fields),
        "query": {"splunk": logic},
    }
    return validate_detection(det, catalog, logic_override=logic)


def apply_jev_policy(result: RuleValidation, jev_answers: Dict[str, Any]) -> RuleValidation:
    """
    Merge Jev answers into a deterministic result.
    Policy:
      - deterministic TELEMETRY_GAP / FAIL stays unless Jev clearly cannot override gaps
      - safe_to_import >= 0.85 + high confidence + no invalid → PASS
      - mid → NEEDS_REVIEW
      - low → FAIL

    Note: typesafe-sdk NoulAnswer has no confidence field (only noul). Prefer an
    explicit safe_to_import.confidence when present; otherwise use
    grounding_quality.confidence as the high-confidence gate.
    """
    result.jev = jev_answers
    if result.verdict == "TELEMETRY_GAP":
        # Catalog miss is authoritative; Jev cannot invent fields
        result.reasons.append("jev skipped for policy: deterministic TELEMETRY_GAP")
        return result
    if result.verdict == "SKIP":
        return result

    safe = float(jev_answers.get("safe_to_import", {}).get("noul", 0.0))
    safe_conf = float(jev_answers.get("safe_to_import", {}).get("confidence", 0.0) or 0.0)
    grounding_conf = float(
        jev_answers.get("grounding_quality", {}).get("confidence", 0.0) or 0.0
    )
    # Noul answers historically lack confidence; fall back to grounding confidence.
    conf = safe_conf if safe_conf > 0.0 else grounding_conf
    fields_exist = float(jev_answers.get("fields_exist", {}).get("noul", 0.0))
    tables_exist = float(jev_answers.get("tables_exist", {}).get("noul", 0.0))
    grounding = jev_answers.get("grounding_quality", {}).get("score")

    if safe >= 0.85 and conf >= 0.7 and fields_exist >= 0.8 and tables_exist >= 0.8:
        if result.verdict in {"NEEDS_REVIEW", "PASS"}:
            result.verdict = "PASS"
            result.reasons.append(
                f"jev safe_to_import={safe:.2f} conf={conf:.2f} grounding={grounding}"
            )
    elif safe >= 0.5 or result.verdict == "NEEDS_REVIEW":
        result.verdict = "NEEDS_REVIEW"
        result.reasons.append(f"jev mid-band safe_to_import={safe:.2f}")
    else:
        result.verdict = "FAIL"
        result.reasons.append(f"jev low safe_to_import={safe:.2f}")
    return result


def iter_in_repo_detections(detections_root: Path) -> Iterable[Tuple[Path, Dict[str, Any]]]:
    for path in sorted(detections_root.rglob("*.y*ml")):
        if path.name.startswith("."):
            continue
        obj = _load_yaml(path)
        for det in _normalize_detection(obj):
            yield path, det


def run_in_repo(
    catalog: TelemetryCatalog,
    detections_root: Path,
    *,
    use_jev: bool = False,
    cache_dir: Optional[Path] = None,
) -> List[RuleValidation]:
    results: List[RuleValidation] = []
    for path, det in iter_in_repo_detections(detections_root):
        rv = validate_detection(det, catalog, path=path)
        if use_jev and rv.in_scope and rv.verdict in {"NEEDS_REVIEW", "PASS"}:
            from jev_field_grounding import evaluate_rule_with_jev

            answers = evaluate_rule_with_jev(rv, catalog, cache_dir=cache_dir)
            if answers:
                rv = apply_jev_policy(rv, answers)
        results.append(rv)
    return results


def run_candidates(
    catalog: TelemetryCatalog,
    candidates: List[Dict[str, Any]],
    *,
    use_jev: bool = False,
    cache_dir: Optional[Path] = None,
) -> List[RuleValidation]:
    results: List[RuleValidation] = []
    for cand in candidates:
        rv = validate_candidate(cand, catalog)
        if use_jev and rv.in_scope and rv.verdict in {"NEEDS_REVIEW", "PASS", "TELEMETRY_GAP"}:
            # Still call Jev for NEEDS_REVIEW/PASS; TELEMETRY_GAP recorded but not upgraded
            if rv.verdict != "TELEMETRY_GAP":
                from jev_field_grounding import evaluate_rule_with_jev

                answers = evaluate_rule_with_jev(rv, catalog, cache_dir=cache_dir)
                if answers:
                    rv = apply_jev_policy(rv, answers)
        results.append(rv)
    return results


def write_report(results: List[RuleValidation], out_path: Path, *, catalog_version: int) -> Dict[str, Any]:
    summary = {
        "PASS": 0,
        "FAIL": 0,
        "NEEDS_REVIEW": 0,
        "TELEMETRY_GAP": 0,
        "SKIP": 0,
    }
    for r in results:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "catalog_version": catalog_version,
        "question_set_version": QUESTION_SET_VERSION,
        "jev_model": JEV_MODEL,
        "summary": summary,
        "results": [r.to_dict() for r in results],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate detection tables/fields against telemetry catalog")
    parser.add_argument("--in-repo", action="store_true", help="Validate detections/ in this repo")
    parser.add_argument("--candidates", type=Path, help="JSON file of RuleAtlas-normalized candidates")
    parser.add_argument("--catalog", type=Path, help="Path to catalog.json")
    parser.add_argument("--report", type=Path, help="Write JSON report path")
    parser.add_argument("--jev", action="store_true", help="Call Jev for soft-match cases (needs TYPESAFE_API_KEY)")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on TELEMETRY_GAP/FAIL for in-scope rules")
    parser.add_argument("--cache-dir", type=Path, help="Jev answer cache directory")
    args = parser.parse_args(argv)

    root = _repo_root()
    catalog_path = args.catalog or (root / "content" / "telemetry" / "catalog.json")
    catalog = TelemetryCatalog.load(catalog_path)
    cache_dir = args.cache_dir or (root / "content" / "validation" / "cache")

    results: List[RuleValidation] = []
    if args.in_repo:
        results.extend(
            run_in_repo(
                catalog,
                root / "detections",
                use_jev=args.jev,
                cache_dir=cache_dir,
            )
        )
    if args.candidates:
        raw = json.loads(args.candidates.read_text(encoding="utf-8"))
        cands = raw if isinstance(raw, list) else raw.get("candidates", [])
        results.extend(
            run_candidates(catalog, cands, use_jev=args.jev, cache_dir=cache_dir)
        )

    if not args.in_repo and not args.candidates:
        parser.error("Specify --in-repo and/or --candidates")

    report_path = args.report or (root / "content" / "validation" / "rule_field_report.json")
    report = write_report(results, report_path, catalog_version=catalog.version)

    in_scope = [r for r in results if r.in_scope]
    print(
        f"Validated {len(results)} rules ({len(in_scope)} in-scope). "
        f"summary={report['summary']} report={report_path}"
    )

    if args.strict:
        bad = [r for r in in_scope if r.verdict in {"FAIL", "TELEMETRY_GAP"}]
        if bad:
            for r in bad[:50]:
                print(f"{r.verdict}: {r.id} {r.path}: {'; '.join(r.reasons)}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    # Allow running as script from pipelines/validate
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    raise SystemExit(main())
