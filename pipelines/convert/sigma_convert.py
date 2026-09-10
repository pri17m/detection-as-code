#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


def _try_import_sigma() -> Tuple[Optional[Any], Optional[Any], Optional[Any]]:
    try:
        from sigma.collection import SigmaCollection  # type: ignore
        from sigma.backends.splunk import SplunkBackend  # type: ignore
        from sigma.backends.kusto import KustoBackend  # type: ignore

        return SigmaCollection, SplunkBackend, KustoBackend
    except Exception:
        return None, None, None


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _dump_yaml(obj: Dict[str, Any]) -> str:
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True)


def _slug(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")[:80] or "rule"


@dataclass(frozen=True)
class Converted:
    sigma_path: Path
    dac_sigma: Dict[str, Any]
    dac_splunk: Optional[Dict[str, Any]]
    dac_defender: Optional[Dict[str, Any]]


def _extract_attack_techniques(sigma_obj: Dict[str, Any]) -> List[str]:
    tags = sigma_obj.get("tags") or []
    technique_ids: List[str] = []
    if isinstance(tags, list):
        for t in tags:
            if isinstance(t, str) and t.startswith("attack.t"):
                # attack.t1059.001 -> T1059.001
                m = re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", t)
                if m:
                    technique_ids.append(m.group(1).upper())
    return sorted(set(technique_ids))


def convert_sigma_rule(
    *,
    sigma_path: Path,
    sigma_obj: Dict[str, Any],
    out_id: str,
    technique_ids: List[str],
    emit_splunk: bool,
    emit_defender: bool,
) -> Converted:
    title = str(sigma_obj.get("title") or sigma_path.stem)
    desc = str(sigma_obj.get("description") or "Sigma-derived detection (unvalidated).")

    tags = sigma_obj.get("tags") or []
    if not technique_ids:
        raise ValueError("Sigma rule missing ATT&CK technique tags (attack.t####[.###])")

    dac_sigma: Dict[str, Any] = {
        "id": out_id,
        "title": title,
        "description": desc,
        "author": str(sigma_obj.get("author") or "Sigma"),
        "status": "experimental",
        "platforms": ["splunk"] if emit_splunk else ["splunk"],
        "sourcetypes": ["WinEventLog:Security"],
        "mitre": {
            "tactics": [],
            "techniques": technique_ids,
        },
        "severity": "medium",
        "false_positives": [str(x) for x in (sigma_obj.get("falsepositives") or [])] if isinstance(sigma_obj.get("falsepositives"), list) else [],
        "references": [str(x) for x in (sigma_obj.get("references") or [])] if isinstance(sigma_obj.get("references"), list) else [str(sigma_path)],
        "telemetry_validated": False,
        "required_fields": [],
        "sigma": {"path": str(sigma_path), "rule_id": str(sigma_obj.get("id") or "")},
        "tags": [str(x) for x in tags] if isinstance(tags, list) else [],
    }

    SigmaCollection, SplunkBackend, KustoBackend = _try_import_sigma()
    dac_splunk = None
    dac_defender = None

    if SigmaCollection and SplunkBackend and emit_splunk:
        try:
            coll = SigmaCollection.from_yaml(sigma_path.read_text(encoding="utf-8"))
            backend = SplunkBackend()
            rules = backend.convert(coll)
            spl = "\n".join([str(x) for x in rules if str(x).strip()])
            dac_splunk = {
                **{k: v for k, v in dac_sigma.items() if k != "platforms"},
                "platforms": ["splunk"],
                "query": {"splunk": spl},
            }
        except Exception:
            dac_splunk = None

    if SigmaCollection and KustoBackend and emit_defender:
        try:
            coll = SigmaCollection.from_yaml(sigma_path.read_text(encoding="utf-8"))
            backend = KustoBackend()
            rules = backend.convert(coll)
            kql = "\n".join([str(x) for x in rules if str(x).strip()])
            dac_defender = {
                **{k: v for k, v in dac_sigma.items() if k != "platforms"},
                "platforms": ["defender"],
                "query": {"defender": kql},
            }
        except Exception:
            dac_defender = None

    return Converted(sigma_path=sigma_path, dac_sigma=dac_sigma, dac_splunk=dac_splunk, dac_defender=dac_defender)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Folder containing Sigma rules (YAML)")
    ap.add_argument("--output", required=True, help="Output folder for normalized Sigma DaC detections")
    ap.add_argument("--emit-splunk", default=None, help="Folder to emit Splunk detections converted from Sigma")
    ap.add_argument("--emit-defender", default=None, help="Folder to emit Defender detections converted from Sigma")
    ap.add_argument("--id-prefix", default="DAC-SIG-", help="DaC id prefix (default DAC-SIG-)")
    ap.add_argument("--start", type=int, default=1, help="Starting numeric id (default 1)")
    args = ap.parse_args()

    in_root = Path(args.input).resolve()
    out_root = Path(args.output).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    out_splunk = Path(args.emit_splunk).resolve() if args.emit_splunk else None
    out_defender = Path(args.emit_defender).resolve() if args.emit_defender else None
    if out_splunk:
        out_splunk.mkdir(parents=True, exist_ok=True)
    if out_defender:
        out_defender.mkdir(parents=True, exist_ok=True)

    sigma_files = sorted([p for p in in_root.rglob("*.y*ml") if p.is_file()])
    if not sigma_files:
        print(f"No Sigma YAML found under {in_root}", file=sys.stderr)
        return 2

    wrote = 0
    for p in sigma_files:
        obj = _load_yaml(p)
        if not isinstance(obj, dict) or "detection" not in obj:
            continue
        technique_ids = _extract_attack_techniques(obj)
        if not technique_ids:
            continue
        out_id = f"{args.id_prefix}{(args.start + wrote):04d}"

        conv = convert_sigma_rule(
            sigma_path=p,
            sigma_obj=obj,
            out_id=out_id,
            technique_ids=technique_ids,
            emit_splunk=bool(out_splunk),
            emit_defender=bool(out_defender),
        )

        # Normalize sigma detection object (metadata-only).
        sigma_out_path = out_root / f"{out_id}-{_slug(conv.dac_sigma['title'])}.yaml"
        sigma_out_path.write_text(_dump_yaml(conv.dac_sigma), encoding="utf-8")
        wrote += 1

        if out_splunk and conv.dac_splunk and conv.dac_splunk.get("query"):
            spl_out = out_splunk / f"{out_id}-{_slug(conv.dac_splunk['title'])}.yaml"
            spl_out.write_text(_dump_yaml(conv.dac_splunk), encoding="utf-8")

        if out_defender and conv.dac_defender and conv.dac_defender.get("query"):
            def_out = out_defender / f"{out_id}-{_slug(conv.dac_defender['title'])}.yaml"
            def_out.write_text(_dump_yaml(conv.dac_defender), encoding="utf-8")

    print(f"Wrote {wrote} normalized Sigma detections to {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

