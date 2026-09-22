#!/usr/bin/env python3
"""Normalize RuleAtlas search/export records into DaC candidate objects."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map a RuleAtlas store.search() hit (or export row) into a stable candidate.

    RuleAtlas field names vary slightly by adapter; accept common keys.
    """
    title = (
        record.get("title")
        or record.get("name")
        or record.get("rule_name")
        or ""
    )
    logic = (
        record.get("logic")
        or record.get("query")
        or record.get("detection")
        or record.get("content")
        or ""
    )
    if isinstance(logic, dict):
        logic = json.dumps(logic, sort_keys=True)
    logic = str(logic)

    source_id = str(record.get("source") or record.get("source_id") or record.get("repo") or "")
    path = str(record.get("path") or record.get("file_path") or record.get("filepath") or "")
    permalink = str(
        record.get("permalink")
        or record.get("revision_url")
        or record.get("html_url")
        or record.get("url")
        or ""
    )
    mitre = record.get("mitre") or record.get("techniques") or record.get("attack") or []
    if isinstance(mitre, str):
        mitre = [mitre]
    if isinstance(mitre, dict):
        mitre = mitre.get("techniques") or mitre.get("ids") or []

    content_hash = _sha256(f"{source_id}\0{path}\0{logic}")
    return {
        "id": f"ra-{content_hash[:12]}",
        "source_id": source_id,
        "title": str(title),
        "logic": logic,
        "mitre": [str(x) for x in mitre if x],
        "path": path,
        "permalink": permalink,
        "content_hash": content_hash,
        "raw_keys": sorted(record.keys()),
    }


def normalize_many(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        cand = normalize_record(rec)
        if cand["content_hash"] in seen:
            continue
        seen.add(cand["content_hash"])
        out.append(cand)
    return out


def write_candidates(candidates: List[Dict[str, Any]], path: str) -> None:
    payload = {"count": len(candidates), "candidates": candidates}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")


def load_candidates(path: str) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        c = raw.get("candidates")
        if isinstance(c, list):
            return c
    raise ValueError(f"{path}: expected list or {{candidates: [...]}}")
