#!/usr/bin/env python3
"""Jev field-grounding pack: typed questions over catalog slice + rule excerpt."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from telemetry_catalog import TelemetryCatalog
from validate_fields import JEV_MODEL, QUESTION_SET_VERSION, RuleValidation

PACK_DIR = Path(__file__).resolve().parent / "jev_packs" / "field_grounding"


def _load_pack() -> Dict[str, Any]:
    pack_path = PACK_DIR / "pack.yaml"
    try:
        import yaml

        return yaml.safe_load(pack_path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise RuntimeError(f"Missing Jev pack: {pack_path}") from e


def _cache_key(rule: RuleValidation) -> str:
    return f"{rule.content_hash}_{QUESTION_SET_VERSION}_{JEV_MODEL.replace('.', '_')}"


def _read_cache(cache_dir: Path, key: str) -> Optional[Dict[str, Any]]:
    path = cache_dir / f"{key}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_cache(cache_dir: Path, key: str, payload: Dict[str, Any]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"{key}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def build_state(rule: RuleValidation, catalog: TelemetryCatalog) -> Dict[str, Any]:
    slice_ = catalog.slice(families=rule.families or None)
    logic_excerpt = ""
    if rule.path:
        # Prefer not to re-read huge files; include findings instead
        pass
    return {
        "telemetry_catalog_slice": slice_,
        "rule": {
            "id": rule.id,
            "title": rule.title,
            "path": rule.path,
            "families": rule.families,
            "extracted_tables": [t.name for t in rule.tables],
            "extracted_fields": [
                {"name": f.name, "status": f.status, "canonical": f.canonical, "source": f.source}
                for f in rule.fields
            ],
            "deterministic_verdict": rule.verdict,
            "reasons": rule.reasons,
            "logic_excerpt": logic_excerpt,
        },
        "question_set_version": QUESTION_SET_VERSION,
    }


def evaluate_rule_with_jev(
    rule: RuleValidation,
    catalog: TelemetryCatalog,
    *,
    cache_dir: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """
    Call TypeSafe Jev with the field_grounding pack.
    Returns normalized answer dict or None if API key / SDK unavailable.
    """
    if not os.environ.get("TYPESAFE_API_KEY"):
        return None

    cache_dir = cache_dir or Path("content/validation/cache")
    key = _cache_key(rule)
    cached = _read_cache(cache_dir, key)
    if cached:
        return cached.get("answers")

    try:
        from typesafe_sdk import Choice, Noul, Score, TypeSafeClient
    except ImportError:
        return None

    pack = _load_pack()
    state = build_state(rule, catalog)
    questions_cfg = pack.get("questions") or {}

    questions: Dict[str, Any] = {}
    for qid, q in questions_cfg.items():
        qtype = q.get("type")
        instructions = q.get("instructions") or ""
        if qtype == "noul":
            questions[qid] = Noul(instructions=instructions)
        elif qtype == "choice":
            criteria = q.get("criteria") or {}
            questions[qid] = Choice(instructions=instructions, criteria=criteria)
        elif qtype == "score":
            criteria = q.get("criteria") or []
            questions[qid] = Score(instructions=instructions, criteria=criteria)

    client = TypeSafeClient(model=JEV_MODEL)
    result = client.system_one(state, questions)

    answers: Dict[str, Any] = {}
    for qid, q in questions_cfg.items():
        qtype = q.get("type")
        if qtype == "noul":
            ans = result.nouls.get(qid)
            if ans is not None:
                answers[qid] = {
                    "noul": float(ans.noul),
                    "confidence": float(getattr(ans, "confidence", 0.0) or 0.0),
                }
        elif qtype == "choice":
            ans = result.choices.get(qid)
            if ans is not None:
                answers[qid] = {
                    "choice": ans.choice,
                    "confidence": float(getattr(ans, "confidence", 0.0) or 0.0),
                    "probabilities": dict(getattr(ans, "probabilities", {}) or {}),
                }
        elif qtype == "score":
            ans = result.scores.get(qid)
            if ans is not None:
                answers[qid] = {
                    "score": ans.score,
                    "confidence": float(getattr(ans, "confidence", 0.0) or 0.0),
                    "probabilities": dict(getattr(ans, "probabilities", {}) or {}),
                }

    _write_cache(
        cache_dir,
        key,
        {
            "model": JEV_MODEL,
            "question_set_version": QUESTION_SET_VERSION,
            "content_hash": rule.content_hash,
            "answers": answers,
        },
    )
    return answers
