#!/usr/bin/env python3
"""Load and slice the machine-readable telemetry catalog."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set


WINDOWS_HINTS = (
    "WinEventLog",
    "XmlWinEventLog",
    "sysmon",
    "windows_security",
    "windows_system",
    "windows_powershell",
    "windows_sysmon",
)
CLOUDTRAIL_HINTS = ("aws:cloudtrail", "aws_cloudtrail", "cloudtrail")


@dataclass(frozen=True)
class FieldRef:
    name: str
    aliases: tuple[str, ...]
    status: str
    table_id: str


@dataclass(frozen=True)
class TableRef:
    id: str
    kind: str
    family: str
    names: tuple[str, ...]
    event_codes: tuple[str, ...]
    fields: tuple[FieldRef, ...]


class TelemetryCatalog:
    def __init__(self, data: Dict[str, Any], *, path: Optional[Path] = None) -> None:
        self.data = data
        self.path = path
        self.version = int(data.get("version", 0))
        self.tables: Dict[str, TableRef] = {}
        self._name_to_table: Dict[str, str] = {}
        self._alias_to_canonical: Dict[str, str] = {}
        self._canonical_fields: Set[str] = set()
        self._load()

    @classmethod
    def load(cls, path: Path) -> "TelemetryCatalog":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path}: catalog must be a JSON object")
        return cls(data, path=path)

    def _load(self) -> None:
        platforms = self.data.get("platforms")
        if not isinstance(platforms, dict):
            raise ValueError("catalog.platforms must be an object")
        for _plat, pdata in platforms.items():
            if not isinstance(pdata, dict):
                continue
            tables = pdata.get("tables")
            if not isinstance(tables, list):
                continue
            for t in tables:
                if not isinstance(t, dict):
                    continue
                tid = t.get("id")
                if not isinstance(tid, str):
                    continue
                field_refs: List[FieldRef] = []
                for f in t.get("fields") or []:
                    if not isinstance(f, dict) or not isinstance(f.get("name"), str):
                        continue
                    name = f["name"]
                    aliases = tuple(a for a in (f.get("aliases") or []) if isinstance(a, str))
                    status = str(f.get("status") or "validated")
                    fr = FieldRef(name=name, aliases=aliases, status=status, table_id=tid)
                    field_refs.append(fr)
                    self._canonical_fields.add(name)
                    self._alias_to_canonical[name.lower()] = name
                    for a in aliases:
                        self._alias_to_canonical[a.lower()] = name
                names = tuple(n for n in (t.get("names") or []) if isinstance(n, str))
                event_codes = tuple(str(c) for c in (t.get("event_codes") or []))
                tr = TableRef(
                    id=tid,
                    kind=str(t.get("kind") or "table"),
                    family=str(t.get("family") or ""),
                    names=names,
                    event_codes=event_codes,
                    fields=tuple(field_refs),
                )
                self.tables[tid] = tr
                for n in names:
                    self._name_to_table[_normalize_table_name(n)] = tid

    def resolve_table(self, name: str) -> Optional[TableRef]:
        key = _normalize_table_name(name)
        tid = self._name_to_table.get(key)
        if tid:
            return self.tables[tid]
        # glob-ish: aws:cloudtrail* → aws_cloudtrail
        for table in self.tables.values():
            for n in table.names:
                if n.endswith("*") and key.startswith(_normalize_table_name(n[:-1])):
                    return table
        return None

    def resolve_field(self, name: str, *, table_ids: Optional[Iterable[str]] = None) -> tuple[str, str]:
        """
        Return (status, canonical_name).
        status: valid | alias | unknown
        """
        needle = name.strip().strip("'\"")
        if not needle:
            return "unknown", needle
        lower = needle.lower()

        if table_ids:
            for tid in table_ids:
                table = self.tables.get(tid)
                if not table:
                    continue
                for fr in table.fields:
                    if fr.name.lower() == lower:
                        return "valid", fr.name
                    if any(a.lower() == lower for a in fr.aliases):
                        return "alias", fr.name

        canonical = self._alias_to_canonical.get(lower)
        if canonical is None:
            return "unknown", needle
        if canonical.lower() == lower:
            return "valid", canonical
        return "alias", canonical

    def slice(self, *, table_ids: Optional[Iterable[str]] = None, families: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """Return a compact catalog slice suitable for Jev state."""
        wanted_ids: Set[str] = set(table_ids or [])
        fams = set(families or [])
        if fams:
            for tid, t in self.tables.items():
                if t.family in fams:
                    wanted_ids.add(tid)
        if not wanted_ids:
            wanted_ids = set(self.tables.keys())

        out_tables = []
        for tid in sorted(wanted_ids):
            t = self.tables.get(tid)
            if not t:
                continue
            out_tables.append(
                {
                    "id": t.id,
                    "family": t.family,
                    "kind": t.kind,
                    "names": list(t.names),
                    "event_codes": list(t.event_codes),
                    "fields": [
                        {"name": f.name, "aliases": list(f.aliases), "status": f.status}
                        for f in t.fields
                    ],
                }
            )
        return {"version": self.version, "tables": out_tables}

    def families_for_sourcetypes(self, sourcetypes: Iterable[str]) -> Set[str]:
        families: Set[str] = set()
        for st in sourcetypes:
            table = self.resolve_table(st)
            if table:
                families.add(table.family)
                continue
            low = st.lower()
            if any(h.lower() in low for h in WINDOWS_HINTS):
                families.add("windows")
            if any(h.lower() in low for h in CLOUDTRAIL_HINTS):
                families.add("cloudtrail")
        return families

    def in_scope(self, sourcetypes: Iterable[str]) -> bool:
        return bool(self.families_for_sourcetypes(sourcetypes))


def _normalize_table_name(name: str) -> str:
    n = name.strip()
    if n.startswith("`") and n.endswith("`") and len(n) >= 2:
        n = n[1:-1]
    return n.lower()


def default_catalog_path(repo_root: Path) -> Path:
    return repo_root / "content" / "telemetry" / "catalog.json"


def load_default_catalog(repo_root: Path) -> TelemetryCatalog:
    return TelemetryCatalog.load(default_catalog_path(repo_root))
