#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATE = ROOT / "pipelines" / "validate"
RULEATLAS = ROOT / "pipelines" / "ruleatlas"
sys.path.insert(0, str(VALIDATE))
sys.path.insert(0, str(RULEATLAS))

from telemetry_catalog import TelemetryCatalog  # noqa: E402
from validate_fields import (  # noqa: E402
    apply_jev_policy,
    extract_from_spl,
    validate_candidate,
    validate_detection,
)
from normalize import normalize_record  # noqa: E402


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = TelemetryCatalog.load(ROOT / "content" / "telemetry" / "catalog.json")

    def test_version(self) -> None:
        self.assertEqual(self.catalog.version, 1)

    def test_resolve_cloudtrail_macro(self) -> None:
        t = self.catalog.resolve_table("`aws_cloudtrail`")
        self.assertIsNotNone(t)
        assert t is not None
        self.assertEqual(t.id, "aws_cloudtrail")

    def test_resolve_field_alias(self) -> None:
        status, canonical = self.catalog.resolve_field(
            "mfaAuthenticated", table_ids=["aws_cloudtrail"]
        )
        self.assertEqual(status, "alias")
        self.assertEqual(
            canonical, "userIdentity.sessionContext.attributes.mfaAuthenticated"
        )

    def test_slice_families(self) -> None:
        sl = self.catalog.slice(families=["cloudtrail"])
        ids = {t["id"] for t in sl["tables"]}
        self.assertEqual(ids, {"aws_cloudtrail"})


class ExtractTests(unittest.TestCase):
    def test_extract_spl_cloudtrail(self) -> None:
        tables, fields = extract_from_spl(
            "`aws_cloudtrail` eventName=ConsoleLogin additionalEventData.MFAUsed=No"
        )
        self.assertIn("aws_cloudtrail", tables)
        self.assertIn("eventName", fields)
        self.assertIn("additionalEventData.MFAUsed", fields)


class ValidateDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = TelemetryCatalog.load(ROOT / "content" / "telemetry" / "catalog.json")

    def test_aws_detection_pass(self) -> None:
        det = {
            "id": "DAC-AWS-TEST",
            "title": "test",
            "sourcetypes": ["aws:cloudtrail"],
            "required_fields": ["eventName", "userIdentity.arn", "additionalEventData.MFAUsed"],
            "query": {
                "splunk": "`aws_cloudtrail` eventName=ConsoleLogin additionalEventData.MFAUsed=No"
            },
        }
        rv = validate_detection(det, self.catalog)
        self.assertTrue(rv.in_scope)
        self.assertEqual(rv.verdict, "PASS")

    def test_unknown_required_field_gap(self) -> None:
        det = {
            "id": "DAC-AWS-GAP",
            "title": "gap",
            "sourcetypes": ["aws:cloudtrail"],
            "required_fields": ["notARealCloudTrailField"],
            "query": {"splunk": "sourcetype=aws:cloudtrail eventName=AssumeRole"},
        }
        rv = validate_detection(det, self.catalog)
        self.assertEqual(rv.verdict, "TELEMETRY_GAP")

    def test_out_of_scope_skip(self) -> None:
        det = {
            "id": "DAC-AZ-TEST",
            "title": "azure",
            "sourcetypes": ["azure:monitor:activity"],
            "required_fields": ["operationName"],
            "query": {"splunk": "sourcetype=azure:monitor:activity operationName=foo"},
        }
        rv = validate_detection(det, self.catalog)
        self.assertEqual(rv.verdict, "SKIP")

    def test_jev_policy_does_not_override_gap(self) -> None:
        det = {
            "id": "DAC-AWS-GAP2",
            "title": "gap",
            "sourcetypes": ["aws:cloudtrail"],
            "required_fields": ["totallyMissing"],
            "query": {"splunk": "sourcetype=aws:cloudtrail eventName=AssumeRole"},
        }
        rv = validate_detection(det, self.catalog)
        rv = apply_jev_policy(
            rv,
            {
                "safe_to_import": {"noul": 0.99, "confidence": 0.99},
                "fields_exist": {"noul": 0.99},
                "tables_exist": {"noul": 0.99},
                "grounding_quality": {"score": "solid"},
            },
        )
        self.assertEqual(rv.verdict, "TELEMETRY_GAP")


class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = TelemetryCatalog.load(ROOT / "content" / "telemetry" / "catalog.json")

    def test_smoke_candidates_file(self) -> None:
        raw = json.loads(
            (ROOT / "content" / "validation" / "candidates.smoke.json").read_text()
        )
        for cand in raw["candidates"]:
            rv = validate_candidate(cand, self.catalog)
            self.assertTrue(rv.in_scope, msg=f"{cand['id']} not in scope")
            self.assertIn(rv.verdict, {"PASS", "NEEDS_REVIEW"}, msg=f"{cand['id']}={rv.verdict} {rv.reasons}")

    def test_normalize_record(self) -> None:
        cand = normalize_record(
            {
                "title": "Example",
                "logic": "sourcetype=aws:cloudtrail eventName=AssumeRole",
                "source": "splunk",
                "path": "a.yml",
                "techniques": ["T1078.004"],
            }
        )
        self.assertTrue(cand["id"].startswith("ra-"))
        self.assertEqual(cand["source_id"], "splunk")
        self.assertIn("T1078.004", cand["mitre"])


if __name__ == "__main__":
    unittest.main()
