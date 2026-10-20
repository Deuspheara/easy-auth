"""Fail-closed resource reporting tests; mocked rows establish no crypto/resource safety."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import observe

spec = importlib.util.spec_from_file_location(
    "parser_observe", Path(__file__).resolve().parents[1] / "parser-probe" / "observe.py")
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)
sys.modules["parser_observe"] = parser
sys.modules["signature_observe"] = observe
import resource_observe as resources


def rows():
    return [{"case": case, "mode": mode, "accepted": case in resources.POSITIVES,
             "trusted_subject": case in resources.POSITIVES, "attacker_marker": False,
             "wrapper_marker": False,
             "error_class": "none" if case in resources.POSITIVES else "invalid_signature"}
            for case in sorted(resources.CASES) for mode in sorted(observe.MODES)]


def counts():
    return {"sentinel_file_calls": 0, "connect_calls": 0, "http_requests": 0,
            "native_diagnostics_emitted": False}


class ResourceReportingTests(unittest.TestCase):
    def test_each_observed_resource_call_prevents_a_pass(self):
        for key in ("sentinel_file_calls", "connect_calls", "http_requests"):
            with self.subTest(key=key):
                calls = counts()
                calls[key] = 1
                result = resources.report(rows(), calls, {}, {})
                self.assertFalse(result["candidate_controls_passed"])

    def test_engine_error_stays_unresolved_without_observed_resource_calls(self):
        values = rows()
        for row in values:
            if row["case"] in resources.FORBIDDEN:
                row["error_class"] = "engine_error"
        result = resources.report(values, counts(), {}, {})
        self.assertFalse(result["candidate_controls_passed"])
        self.assertEqual(result["unresolved_engine_rows"], len(resources.FORBIDDEN) * 2)

    def test_failed_signed_controls_never_become_security_rejections(self):
        for failed in sorted(resources.POSITIVES):
            with self.subTest(failed=failed):
                values = rows()
                for row in values:
                    if row["case"] == failed:
                        row.update(accepted=False, trusted_subject=False,
                                   error_class="invalid_signature")
                with tempfile.TemporaryDirectory() as directory:
                    with patch.object(parser, "capture", return_value=({"rows": values}, False)):
                        with self.assertRaisesRegex(parser.InfrastructureFailure,
                                                    "signed_positive_control_failed"):
                            resources.observe("fixture", 1, Path(directory))

    def test_missing_case_is_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(parser, "capture", return_value=({"rows": rows()[:-1]}, False)):
                with self.assertRaisesRegex(observe.InfrastructureFailure,
                                            "engine_cases_incomplete"):
                    resources.observe("fixture", 1, Path(directory))


if __name__ == "__main__":
    unittest.main()
