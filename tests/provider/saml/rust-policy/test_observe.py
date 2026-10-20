"""Fault the reporting boundary using recorded finite outcomes, never XML."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


parser = load("parser_observe", ROOT.parent / "native/parser-probe/observe.py")
load("comparison_run", ROOT.parent / "comparison/run.py")
observer = load("policy_observe", ROOT / "observe.py")


class ReportingFaults(unittest.TestCase):
    def setUp(self):
        self.report = json.loads((ROOT / "results/2026-10-20-exact-policy.json").read_text())
        self.exact = self.report["exact_rows"]
        self.broad = self.report["broad_profile_rows"]
        self.counts = self.report["aggregate_exact_child"]

    def passed(self):
        return observer.policy_passed(self.exact, self.broad, self.counts)

    def test_recorded_controls_pass(self):
        self.assertTrue(self.passed())

    def test_missing_outcome_is_infrastructure_failure(self):
        keys = {(row["case"], row["mode"]) for row in self.exact}
        with self.assertRaises(parser.InfrastructureFailure):
            observer.validate_rows(self.exact[:-1], keys, "exact-flow")

    def test_unknown_engine_error_cannot_be_counted_as_safe_rejection(self):
        denied = next(row for row in self.exact if not row["accepted"])
        denied["error_class"] = "other_rejection_unresolved"
        self.assertFalse(self.passed())

    def test_file_network_observations_cannot_pass(self):
        for key in ("sentinel_file_calls", "connect_calls", "http_requests"):
            with self.subTest(key=key):
                counts = copy.deepcopy(self.counts)
                counts[key] = 1
                self.assertFalse(observer.policy_passed(self.exact, self.broad, counts))

    def test_forged_identity_cannot_pass(self):
        next(row for row in self.exact if row["accepted"])["attacker_marker"] = True
        self.assertFalse(self.passed())

    def test_unapproved_algorithm_acceptance_cannot_pass(self):
        next(row for row in self.exact if row["case"] in observer.NONPOLICY)["accepted"] = True
        self.assertFalse(self.passed())


if __name__ == "__main__":
    unittest.main()
