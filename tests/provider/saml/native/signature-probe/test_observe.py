"""Fail-closed reporting tests; these do not simulate cryptographic verification."""
import unittest
from unittest.mock import patch

import observe


def outcome(case, mode, accepted=True, error="none"):
    return {"case": case, "mode": mode, "accepted": accepted,
            "trusted_subject": accepted, "attacker_marker": False,
            "wrapper_marker": False, "error_class": error}


def complete_rows():
    return [outcome(case, mode) for case in sorted(observe.CASES)
            for mode in sorted(observe.MODES)]


class ReportingTests(unittest.TestCase):
    def test_missing_duplicate_and_contradictory_rows_are_infrastructure_failures(self):
        rows = complete_rows()
        contradictory = outcome("unsigned", "rooted", False, "invalid_signature")
        contradictory["attacker_marker"] = True
        for invalid in (rows[:-1], rows + [rows[0]], [contradictory]):
            with self.subTest(invalid=invalid[:1]):
                with self.assertRaises(observe.InfrastructureFailure):
                    observe.validate(invalid)

    def test_failed_positive_is_never_reported_as_secure_rejection(self):
        for failed in sorted(observe.POSITIVES):
            with self.subTest(failed=failed):
                rows = complete_rows()
                for row in rows:
                    if row["case"] == failed:
                        row.update(accepted=False, trusted_subject=False,
                                   error_class="invalid_signature")
                with patch.object(observe, "capture", return_value=(rows, False)):
                    with self.assertRaisesRegex(observe.InfrastructureFailure,
                                                "signed_positive_control_failed"):
                        observe.run()

    def test_engine_failure_is_unresolved_and_does_not_pass_candidate(self):
        rows = complete_rows()
        for row in rows:
            if row["case"] in observe.DENIALS | observe.SYNTAX:
                row.update(accepted=False, trusted_subject=False,
                           error_class="engine_error")
        with patch.object(observe, "capture", return_value=(rows, True)):
            result = observe.run()
        self.assertFalse(result["candidate_controls_passed"])
        self.assertEqual(result["unresolved_engine_rows"],
                         len(observe.DENIALS | observe.SYNTAX) * len(observe.MODES))

    def test_unsigned_acceptance_and_foreign_content_are_policy_gaps(self):
        self.assertEqual(observe.assess(outcome("unsigned", "rooted")), "policy_gap")
        wrapped = outcome("forged-sibling-before", "predigest")
        wrapped["attacker_marker"] = True
        self.assertEqual(observe.assess(wrapped), "policy_gap")


if __name__ == "__main__":
    unittest.main()
