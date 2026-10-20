"""Infrastructure failures must never be reported as advisory clearance."""
import unittest

from check_dependency_report import assess


def healthy():
    return [{"type": "summary", "fields": {
        name: {"errors": 0, "warnings": 0, "notes": 0, "helps": 0}
        for name in ("advisories", "licenses", "sources")}}]


class DependencyReporting(unittest.TestCase):
    def test_exit_zero_with_error_log_fails_closed(self):
        rows = healthy() + [{"type": "log", "fields": {"level": "ERROR"}}]
        self.assertEqual(assess(rows, 0)["status"], "infrastructure_failed")

    def test_missing_summary_fails_closed(self):
        self.assertEqual(assess([], 0)["status"], "infrastructure_failed")

    def test_actual_check_failure_is_retained(self):
        rows = healthy()
        rows[0]["fields"]["advisories"]["errors"] = 1
        self.assertEqual(assess(rows, 1)["status"], "checks_failed")

    def test_clean_summary_retains_warnings(self):
        rows = healthy()
        rows[0]["fields"]["licenses"]["warnings"] = 7
        report = assess(rows, 0)
        self.assertEqual(report["status"], "checks_passed")
        self.assertEqual(report["summary"]["licenses"]["warnings"], 7)


if __name__ == "__main__":
    unittest.main()
