import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import cybersentinel_kev as app

class CyberSentinelLogicTests(unittest.TestCase):
    def test_version_comparison(self):
        self.assertEqual(app.compare_versions("1.10", "1.9"), 1)
        self.assertEqual(app.compare_versions("1.2", "1.2.0"), 0)
        self.assertIsNone(app.compare_versions("", "1.0"))

    def test_inclusive_and_exclusive_bounds(self):
        match = {"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}
        self.assertEqual(app.evaluate_version("1.0", match), "Affected")
        self.assertEqual(app.evaluate_version("1.9", match), "Affected")
        self.assertEqual(app.evaluate_version("2.0", match), "Outside affected range")

    def test_cvss_extraction(self):
        raw = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/test"}}]}}}]}
        self.assertEqual(app.nvd_cvss_summary(raw), (9.8, "CRITICAL", "CVSS:3.1/test", "cvssMetricV31"))

    def test_risk_score_is_bounded_and_ransomware_increases_score(self):
        record = {"known_ransomware": "Known", "due_date": ""}
        base = app.risk_priority_score({"known_ransomware": "Unknown", "due_date": ""}, "Needs NVD enrichment")
        ransomware = app.risk_priority_score(record, "Needs NVD enrichment")
        self.assertEqual(ransomware - base, 20)
        self.assertLessEqual(app.risk_priority_score(record, "Affected version range", 10.0), 100)

if __name__ == "__main__":
    unittest.main(verbosity=2)
