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

    def test_kev_search_preserves_cve_hyphens(self):
        import sqlite3
        con = sqlite3.connect(":memory:")
        con.row_factory = app.sqlite3.Row
        con.execute("""CREATE TABLE kev (
            cve_id TEXT, vendor_project TEXT, product TEXT,
            vulnerability_name TEXT, date_added TEXT,
            known_ransomware TEXT, due_date TEXT
        )""")
        con.execute(
            "INSERT INTO kev VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("CVE-2021-44228", "Apache", "Log4j2",
             "Apache Log4j2 Remote Code Execution Vulnerability",
             "2021-12-10", "Known", "2021-12-24")
        )
        rows = app.search_kev_rows(con, "CVE-2021-44228")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cve_id"], "CVE-2021-44228")
        con.close()

    def test_cpe_parser_handles_escaped_colons(self):
        vendor, product, version = app.cpe_vendor_product(
            r"cpe:2.3:a:apache:log4j\:core:2.14.1:*:*:*:*:*:*"
        )
        self.assertEqual(vendor, "apache")
        self.assertEqual(product, "log4j:core")
        self.assertEqual(version, "2.14.1")

    def test_asset_edit_preserves_record_id_and_updates_fields(self):
        import tempfile
        original_db_path = app.DB_PATH
        try:
            with tempfile.TemporaryDirectory(prefix="cybersentinel-asset-test-") as tmp:
                app.DB_PATH = Path(tmp) / "assets.sqlite3"
                app.init_db()
                original = {
                    "organization": "Test Org", "asset_name": "laptop",
                    "vendor": "WD", "product": "HP ProBook", "version": "7",
                    "environment": "test", "owner": "tester", "notes": ""
                }
                asset_id = app.save_asset_record(original)
                corrected = dict(original, vendor="Microsoft", product="Windows 7", version="6.1")
                updated_id = app.save_asset_record(corrected, asset_id)
                self.assertEqual(updated_id, asset_id)
                with app.db() as con:
                    row = con.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
                self.assertEqual(row["vendor"], "Microsoft")
                self.assertEqual(row["product"], "Windows 7")
                self.assertEqual(row["version"], "6.1")
                self.assertEqual(row["asset_name"], "laptop")
        finally:
            app.DB_PATH = original_db_path

    def test_zero_candidates_are_not_reported_as_safe(self):
        asset = {"asset_name": "laptop"}
        self.assertIn(
            "coverage not established",
            app.asset_assessment_label(asset, [])
        )

    def test_asset_assessment_flags_affected_version_as_potential_finding(self):
        asset = {"asset_name": "server"}
        fake_kev = {"cve_id": "CVE-2021-44228"}
        self.assertEqual(
            app.asset_assessment_label(asset, [(fake_kev, "Affected version range")]),
            "Potential affected-version finding"
        )

    def test_notebook_is_created_before_first_use_in_gui_builder(self):
        import ast
        import inspect
        import textwrap
        tree = ast.parse(textwrap.dedent(inspect.getsource(app.App.build_ui)))
        notebook_assignment = None
        first_notebook_read = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                       and target.value.id == "self" and target.attr == "tabs"
                       for target in node.targets):
                    notebook_assignment = node.lineno
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                if isinstance(node.value, ast.Name) and node.value.id == "self" and node.attr == "tabs":
                    first_notebook_read = node.lineno if first_notebook_read is None else min(first_notebook_read, node.lineno)
        self.assertIsNotNone(notebook_assignment, "build_ui must create the Notebook")
        self.assertIsNotNone(first_notebook_read, "build_ui must use the Notebook")
        self.assertLess(notebook_assignment, first_notebook_read,
                        "Notebook must be initialized before any access")

    def test_application_window_initializes_and_builds_tabs(self):
        import tempfile
        import shutil
        from pathlib import Path
        original_db_path = app.DB_PATH
        temp_dir = Path(tempfile.mkdtemp(prefix="cybersentinel-test-"))
        root = None
        try:
            app.DB_PATH = temp_dir / "cybersentinel_test.sqlite3"
            app.init_db()
            root = app.App()
            root.update_idletasks()
            self.assertEqual(len(root.tabs.tabs()), 3)
            self.assertEqual(root.tabs.tab(root.tabs.tabs()[0], "text"), "Risk Dashboard")
        finally:
            if root is not None:
                root.destroy()
            app.DB_PATH = original_db_path
            shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main(verbosity=2)
