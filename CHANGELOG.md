## 0.3.2
- Added editing for existing authorized software inventory records.
- Added explicit asset coverage assessment; zero KEV candidates are not treated as evidence of safety.
- Clarified software inventory entry semantics.
- Corrected CPE 2.3 escaped-colon parsing and added regression tests.

# v0.3.0 — 16 November 2026

- Added a local risk dashboard and prioritized finding queue.
- Added NVD CVSS score/severity/vector display after per-CVE enrichment.
- Added transparent heuristic risk scoring with explicit non-probabilistic caveat.
- Added unit tests for version bounds, CVSS extraction, and score behavior.
- Preserved local SQLite data location and avoided changes to the Sales Assistant CRM or its Supabase project.
