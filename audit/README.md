# Code audit, 2026-10-14

Code-only security and consensus-consistency audit of commit `125e9e5`, with a
comparison against Bitcoin Core master `f13ae51`.

| Path | What it is |
| --- | --- |
| `GnB-SMH-Code-Audit-2026-10-14.pdf` | The report (English): 70 findings (5 Critical, 19 High), component comparison, historical bug-class matrix, weighted scorecard (GnB 3.1 / 10, Bitcoin Core 9.1 / 10), full test-module inventory |
| `consistency/` | Independent consistency harness (35 tests): Bitcoin Core vectors and ports, BCHN aserti3-2d, rust-bitcoin and the normative Python GnB-SMH as oracles for compact targets, ASERT, Merkle roots, amounts, PoW and chain work. Its own workspace; `cd audit/consistency && cargo test --release` |
| `consistency/scripts/mutants_vs_harness.py` | Re-runs the cargo-mutants survivors of `gnb-smh` against the harness |
| `poc/` | 73 proof-of-concept tests from the review, kept out of the project's suites; see `poc/README.md` |
| `report/` | Report sources: `gen_inventory.py`, `gen_content.py`, `inputs/*.json` (findings and data), `build_report.py`, `print_pdf.cjs` |

Rebuild the PDF (needs Python 3 and Node with Playwright/Chromium):

```sh
python3 audit/report/gen_inventory.py
python3 audit/report/gen_content.py
python3 audit/report/build_report.py
node audit/report/print_pdf.cjs audit/report/out/report.html audit/GnB-SMH-Code-Audit-2026-10-14.pdf
```
