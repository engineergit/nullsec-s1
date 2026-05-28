"""Curation Sprint 003 — supplementary cases.

One more real DANGEROUS_SHELL_COMMAND case (to push that category to 17), plus two
additional reject-tests covering different weak-provenance types (cve without ID,
semgrep without rule_id) so the sprint demonstrates provenance enforcement across
source types.
"""
from __future__ import annotations

CASES_SUP = [
    dict(category="DANGEROUS_SHELL_COMMAND", source_type="vibecoded_failure",
         source_ref="nullsec scanner: AI-generated CSV formula / spreadsheet export",
         references={"case_id": "VIBE-CSV-101", "cwe": "CWE-1236", "owasp": "A03:2021-Injection"},
         lang="python", framework="flask", filename="export_csv.py",
         code="def row(user):\n    return f'{user.name},{user.note}'  # written straight into CSV\n",
         completion=dict(severity="MEDIUM",
             exploit="A user.note beginning with =cmd|'/c calc'!A1 is interpreted as a formula (CSV injection) when the export opens in a spreadsheet.",
             patch="-    return f'{user.name},{user.note}'\n+    def esc(v):\n+        return (\"'\" + v) if v and v[0] in ('=','+','-','@','\\t','\\r') else v\n+    return f'{esc(user.name)},{esc(user.note)}'",
             reviewer_notes="AI-generated app failure: CSV/formula injection in export. Prefix-escape dangerous leading chars. CWE-1236."),
         ),
    # ---- reject-tests (intentional, to exercise provenance enforcement) ----
    dict(category="SQL_INJECTION", source_type="cve",
         source_ref="some SQL injection (no id)",
         references={"cwe": "CWE-89"},  # cve type but no CVE id
         lang="python", framework="flask", filename="r.py",
         code="cur.execute('SELECT * FROM t WHERE x=' + v)\n",
         completion=dict(exploit="injection", patch="-x=' + v\n+x=%s,(v,)",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=cve without a real CVE ID"),
    dict(category="XSS", source_type="semgrep",
         source_ref="common vulnerability",
         references={"cwe": "CWE-79"},  # semgrep type but no rule_id, vague ref
         lang="javascript", framework="react", filename="r.jsx",
         code="el.innerHTML = input;\n",
         completion=dict(exploit="xss", patch="-innerHTML\n+textContent",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=semgrep without a rule_id; reference 'common vulnerability' is vague"),
]
