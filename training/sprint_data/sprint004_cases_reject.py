"""Curation Sprint 004 — reject-tests.

These are INTENTIONAL weak-provenance candidates, staged in addition to the 128
real cases. They must be auto-blocked at approval and then rejected with reasons,
demonstrating that provenance enforcement still holds. They do NOT count toward
the per-category 8 (they are excluded from the corpus).
"""
from __future__ import annotations

CASES_REJECT = [
    dict(category="SQL_INJECTION", source_type="cve",
         source_ref="a SQL injection bug (no identifier)",
         references={"cwe": "CWE-89"},  # cve type, but no CVE id
         lang="python", framework="flask", filename="r1.py",
         code="cur.execute('SELECT * FROM accounts WHERE id=' + request.args['id'])\n",
         completion=dict(exploit="injection", patch="-id=' + request.args['id']\n+id=%s,(request.args['id'],)",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=cve without a real CVE ID"),
    dict(category="COMMAND_INJECTION", source_type="semgrep",
         source_ref="known issue",
         references={"cwe": "CWE-78"},  # semgrep type, but no rule_id + vague ref
         lang="python", framework="flask", filename="r2.py",
         code="os.system('ping ' + request.args['h'])\n",
         completion=dict(exploit="cmd injection", patch="-os.system('ping ' + request.args['h'])\n+subprocess.run(['ping', request.args['h']])",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=semgrep without a rule_id; reference 'known issue' is vague"),
    dict(category="MCP_TOOL_ABUSE", source_type="vibecoded_failure",
         source_ref="some blog",
         references={"cwe": "CWE-78"},  # vibecoded but no case_id + AI-failure notes, vague ref
         lang="python", framework="mcp", filename="r3.py",
         code="@mcp.tool()\ndef sh(c): return os.popen(c).read()\n",
         completion=dict(exploit="rce", patch="-def sh(c): return os.popen(c).read()\n+# remove",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=vibecoded_failure without a case_id and without notes explaining the AI-generated failure; reference 'some blog' is vague"),
    dict(category="XSS", source_type="owasp",
         source_ref="common vulnerability",
         references={},  # owasp type but no OWASP category reference + vague ref
         lang="javascript", framework="react", filename="r4.jsx",
         code="el.innerHTML = location.hash;\n",
         completion=dict(exploit="dom xss", patch="-el.innerHTML = location.hash;\n+el.textContent = location.hash;",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=owasp without an OWASP category reference; reference 'common vulnerability' is vague"),
]
