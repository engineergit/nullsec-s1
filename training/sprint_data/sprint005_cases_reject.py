"""Curation Sprint 005 — reject-tests.

INTENTIONAL weak-provenance candidates, staged in addition to the 80 real cases.
They must be auto-blocked at approval and then rejected with reasons. They do NOT
count toward the per-category 5 (excluded from the corpus).
"""
from __future__ import annotations

CASES_REJECT = [
    dict(category="SSRF", source_type="cve",
         source_ref="an SSRF bug (no id)",
         references={"cwe": "CWE-918"},  # cve type, no CVE id
         lang="python", framework="flask", filename="rj1.py",
         code="requests.get(request.args['u'])\n",
         completion=dict(exploit="ssrf", patch="-requests.get(request.args['u'])\n+guard(request.args['u'])",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=cve without a real CVE ID"),
    dict(category="DEPENDENCY_RISK", source_type="semgrep",
         source_ref="internet",
         references={"cwe": "CWE-1104"},  # semgrep type, no rule_id + vague ref
         lang="json", framework="npm", filename="rj2.json",
         code="{ \"dependencies\": { \"left-pad\": \"0.0.1\" } }\n",
         completion=dict(exploit="outdated", patch="-0.0.1\n+1.3.0",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=semgrep without a rule_id; reference 'internet' is vague"),
    dict(category="WALLET_TRANSACTION_RISK", source_type="vibecoded_failure",
         source_ref="known issue",
         references={"cwe": "CWE-840"},  # vibecoded but no case_id/AI-failure notes + vague ref
         lang="javascript", framework="ethers", filename="rj3.js",
         code="await wallet.sendTransaction({ to, value });\n",
         completion=dict(exploit="drain", patch="-{ to, value }\n+{ to, value: capped }",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=vibecoded_failure without case_id and AI-failure notes; reference 'known issue' is vague"),
    dict(category="SMART_CONTRACT_RISK", source_type="owasp",
         source_ref="common vulnerability",
         references={},  # owasp type but no OWASP/SWC reference + vague ref
         lang="solidity", framework="foundry", filename="Rj4.sol",
         code="function withdraw() external { payable(msg.sender).transfer(address(this).balance); }\n",
         completion=dict(exploit="open withdraw", patch="-external {\n+external onlyOwner {",
             reviewer_notes="reject test"),
         _expect="reject",
         _reject_reason="source_type=owasp without an OWASP/SWC category reference; reference 'common vulnerability' is vague"),
]
