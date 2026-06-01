import type { CollectionResult, Finding, ScanReport, Severity } from "./types.js";

type Rule = {
  severity: Severity;
  title: string;
  pattern: RegExp;
  description: string;
  recommendation: string;
};

const RULES: Rule[] = [
  {
    severity: "critical",
    title: "Hardcoded private key",
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    description: "A private key appears to be committed in source.",
    recommendation: "Remove the key, rotate it, and load secrets from a secret manager.",
  },
  {
    severity: "high",
    title: "Hardcoded API key",
    pattern: /(api[_-]?key|secret|token)\s*[:=]\s*["'][A-Za-z0-9_\-]{24,}["']/i,
    description: "A long token-like value appears to be hardcoded.",
    recommendation: "Move secrets to environment or managed secret storage.",
  },
  {
    severity: "high",
    title: "Dangerous eval usage",
    pattern: /\beval\s*\(/,
    description: "Dynamic code execution can execute attacker-controlled input.",
    recommendation: "Remove eval and use a constrained parser or explicit dispatch table.",
  },
  {
    severity: "high",
    title: "Unsafe shell execution",
    pattern: /\b(exec|execSync|spawn|spawnSync)\s*\([^,\n]*\$\{|shell\s*:\s*true|subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True/,
    description: "Shell execution may include untrusted input.",
    recommendation: "Use argv arrays, avoid shell mode, and validate/allowlist commands.",
  },
  {
    severity: "medium",
    title: "Wildcard CORS",
    pattern: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|cors\s*\(\s*\{[^}]*origin\s*:\s*["']\*/is,
    description: "Wildcard CORS can expose APIs to arbitrary origins.",
    recommendation: "Restrict CORS origins to known trusted domains.",
  },
  {
    severity: "medium",
    title: "Public admin route pattern",
    pattern: /(app|pages|src)\/api\/admin|\/admin/i,
    description: "Admin route pattern found. Verify authentication and authorization are enforced.",
    recommendation: "Require session and role checks before privileged operations.",
  },
  {
    severity: "medium",
    title: "Risky crypto signing pattern",
    pattern: /\bsign(Message|Transaction|TypedData)|privateKeyToAccount|new Wallet\(/,
    description: "Crypto signing or private key handling appears in source.",
    recommendation: "Constrain signing scope, use wallet-managed keys, and require explicit user consent.",
  },
  {
    severity: "low",
    title: "Dangerous dependency script",
    pattern: /"postinstall"\s*:\s*"[^"]*(curl|wget|bash|sh|node\s+-e)/,
    description: "Dependency lifecycle scripts can run arbitrary code during install.",
    recommendation: "Remove risky lifecycle scripts or document and pin trusted dependencies.",
  },
];

function lineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function scoreFor(findings: Finding[]): number {
  if (findings.some((f) => f.severity === "critical")) return 95;
  if (findings.some((f) => f.severity === "high")) return 75;
  if (findings.some((f) => f.severity === "medium")) return 45;
  if (findings.some((f) => f.severity === "low")) return 20;
  return 0;
}

export function runHeuristicScan(collection: CollectionResult): ScanReport {
  const findings: Finding[] = [];

  for (const file of collection.files) {
    for (const rule of RULES) {
      const match = rule.pattern.exec(file.content);
      if (!match) continue;
      findings.push({
        severity: rule.severity,
        title: rule.title,
        file: file.path,
        line: lineNumber(file.content, match.index),
        description: rule.description,
        recommendation: rule.recommendation,
      });
    }
  }

  return {
    summary: findings.length
      ? `Local heuristic scan found ${findings.length} potential issue(s).`
      : "Local heuristic scan found no matching heuristic issues.",
    risk_score: scoreFor(findings),
    findings,
    model: { base_model: "local heuristics", adapter_loaded: false },
    local_heuristic: true,
  };
}
