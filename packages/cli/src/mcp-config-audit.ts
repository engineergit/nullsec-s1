import { basename } from "node:path";
import type { Finding, Severity } from "./types.js";

type Rule = {
  severity: Severity;
  title: string;
  pattern: RegExp;
  description: string;
  recommendation: string;
};

const RULES: Rule[] = [
  {
    severity: "high",
    title: "MCP command path should be pinned",
    pattern: /"command"\s*:\s*"(npx|pnpm|npm|yarn|bun|uvx|python|node|bash|sh)"/i,
    description: "MCP server command uses a PATH-resolved executable or package runner.",
    recommendation: "Pin commands to trusted absolute paths or reviewed package versions.",
  },
  {
    severity: "high",
    title: "Shell execution in MCP config",
    pattern: /"command"\s*:\s*"(bash|sh|zsh|cmd|powershell|pwsh)"|"args"\s*:\s*\[[^\]]*"-c"/is,
    description: "MCP config can launch a shell, which expands the blast radius of agent-controlled inputs.",
    recommendation: "Call a fixed executable directly and avoid shell flags such as -c.",
  },
  {
    severity: "medium",
    title: "Dangerous MCP command arguments",
    pattern: /(--allow-all|--dangerously|--unsafe|--privileged|--no-sandbox|--write|--exec|--eval|-e\b)/i,
    description: "MCP command arguments appear to grant broad or unsafe execution behavior.",
    recommendation: "Remove broad flags and allow only the minimum permissions required.",
  },
  {
    severity: "high",
    title: "Environment exposure in MCP config",
    pattern: /"env"\s*:\s*\{[^}]*("|')(API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY|ACCESS_KEY)/is,
    description: "MCP config passes sensitive-looking environment variables to a tool process.",
    recommendation: "Use least-privilege scoped credentials and avoid exposing secrets to broad tools.",
  },
  {
    severity: "medium",
    title: "Broad filesystem access in MCP config",
    pattern: /(\/|~\/|\$HOME|--root|--workspace|--directory|--dir|--path)[^"\]]*/i,
    description: "MCP tool appears to receive broad filesystem access.",
    recommendation: "Restrict filesystem roots to the smallest project directories needed.",
  },
  {
    severity: "medium",
    title: "Remote URL in MCP config",
    pattern: /https?:\/\/[^\s"']+/i,
    description: "MCP config references a remote URL that may receive tool traffic or code context.",
    recommendation: "Review remote endpoints and prefer trusted, authenticated transports.",
  },
  {
    severity: "high",
    title: "Package or script execution in MCP config",
    pattern: /"command"\s*:\s*"(npx|pnpm|npm|yarn|bun|uvx)"|"args"\s*:\s*\[[^\]]*"(run|dlx|exec|x)"/is,
    description: "MCP config may execute package manager scripts or fetch packages at runtime.",
    recommendation: "Pin package versions and avoid runtime package/script execution where possible.",
  },
  {
    severity: "high",
    title: "Broad MCP tool permissions",
    pattern: /(allowAll|allTools|full_access|full-access|readWrite|read-write|write_all|write-all|dangerouslyAllow)/i,
    description: "MCP config appears to grant broad tool permissions.",
    recommendation: "Allowlist specific tools and operations required by the workflow.",
  },
];

function lineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

export function inspectMcpConfig(content: string, path = "mcp-config.json"): Finding[] {
  const findings: Finding[] = [];
  for (const rule of RULES) {
    const match = rule.pattern.exec(content);
    if (!match) continue;
    findings.push({
      severity: rule.severity,
      title: rule.title,
      category: "MCP_CONFIG_RISK",
      file: basename(path),
      line: lineNumber(content, match.index),
      evidence: match[0].slice(0, 240),
      description: rule.description,
      recommendation: rule.recommendation,
    });
  }
  return findings;
}
