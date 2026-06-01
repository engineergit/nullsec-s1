"use client";

import { useMemo, useState } from "react";
import { examples } from "@/lib/scan/examples";
import { detectLanguage, languages } from "@/lib/scan/language";
import type { NullsecVerdict, ScanResponse } from "@/lib/scan/types";

const links = [
  { label: "GitHub", href: "https://github.com/trynullsec/nullsec-s1" },
  { label: "Hugging Face", href: "https://huggingface.co/Trynullsec/nullsec-s1" },
  {
    label: "Release",
    href: "https://github.com/trynullsec/nullsec-s1/releases/tag/v1.0.0-rc25",
  },
];

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function severityClass(severity?: string) {
  if (severity === "CRITICAL") return "pill pill-critical";
  if (severity === "HIGH") return "pill pill-high";
  if (severity === "MEDIUM") return "pill pill-medium";
  if (severity === "LOW") return "pill pill-low";
  return "pill pill-info";
}

function checksToEntries(verdict: NullsecVerdict) {
  if (Array.isArray(verdict.checks_performed)) {
    return verdict.checks_performed.map((check, index) => [`check_${index + 1}`, check] as const);
  }
  return Object.entries(verdict.checks_performed ?? {});
}

export default function ScanPage() {
  const [filename, setFilename] = useState("app/api/admin/route.ts");
  const [language, setLanguage] = useState("typescript");
  const [code, setCode] = useState(examples[0].code);
  const [isScanning, setIsScanning] = useState(false);
  const [response, setResponse] = useState<ScanResponse | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  const verdict = response?.ok ? response.verdict : null;
  const charCount = code.length;
  const canScan = filename.trim().length > 0 && code.trim().length > 0 && charCount <= 50_000;

  const rawJson = useMemo(() => {
    if (!verdict) return "";
    return JSON.stringify(verdict, null, 2);
  }, [verdict]);

  function updateFilename(value: string) {
    setFilename(value);
    const detected = detectLanguage(value);
    if (detected) {
      setLanguage(detected);
    }
  }

  async function scan() {
    if (!canScan) return;
    setIsScanning(true);
    setResponse(null);
    setShowRaw(false);

    try {
      const result = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ filename, language, code }),
      });
      const payload = (await result.json()) as ScanResponse;
      setResponse(payload);
    } catch {
      setResponse({
        ok: false,
        error: {
          code: "backend_unavailable",
          message: "Nullsec-S1 backend unavailable. Please try again later.",
        },
      });
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <main className="shell">
      <section className="hero">
        <nav className="nav">
          <div className="brand">
            <span className="brand-mark">N</span>
            <span>Nullsec-S1</span>
          </div>
          <div className="nav-links">
            {links.map((link) => (
              <a key={link.href} href={link.href} target="_blank" rel="noreferrer">
                {link.label}
              </a>
            ))}
          </div>
        </nav>

        <div className="hero-grid">
          <div>
            <div className="eyebrow">Live scanner MVP</div>
            <h1>Audit AI-generated code with Nullsec-S1.</h1>
            <p className="hero-copy">
              Paste a file or snippet, choose the language, and send it to a real Nullsec-S1
              backend for a structured security verdict.
            </p>
            <div className="hero-actions">
              <button className="primary-button" disabled={!canScan || isScanning} onClick={scan}>
                {isScanning ? "Scanning..." : "Scan source"}
              </button>
              <span className="scope-note">
                No code execution, no source storage, JSON verdicts only.
              </span>
            </div>
          </div>

          <div className="benchmark-card">
            <span className="metric-label">Benchmark strip</span>
            <strong>0.9245 F1</strong>
            <p>
              Nullsec-S1 ranked #1 by F1 score on the Nullsec RC2/v1.1 111-case
              benchmark against compared baselines.
            </p>
          </div>
        </div>
      </section>

      <section className="scanner-grid">
        <div className="panel input-panel">
          <div className="panel-header">
            <div>
              <span className="eyebrow">Input</span>
              <h2>Source to scan</h2>
            </div>
            <span className={cx("counter", charCount > 50_000 && "counter-danger")}>
              {charCount.toLocaleString()} / 50,000
            </span>
          </div>

          <div className="form-grid">
            <label>
              <span>Filename</span>
              <input
                value={filename}
                onChange={(event) => updateFilename(event.target.value)}
                placeholder="app/api/admin/route.ts"
              />
            </label>
            <label>
              <span>Language</span>
              <select value={language} onChange={(event) => setLanguage(event.target.value)}>
                {languages.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="example-row">
            {examples.map((example) => (
              <button
                key={example.label}
                type="button"
                onClick={() => {
                  setFilename(example.filename);
                  setLanguage(example.language);
                  setCode(example.code);
                  setResponse(null);
                }}
              >
                {example.label}
              </button>
            ))}
          </div>

          <textarea
            spellCheck={false}
            value={code}
            onChange={(event) => setCode(event.target.value)}
            aria-label="Source code"
          />

          <div className="input-footer">
            <p>Submitted code is proxied to the configured Nullsec-S1 backend only.</p>
            <button className="primary-button" disabled={!canScan || isScanning} onClick={scan}>
              {isScanning ? "Scanning..." : "Scan"}
            </button>
          </div>
        </div>

        <div className="panel result-panel">
          <div className="panel-header">
            <div>
              <span className="eyebrow">Verdict</span>
              <h2>Security report</h2>
            </div>
            {verdict && (
              <span className={verdict.production_ready ? "ready-badge ready" : "ready-badge blocked"}>
                {verdict.production_ready ? "Production ready" : "Blocked"}
              </span>
            )}
          </div>

          {!response && !isScanning && (
            <div className="empty-state">
              <div className="orb" />
              <p>Run a scan to receive a Safety-Layer-enforced JSON verdict.</p>
            </div>
          )}

          {isScanning && (
            <div className="empty-state">
              <div className="loader" />
              <p>Waiting for Nullsec-S1 inference...</p>
            </div>
          )}

          {response && !response.ok && (
            <div className="error-card">
              <strong>{response.error.message}</strong>
              <p>Code was not scanned. Configure a real backend URL and try again.</p>
            </div>
          )}

          {verdict && (
            <div className="result-stack">
              <div className="score-grid">
                <div>
                  <span>Severity</span>
                  <strong className={severityClass(verdict.severity)}>{verdict.severity}</strong>
                </div>
                <div>
                  <span>Risk score</span>
                  <strong>{verdict.risk_score}/100</strong>
                </div>
                <div>
                  <span>Confidence</span>
                  <strong>{verdict.confidence}</strong>
                </div>
              </div>

              {verdict.reasoning_summary && (
                <div className="summary-card">
                  <span>Summary</span>
                  <p>{verdict.reasoning_summary}</p>
                </div>
              )}

              <div className="findings">
                <h3>Findings</h3>
                {verdict.findings.length === 0 ? (
                  <div className="clean-card">No findings returned by the backend verdict.</div>
                ) : (
                  verdict.findings.map((finding, index) => (
                    <article className="finding-card" key={`${finding.category}-${index}`}>
                      <div className="finding-topline">
                        <span className={severityClass(finding.severity)}>{finding.severity}</span>
                        <span className="category">{finding.category}</span>
                      </div>
                      <h4>{finding.summary ?? finding.description}</h4>
                      {(finding.recommendation ?? finding.recommended_fix) && (
                        <p>
                          <strong>Recommendation:</strong>{" "}
                          {finding.recommendation ?? finding.recommended_fix}
                        </p>
                      )}
                      {finding.exploit_scenario && (
                        <p>
                          <strong>Exploit scenario:</strong> {finding.exploit_scenario}
                        </p>
                      )}
                    </article>
                  ))
                )}
              </div>

              <div className="checks">
                <h3>Checks performed</h3>
                <div className="check-grid">
                  {checksToEntries(verdict).map(([name, check]) => (
                    <div className="check-card" key={name}>
                      <span>{name.replaceAll("_", " ")}</span>
                      <strong>{check.status}</strong>
                      <p>{check.note}</p>
                    </div>
                  ))}
                </div>
              </div>

              <button className="secondary-button" onClick={() => setShowRaw((value) => !value)}>
                {showRaw ? "Hide raw JSON" : "Show raw JSON"}
              </button>
              {showRaw && <pre className="raw-json">{rawJson}</pre>}
            </div>
          )}
        </div>
      </section>

      <footer>
        <p>
          Measured on the Nullsec RC2/v1.1 benchmark. Results do not guarantee universal
          vulnerability detection or replace independent security review.
        </p>
      </footer>
    </main>
  );
}
