import test from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "../src/index.js";

test("parseArgs supports doctor command", () => {
  const options = parseArgs(["doctor", "--python", "python"]);
  assert.equal(options.command, "doctor");
  if (options.command === "doctor") {
    assert.equal(options.python, "python");
  }
});

test("parseArgs supports serve command defaults and overrides", () => {
  const options = parseArgs(["serve", "--host", "0.0.0.0", "--port", "9000", "--eager-load"]);
  assert.equal(options.command, "serve");
  if (options.command === "serve") {
    assert.equal(options.host, "0.0.0.0");
    assert.equal(options.port, 9000);
    assert.equal(options.adapterPath, "Trynullsec/nullsec-s1");
    assert.equal(options.eagerLoad, true);
  }
});

test("parseArgs supports scan local model mode", () => {
  const options = parseArgs(["scan", "--local-model"]);
  assert.equal(options.command, "scan");
  if (options.command === "scan") {
    assert.equal(options.localModel, true);
    assert.equal(options.apiUrl, "http://localhost:8000");
    assert.equal(options.useAnalyzeEndpoint, true);
  }
});

test("parseArgs supports scan positional path and stdin", () => {
  const pathOptions = parseArgs(["scan", "./src", "--max-files", "50", "--include-lockfiles", "--api", "https://example.test/api"]);
  assert.equal(pathOptions.command, "scan");
  if (pathOptions.command === "scan") {
    assert.equal(pathOptions.path, "./src");
    assert.equal(pathOptions.maxFiles, 50);
    assert.equal(pathOptions.maxBytes, 256000);
    assert.equal(pathOptions.includeLockfiles, true);
    assert.equal(pathOptions.apiUrl, "https://example.test/api");
  }

  const stdinOptions = parseArgs(["scan", "--stdin"]);
  assert.equal(stdinOptions.command, "scan");
  if (stdinOptions.command === "scan") {
    assert.equal(stdinOptions.stdin, true);
    assert.equal(stdinOptions.path, undefined);
  }
});

test("parseArgs defaults scan and health to public API", () => {
  const scan = parseArgs(["scan"]);
  assert.equal(scan.command, "scan");
  if (scan.command === "scan") {
    assert.equal(scan.apiUrl, "https://s1.trynullsec.com/api");
  }

  const health = parseArgs(["health"]);
  assert.equal(health.command, "health");
  if (health.command === "health") {
    assert.equal(health.apiUrl, "https://s1.trynullsec.com/api");
  }
});

test("parseArgs supports scan-mcp command", () => {
  const options = parseArgs(["scan-mcp", "./mcp.json", "--json"]);
  assert.equal(options.command, "scan-mcp");
  if (options.command === "scan-mcp") {
    assert.equal(options.path, "./mcp.json");
    assert.equal(options.json, true);
    assert.equal(options.apiUrl, "https://s1.trynullsec.com/api");
  }
});
