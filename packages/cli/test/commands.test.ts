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
  }
});
