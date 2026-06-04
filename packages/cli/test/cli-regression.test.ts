import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import assert from "node:assert/strict";

const cliPath = resolve("dist/cli.js");

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "nullsec-s1-cli-"));
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(join(root, "src", "app.ts"), "export const ok = true;\n");
  return root;
}

test("scan --no-network emits report header", async () => {
  const root = await fixture();
  try {
    const result = spawnSync("node", [cliPath, "scan", "--path", root, "--no-network"], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0);
    assert.match(result.stdout, /Nullsec-S1 Security Scan/);
    assert.match(result.stdout, /Mode: Local heuristic scan/);
    assert.match(result.stdout, /Files scanned:/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("scan --show-all prints findings for unsafe fixture", async () => {
  const root = await fixture();
  try {
    await writeFile(join(root, "src", "unsafe.ts"), "eval(input)\n");
    const result = spawnSync("node", [cliPath, "scan", "--path", root, "--no-network", "--show-all"], {
      encoding: "utf8",
    });
    assert.equal(result.status, 1);
    assert.match(result.stdout, /Dangerous eval usage/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("scan backend unavailable exits with code 2 and error", async () => {
  const root = await fixture();
  try {
    const result = spawnSync("node", [cliPath, "scan", "--path", root, "--api-url", "http://127.0.0.1:9"], {
      encoding: "utf8",
    });
    assert.equal(result.status, 2);
    assert.match(result.stderr + result.stdout, /backend unavailable|connect|fetch failed|ECONNREFUSED/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("unknown command exits 2 and prints usage", () => {
  const result = spawnSync("node", [cliPath, "unknown"], { encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr + result.stdout, /Usage: npx @s1-clm\/s1/);
});
