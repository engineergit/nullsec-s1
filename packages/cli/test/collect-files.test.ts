import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import assert from "node:assert/strict";
import { collectFiles } from "../src/collect-files.js";
import { runHeuristicScan } from "../src/heuristics.js";

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "nullsec-s1-"));
  await mkdir(join(root, "src"));
  await mkdir(join(root, "node_modules"));
  await writeFile(join(root, "src", "index.ts"), "export const ok = true;\n");
  await writeFile(join(root, ".env"), "SECRET=real\n");
  await writeFile(join(root, ".env.example"), "SECRET=\n");
  await writeFile(join(root, "private.pem"), "-----BEGIN PRIVATE KEY-----\n");
  await writeFile(join(root, "adapter_model.safetensors"), "weights");
  await writeFile(join(root, "node_modules", "lib.js"), "eval('bad')");
  return root;
}

test("collectFiles includes source and safe config files", async () => {
  const root = await fixture();
  try {
    const result = await collectFiles({ path: root, maxFiles: 200, maxBytes: 1_000_000 });
    assert.deepEqual(
      result.files.map((file) => file.path).sort(),
      [".env.example", "src/index.ts"],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("collectFiles skips env files, private keys, weights, and node_modules", async () => {
  const root = await fixture();
  try {
    const result = await collectFiles({ path: root, maxFiles: 200, maxBytes: 1_000_000 });
    const skipped = result.skipped.map((skip) => skip.path);
    assert.ok(skipped.includes(".env"));
    assert.ok(skipped.includes("private.pem"));
    assert.ok(skipped.includes("adapter_model.safetensors"));
    assert.ok(skipped.includes("node_modules"));
    assert.ok(result.skipped.some((skip) => skip.path === ".env" && skip.sensitive));
    assert.ok(result.skipped.some((skip) => skip.path === "node_modules" && !skip.sensitive));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("collectFiles excludes Python runtimes and cache directories recursively", async () => {
  const root = await mkdtemp(join(tmpdir(), "nullsec-s1-"));
  try {
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(join(root, ".venv", "lib", "python3.11", "site-packages"), { recursive: true });
    await mkdir(join(root, "venv", "lib", "python3.11", "site-packages"), { recursive: true });
    await mkdir(join(root, "__pycache__"), { recursive: true });
    await mkdir(join(root, ".pytest_cache"), { recursive: true });
    await writeFile(join(root, "src", "app.ts"), "export const ok = true;\n");
    await writeFile(join(root, ".venv", "lib", "python3.11", "site-packages", "example.py"), "eval(input())\n");
    await writeFile(join(root, "venv", "lib", "python3.11", "site-packages", "example.py"), "eval(input())\n");
    await writeFile(join(root, "__pycache__", "x.py"), "eval(input())\n");
    await writeFile(join(root, ".pytest_cache", "x.py"), "eval(input())\n");

    const result = await collectFiles({ path: root, maxFiles: 200, maxBytes: 1_000_000 });

    assert.deepEqual(result.files.map((file) => file.path), ["src/app.ts"]);
    assert.ok(result.skipped.some((skip) => skip.path === ".venv" && !skip.sensitive));
    assert.ok(result.skipped.some((skip) => skip.path === "venv" && !skip.sensitive));
    assert.ok(result.skipped.some((skip) => skip.path === "__pycache__" && !skip.sensitive));
    assert.ok(result.skipped.some((skip) => skip.path === ".pytest_cache" && !skip.sensitive));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("heuristic scan cannot report findings from excluded .venv files", async () => {
  const root = await mkdtemp(join(tmpdir(), "nullsec-s1-"));
  try {
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(join(root, ".venv", "lib", "python3.11", "site-packages"), { recursive: true });
    await writeFile(join(root, "src", "app.ts"), "export const ok = true;\n");
    await writeFile(
      join(root, ".venv", "lib", "python3.11", "site-packages", "example.py"),
      "API_KEY = 'STRIPE_KEY_PLACEHOLDER_DO_NOT_USE'\neval(input())\n",
    );

    const result = await collectFiles({ path: root, maxFiles: 200, maxBytes: 1_000_000 });
    const report = runHeuristicScan(result);

    assert.deepEqual(result.files.map((file) => file.path), ["src/app.ts"]);
    assert.equal(report.findings.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test(".nullsecignore skips benchmarks and corpus directories", async () => {
  const root = await mkdtemp(join(tmpdir(), "nullsec-s1-"));
  try {
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(join(root, "benchmarks"), { recursive: true });
    await mkdir(join(root, "corpus"), { recursive: true });
    await writeFile(join(root, ".nullsecignore"), "benchmarks/\ncorpus/\n");
    await writeFile(join(root, "src", "app.ts"), "export const ok = true;\n");
    await writeFile(join(root, "benchmarks", "fixture.ts"), "eval(input)\n");
    await writeFile(join(root, "corpus", "fixture.ts"), "eval(input)\n");

    const result = await collectFiles({ path: root, maxFiles: 200, maxBytes: 1_000_000 });

    assert.deepEqual(result.files.map((file) => file.path), ["src/app.ts"]);
    assert.ok(result.skipped.some((skip) => skip.path === "benchmarks"));
    assert.ok(result.skipped.some((skip) => skip.path === "corpus"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("collectFiles supports explicit excludes", async () => {
  const root = await mkdtemp(join(tmpdir(), "nullsec-s1-"));
  try {
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(join(root, "corpus"), { recursive: true });
    await writeFile(join(root, "src", "app.ts"), "export const ok = true;\n");
    await writeFile(join(root, "corpus", "fixture.ts"), "eval(input)\n");

    const result = await collectFiles({
      path: root,
      maxFiles: 200,
      maxBytes: 1_000_000,
      excludes: ["corpus"],
    });

    assert.deepEqual(result.files.map((file) => file.path), ["src/app.ts"]);
    assert.ok(result.skipped.some((skip) => skip.path === "corpus"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
