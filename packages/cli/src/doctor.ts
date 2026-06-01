import { existsSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_ADAPTER_PATH, DEFAULT_BASE_MODEL, runtimeRoot } from "./runtime.js";
import { runCommand } from "./system.js";

export async function runDoctor(options: { python: string }): Promise<number> {
  const runtime = runtimeRoot();
  const checks: Array<{ label: string; ok: boolean; detail: string }> = [];

  checks.push({
    label: "Bundled backend source",
    ok: existsSync(join(runtime, "serving", "server.py")) && existsSync(join(runtime, "nullsec", "core", "engine.py")),
    detail: runtime,
  });

  const py = await runCommand(options.python, ["--version"]);
  checks.push({
    label: "Python",
    ok: py.code === 0,
    detail: (py.stdout || py.stderr).trim() || options.python,
  });

  const deps = await runCommand(options.python, [
    "-c",
    "import fastapi, uvicorn, pydantic, yaml; print('runtime deps ok')",
  ]);
  checks.push({
    label: "FastAPI runtime deps",
    ok: deps.code === 0,
    detail: deps.code === 0 ? deps.stdout.trim() : deps.stderr.trim(),
  });

  const gpuDeps = await runCommand(options.python, [
    "-c",
    "import torch, transformers, peft; print('model deps ok')",
  ]);
  checks.push({
    label: "Model deps",
    ok: gpuDeps.code === 0,
    detail:
      gpuDeps.code === 0
        ? gpuDeps.stdout.trim()
        : "missing torch/transformers/peft; install requirements-train-cu121.txt for local model serving",
  });

  process.stdout.write("Nullsec S1 Doctor\n\n");
  for (const check of checks) {
    process.stdout.write(`${check.ok ? "OK" : "MISSING"}  ${check.label}: ${check.detail}\n`);
  }
  process.stdout.write("\nDefaults\n");
  process.stdout.write(`Base model: ${process.env.NULLSEC_BASE_MODEL || DEFAULT_BASE_MODEL}\n`);
  process.stdout.write(`Adapter: ${process.env.NULLSEC_ADAPTER_PATH || DEFAULT_ADAPTER_PATH}\n`);

  return checks.every((check) => check.ok) ? 0 : 1;
}
