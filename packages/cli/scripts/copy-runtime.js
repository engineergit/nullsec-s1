import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const repoRoot = resolve("../..");
const runtime = resolve("runtime");

await rm(runtime, { recursive: true, force: true });
await mkdir(runtime, { recursive: true });

for (const name of ["serving", "nullsec", "taxonomy", "cli"]) {
  await cp(resolve(repoRoot, name), resolve(runtime, name), {
    recursive: true,
    filter: (source) =>
      !source.includes("__pycache__") &&
      !source.endsWith(".pyc") &&
      !source.includes(".pytest_cache"),
  });
}

for (const name of ["pyproject.toml", "requirements.txt", "requirements-train-cu121.txt"]) {
  await cp(resolve(repoRoot, name), resolve(runtime, name));
}

await writeFile(
  resolve(runtime, "README.md"),
  `# Bundled Nullsec S1 Runtime

This directory is bundled with the npm package so \`npx @s1-clm/s1 serve\` can
start the FastAPI backend. It does not include model weights. The backend loads
\`Qwen/Qwen2.5-Coder-7B-Instruct\` and \`Trynullsec/nullsec-s1\` from Hugging Face
or from paths configured with \`NULLSEC_BASE_MODEL\` and \`NULLSEC_ADAPTER_PATH\`.
`,
);
