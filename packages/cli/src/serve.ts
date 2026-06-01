import { spawn } from "node:child_process";
import { DEFAULT_ADAPTER_PATH, DEFAULT_BASE_MODEL, runtimeRoot } from "./runtime.js";

export async function runServe(options: {
  python: string;
  host: string;
  port: number;
  baseModel?: string;
  adapterPath?: string;
  corsOrigins?: string;
  eagerLoad?: boolean;
}): Promise<number> {
  const runtime = runtimeRoot();
  const env = {
    ...process.env,
    NULLSEC_BASE_MODEL: options.baseModel || process.env.NULLSEC_BASE_MODEL || DEFAULT_BASE_MODEL,
    NULLSEC_ADAPTER_PATH: options.adapterPath || process.env.NULLSEC_ADAPTER_PATH || DEFAULT_ADAPTER_PATH,
    NULLSEC_CORS_ORIGINS: options.corsOrigins || process.env.NULLSEC_CORS_ORIGINS || "http://localhost:3000,https://s1.trynullsec.com",
    NULLSEC_EAGER_LOAD: options.eagerLoad ? "1" : process.env.NULLSEC_EAGER_LOAD || "0",
    PYTHONPATH: [runtime, process.env.PYTHONPATH].filter(Boolean).join(":"),
  };

  process.stdout.write("Starting Nullsec S1 local backend\n");
  process.stdout.write(`Runtime: ${runtime}\n`);
  process.stdout.write(`Base model: ${env.NULLSEC_BASE_MODEL}\n`);
  process.stdout.write(`Adapter: ${env.NULLSEC_ADAPTER_PATH}\n`);
  process.stdout.write(`Listen: http://${options.host}:${options.port}\n\n`);

  const child = spawn(
    options.python,
    ["-m", "uvicorn", "serving.server:app", "--host", options.host, "--port", String(options.port)],
    { cwd: runtime, env, stdio: "inherit" },
  );

  return await new Promise((resolve) => {
    child.on("error", (error) => {
      process.stderr.write(`Failed to start backend: ${error.message}\n`);
      resolve(3);
    });
    child.on("close", (code) => {
      resolve(code ?? 0);
    });
  });
}
