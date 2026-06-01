import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export function packageRoot(): string {
  return resolve(here, "..");
}

export function runtimeRoot(): string {
  return resolve(packageRoot(), "runtime");
}

export function defaultPython(): string {
  return process.env.NULLSEC_PYTHON || "python3";
}

export const DEFAULT_BASE_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct";
export const DEFAULT_ADAPTER_PATH = "Trynullsec/nullsec-s1";
