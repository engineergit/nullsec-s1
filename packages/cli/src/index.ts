#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { runDoctor } from "./doctor.js";
import { runServe } from "./serve.js";
import { defaultPython, DEFAULT_ADAPTER_PATH, DEFAULT_BASE_MODEL } from "./runtime.js";
import { errorExitCode, parseSeverity, runScan } from "./scan.js";
import type { CliOptions, CommandOptions, ServeOptions } from "./types.js";

function usage(): string {
  return `Usage: npx @s1-clm/s1 <command> [options]

Commands:
  scan                 Scan a project via hosted API, local backend, or heuristics
  serve                Start the bundled Nullsec S1 FastAPI backend
  doctor               Check local backend/model dependencies

Options:
  --path <path>          Project path to scan (default: current directory)
  --api-url <url>        Nullsec S1 backend URL (default: NULLSEC_API_URL or https://s1.trynullsec.com/api)
  --json                 Print JSON report
  --output <file>        Write report to file
  --fail-on <severity>   Exit 1 on severity threshold: critical, high, medium, low, info
  --no-network           Run local heuristic scan only
  --local-model          Scan through http://localhost:8000 unless --api-url is set
  --exclude <path>       Exclude a path or pattern; can be repeated
  --show-all             Print every finding instead of the first 20
  --max-files <n>        Max files to collect (default: 200)
  --max-bytes <n>        Max total bytes to collect (default: 1000000)
  --python <bin>         Python binary for serve/doctor (default: python3)
  --host <host>          Backend host for serve (default: 127.0.0.1)
  --port <port>          Backend port for serve (default: 8000)
  --base-model <id>      Base model for serve
  --adapter <id|path>    PEFT adapter repo/path for serve
  --eager-load           Load the model at backend startup
  --help                 Show help`;
}

export function parseArgs(argv: string[]): CommandOptions {
  const [command, ...rest] = argv;
  if (!command || command === "--help" || command === "-h") {
    process.stdout.write(`${usage()}\n`);
    process.exit(0);
  }
  if (!["scan", "serve", "doctor"].includes(command)) {
    throw new Error(`Unknown command: ${command}`);
  }

  if (command === "doctor") {
    let python = defaultPython();
    for (let index = 0; index < rest.length; index += 1) {
      const arg = rest[index];
      if (arg === "--python") {
        const value = rest[index + 1];
        if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
        python = value;
        index += 1;
      } else if (arg === "--help" || arg === "-h") {
        process.stdout.write(`${usage()}\n`);
        process.exit(0);
      } else {
        throw new Error(`Unknown option for doctor: ${arg}`);
      }
    }
    return { command: "doctor", python };
  }

  if (command === "serve") {
    const options: ServeOptions = {
      command: "serve",
      python: defaultPython(),
      host: "127.0.0.1",
      port: 8000,
      baseModel: process.env.NULLSEC_BASE_MODEL || DEFAULT_BASE_MODEL,
      adapterPath: process.env.NULLSEC_ADAPTER_PATH || DEFAULT_ADAPTER_PATH,
      corsOrigins: process.env.NULLSEC_CORS_ORIGINS || "http://localhost:3000,https://s1.trynullsec.com",
      eagerLoad: process.env.NULLSEC_EAGER_LOAD === "1",
    };
    for (let index = 0; index < rest.length; index += 1) {
      const arg = rest[index];
      const next = () => {
        const value = rest[index + 1];
        if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
        index += 1;
        return value;
      };
      if (arg === "--python") options.python = next();
      else if (arg === "--host") options.host = next();
      else if (arg === "--port") options.port = Number.parseInt(next(), 10);
      else if (arg === "--base-model") options.baseModel = next();
      else if (arg === "--adapter") options.adapterPath = next();
      else if (arg === "--cors-origins") options.corsOrigins = next();
      else if (arg === "--eager-load") options.eagerLoad = true;
      else if (arg === "--help" || arg === "-h") {
        process.stdout.write(`${usage()}\n`);
        process.exit(0);
      } else {
        throw new Error(`Unknown option for serve: ${arg}`);
      }
    }
    if (!Number.isInteger(options.port) || options.port < 1) {
      throw new Error("--port must be a positive integer.");
    }
    return options;
  }

  const options: CliOptions = {
    command: "scan",
    path: process.cwd(),
    apiUrl: process.env.NULLSEC_API_URL || "https://s1.trynullsec.com/api",
    json: false,
    noNetwork: false,
    maxFiles: 200,
    maxBytes: 1_000_000,
    excludes: [],
    showAll: false,
    localModel: false,
  };

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    const next = () => {
      const value = rest[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
      index += 1;
      return value;
    };

    if (arg === "--path") options.path = next();
    else if (arg === "--api-url") options.apiUrl = next();
    else if (arg === "--json") options.json = true;
    else if (arg === "--output") options.output = next();
    else if (arg === "--fail-on") options.failOn = parseSeverity(next());
    else if (arg === "--no-network") options.noNetwork = true;
    else if (arg === "--local-model") options.localModel = true;
    else if (arg === "--exclude") options.excludes.push(next());
    else if (arg === "--show-all") options.showAll = true;
    else if (arg === "--max-files") options.maxFiles = Number.parseInt(next(), 10);
    else if (arg === "--max-bytes") options.maxBytes = Number.parseInt(next(), 10);
    else if (arg === "--help" || arg === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (!Number.isInteger(options.maxFiles) || options.maxFiles < 1) {
    throw new Error("--max-files must be a positive integer.");
  }
  if (!Number.isInteger(options.maxBytes) || options.maxBytes < 1) {
    throw new Error("--max-bytes must be a positive integer.");
  }

  return options;
}

export async function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    const code =
      options.command === "scan"
        ? await runScan(options)
        : options.command === "serve"
          ? await runServe(options)
          : await runDoctor(options);
    process.exitCode = code;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected scan failure.";
    process.stderr.write(`Nullsec S1 scan failed: ${message}\n`);
    process.exitCode = errorExitCode(error);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
