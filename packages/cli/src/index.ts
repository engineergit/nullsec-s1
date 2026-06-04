import { runDoctor } from "./doctor.js";
import { runServe } from "./serve.js";
import { defaultPython, DEFAULT_ADAPTER_PATH, DEFAULT_BASE_MODEL } from "./runtime.js";
import {
  DEFAULT_API_URL,
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_FILES,
  LOCAL_API_URL,
  errorExitCode,
  parseSeverity,
  runHealth,
  runScan,
  runScanMcp,
} from "./scan.js";
import type { CliOptions, CommandOptions, HealthOptions, ScanMcpOptions, ServeOptions } from "./types.js";

function usage(): string {
  return `Usage: npx @s1-clm/s1 <command> [options]

Commands:
  scan [path]          Scan a file, project, or stdin via the Nullsec S1 API
  health               Check the public Nullsec-S1 API health endpoint
  scan-mcp <path>      Scan an MCP config JSON file
  serve                Start the bundled Nullsec S1 FastAPI backend
  doctor               Check local backend/model dependencies

Options:
  --path <path>          Scan path (legacy alias; default: current directory)
  --stdin                Read raw code/text from stdin
  --api <url>            Nullsec-S1 API base URL (default: https://s1.trynullsec.com/api)
  --api-url <url>        Alias for --api
  --json                 Print JSON report
  --output <file>        Write report to file
  --fail-on <severity>   Exit 1 on severity threshold (default: high)
  --no-network           Run local heuristic scan only
  --local                Use local heuristic mode
  --local-model          Use http://localhost:8000 API for model-backed local scans
  --exclude <path>       Exclude a path or pattern; can be repeated
  --include-lockfiles    Include lockfiles during directory scans
  --show-all             Print every finding instead of the first 20
  --max-files <n>        Max files to collect (default: 200)
  --max-bytes <n>        Max bytes per file/stdin input (default: 256000)
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
  if (!["scan", "health", "scan-mcp", "serve", "doctor"].includes(command)) {
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

  const baseScanOptions = {
    apiUrl: process.env.NULLSEC_S1_API_URL || process.env.NULLSEC_API_URL || DEFAULT_API_URL,
    json: false,
    showAll: false,
  };

  if (command === "health") {
    const options: HealthOptions = {
      command: "health",
      apiUrl: baseScanOptions.apiUrl,
    };
    for (let index = 0; index < rest.length; index += 1) {
      const arg = rest[index];
      const next = () => {
        const value = rest[index + 1];
        if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
        index += 1;
        return value;
      };
      if (arg === "--api" || arg === "--api-url") options.apiUrl = next();
      else if (arg === "--help" || arg === "-h") {
        process.stdout.write(`${usage()}\n`);
        process.exit(0);
      } else {
        throw new Error(`Unknown option for health: ${arg}`);
      }
    }
    return options;
  }

  if (command === "scan-mcp") {
    const options: ScanMcpOptions = {
      command: "scan-mcp",
      path: "",
      ...baseScanOptions,
    };
    for (let index = 0; index < rest.length; index += 1) {
      const arg = rest[index];
      const next = () => {
        const value = rest[index + 1];
        if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
        index += 1;
        return value;
      };
      if (arg === "--api" || arg === "--api-url") options.apiUrl = next();
      else if (arg === "--json") options.json = true;
      else if (arg === "--output") options.output = next();
      else if (arg === "--fail-on") options.failOn = parseSeverity(next());
      else if (arg === "--show-all") options.showAll = true;
      else if (arg === "--help" || arg === "-h") {
        process.stdout.write(`${usage()}\n`);
        process.exit(0);
      } else if (arg.startsWith("--")) {
        throw new Error(`Unknown option for scan-mcp: ${arg}`);
      } else if (!options.path) {
        options.path = arg;
      } else {
        throw new Error(`Unexpected positional argument for scan-mcp: ${arg}`);
      }
    }
    if (!options.path) throw new Error("scan-mcp requires a config path.");
    return options;
  }

  const options: CliOptions = {
    command: "scan",
    path: undefined,
    ...baseScanOptions,
    noNetwork: false,
    useAnalyzeEndpoint: false,
    maxFiles: DEFAULT_MAX_FILES,
    maxBytes: DEFAULT_MAX_BYTES,
    excludes: [],
    localModel: false,
    stdin: false,
    includeLockfiles: false,
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
    else if (arg === "--api" || arg === "--api-url") options.apiUrl = next();
    else if (arg === "--json") options.json = true;
    else if (arg === "--output") options.output = next();
    else if (arg === "--fail-on") options.failOn = parseSeverity(next());
    else if (arg === "--no-network" || arg === "--local") options.noNetwork = true;
    else if (arg === "--local-model") {
      options.localModel = true;
      options.apiUrl = LOCAL_API_URL;
      options.useAnalyzeEndpoint = true;
    }
    else if (arg === "--analyze-endpoint") options.useAnalyzeEndpoint = true;
    else if (arg === "--stdin") options.stdin = true;
    else if (arg === "--include-lockfiles") options.includeLockfiles = true;
    else if (arg === "--exclude") options.excludes.push(next());
    else if (arg === "--show-all") options.showAll = true;
    else if (arg === "--max-files") options.maxFiles = Number.parseInt(next(), 10);
    else if (arg === "--max-bytes") options.maxBytes = Number.parseInt(next(), 10);
    else if (arg === "--help" || arg === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (!options.path) {
      options.path = arg;
    } else {
      throw new Error(`Unexpected positional argument: ${arg}`);
    }
  }
  if (!options.path && !options.stdin) options.path = process.cwd();
  if (options.path && options.stdin) throw new Error("Use either a path or --stdin, not both.");

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
        : options.command === "health"
          ? await runHealth(options)
        : options.command === "scan-mcp"
          ? await runScanMcp(options)
        : options.command === "serve"
          ? await runServe(options)
          : await runDoctor(options);
    process.exitCode = code;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected scan failure.";
    process.stderr.write(`Nullsec S1 scan failed: ${message}\n`);
    if (error instanceof Error && /^Unknown (command|option)/.test(error.message)) {
      process.stderr.write(`${usage()}\n`);
    }
    process.exitCode = errorExitCode(error);
  }
}
