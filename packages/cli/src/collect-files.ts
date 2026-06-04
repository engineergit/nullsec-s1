import { lstat, readdir, readFile } from "node:fs/promises";
import { basename, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { CollectedFile, CollectionResult, SkippedFile } from "./types.js";

const EXCLUDED_DIRS = new Set([
  "node_modules",
  ".git",
  ".next",
  ".nuxt",
  "dist",
  "dist-test",
  "build",
  "coverage",
  ".cache",
  ".turbo",
  ".vercel",
  ".netlify",
  ".venv",
  "venv",
  "env",
  "ENV",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".ruff_cache",
  ".tox",
  ".nox",
  "site-packages",
  ".eggs",
  ".pnpm-store",
  ".yarn",
  "bower_components",
  "jspm_packages",
]);

const INCLUDED_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".go",
  ".rs",
  ".sol",
  ".move",
  ".json",
  ".toml",
  ".yaml",
  ".yml",
  ".md",
]);

const INCLUDED_BASENAMES = new Set([
  ".env.example",
  "Dockerfile",
  "docker-compose.yml",
  "package.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "package-lock.json",
]);

const LOCKFILE_BASENAMES = new Set(["pnpm-lock.yaml", "yarn.lock", "package-lock.json"]);

const SENSITIVE_BASENAMES = new Set([
  ".env",
  ".env.local",
  ".env.production",
  ".env.development",
  ".env.test",
  "adapter_model.safetensors",
]);

const EXCLUDED_EXTENSIONS = new Set([
  ".pem",
  ".key",
  ".p8",
  ".p12",
  ".safetensors",
  ".bin",
  ".pt",
  ".pth",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".svg",
  ".mp4",
  ".mov",
  ".avi",
  ".zip",
  ".tar",
  ".gz",
  ".tgz",
  ".7z",
]);

const LANGUAGE_BY_EXT: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".py": "python",
  ".go": "go",
  ".rs": "rust",
  ".sol": "solidity",
  ".move": "move",
  ".json": "json",
  ".toml": "toml",
  ".yaml": "yaml",
  ".yml": "yaml",
  ".md": "markdown",
};
const MAX_BACKEND_FILE_CHARS = Number.parseInt(process.env.NULLSEC_MAX_CODE_CHARS || "50000", 10);

export type CollectOptions = {
  path: string;
  maxFiles: number;
  maxBytes: number;
  maxTotalBytes?: number;
  excludes?: string[];
  includeLockfiles?: boolean;
};

type IgnoreRule = {
  raw: string;
  directoryOnly: boolean;
  basenameOnly: boolean;
  prefix: string;
};

function toPosix(path: string): string {
  return path.split(sep).join("/");
}

function languageFor(path: string): string {
  const name = basename(path);
  if (name === "Dockerfile") return "dockerfile";
  if (name.endsWith(".env.example")) return "dotenv";
  return LANGUAGE_BY_EXT[extname(name)] ?? "text";
}

function skipReason(relPath: string, entryName: string, isDirectory: boolean): SkippedFile | null {
  if (isDirectory && (EXCLUDED_DIRS.has(entryName) || entryName.endsWith(".egg-info"))) {
    return { path: relPath, reason: "dependency/generated directory skipped", sensitive: false };
  }

  const name = basename(relPath);
  const ext = extname(name);
  const lower = name.toLowerCase();

  if (SENSITIVE_BASENAMES.has(name) || lower.includes("privatekey") || lower.includes("private-key")) {
    return { path: relPath, reason: "sensitive file skipped", sensitive: true };
  }
  if (EXCLUDED_EXTENSIONS.has(ext)) {
    return { path: relPath, reason: "binary/private/generated file skipped", sensitive: ext === ".pem" || ext === ".key" };
  }
  return null;
}

function shouldInclude(relPath: string): boolean {
  const name = basename(relPath);
  return INCLUDED_BASENAMES.has(name) || INCLUDED_EXTENSIONS.has(extname(name));
}

export function languageForPath(path: string): string {
  return languageFor(path);
}

function isLikelyBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  return sample.includes(0);
}

function buildCollection(root: string, projectName: string, files: CollectedFile[], skipped: SkippedFile[]): CollectionResult {
  return {
    root,
    projectName,
    files,
    skipped,
    totalBytes: files.reduce((total, file) => total + file.bytes, 0),
  };
}

export function collectTextInput(params: {
  content: string;
  path?: string;
  language?: string;
  projectName?: string;
  maxBytes: number;
}): CollectionResult {
  const filename = params.path || "stdin.txt";
  const buffer = Buffer.from(params.content, "utf8");
  const skipped: SkippedFile[] = [];
  if (!params.content.trim()) {
    skipped.push({ path: filename, reason: "empty input skipped", sensitive: false });
    return buildCollection(process.cwd(), params.projectName || "stdin", [], skipped);
  }
  if (buffer.byteLength > params.maxBytes || params.content.length > MAX_BACKEND_FILE_CHARS) {
    skipped.push({ path: filename, reason: "input exceeds max content length", sensitive: false });
    return buildCollection(process.cwd(), params.projectName || "stdin", [], skipped);
  }
  return buildCollection(
    process.cwd(),
    params.projectName || "stdin",
    [
      {
        path: filename,
        absolutePath: filename,
        language: params.language || languageFor(filename),
        content: params.content,
        bytes: buffer.byteLength,
      },
    ],
    skipped,
  );
}

async function collectSingleFile(path: string, options: CollectOptions): Promise<CollectionResult> {
  const absolutePath = resolve(path);
  const name = basename(absolutePath);
  const skipped: SkippedFile[] = [];
  const skip = skipReason(name, name, false);
  if (skip) {
    skipped.push(skip);
    return buildCollection(absolutePath, name, [], skipped);
  }
  if (!shouldInclude(name)) {
    skipped.push({ path: name, reason: "unsupported file type skipped", sensitive: false });
    return buildCollection(absolutePath, name, [], skipped);
  }
  // A direct file path is an explicit include; directory walks skip lockfiles by default.
  if (options.includeLockfiles === false && LOCKFILE_BASENAMES.has(name)) {
    skipped.push({ path: name, reason: "large lockfile skipped", sensitive: false });
    return buildCollection(absolutePath, name, [], skipped);
  }
  const stat = await lstat(absolutePath);
  if (stat.size > options.maxBytes) {
    skipped.push({ path: name, reason: "file exceeds per-file byte limit", sensitive: false });
    return buildCollection(absolutePath, name, [], skipped);
  }
  const buffer = await readFile(absolutePath);
  if (isLikelyBinary(buffer)) {
    skipped.push({ path: name, reason: "binary file skipped", sensitive: false });
    return buildCollection(absolutePath, name, [], skipped);
  }
  const content = buffer.toString("utf8");
  if (!content) {
    skipped.push({ path: name, reason: "empty file skipped", sensitive: false });
    return buildCollection(absolutePath, name, [], skipped);
  }
  if (content.length > MAX_BACKEND_FILE_CHARS) {
    skipped.push({
      path: name,
      reason: `file exceeds backend max content length (${MAX_BACKEND_FILE_CHARS})`,
      sensitive: false,
    });
    return buildCollection(absolutePath, name, [], skipped);
  }
  return buildCollection(
    absolutePath,
    name,
    [
      {
        path: name,
        absolutePath,
        language: languageFor(name),
        content,
        bytes: buffer.byteLength,
      },
    ],
    skipped,
  );
}

function normalizeIgnorePattern(pattern: string): IgnoreRule | null {
  const trimmed = pattern.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  const noLeadingSlash = trimmed.replace(/^\/+/, "");
  const directoryOnly = noLeadingSlash.endsWith("/");
  const withoutTrailingSlash = noLeadingSlash.replace(/\/+$/, "");
  const prefix = withoutTrailingSlash.replace(/\*+$/, "");
  return {
    raw: withoutTrailingSlash,
    directoryOnly,
    basenameOnly: !withoutTrailingSlash.includes("/"),
    prefix,
  };
}

function matchesIgnoreRule(relPath: string, isDirectory: boolean, rule: IgnoreRule): boolean {
  const normalized = relPath.replace(/\/+$/, "");
  const name = basename(normalized);
  if (rule.directoryOnly && !isDirectory) return false;
  if (rule.raw.includes("*")) {
    const escaped = rule.raw
      .split("*")
      .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join(".*");
    const pattern = new RegExp(`^${escaped}$`);
    if (rule.basenameOnly) return pattern.test(name);
    return pattern.test(normalized);
  }
  if (rule.basenameOnly) return name === rule.raw || normalized === rule.raw || normalized.startsWith(`${rule.raw}/`);
  return normalized === rule.raw || normalized.startsWith(`${rule.raw}/`);
}

async function readNullsecIgnore(root: string): Promise<IgnoreRule[]> {
  try {
    const source = await readFile(join(root, ".nullsecignore"), "utf8");
    return source.split(/\r?\n/).flatMap((line) => {
      const rule = normalizeIgnorePattern(line);
      return rule ? [rule] : [];
    });
  } catch {
    return [];
  }
}

function customSkip(relPath: string, isDirectory: boolean, rules: IgnoreRule[]): SkippedFile | null {
  const match = rules.find((rule) => matchesIgnoreRule(relPath, isDirectory, rule));
  if (!match) return null;
  return { path: relPath, reason: "custom ignore pattern skipped", sensitive: false };
}

export async function collectFiles(options: CollectOptions): Promise<CollectionResult> {
  const root = resolve(options.path);
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory()) {
    return collectSingleFile(root, options);
  }

  const files: CollectedFile[] = [];
  const skipped: SkippedFile[] = [];
  const customRules = [
    ...(await readNullsecIgnore(root)),
    ...(options.excludes ?? []).flatMap((pattern) => {
      const rule = normalizeIgnorePattern(pattern);
      return rule ? [rule] : [];
    }),
  ];
  let totalBytes = 0;
  const maxTotalBytes = options.maxTotalBytes ?? options.maxBytes * options.maxFiles;

  async function walk(dir: string): Promise<void> {
    if (files.length >= options.maxFiles || totalBytes >= maxTotalBytes) return;

    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (files.length >= options.maxFiles || totalBytes >= maxTotalBytes) return;

      const absolutePath = join(dir, entry.name);
      const relPath = toPosix(relative(root, absolutePath));
      const custom = customSkip(relPath, entry.isDirectory(), customRules);
      if (custom) {
        skipped.push(custom);
        continue;
      }
      const skip = skipReason(relPath, entry.name, entry.isDirectory());
      if (skip) {
        skipped.push(skip);
        continue;
      }

      if (entry.isDirectory()) {
        await walk(absolutePath);
        continue;
      }
      if (!entry.isFile() || !shouldInclude(relPath)) continue;
      if (!options.includeLockfiles && LOCKFILE_BASENAMES.has(entry.name)) {
        skipped.push({ path: relPath, reason: "large lockfile skipped", sensitive: false });
        continue;
      }

      const stat = await lstat(absolutePath);
      if (stat.size > options.maxBytes) {
        skipped.push({ path: relPath, reason: "file exceeds per-file byte limit", sensitive: false });
        continue;
      }
      if (totalBytes + stat.size > maxTotalBytes) {
        skipped.push({ path: relPath, reason: "scan byte budget reached", sensitive: false });
        continue;
      }

      const buffer = await readFile(absolutePath);
      if (isLikelyBinary(buffer)) {
        skipped.push({ path: relPath, reason: "binary file skipped", sensitive: false });
        continue;
      }
      const content = buffer.toString("utf8");
      if (!content) {
        skipped.push({ path: relPath, reason: "empty file skipped", sensitive: false });
        continue;
      }
      if (content.length > MAX_BACKEND_FILE_CHARS) {
        skipped.push({
          path: relPath,
          reason: `file exceeds backend max content length (${MAX_BACKEND_FILE_CHARS})`,
          sensitive: false,
        });
        continue;
      }

      files.push({
        path: relPath,
        absolutePath,
        language: languageFor(relPath),
        content,
        bytes: buffer.byteLength,
      });
      totalBytes += buffer.byteLength;
    }
  }

  await walk(root);

  return {
    root,
    projectName: basename(isAbsolute(root) ? root : resolve(root)),
    files,
    skipped,
    totalBytes,
  };
}
