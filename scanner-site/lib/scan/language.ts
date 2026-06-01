const extensionMap: Record<string, string> = {
  py: "python",
  js: "javascript",
  jsx: "javascript",
  ts: "typescript",
  tsx: "typescript",
  sol: "solidity",
  go: "go",
  java: "java",
  php: "php",
  rb: "ruby",
  sh: "bash",
  json: "json",
  yaml: "yaml",
  yml: "yaml",
};

export const languages = [
  "typescript",
  "javascript",
  "python",
  "solidity",
  "go",
  "java",
  "php",
  "ruby",
  "bash",
  "json",
  "yaml",
  "other",
];

export function detectLanguage(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase();
  if (!ext || ext === filename) {
    return "";
  }
  return extensionMap[ext] ?? ext;
}
