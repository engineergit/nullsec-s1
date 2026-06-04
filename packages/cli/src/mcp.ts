#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { DEFAULT_API_URL, scanMcpConfigText, scanPath, scanText } from "./scan.js";
import type { ScanReport } from "./types.js";

function apiUrl(): string {
  return process.env.NULLSEC_S1_API_URL || process.env.NULLSEC_API_URL || DEFAULT_API_URL;
}

function toolResult(report: ScanReport) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            summary: report.summary,
            severity_counts: report.severity_counts,
            findings: report.findings,
            recommendations: report.recommendations,
            production_ready: report.production_ready,
          },
          null,
          2,
        ),
      },
    ],
  };
}

const server = new McpServer({
  name: "nullsec-s1",
  version: "0.1.0",
});

server.registerTool(
  "nullsec_s1_scan_text",
  {
    title: "Scan text with Nullsec S1",
    description: "Audit raw code or text with the configured Nullsec S1 API.",
    inputSchema: {
      text: z.string().min(1),
      language: z.string().optional(),
    },
  },
  async ({ text, language }) => toolResult(await scanText(apiUrl(), text, language || "text", "mcp-input.txt")),
);

server.registerTool(
  "nullsec_s1_scan_file",
  {
    title: "Scan file with Nullsec S1",
    description: "Audit a single local file with the configured Nullsec S1 API.",
    inputSchema: {
      path: z.string().min(1),
    },
  },
  async ({ path }) => toolResult(await scanPath(apiUrl(), path, { maxFiles: 1 })),
);

server.registerTool(
  "nullsec_s1_scan_project",
  {
    title: "Scan project with Nullsec S1",
    description: "Audit a local directory with the configured Nullsec S1 API.",
    inputSchema: {
      path: z.string().min(1),
    },
  },
  async ({ path }) => toolResult(await scanPath(apiUrl(), path)),
);

server.registerTool(
  "nullsec_s1_scan_mcp_config",
  {
    title: "Scan MCP config with Nullsec S1",
    description: "Audit an MCP config JSON file or raw JSON for command, env, filesystem, URL, and permission risks.",
    inputSchema: {
      path: z.string().optional(),
      json: z.string().optional(),
    },
  },
  async ({ path, json }) => {
    if (!path && !json) {
      throw new Error("Provide either path or json.");
    }
    const content = json ?? (await readFile(path!, "utf8"));
    return toolResult(await scanMcpConfigText(apiUrl(), content, path || "mcp-config.json"));
  },
);

await server.connect(new StdioServerTransport());
