import type { ScanRequest } from "./types";

export type ExampleSnippet = ScanRequest & {
  label: string;
};

export const examples: ExampleSnippet[] = [
  {
    label: "Unsafe admin route",
    filename: "app/api/admin/route.ts",
    language: "typescript",
    code: `export async function POST(req: Request) {
  const { userId, role } = await req.json();
  await db.user.update({ where: { id: userId }, data: { role } });
  return Response.json({ ok: true });
}
`,
  },
  {
    label: "Exposed secret",
    filename: "src/supabaseClient.ts",
    language: "typescript",
    code: `import { createClient } from "@supabase/supabase-js";

export const admin = createClient(
  "https://project.supabase.co",
  "supabase-service-role-secret"
);
`,
  },
  {
    label: "MCP shell tool",
    filename: "tools/run-command.ts",
    language: "typescript",
    code: `import { exec } from "node:child_process";

export async function runTool(input: { command: string }) {
  return new Promise((resolve, reject) => {
    exec(input.command, (error, stdout) => {
      if (error) reject(error);
      resolve(stdout);
    });
  });
}
`,
  },
  {
    label: "Safe route",
    filename: "app/api/profile/route.ts",
    language: "typescript",
    code: `import { auth } from "@/auth";

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const profile = await db.user.findUnique({
    where: { id: session.user.id },
    select: { id: true, name: true, email: true },
  });

  return Response.json({ profile });
}
`,
  },
];
