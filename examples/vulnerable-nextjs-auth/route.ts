// app/api/admin/users/route.ts
// VULNERABLE EXAMPLE — a Next.js route handler that performs a privileged action
// with no authentication or authorization check. Do not ship this.

import { NextResponse } from "next/server";
import { db } from "@/lib/db";

// Anyone who can reach this URL can delete any user. There is no session check,
// no role check, and the method is reachable from the public internet.
export async function POST(req: Request) {
  const { userId } = await req.json();

  // No auth. No "is the caller an admin?" check. No rate limit.
  await db.user.delete({ where: { id: userId } });

  return NextResponse.json({ ok: true, deleted: userId });
}
