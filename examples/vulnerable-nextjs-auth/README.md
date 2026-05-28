# Example — Broken / missing authentication (Next.js)

**File:** [`route.ts`](route.ts) · **Category:** `BROKEN_AUTH` · **Failing dimension:** `auth`

A common AI-generated pattern: a route handler that performs a destructive,
privileged action (deleting a user) with **no authentication and no role check**.
The endpoint is reachable by anyone on the internet.

## Why it is unsafe

- No session/identity verification — the caller is never authenticated.
- No authorization — even an authenticated non-admin could call it.
- No rate limit — it can be scripted to mass-delete records.

## Expected category

`BROKEN_AUTH` (default severity **CRITICAL**, CWE-287 / CWE-306 / CWE-862). The
finding maps to the `auth` check dimension.

## Expected verdict (illustrative — not model output)

```jsonc
{
  "production_ready": false,        // Safety Layer: R2 (auth=fail) + R3 (CRITICAL) + R6
  "severity": "CRITICAL",
  "checks_performed": {
    "auth": { "status": "fail", "note": "privileged delete with no identity/role check" }
    // ...the other 7 dimensions reported explicitly...
  },
  "findings": [
    { "category": "BROKEN_AUTH", "severity": "CRITICAL", "file": "route.ts", "line": 12 }
  ]
}
```

## Exploit scenario

An attacker sends `POST /api/admin/users` with `{ "userId": "<any id>" }` and
deletes arbitrary accounts — no credentials required.

## Secure patch direction

Authenticate the request and require an admin role before the action; deny by
default.

```ts
import { auth } from "@/lib/auth";

export async function POST(req: Request) {
  const session = await auth();
  if (!session || session.user.role !== "admin") {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const { userId } = await req.json();
  await db.user.delete({ where: { id: userId } });
  return NextResponse.json({ ok: true, deleted: userId });
}
```

Add rate limiting on the route, and consider a soft-delete with an audit log for
destructive admin actions.
