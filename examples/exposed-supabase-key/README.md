# Example — Exposed secret (Supabase service_role key)

**File:** [`supabaseClient.ts`](supabaseClient.ts) · **Category:** `EXPOSED_SECRET` · **Failing dimension:** `secrets`

A frequent AI-generated mistake: hardcoding a Supabase **`service_role`** key into
code that is bundled and shipped to the browser. The `service_role` key bypasses
Row Level Security and grants full admin access to the database.

> The key in the file is an **obviously-fake placeholder**
> (`EXAMPLE_PLACEHOLDER_NOT_A_REAL_KEY`). Never commit a real key.

## Why it is unsafe

- The `service_role` key is an admin credential; it must stay server-side only.
- Anything in a client bundle is fully readable by any visitor.
- With this key, an attacker reads and writes the entire database, ignoring RLS.

## Expected category

`EXPOSED_SECRET` (default severity **CRITICAL**, CWE-798 / CWE-312 / CWE-256).
Maps to the `secrets` check dimension. The taxonomy lists `service_role` among its
detection signals.

## Expected verdict (illustrative — not model output)

```jsonc
{
  "production_ready": false,        // Safety Layer: R2 (secrets=fail) + R3 (CRITICAL)
  "severity": "CRITICAL",
  "checks_performed": {
    "secrets": { "status": "fail", "note": "service_role key shipped to client" }
  },
  "findings": [
    { "category": "EXPOSED_SECRET", "severity": "CRITICAL", "file": "supabaseClient.ts", "line": 14 }
  ]
}
```

## Exploit scenario

An attacker opens the site, reads the bundled JS, extracts the `service_role` key,
and uses it to dump or modify every table — bypassing all RLS policies.

## Secure patch direction

Never embed the `service_role` key client-side. Use the **anon** key in the
browser (gated by RLS), and keep the `service_role` key in a server-only
environment variable used only in server code.

```ts
// Browser: anon key only, protected by RLS.
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
);

// Server only (never imported by client components):
export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!, // server env, never bundled
);
```

Then **rotate the leaked key immediately** — a key that ever reached a client must
be considered compromised.
