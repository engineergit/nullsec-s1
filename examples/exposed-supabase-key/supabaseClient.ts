// lib/supabaseClient.ts
// VULNERABLE EXAMPLE — a Supabase service_role key hardcoded into client-shipped
// code. The service_role key bypasses Row Level Security and must NEVER reach the
// browser. The value below is an obviously-fake placeholder.

import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = "https://EXAMPLE-project.supabase.co";

// SECURITY DISASTER: this is the service_role (admin) key, embedded in a file
// that gets bundled and shipped to the browser. It grants full read/write to the
// entire database, ignoring RLS.
const SUPABASE_SERVICE_ROLE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.EXAMPLE_PLACEHOLDER_NOT_A_REAL_KEY.service_role";

export const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
