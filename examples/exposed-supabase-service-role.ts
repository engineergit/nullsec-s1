// Unsafe example: Supabase service_role key exposed to a browser bundle.
// Expected category: EXPOSED_SECRET.
// The value below is an obvious placeholder, not a real key.

import { createClient } from "@supabase/supabase-js";

export const supabaseAdmin = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY,
);
